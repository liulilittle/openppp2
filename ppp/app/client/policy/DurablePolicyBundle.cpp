#include "DurablePolicyBundle.h"
#include <ppp/Filesystem.h>

#include <json/json.h>
#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ppp::app::client::policy {
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;
namespace {
constexpr std::size_t kSourceLimit = 64u * 1024u * 1024u;
constexpr std::size_t kBundleLimit = 256u * 1024u * 1024u;

bool SafeName(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '-' || ch == '_';
    });
}

bool SafeDigest(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

Json::String Jstr(const std::string& value) { return Json::String(value.data(), value.size()); }
std::string Stdstr(const Json::String& value) { return std::string(value.data(), value.size()); }

bool ReadFile(const fs::path& path, std::size_t max_size, std::string& bytes) {
    error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > max_size || size > std::numeric_limits<std::size_t>::max()) return false;
    std::ifstream input(ppp::filesystem::StreamPath(path), std::ios::binary);
    if (!input) return false;
    bytes.resize(static_cast<std::size_t>(size));
    if (size != 0) input.read(bytes.data(), static_cast<std::streamsize>(size));
    return input.good() || input.eof() && static_cast<std::size_t>(input.gcount()) == bytes.size();
}

bool FlushFile(const fs::path& path) {
#if defined(_WIN32)
    HANDLE handle = CreateFileW(path.wstring().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    const bool ok = FlushFileBuffers(handle) != 0;
    ::CloseHandle(handle);
    return ok;
#else
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
#endif
}

bool FlushDirectory(const fs::path& path) {
#if defined(_WIN32)
    // Directory handles cannot be flushed portably on Windows; pointer replacement uses WRITE_THROUGH.
    (void)path;
    return true;
#else
    int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
#endif
}

bool AtomicWrite(const fs::path& target, const std::string& bytes, std::string& error,
    const std::function<bool(FileDurablePolicyBundleStore::Stage)>& allow_stage,
    bool* rename_attempted = nullptr) {
    if (rename_attempted) *rename_attempted = false;
    static std::atomic_uint64_t sequence{0};
    fs::path temporary = target;
    temporary += ".tmp-" + std::to_string(sequence.fetch_add(1, std::memory_order_relaxed)) +
        "-" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    if (allow_stage && !allow_stage(FileDurablePolicyBundleStore::Stage::Write)) {
        error = "cannot write durable temporary file";
        return false;
    }
    error_code ec;
    {
        std::ofstream output(ppp::filesystem::StreamPath(temporary), std::ios::binary | std::ios::trunc);
        if (!output) { error = "cannot create durable temporary file"; return false; }
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) { error = "cannot write durable temporary file"; output.close(); fs::remove(temporary, ec); return false; }
    }
    if (allow_stage && !allow_stage(FileDurablePolicyBundleStore::Stage::Flush)) {
        error = "cannot flush durable temporary file";
        fs::remove(temporary, ec);
        return false;
    }
    if (!FlushFile(temporary)) {
        error = "cannot fsync durable temporary file";
        fs::remove(temporary, ec);
        return false;
    }
    if (allow_stage && !allow_stage(FileDurablePolicyBundleStore::Stage::Rename)) {
        error = "cannot atomically replace durable pointer";
        fs::remove(temporary, ec);
        return false;
    }
    if (rename_attempted) *rename_attempted = true;
#if defined(_WIN32)
    for (int attempt = 0; ; ++attempt) {
        if (MoveFileExW(temporary.wstring().c_str(), target.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { ec.clear(); break; }
        ec = error_code(GetLastError(), std::system_category());
        if (attempt >= 100) { error = "cannot atomically replace durable pointer: last win32 error " + std::to_string(ec.value()); return false; }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        // Antivirus/indexer scans can transiently lock freshly written files.
    }
#else
    fs::rename(temporary, target, ec);
#endif
    if (ec) {
        error = "cannot atomically replace durable pointer";
        fs::remove(temporary, ec);
        return false;
    }
    if ((allow_stage && !allow_stage(FileDurablePolicyBundleStore::Stage::DirectoryFlush)) ||
        !FlushDirectory(target.parent_path())) {
        error = "cannot fsync durable directory";
        return false;
    }
    return true;
}

bool EnsureDirectory(const fs::path& path, std::string& error) {
    error_code ec;
    fs::create_directories(path, ec);
    if (ec || !fs::is_directory(path, ec) || ec) {
        error = "cannot create durable policy directory";
        return false;
    }
    return true;
}

Json::Value SourceManifest(const DurablePolicySource& source) {
    Json::Value value(Json::objectValue);
    value["format"] = Jstr(source.format);
    value["tag"] = Jstr(source.tag);
    value["sha256"] = Jstr(source.sha256);
    value["content_sha256"] = Jstr(PolicySha256(source.bytes));
    value["length"] = Json::UInt64(source.bytes.size());
    value["validated_at_ms"] = Json::Int64(source.validated_at_ms);
    value["url"] = Jstr(RedactPolicySourceUrl(source.url_redacted));
    value["url_fingerprint"] = Jstr(source.url_fingerprint);
    value["etag"] = Jstr(source.etag);
    value["last_modified"] = Jstr(source.last_modified);
    return value;
}

bool ReadPointer(const fs::path& path, std::string& digest) {
    std::string content;
    if (!ReadFile(path, 128, content)) return false;
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) content.pop_back();
    if (!SafeDigest(content)) return false;
    content = Lower(std::move(content));
    digest = std::move(content);
    return true;
}

bool RemoveAndFlush(const fs::path& path, std::string& error,
    const std::function<bool(FileDurablePolicyBundleStore::Stage)>& allow_stage) {
    error_code ec;
    fs::remove(path, ec);
    if (ec) { error = "cannot remove durable pointer"; return false; }
    if ((allow_stage && !allow_stage(FileDurablePolicyBundleStore::Stage::DirectoryFlush)) ||
        !FlushDirectory(path.parent_path())) { error = "cannot fsync durable directory"; return false; }
    return true;
}

bool PersistImmutable(const fs::path& path, const std::string& bytes, std::size_t max_size,
    std::string& error,
    const std::function<bool(FileDurablePolicyBundleStore::Stage)>& allow_stage) {
    error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (!ec && !ppp::filesystem::IsNotFound(status.type())) {
        std::string existing;
        if (!fs::is_regular_file(status) || !ReadFile(path, max_size, existing) || existing != bytes) {
            error = "content-addressed durable file already exists with different or invalid contents";
            return false;
        }
        return true;
    }
    if (ec && !ppp::filesystem::IsNotFound(ec)) {
        error = "cannot inspect content-addressed durable file";
        return false;
    }
    bool rename_attempted = false;
    if (AtomicWrite(path, bytes, error, allow_stage, &rename_attempted)) return true;
    if (!rename_attempted || error != "cannot atomically replace durable pointer") return false;

    // A concurrent writer may have completed the same content-addressed write.
    ec.clear();
    const auto after_status = fs::symlink_status(path, ec);
    std::string existing;
    if (!ec && fs::is_regular_file(after_status) && ReadFile(path, max_size, existing) && existing == bytes) {
        error.clear();
        return true;
    }
    return false;
}

DurablePolicyLoad LoadManifest(const fs::path& directory, const std::string& identity,
    const std::string& digest, bool found) {
    DurablePolicyLoad result;
    result.found = found;
    if (!SafeDigest(identity) || !SafeDigest(digest)) { result.error = "invalid durable identity or manifest digest"; return result; }
    std::string text;
    if (!ReadFile(directory / ("manifest-" + digest + ".json"), 1024u * 1024u, text) || PolicySha256(text) != digest) {
        result.error = "durable manifest is missing or corrupt"; return result;
    }
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true; builder["failIfExtra"] = true;
    builder["allowComments"] = false; builder["allowTrailingCommas"] = false;
    Json::Value manifest;
    Json::String parse_error;
    auto reader = std::unique_ptr<Json::CharReader>(builder.newCharReader());
    if (!reader->parse(text.data(), text.data() + text.size(), &manifest, &parse_error) ||
        !manifest.isObject() || !manifest["schema"].isUInt() || manifest["schema"].asUInt() != 1 ||
        !manifest["identity"].isString() || Stdstr(manifest["identity"].asString()) != identity ||
        !manifest["rules"].isObject() || !manifest["sources"].isObject()) {
        result.error = "durable manifest schema or identity is invalid"; return result;
    }
    const fs::path blobs = directory / "blobs";
    auto load_blob = [&](const Json::Value& record, std::string& bytes) {
        if (!record.isObject() || !record["content_sha256"].isString() || !record["length"].isUInt64()) return false;
        const std::string hash = Stdstr(record["content_sha256"].asString());
        const auto length = record["length"].asUInt64();
        if (!SafeDigest(hash) || length > kSourceLimit) return false;
        const std::string canonical_hash = Lower(hash);
        return ReadFile(blobs / canonical_hash, kSourceLimit, bytes) && bytes.size() == length &&
            PolicySha256(bytes) == canonical_hash;
    };
    if (!manifest["rules"].isMember("validated_at_ms") || !manifest["rules"]["validated_at_ms"].isInt64() ||
        !load_blob(manifest["rules"], result.bundle.rules)) {
        result.error = "durable rules payload is missing or corrupt"; return result;
    }
    result.bundle.schema = 1;
    result.bundle.identity_fingerprint = identity;
    result.bundle.rules_validated_at_ms = manifest["rules"]["validated_at_ms"].asInt64();
    std::size_t aggregate = result.bundle.rules.size();
    for (const auto& name_value : manifest["sources"].getMemberNames()) {
        const std::string name(name_value.data(), name_value.size());
        const auto& record = manifest["sources"][name_value];
        if (!SafeName(name) || !record.isObject() || !record["format"].isString() || !record["tag"].isString() ||
            !record["sha256"].isString() || !record["url"].isString() || !record["url_fingerprint"].isString() ||
            !record["etag"].isString() || !record["last_modified"].isString() ||
            !record["validated_at_ms"].isInt64()) {
            result.error = "durable source manifest fields have invalid types"; return result;
        }
        DurablePolicySource source;
        source.name = name;
        source.format = Stdstr(record["format"].asString());
        source.tag = Stdstr(record["tag"].asString());
        source.sha256 = Stdstr(record["sha256"].asString());
        source.url_redacted = Stdstr(record["url"].asString());
        source.url_fingerprint = Stdstr(record["url_fingerprint"].asString());
        source.etag = Stdstr(record["etag"].asString());
        source.last_modified = Stdstr(record["last_modified"].asString());
        source.validated_at_ms = record["validated_at_ms"].asInt64();
        if ((!source.sha256.empty() && !SafeDigest(source.sha256)) ||
            (!source.url_fingerprint.empty() && !SafeDigest(source.url_fingerprint))) {
            result.error = "durable source pin is malformed"; return result;
        }
        if (!load_blob(record, source.bytes) || aggregate > kBundleLimit - source.bytes.size() ||
            (!source.sha256.empty() && PolicySha256(source.bytes) != Lower(source.sha256))) {
            result.error = "durable rule-set reference is missing, corrupt, or over limit"; return result;
        }
        aggregate += source.bytes.size();
        result.bundle.rule_sets.emplace(name, std::move(source));
    }
    if (aggregate > kBundleLimit) result.error = "durable policy bundle exceeds aggregate size limit";
    return result;
}

} // namespace

std::string PolicySha256(const std::string& bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &digest_size, EVP_sha256(), nullptr) != 1 || digest_size != 32) return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string result(64, '0');
    for (std::size_t i = 0; i < 32; ++i) {
        result[i * 2] = hex[digest[i] >> 4];
        result[i * 2 + 1] = hex[digest[i] & 15];
    }
    return result;
}

std::string RedactPolicySourceUrl(const std::string& url) {
    const auto scheme = url.find("://");
    if (scheme == std::string::npos) return "[invalid-url]";
    const auto authority_begin = scheme + 3;
    const auto authority_end = url.find_first_of("/?#", authority_begin);
    std::string authority = url.substr(authority_begin,
        (authority_end == std::string::npos ? url.size() : authority_end) - authority_begin);
    const auto at = authority.rfind('@');
    if (at != std::string::npos) authority.erase(0, at + 1);
    if (authority.empty()) return "[invalid-url]";
    return url.substr(0, scheme + 3) + authority + "/[redacted]";
}

std::string PolicyStoreRootForConfig(const std::string& config_path) {
    if (config_path.empty()) return {};
    return (fs::absolute(config_path).parent_path() / ".ppp-policy").lexically_normal().string();
}

FileDurablePolicyBundleStore::FileDurablePolicyBundleStore(std::string root_directory, Options options)
    : root_directory_(std::move(root_directory)), options_(std::move(options)) {}

bool FileDurablePolicyBundleStore::StageAllowed(Stage stage) const {
    return !options_.allow_stage || options_.allow_stage(stage);
}

std::unique_ptr<DurablePolicyWriterLock> FileDurablePolicyBundleStore::AcquireWriterLock(std::string& error) {
    if (root_directory_.empty()) { error = "durable policy store path is empty"; return {}; }
    const fs::path lock_path = fs::path(root_directory_) / ".writer.lock";
    if (!EnsureDirectory(lock_path.parent_path(), error)) return {};
#if defined(_WIN32)
    HANDLE handle = CreateFileW(lock_path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { error = "cannot open durable policy lock"; return {}; }
    OVERLAPPED overlapped{};
    if (!LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped)) {
        ::CloseHandle(handle); error = "cannot acquire durable policy lock"; return {};
    }
    class Lock final : public DurablePolicyWriterLock {
    public:
        Lock(HANDLE h, OVERLAPPED o) : handle(h), overlapped(o) {}
        ~Lock() override { UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &overlapped); ::CloseHandle(handle); }
        HANDLE handle; OVERLAPPED overlapped;
    };
    return std::make_unique<Lock>(handle, overlapped);
#else
    int fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0 || ::flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) ::close(fd);
        error = "cannot acquire durable policy lock";
        return {};
    }
    class Lock final : public DurablePolicyWriterLock {
    public:
        explicit Lock(int value) : fd(value) {}
        ~Lock() override { ::flock(fd, LOCK_UN); ::close(fd); }
        int fd;
    };
    return std::make_unique<Lock>(fd);
#endif
}

DurablePolicyLoad FileDurablePolicyBundleStore::LoadCurrent(const std::string& identity) {
    if (!SafeDigest(identity)) { DurablePolicyLoad result; result.error = "invalid durable identity fingerprint"; return result; }
    const fs::path directory = fs::path(root_directory_) / identity;
    std::string digest;
    if (!ReadPointer(directory / "CURRENT", digest)) return {};
    return LoadManifest(directory, identity, digest, true);
}

DurablePolicyLoad FileDurablePolicyBundleStore::LoadPrevious(const std::string& identity) {
    if (!SafeDigest(identity)) { DurablePolicyLoad result; result.error = "invalid durable identity fingerprint"; return result; }
    const fs::path directory = fs::path(root_directory_) / identity;
    std::string digest;
    if (!ReadPointer(directory / "PREVIOUS", digest)) return {};
    return LoadManifest(directory, identity, digest, true);
}

bool FileDurablePolicyBundleStore::Commit(const DurablePolicyBundle& bundle, std::string& error) {
    if (bundle.schema != 1 || !SafeDigest(bundle.identity_fingerprint) || bundle.rules.size() > kSourceLimit) {
        error = "invalid durable policy bundle"; return false;
    }
    std::size_t aggregate = bundle.rules.size();
    for (const auto& entry : bundle.rule_sets) {
        const auto& source = entry.second;
        if (!SafeName(entry.first) || source.name != entry.first || source.bytes.size() > kSourceLimit ||
            aggregate > kBundleLimit - source.bytes.size()) {
            error = "invalid or oversized durable rule-set"; return false;
        }
        if (!source.sha256.empty() && (!SafeDigest(source.sha256) || PolicySha256(source.bytes) != Lower(source.sha256))) {
            error = "configured rule-set SHA-256 mismatch"; return false;
        }
        aggregate += source.bytes.size();
    }
    if (aggregate > kBundleLimit) { error = "durable policy bundle exceeds aggregate size limit"; return false; }
    const fs::path directory = fs::path(root_directory_) / bundle.identity_fingerprint;
    if (!EnsureDirectory(directory / "blobs", error)) return false;
    Json::Value manifest(Json::objectValue);
    manifest["schema"] = Json::UInt(1); manifest["identity"] = Jstr(bundle.identity_fingerprint);
    Json::Value rules(Json::objectValue);
    rules["content_sha256"] = Jstr(PolicySha256(bundle.rules)); rules["length"] = Json::UInt64(bundle.rules.size());
    rules["validated_at_ms"] = Json::Int64(bundle.rules_validated_at_ms);
    manifest["rules"] = rules;
    Json::Value sources(Json::objectValue);
    auto write_blob = [&](const std::string& bytes) {
        const auto digest = PolicySha256(bytes);
        const fs::path path = directory / "blobs" / digest;
        return PersistImmutable(path, bytes, kSourceLimit, error,
            [this](Stage stage) { return StageAllowed(stage); });
    };
    if (!write_blob(bundle.rules)) { if (error.empty()) error = "cannot persist rules blob"; return false; }
    for (const auto& entry : bundle.rule_sets) {
        if (!write_blob(entry.second.bytes)) { if (error.empty()) error = "cannot persist rule-set blob"; return false; }
        sources[Jstr(entry.first)] = SourceManifest(entry.second);
    }
    manifest["sources"] = sources;
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    const Json::String manifest_json = Json::writeString(writer, manifest);
    const std::string manifest_text(manifest_json.data(), manifest_json.size());
    const std::string digest = PolicySha256(manifest_text);
    if (!PersistImmutable(directory / ("manifest-" + digest + ".json"), manifest_text,
            1024u * 1024u, error, [this](Stage stage) { return StageAllowed(stage); })) return false;
    const fs::path current_path = directory / "CURRENT";
    const fs::path previous_path = directory / "PREVIOUS";
    std::string old_current_raw, old_previous_raw, old_current;
    error_code ec;
    const bool had_current = fs::exists(current_path, ec);
    if (ec || (had_current && !ReadFile(current_path, 128, old_current_raw))) { error = "cannot snapshot durable current pointer"; return false; }
    const bool had_previous = fs::exists(previous_path, ec);
    if (ec || (had_previous && !ReadFile(previous_path, 128, old_previous_raw))) { error = "cannot snapshot durable previous pointer"; return false; }
    const bool valid_current = ReadPointer(current_path, old_current);
    auto restore_pointer = [](const fs::path& path, bool existed, const std::string& bytes, std::string& rollback_error) {
        if (existed) return AtomicWrite(path, bytes, rollback_error, {});
        return RemoveAndFlush(path, rollback_error, {});
    };
    auto rollback_pointers = [&] {
        std::string current_error, previous_error;
        const bool current_ok = restore_pointer(current_path, had_current, old_current_raw, current_error);
        const bool previous_ok = restore_pointer(previous_path, had_previous, old_previous_raw, previous_error);
        if (!current_ok || !previous_ok) {
            error += "; pointer rollback failed";
            if (!current_error.empty()) error += ": " + current_error;
            if (!previous_error.empty()) error += ": " + previous_error;
        }
    };
    const auto allow_stage = [this](Stage stage) { return StageAllowed(stage); };
    if (!AtomicWrite(current_path, digest + "\n", error, allow_stage)) { rollback_pointers(); return false; }
    if (valid_current && !AtomicWrite(previous_path, old_current + "\n", error, allow_stage)) {
        rollback_pointers();
        return false;
    }
    return true;
}

bool FileDurablePolicyBundleStore::RefreshCurrent(const DurablePolicyBundle& bundle, std::string& error) {
    if (bundle.schema != 1 || !SafeDigest(bundle.identity_fingerprint) || bundle.rules.size() > kSourceLimit) {
        error = "invalid durable policy bundle"; return false;
    }
    const fs::path directory = fs::path(root_directory_) / bundle.identity_fingerprint;
    if (!EnsureDirectory(directory / "blobs", error)) return false;
    auto persist_blob = [&](const std::string& bytes) {
        const auto digest = PolicySha256(bytes);
        const fs::path path = directory / "blobs" / digest;
        return PersistImmutable(path, bytes, kSourceLimit, error,
            [this](Stage stage) { return StageAllowed(stage); });
    };
    Json::Value manifest(Json::objectValue);
    manifest["schema"] = Json::UInt(1);
    manifest["identity"] = Jstr(bundle.identity_fingerprint);
    Json::Value rules(Json::objectValue);
    rules["content_sha256"] = Jstr(PolicySha256(bundle.rules));
    rules["length"] = Json::UInt64(bundle.rules.size());
    rules["validated_at_ms"] = Json::Int64(bundle.rules_validated_at_ms);
    manifest["rules"] = rules;
    Json::Value sources(Json::objectValue);
    for (const auto& entry : bundle.rule_sets) {
        if (!SafeName(entry.first) || entry.second.name != entry.first || entry.second.bytes.size() > kSourceLimit ||
            (!entry.second.sha256.empty() && (!SafeDigest(entry.second.sha256) ||
                PolicySha256(entry.second.bytes) != Lower(entry.second.sha256))) ||
            !persist_blob(entry.second.bytes)) {
            if (error.empty()) error = "invalid or unpersistable durable rule-set";
            return false;
        }
        sources[Jstr(entry.first)] = SourceManifest(entry.second);
    }
    if (!persist_blob(bundle.rules)) { if (error.empty()) error = "cannot persist rules blob"; return false; }
    manifest["sources"] = sources;
    Json::StreamWriterBuilder writer; writer["indentation"] = "";
    const Json::String manifest_json = Json::writeString(writer, manifest);
    const std::string text(manifest_json.data(), manifest_json.size());
    const auto digest = PolicySha256(text);
    if (!PersistImmutable(directory / ("manifest-" + digest + ".json"), text,
            1024u * 1024u, error, [this](Stage stage) { return StageAllowed(stage); })) return false;
    const fs::path current_path = directory / "CURRENT";
    std::string current, current_raw;
    if (!ReadPointer(current_path, current) || !ReadFile(current_path, 128, current_raw)) { error = "cannot refresh absent durable current bundle"; return false; }
    if (AtomicWrite(current_path, digest + "\n", error,
            [this](Stage stage) { return StageAllowed(stage); })) return true;
    std::string rollback_error;
    if (!AtomicWrite(current_path, current_raw, rollback_error, {})) error += "; current pointer rollback failed: " + rollback_error;
    return false;
}

bool FileDurablePolicyBundleStore::RestorePreviousAsCurrent(const std::string& identity, std::string& error) {
    if (!SafeDigest(identity)) { error = "invalid durable identity fingerprint"; return false; }
    const fs::path directory = fs::path(root_directory_) / identity;
    std::string previous;
    std::string current;
    if (!ReadPointer(directory / "PREVIOUS", previous)) {
        return RemoveAndFlush(directory / "CURRENT", error, [this](Stage stage) { return StageAllowed(stage); });
    }
    const auto loaded_previous = LoadManifest(directory, identity, previous, true);
    if (!loaded_previous.Ok()) { error = "durable previous policy bundle failed integrity validation"; return false; }
    ReadPointer(directory / "CURRENT", current);
    if (current == previous) return true;
    std::string current_raw;
    error_code ec;
    const bool had_current = fs::exists(directory / "CURRENT", ec);
    if (ec || (had_current && !ReadFile(directory / "CURRENT", 128, current_raw))) { error = "cannot snapshot current pointer before fallback"; return false; }
    if (AtomicWrite(directory / "CURRENT", previous + "\n", error,
            [this](Stage stage) { return StageAllowed(stage); })) return true;
    std::string rollback_error;
    const bool rolled_back = had_current
        ? AtomicWrite(directory / "CURRENT", current_raw, rollback_error, {})
        : RemoveAndFlush(directory / "CURRENT", rollback_error, {});
    if (!rolled_back) error += "; current pointer rollback failed: " + rollback_error;
    return false;
}

bool FileDurablePolicyBundleStore::ClearCurrent(const std::string& identity, std::string& error) {
    if (!SafeDigest(identity)) { error = "invalid durable identity fingerprint"; return false; }
    const fs::path directory = fs::path(root_directory_) / identity;
    error_code ec;
    fs::remove(directory / "CURRENT", ec);
    if (ec) { error = "cannot clear durable current pointer"; return false; }
    if ((StageAllowed(Stage::DirectoryFlush) == false) || !FlushDirectory(directory)) {
        error = "cannot fsync durable directory"; return false;
    }
    return true;
}

bool FileDurablePolicyBundleStore::CapturePointerState(const std::string& identity,
    DurablePolicyPointerState& state, std::string& error) {
    if (!SafeDigest(identity)) { error = "invalid durable identity fingerprint"; return false; }
    const fs::path directory = fs::path(root_directory_) / identity;
    auto capture = [&](const fs::path& path, bool& present, std::string& bytes) {
        error_code ec;
        present = fs::exists(path, ec);
        return !ec && (!present || ReadFile(path, 128, bytes));
    };
    state = {};
    if (!capture(directory / "CURRENT", state.current_present, state.current_bytes) ||
        !capture(directory / "PREVIOUS", state.previous_present, state.previous_bytes)) {
        error = "cannot capture durable pointer state";
        return false;
    }
    return true;
}

bool FileDurablePolicyBundleStore::RestorePointerState(const std::string& identity,
    const DurablePolicyPointerState& state, std::string& error) {
    if (!SafeDigest(identity)) { error = "invalid durable identity fingerprint"; return false; }
    const fs::path directory = fs::path(root_directory_) / identity;
    if (!EnsureDirectory(directory, error)) return false;
    auto restore = [&](const fs::path& path, bool present, const std::string& bytes) {
        if (present) return AtomicWrite(path, bytes, error,
            [this](Stage stage) { return StageAllowed(stage); });
        return RemoveAndFlush(path, error, [this](Stage stage) { return StageAllowed(stage); });
    };
    const bool current_ok = restore(directory / "CURRENT", state.current_present, state.current_bytes);
    const bool previous_ok = restore(directory / "PREVIOUS", state.previous_present, state.previous_bytes);
    return current_ok && previous_ok;
}

} // namespace ppp::app::client::policy
