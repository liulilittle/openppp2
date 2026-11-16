#include "PolicyStatusFile.h"
#include "PolicyUpdateService.h"
#include <ppp/Filesystem.h>

#include <json/json.h>

#include <atomic>
#include <algorithm>
#include <cerrno>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <limits>
#include <sstream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <process.h>
#else
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/file.h>
#if defined(__linux__)
#include <limits.h>
#endif
#endif

namespace ppp::app::client::policy {
namespace {
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;

bool HasOnlyKeys(const Json::Value& value, const std::initializer_list<const char*>& keys) {
    if (!value.isObject()) return false;
    for (const auto& key : value.getMemberNames()) {
        bool found = false;
        for (const char* allowed : keys) if (key == allowed) { found = true; break; }
        if (!found) return false;
    }
    return true;
}

bool ReadUnsigned(const Json::Value& value, std::uint64_t& output, bool positive = false) {
    if (!value.isUInt64()) return false;
    output = value.asUInt64();
    return !positive || output != 0;
}

bool ReadSigned(const Json::Value& value, std::int64_t& output) {
    if (!value.isInt64()) return false;
    output = value.asInt64();
    return true;
}

std::string FromJsonString(const Json::Value& value) {
    const Json::String text = value.asString();
    return std::string(text.data(), text.size());
}

bool ParseRecord(const Json::Value& root, PolicyStatusRecord& record, std::string& reason) {
    if (!HasOnlyKeys(root, {"schema", "identity", "pid", "process_start", "updated_at_ms",
        "session_generation", "active_version", "prepared_version", "prepared_digest",
        "durable_current", "durable_previous", "last_attempt_ms", "last_success_ms",
        "next_attempt_ms", "last_result", "last_diagnostic", "offline", "counters", "sources"})) {
        reason = "status object has an unknown key or is not an object";
        return false;
    }
    std::uint64_t schema = 0;
    if (!ReadUnsigned(root["schema"], schema, true) || schema != 1 ||
        !root["identity"].isString() || !ReadUnsigned(root["pid"], record.pid, true) ||
        !root["process_start"].isString() || FromJsonString(root["process_start"]).empty() ||
        !ReadSigned(root["updated_at_ms"], record.updated_at_ms) || record.updated_at_ms <= 0 ||
        !ReadUnsigned(root["session_generation"], record.session_generation) ||
        !ReadUnsigned(root["active_version"], record.active_version) ||
        !ReadUnsigned(root["prepared_version"], record.prepared_version) ||
        !root["prepared_digest"].isString() ||
        !root["durable_current"].isString() || !root["durable_previous"].isString() ||
        !ReadSigned(root["last_attempt_ms"], record.last_attempt_ms) ||
        !ReadSigned(root["last_success_ms"], record.last_success_ms) ||
        !ReadSigned(root["next_attempt_ms"], record.next_attempt_ms) ||
        !root["last_result"].isString() || !root["last_diagnostic"].isString() ||
        !root["offline"].isBool() ||
        !root["sources"].isArray()) {
        reason = "status schema or field types are invalid";
        return false;
    }
    record.schema = static_cast<std::uint32_t>(schema);
    record.identity = FromJsonString(root["identity"]);
    record.process_start = FromJsonString(root["process_start"]);
    record.prepared_digest = FromJsonString(root["prepared_digest"]);
    record.durable_current = FromJsonString(root["durable_current"]);
    record.durable_previous = FromJsonString(root["durable_previous"]);
    record.last_result = FromJsonString(root["last_result"]);
    record.last_diagnostic = FromJsonString(root["last_diagnostic"]);
    record.offline = root["offline"].asBool();
    if (root.isMember("counters")) {
        const auto& counters = root["counters"];
        if (!HasOnlyKeys(counters, {"dns_cache_hits", "dns_cache_misses", "dns_cache_coalesced",
            "dns_timeout_attempts", "dns_timeouts", "dns_upstream_failures", "dns_cancelled", "fake_ip_mappings",
            "fake_ip_exhaustions", "fake_ip_persistence_errors", "fake_ip_pending",
            "policy_direct", "policy_proxy", "policy_reject"}) ||
            !ReadUnsigned(counters["dns_cache_hits"], record.counters.dns_cache_hits) ||
            !ReadUnsigned(counters["dns_cache_misses"], record.counters.dns_cache_misses) ||
            !ReadUnsigned(counters["dns_cache_coalesced"], record.counters.dns_cache_coalesced) ||
            (counters.isMember("dns_timeout_attempts") &&
                !ReadUnsigned(counters["dns_timeout_attempts"], record.counters.dns_timeout_attempts)) ||
            !ReadUnsigned(counters["dns_timeouts"], record.counters.dns_timeouts) ||
            !ReadUnsigned(counters["dns_upstream_failures"], record.counters.dns_upstream_failures) ||
            !ReadUnsigned(counters["dns_cancelled"], record.counters.dns_cancelled) ||
            !ReadUnsigned(counters["fake_ip_mappings"], record.counters.fake_ip_mappings) ||
            !ReadUnsigned(counters["fake_ip_exhaustions"], record.counters.fake_ip_exhaustions) ||
            !ReadUnsigned(counters["fake_ip_persistence_errors"], record.counters.fake_ip_persistence_errors) ||
            !ReadUnsigned(counters["fake_ip_pending"], record.counters.fake_ip_pending) ||
            !ReadUnsigned(counters["policy_direct"], record.counters.policy_direct) ||
            !ReadUnsigned(counters["policy_proxy"], record.counters.policy_proxy) ||
            !ReadUnsigned(counters["policy_reject"], record.counters.policy_reject)) {
            reason = "status counters are invalid";
            return false;
        }
    }
    for (const auto& source : root["sources"]) {
        PolicyStatusSource item;
        if (!HasOnlyKeys(source, {"name", "url_redacted", "etag", "last_modified", "sha256", "bytes", "validated_at_ms"}) ||
            !source["name"].isString() || !source["url_redacted"].isString() ||
            !source["etag"].isString() || !source["last_modified"].isString() ||
            !source["sha256"].isString() || !ReadUnsigned(source["bytes"], item.bytes) ||
            !ReadSigned(source["validated_at_ms"], item.validated_at_ms)) {
            reason = "status source entry is invalid";
            return false;
        }
        item.name = FromJsonString(source["name"]);
        item.url_redacted = FromJsonString(source["url_redacted"]);
        item.etag = FromJsonString(source["etag"]);
        item.last_modified = FromJsonString(source["last_modified"]);
        item.sha256 = FromJsonString(source["sha256"]);
        record.sources.emplace_back(std::move(item));
    }
    return true;
}

Json::Value ToJson(const PolicyStatusRecord& status) {
    Json::Value root(Json::objectValue);
    root["schema"] = Json::UInt(status.schema);
    root["identity"] = status.identity.c_str();
    root["pid"] = Json::UInt64(status.pid);
    root["process_start"] = status.process_start.c_str();
    root["updated_at_ms"] = Json::Int64(status.updated_at_ms);
    root["session_generation"] = Json::UInt64(status.session_generation);
    root["active_version"] = Json::UInt64(status.active_version);
    root["prepared_version"] = Json::UInt64(status.prepared_version);
    root["prepared_digest"] = status.prepared_digest.c_str();
    root["durable_current"] = status.durable_current.c_str();
    root["durable_previous"] = status.durable_previous.c_str();
    root["last_attempt_ms"] = Json::Int64(status.last_attempt_ms);
    root["last_success_ms"] = Json::Int64(status.last_success_ms);
    root["next_attempt_ms"] = Json::Int64(status.next_attempt_ms);
    root["last_result"] = status.last_result.c_str();
    root["last_diagnostic"] = status.last_diagnostic.c_str();
    root["offline"] = status.offline;
    Json::Value counters(Json::objectValue);
    counters["dns_cache_hits"] = Json::UInt64(status.counters.dns_cache_hits);
    counters["dns_cache_misses"] = Json::UInt64(status.counters.dns_cache_misses);
    counters["dns_cache_coalesced"] = Json::UInt64(status.counters.dns_cache_coalesced);
    counters["dns_timeout_attempts"] = Json::UInt64(status.counters.dns_timeout_attempts);
    counters["dns_timeouts"] = Json::UInt64(status.counters.dns_timeouts);
    counters["dns_upstream_failures"] = Json::UInt64(status.counters.dns_upstream_failures);
    counters["dns_cancelled"] = Json::UInt64(status.counters.dns_cancelled);
    counters["fake_ip_mappings"] = Json::UInt64(status.counters.fake_ip_mappings);
    counters["fake_ip_exhaustions"] = Json::UInt64(status.counters.fake_ip_exhaustions);
    counters["fake_ip_persistence_errors"] = Json::UInt64(status.counters.fake_ip_persistence_errors);
    counters["fake_ip_pending"] = Json::UInt64(status.counters.fake_ip_pending);
    counters["policy_direct"] = Json::UInt64(status.counters.policy_direct);
    counters["policy_proxy"] = Json::UInt64(status.counters.policy_proxy);
    counters["policy_reject"] = Json::UInt64(status.counters.policy_reject);
    root["counters"] = std::move(counters);
    root["sources"] = Json::Value(Json::arrayValue);
    for (const auto& source : status.sources) {
        Json::Value item(Json::objectValue);
        item["name"] = source.name.c_str();
        item["url_redacted"] = source.url_redacted.c_str();
        item["etag"] = source.etag.c_str();
        item["last_modified"] = source.last_modified.c_str();
        item["sha256"] = source.sha256.c_str();
        item["bytes"] = Json::UInt64(source.bytes);
        item["validated_at_ms"] = Json::Int64(source.validated_at_ms);
        root["sources"].append(std::move(item));
    }
    return root;
}

bool ParseProcessStart(std::uint64_t pid, std::string& token, bool& unverifiable) {
    unverifiable = false;
#if defined(__linux__)
    if (pid > static_cast<std::uint64_t>(std::numeric_limits<pid_t>::max())) return false;
    const std::string statPath = "/proc/" + std::to_string(pid) + "/stat";
    const int fd = ::open(statPath.c_str(), O_RDONLY);
    if (fd < 0) { unverifiable = errno == EACCES; return false; }
    char buffer[4096];
    const ssize_t count = ::read(fd, buffer, sizeof(buffer));
    const int readError = errno;
    ::close(fd);
    if (count <= 0) { unverifiable = count < 0 && readError == EACCES; return false; }
    const std::string line(buffer, static_cast<std::size_t>(count));
    const auto close = line.rfind(')');
    if (close == std::string::npos || close + 2 >= line.size()) return false;
    std::istringstream fields(line.substr(close + 2));
    std::string field;
    // The remaining fields start at stat field 3; starttime is field 22.
    for (unsigned index = 3; index <= 22; ++index) {
        if (!(fields >> field)) return false;
        if (index == 3 && (field == "Z" || field == "X")) return false;
        if (index == 22) {
            std::ifstream bootIdFile("/proc/sys/kernel/random/boot_id");
            std::string bootId;
            if (!std::getline(bootIdFile, bootId) || bootId.empty()) { unverifiable = true; return false; }
            token = bootId + ":" + field;
            return true;
        }
    }
    return false;
#elif defined(_WIN32)
    if (pid > std::numeric_limits<DWORD>::max()) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process) {
        unverifiable = GetLastError() == ERROR_ACCESS_DENIED;
        return false;
    }
    FILETIME creation, exitTime, kernel, user;
    DWORD exitCode = 0;
    const BOOL ok = GetProcessTimes(process, &creation, &exitTime, &kernel, &user) &&
        GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE;
    ::CloseHandle(process);
    if (!ok) { unverifiable = true; return false; }
    ULARGE_INTEGER value;
    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    token = std::to_string(value.QuadPart);
    return true;
#else
    (void)pid;
    (void)token;
    unverifiable = true;
    return false;
#endif
}

bool AtomicReplace(const std::string& path, const std::string& bytes, std::string& error) {
    static std::atomic<std::uint64_t> sequence{0};
    const std::string temporary = path + ".tmp." + std::to_string(
#if defined(_WIN32)
        static_cast<unsigned long long>(_getpid())
#else
        static_cast<unsigned long long>(::getpid())
#endif
        ) + "." + std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
#if defined(_WIN32)
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output || !(output.write(bytes.data(), static_cast<std::streamsize>(bytes.size())))) {
            error = "cannot write temporary status file";
            return false;
        }
        output.flush();
        if (!output) { error = "cannot flush temporary status file"; return false; }
    }
    if (!MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(temporary.c_str());
        error = "cannot atomically replace status file";
        return false;
    }
    return true;
#else
    int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { error = "cannot create temporary status file"; return false; }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            ::close(fd); ::unlink(temporary.c_str()); error = "cannot write temporary status file"; return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    const int flushResult = ::fsync(fd);
    const int closeResult = ::close(fd);
    if (flushResult != 0 || closeResult != 0) {
        ::unlink(temporary.c_str()); error = "cannot flush temporary status file"; return false;
    }
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        ::unlink(temporary.c_str()); error = "cannot atomically replace status file"; return false;
    }
    return true;
#endif
}

} // namespace

struct PolicyStatusWriterLease::Impl final {
    std::string status_path;
    std::string identity;
#if defined(_WIN32)
    HANDLE handle = INVALID_HANDLE_VALUE;
    OVERLAPPED overlapped{};
#else
    int fd = -1;
#endif
};

PolicyStatusRecord MakePolicyStatusRecord(const PolicyUpdateStatus& status,
    std::uint64_t pid, const std::string& processStart, std::uint64_t sessionGeneration,
    std::int64_t updatedAtMs, bool offline) {
    PolicyStatusRecord record;
    record.identity = status.identity_fingerprint;
    record.pid = pid;
    record.process_start = processStart;
    record.updated_at_ms = updatedAtMs;
    record.session_generation = sessionGeneration;
    record.active_version = status.active_version;
    record.prepared_version = status.prepared_version;
    record.prepared_digest = status.prepared_digest;
    record.durable_current = status.durable_current ? "present" : "";
    record.durable_previous = status.durable_previous ? "present" : "";
    record.last_attempt_ms = status.last_attempt_ms;
    record.last_success_ms = status.last_success_ms;
    record.next_attempt_ms = status.next_attempt_ms;
    record.last_result = status.last_result;
    record.last_diagnostic = status.last_diagnostic;
    record.offline = offline || status.offline;
    record.sources.reserve(status.sources.size());
    for (const auto& source : status.sources) {
        record.sources.push_back({source.name, source.url_redacted, source.etag,
            source.last_modified, source.sha256, static_cast<std::uint64_t>(source.bytes),
            source.validated_at_ms});
    }
    return record;
}

PolicyStatusRecord MakePolicyStatusRecord(const PolicyUpdateStatus& status,
    const PolicyStatusCounters& counters, std::uint64_t pid, const std::string& processStart,
    std::uint64_t sessionGeneration, std::int64_t updatedAtMs, bool offline) {
    auto record = MakePolicyStatusRecord(status, pid, processStart, sessionGeneration, updatedAtMs, offline);
    record.counters = counters;
    return record;
}

PolicyStatusWriterLease::PolicyStatusWriterLease() noexcept = default;
PolicyStatusWriterLease::~PolicyStatusWriterLease() { Release(); }
PolicyStatusWriterLease::PolicyStatusWriterLease(PolicyStatusWriterLease&& other) noexcept = default;
PolicyStatusWriterLease& PolicyStatusWriterLease::operator=(PolicyStatusWriterLease&& other) noexcept {
    if (this != &other) {
        Release();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

bool PolicyStatusWriterLease::TryAcquire(const std::string& statusPath,
    const std::string& expectedIdentity, std::string& error) {
    Release();
    error.clear();
    if (statusPath.empty() || expectedIdentity.empty()) {
        error = "status lease arguments are invalid";
        return false;
    }
    const fs::path parent = fs::path(statusPath).parent_path();
    error_code ec;
    if (!parent.empty()) fs::create_directories(parent, ec);
    if (ec) {
        error = "cannot create status directory";
        return false;
    }
    const std::string lockPath = statusPath + ".lock";
    auto lease = std::make_unique<Impl>();
    lease->status_path = statusPath;
    lease->identity = expectedIdentity;
#if defined(_WIN32)
    lease->handle = CreateFileA(lockPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (lease->handle == INVALID_HANDLE_VALUE) {
        error = "cannot open status lease file";
        return false;
    }
    if (!LockFileEx(lease->handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
        0, MAXDWORD, MAXDWORD, &lease->overlapped)) {
        ::CloseHandle(lease->handle);
        lease->handle = INVALID_HANDLE_VALUE;
        error = "status writer lease is already held";
        return false;
    }
#else
    lease->fd = ::open(lockPath.c_str(), O_RDWR | O_CREAT, 0600);
    if (lease->fd < 0) {
        error = "cannot open status lease file";
        return false;
    }
    if (::flock(lease->fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(lease->fd);
        lease->fd = -1;
        error = "status writer lease is already held";
        return false;
    }
#endif
    impl_ = std::move(lease);
    return true;
}

bool PolicyStatusWriterLease::Write(const PolicyStatusRecord& status, std::string& error) const {
    if (!OwnsLease()) {
        error = "status writer lease is not held";
        return false;
    }
    if (status.identity != impl_->identity) {
        error = "status identity does not match writer lease";
        return false;
    }
    return WriteStatusAtomically(impl_->status_path, impl_->identity, status, error);
}

bool PolicyStatusWriterLease::OwnsLease() const noexcept {
    if (!impl_) return false;
#if defined(_WIN32)
    return impl_->handle != INVALID_HANDLE_VALUE;
#else
    return impl_->fd >= 0;
#endif
}

void PolicyStatusWriterLease::Release() noexcept {
    if (!impl_) return;
#if defined(_WIN32)
    if (impl_->handle != INVALID_HANDLE_VALUE) {
        UnlockFileEx(impl_->handle, 0, MAXDWORD, MAXDWORD, &impl_->overlapped);
        ::CloseHandle(impl_->handle);
        impl_->handle = INVALID_HANDLE_VALUE;
    }
#else
    if (impl_->fd >= 0) {
        ::flock(impl_->fd, LOCK_UN);
        ::close(impl_->fd);
        impl_->fd = -1;
    }
#endif
    impl_.reset();
}

const char* PolicyStatusStateName(PolicyStatusState state) noexcept {
    switch (state) {
    case PolicyStatusState::Online: return "online";
    case PolicyStatusState::Offline: return "offline";
    case PolicyStatusState::Stale: return "stale";
    default: return "unverified";
    }
}

bool WriteStatusAtomically(const std::string& path, const std::string& expectedIdentity,
    const PolicyStatusRecord& status, std::string& error) {
    error.clear();
    if (path.empty() || expectedIdentity.empty() || status.schema != 1 ||
        status.identity != expectedIdentity || status.pid == 0 || status.process_start.empty() ||
        status.updated_at_ms <= 0) {
        error = "status record identity or required fields are invalid";
        return false;
    }
#if defined(_WIN32)
    if (status.pid > std::numeric_limits<DWORD>::max()) {
        error = "status process ID is outside the Windows PID range";
        return false;
    }
#endif
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    const Json::String encoded = Json::writeString(builder, ToJson(status));
    return AtomicReplace(path, std::string(encoded.data(), encoded.size()) + "\n", error);
}

bool GetCurrentProcessIdentity(std::uint64_t& pid, std::string& processStart,
    std::string& error) {
    error.clear();
#if defined(_WIN32)
    pid = static_cast<std::uint64_t>(_getpid());
#else
    pid = static_cast<std::uint64_t>(::getpid());
#endif
    bool unverifiable = false;
    if (!ParseProcessStart(pid, processStart, unverifiable)) {
        processStart.clear();
        if (unverifiable) {
            processStart = "unverified";
            return true;
        }
        error = "cannot read current process identity";
        return false;
    }
    return true;
}

PolicyStatusResult ReadStatus(const std::string& path, const std::string& expectedIdentity,
    std::int64_t nowMs, std::int64_t staleAfterMs) {
    PolicyStatusResult result;
    if (path.empty() || expectedIdentity.empty() || nowMs <= 0 || staleAfterMs < 0) {
        result.reason = "status query arguments are invalid";
        return result;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) { result.reason = "status file is unavailable"; return result; }
    constexpr std::size_t maxStatusBytes = 1024u * 1024u;
    std::string bytes;
    bytes.reserve(4096);
    char buffer[4096];
    while (input && bytes.size() <= maxStatusBytes) {
        const auto remaining = maxStatusBytes + 1 - bytes.size();
        input.read(buffer, static_cast<std::streamsize>(std::min(sizeof(buffer), remaining)));
        const auto count = input.gcount();
        if (count > 0) bytes.append(buffer, static_cast<std::size_t>(count));
    }
    if (bytes.size() > maxStatusBytes) {
        result.reason = "status file exceeds the size limit";
        return result;
    }
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    builder["allowComments"] = false;
    builder["allowTrailingCommas"] = false;
    builder["rejectDupKeys"] = true;
    builder["failIfExtra"] = true;
    Json::Value root;
    Json::String parseError;
    auto reader = std::unique_ptr<Json::CharReader>(builder.newCharReader());
    if (!reader || !reader->parse(bytes.data(), bytes.data() + bytes.size(), &root, &parseError) ||
        !ParseRecord(root, result.record, result.reason)) {
        if (result.reason.empty()) result.reason = "status file is malformed";
        return result;
    }
    if (result.record.identity != expectedIdentity) {
        result.reason = "status identity does not match requested identity";
        return result;
    }
    if (result.record.updated_at_ms > nowMs) {
        result.state = PolicyStatusState::Stale;
        result.reason = "status timestamp is in the future";
        return result;
    }
    if (nowMs - result.record.updated_at_ms > staleAfterMs) {
        result.state = PolicyStatusState::Stale;
        result.reason = "status timestamp is too old";
        return result;
    }
    if (result.record.offline) {
        result.state = PolicyStatusState::Offline;
        result.reason = "status file marks the process offline";
        return result;
    }
    std::string actualStart;
    bool unverifiable = false;
    if (!ParseProcessStart(result.record.pid, actualStart, unverifiable)) {
        result.state = unverifiable ? PolicyStatusState::Unverified : PolicyStatusState::Offline;
        result.reason = unverifiable ? "process identity cannot be verified" : "process is not running";
        return result;
    }
    if (actualStart != result.record.process_start) {
        result.state = PolicyStatusState::Offline;
        result.reason = "process start identity does not match";
        return result;
    }
    result.state = PolicyStatusState::Online;
    result.reason = "process identity and status freshness are verified";
    return result;
}

} // namespace ppp::app::client::policy
