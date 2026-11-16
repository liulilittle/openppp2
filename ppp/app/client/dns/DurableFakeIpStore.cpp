#include "DurableFakeIpStore.h"
#include <ppp/Filesystem.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ppp::app::client::dns {
namespace {
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;
constexpr uint32_t kSchema = 1;
constexpr std::size_t kMaxStoreFileBytes = 64u * 1024u * 1024u;
constexpr std::size_t kMaxHostnameBytes = 253;

void SetError(std::string* error, const std::string& value) {
    if (error) *error = value;
}

uint64_t Checksum(const std::string& value) {
    uint64_t hash = 14695981039346656037ull;
    for (unsigned char ch : value) {
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string Hex(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = digits[value & 15u];
        value >>= 4;
    }
    return out;
}

std::string Encode(const std::string& value) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2);
    for (unsigned char ch : value) {
        out.push_back(digits[ch >> 4]);
        out.push_back(digits[ch & 15]);
    }
    return out;
}

bool Decode(const std::string& value, std::string& out) {
    if ((value.size() & 1u) != 0) return false;
    auto digit = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
    };
    out.clear();
    out.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        int high = digit(value[i]);
        int low = digit(value[i + 1]);
        if (high < 0 || low < 0) return false;
        out.push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}

bool ParseUnsigned(const std::string& text, uint64_t& value) {
    if (text.empty()) return false;
    uint64_t result = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10) return false;
        result = result * 10 + digit;
    }
    value = result;
    return true;
}

bool ParseCidr(const std::string& cidr, uint32_t& network, uint32_t& mask,
               uint32_t& first, uint32_t& last, unsigned& prefix) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 == cidr.size() ||
        cidr.find('/', slash + 1) != std::string::npos) return false;
    const std::string ip = cidr.substr(0, slash);
    uint64_t parsed_prefix = 0;
    if (!ParseUnsigned(cidr.substr(slash + 1), parsed_prefix) || parsed_prefix == 0 || parsed_prefix > 32) return false;
    uint32_t address = 0;
    std::size_t offset = 0;
    for (int part = 0; part < 4; ++part) {
        const std::size_t dot = ip.find('.', offset);
        const std::size_t end = dot == std::string::npos ? ip.size() : dot;
        if (end == offset || (part < 3 && dot == std::string::npos) || (part == 3 && dot != std::string::npos)) return false;
        uint64_t octet = 0;
        if (!ParseUnsigned(ip.substr(offset, end - offset), octet) || octet > 255) return false;
        address = (address << 8) | static_cast<uint32_t>(octet);
        offset = end + 1;
    }
    prefix = static_cast<unsigned>(parsed_prefix);
    mask = prefix == 32 ? 0xffffffffu : 0xffffffffu << (32u - prefix);
    network = address & mask;
    const uint64_t end = static_cast<uint64_t>(network) | static_cast<uint32_t>(~mask);
    const uint64_t start = static_cast<uint64_t>(network) + 4;
    if (end == 0 || start >= end) return false;
    first = static_cast<uint32_t>(start);
    last = static_cast<uint32_t>(end - 1);
    return first <= last;
}

std::string NormalizeHostname(const std::string& hostname) {
    std::string result;
    result.reserve(hostname.size());
    for (unsigned char ch : hostname) {
        if (ch == 0 || ch > 0x7f) return {};
        result.push_back(static_cast<char>(std::tolower(ch)));
    }
    if (!result.empty() && result.back() == '.') result.pop_back();
    if (result.empty() || result.size() > kMaxHostnameBytes) return {};
    std::size_t start = 0;
    while (start < result.size()) {
        const auto dot = result.find('.', start);
        const auto end = dot == std::string::npos ? result.size() : dot;
        const auto length = end - start;
        if (length == 0 || length > 63 || result[start] == '-' || result[end - 1] == '-') return {};
        for (std::size_t i = start; i < end; ++i) {
            const unsigned char ch = static_cast<unsigned char>(result[i]);
            if (!(std::isalnum(ch) || ch == '-')) return {};
        }
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return result;
}

#if !defined(_WIN32)
bool WriteAll(int fd, const char* bytes, std::size_t size) {
    while (size != 0) {
        const ssize_t written = ::write(fd, bytes, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        bytes += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}
#endif

bool ReadFile(const fs::path& path, std::string& bytes) {
    error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxStoreFileBytes) return false;
    std::ifstream file(ppp::filesystem::StreamPath(path), std::ios::binary);
    if (!file) return false;
    bytes.resize(static_cast<std::size_t>(size));
    if (!bytes.empty()) file.read(&bytes[0], static_cast<std::streamsize>(bytes.size()));
    return file.good() || (file.eof() && static_cast<std::size_t>(file.gcount()) == bytes.size());
}

std::string SnapshotBody(const std::string& identity, uint32_t network, unsigned prefix,
                         uint64_t sequence, const std::map<uint32_t, std::string>& entries) {
    std::string body = "DFAKEIP|1|" + Encode(identity) + "|" + std::to_string(network) + "|" +
        std::to_string(prefix) + "|" + std::to_string(sequence) + "|" + std::to_string(entries.size()) + "|\n";
    for (const auto& item : entries)
        body += "E|" + std::to_string(item.first) + "|" + Encode(item.second) + "\n";
    return body;
}

std::string SnapshotBytes(const std::string& identity, uint32_t network, unsigned prefix,
                          uint64_t sequence, const std::map<uint32_t, std::string>& entries) {
    const auto body = SnapshotBody(identity, network, prefix, sequence, entries);
    const auto newline = body.find('\n');
    return body.substr(0, newline) + Hex(Checksum(body)) + "\n" + body.substr(newline + 1);
}

bool DurableFlushDirectory(const fs::path& path) {
#if defined(_WIN32)
    (void)path;
    return true;
#else
    int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
#endif
}

bool EnsureStorageDirectory(const fs::path& directory,
                            const DurableFakeIpStore::Options& options,
                            std::string* error) {
#if defined(_WIN32)
    // Windows has no portable equivalent to fsync(parent-directory); file flushes
    // and MOVEFILE_WRITE_THROUGH remain the available durability primitives here.
    error_code ec;
    if (!fs::exists(directory, ec)) {
        if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::DirectoryCreate)) {
            SetError(error, "storage directory create failed");
            return false;
        }
        fs::create_directories(directory, ec);
    }
    return !ec && fs::is_directory(directory, ec) && !ec;
#else
    fs::path current = directory.root_path();
    for (const auto& component : directory.relative_path()) {
        current /= component;
        struct stat status;
        if (::stat(current.c_str(), &status) != 0) {
            if (errno != ENOENT) { SetError(error, "storage directory metadata unavailable"); return false; }
            if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::DirectoryCreate)) {
                SetError(error, "storage directory create failed");
                return false;
            }
            if (::mkdir(current.c_str(), 0700) != 0 && errno != EEXIST) {
                SetError(error, "storage directory create failed");
                return false;
            }
            if (::stat(current.c_str(), &status) != 0) {
                SetError(error, "storage directory metadata unavailable");
                return false;
            }
        }
        if (!S_ISDIR(status.st_mode)) { SetError(error, "storage path component is not a directory"); return false; }

        const fs::path parent = current.parent_path().empty() ? fs::path("/") : current.parent_path();
        if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::ParentFlush)) {
            SetError(error, "storage directory parent flush failed");
            return false;
        }
        int fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
        if (fd < 0) { SetError(error, "storage directory parent open failed"); return false; }
        const bool flushed = ::fsync(fd) == 0;
        const bool closed = ::close(fd) == 0;
        if (!flushed || !closed) { SetError(error, "storage directory parent flush failed"); return false; }
    }
    struct stat status;
    if (::stat(directory.c_str(), &status) != 0 || !S_ISDIR(status.st_mode)) {
        SetError(error, "storage directory unavailable");
        return false;
    }
    return true;
#endif
}

bool CreateDurableEmptyFile(const fs::path& path) {
#if defined(_WIN32)
    HANDLE file = CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const bool ok = FlushFileBuffers(file) != 0;
    ::CloseHandle(file);
    return ok;
#else
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    const bool close_ok = ::close(fd) == 0;
    return ok && close_ok;
#endif
}

bool AtomicWrite(const fs::path& directory, const fs::path& target, const std::string& bytes,
                 const DurableFakeIpStore::Options& options, std::string* error) {
    const fs::path temporary = target.string() + ".tmp";
    if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::SnapshotWrite)) {
        SetError(error, "snapshot write failed"); return false;
    }
#if defined(_WIN32)
    HANDLE handle = CreateFileW(temporary.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { SetError(error, "snapshot open failed"); return false; }
    std::size_t offset = 0;
    bool wrote = true;
    while (offset < bytes.size()) {
        DWORD count = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
        if (!WriteFile(handle, bytes.data() + offset, chunk, &count, nullptr) || count == 0) { wrote = false; break; }
        offset += count;
    }
    if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::SnapshotFlush)) wrote = false;
    if (wrote && !FlushFileBuffers(handle)) wrote = false;
    ::CloseHandle(handle);
    if (!wrote) { SetError(error, "snapshot flush failed"); return false; }
    if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::SnapshotRename)) {
        SetError(error, "snapshot rename failed"); return false;
    }
    if (!MoveFileExW(temporary.wstring().c_str(), target.wstring().c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { SetError(error, "snapshot rename failed"); return false; }
#else
    int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { SetError(error, "snapshot open failed"); return false; }
    bool wrote = WriteAll(fd, bytes.data(), bytes.size());
    if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::SnapshotFlush)) wrote = false;
    if (wrote && ::fsync(fd) != 0) wrote = false;
    const int close_result = ::close(fd);
    if (close_result != 0) wrote = false;
    if (!wrote) { SetError(error, "snapshot flush failed"); return false; }
    if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::SnapshotRename)) {
        SetError(error, "snapshot rename failed"); return false;
    }
    if (::rename(temporary.c_str(), target.c_str()) != 0) { SetError(error, "snapshot rename failed"); return false; }
#endif
    if (options.allow_stage && !options.allow_stage(DurableFakeIpStore::Stage::DirectoryFlush)) {
        SetError(error, "directory flush failed"); return false;
    }
    if (!DurableFlushDirectory(directory)) { SetError(error, "directory flush failed"); return false; }
    return true;
}

bool ParseLines(const std::string& bytes, std::vector<std::string>& lines) {
    std::size_t start = 0;
    while (start < bytes.size()) {
        const auto newline = bytes.find('\n', start);
        if (newline == std::string::npos) return false;
        lines.emplace_back(bytes.substr(start, newline - start));
        start = newline + 1;
    }
    return true;
}

bool Split(const std::string& line, std::vector<std::string>& fields) {
    std::size_t start = 0;
    for (;;) {
        const auto bar = line.find('|', start);
        fields.emplace_back(line.substr(start, bar == std::string::npos ? bar : bar - start));
        if (bar == std::string::npos) return true;
        start = bar + 1;
    }
}

bool ParseSnapshot(const std::string& bytes, const std::string& identity, uint32_t network,
                   unsigned prefix, uint32_t first, uint32_t last, uint64_t& sequence,
                   std::map<std::string, uint32_t>& by_hostname,
                   std::map<uint32_t, std::string>& by_address) {
    std::vector<std::string> lines;
    if (!ParseLines(bytes, lines) || lines.empty()) return false;
    std::vector<std::string> header;
    Split(lines[0], header);
    if (header.size() != 8 || header[0] != "DFAKEIP" || header[1] != "1" ||
        header[2] != Encode(identity)) return false;
    uint64_t n = 0, p = 0, seq = 0, count = 0;
    if (!ParseUnsigned(header[3], n) || n != network || !ParseUnsigned(header[4], p) || p != prefix ||
        !ParseUnsigned(header[5], seq) || !ParseUnsigned(header[6], count) || count != lines.size() - 1) return false;
    std::string body = "DFAKEIP|1|" + header[2] + "|" + header[3] + "|" + header[4] + "|" + header[5] + "|" + header[6] + "|\n";
    for (std::size_t i = 1; i < lines.size(); ++i) body += lines[i] + "\n";
    if (header[7] != Hex(Checksum(body))) return false;
    for (std::size_t i = 1; i < lines.size(); ++i) {
        std::vector<std::string> fields;
        Split(lines[i], fields);
        if (fields.size() != 3 || fields[0] != "E") return false;
        uint64_t address64 = 0;
        std::string hostname;
        if (!ParseUnsigned(fields[1], address64) || address64 > 0xffffffffu ||
            !Decode(fields[2], hostname) || NormalizeHostname(hostname) != hostname || hostname.empty()) return false;
        const uint32_t address = static_cast<uint32_t>(address64);
        if (address < first || address > last || by_hostname.count(hostname) || by_address.count(address)) return false;
        by_hostname[hostname] = address;
        by_address[address] = hostname;
    }
    sequence = seq;
    return true;
}

} // namespace

DurableFakeIpStore::~DurableFakeIpStore() { Close(); }

bool DurableFakeIpStore::StageAllowed(Stage stage) const {
    return !options_.allow_stage || options_.allow_stage(stage);
}

bool DurableFakeIpStore::Open(const std::string& directory, const std::string& identity,
                              const std::string& cidr, const Options& options, std::string* error) {
    std::lock_guard<std::mutex> io_lock(io_mutex_);
    CloseWithIoLock();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        mapping_count_ = 0;
        pool_exhaustions_ = 0;
        persistence_errors_ = 0;
    }
    if (directory.empty() || identity.empty() || identity.size() > 1024 ||
        identity.find('\0') != std::string::npos) { SetError(error, "invalid directory or identity"); return false; }
    unsigned prefix = 0;
    uint32_t network = 0, mask = 0, first = 0, last = 0;
    if (!ParseCidr(cidr, network, mask, first, last, prefix)) { SetError(error, "invalid IPv4 CIDR"); return false; }
    const uint64_t pool_end = static_cast<uint64_t>(network) | static_cast<uint32_t>(~mask);
    constexpr uint32_t relay_network = 0xc6130000u;
    constexpr uint32_t relay_mask = 0xffff0000u;
    constexpr uint32_t relay_end = relay_network | static_cast<uint32_t>(~relay_mask);
    if (network <= relay_end && pool_end >= relay_network) {
        SetError(error, "configured pool overlaps reserved internal relay range");
        return false;
    }
    auto fail_persistence = [&](const std::string& message) {
        SetError(error, message);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++persistence_errors_;
        }
        CloseWithIoLock();
        return false;
    };
    options_ = options;
    error_code ec;
    const fs::path absolute_directory = fs::absolute(directory, ec).lexically_normal();
    if (ec) return fail_persistence("storage path unavailable");
    if (!EnsureStorageDirectory(absolute_directory, options_, error)) return fail_persistence("storage directory unavailable");
    directory_ = absolute_directory.string();
    const fs::path lock_path = fs::path(directory_) / "fake-ip.lock";
    if (!StageAllowed(Stage::Lock)) return fail_persistence("storage lock failed");
#if defined(_WIN32)
    HANDLE lock = CreateFileW(lock_path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (lock == INVALID_HANDLE_VALUE) return fail_persistence("storage lock is already held or unavailable");
    lock_handle_ = reinterpret_cast<intptr_t>(lock);
#else
    int lock = ::open(lock_path.c_str(), O_RDWR | O_CREAT, 0600);
    if (lock < 0 || ::flock(lock, LOCK_EX | LOCK_NB) != 0) {
        if (lock >= 0) ::close(lock);
        return fail_persistence("storage lock is already held or unavailable");
    }
    lock_handle_ = lock;
#endif
    identity_ = identity;
    cidr_ = cidr;
    network_ = network; mask_ = mask; first_ = first; last_ = last;
    sequence_ = 0; by_hostname_.clear(); by_address_.clear();
    const fs::path snapshot_path = fs::path(directory_) / "fake-ip.snapshot";
    const fs::path journal_path = fs::path(directory_) / "fake-ip.journal";
    const bool snapshot_exists = fs::exists(snapshot_path, ec);
    if (ec) return fail_persistence("snapshot metadata unavailable");
    const bool journal_exists = fs::exists(journal_path, ec);
    if (ec) return fail_persistence("journal metadata unavailable");
    if (snapshot_exists) {
        std::string bytes;
        if (!ReadFile(snapshot_path, bytes) || !ParseSnapshot(bytes, identity_, network_, prefix,
                first_, last_, sequence_, by_hostname_, by_address_)) {
            return fail_persistence("snapshot is corrupt or does not match configured identity and pool");
        }
        if (!journal_exists && (sequence_ != 0 || !by_hostname_.empty())) {
            return fail_persistence("journal is missing");
        }
        if (!journal_exists && (!CreateDurableEmptyFile(journal_path) || !DurableFlushDirectory(directory_))) {
            return fail_persistence("journal create or flush failed");
        }
    } else {
        if (journal_exists) return fail_persistence("journal exists without a snapshot");
        const auto bytes = SnapshotBytes(identity_, network_, prefix, 0, by_address_);
        if (!AtomicWrite(directory_, snapshot_path, bytes, options_, error)) return fail_persistence("snapshot write failed");
        if (!CreateDurableEmptyFile(journal_path)) return fail_persistence("journal create or flush failed");
        if (!DurableFlushDirectory(directory_)) return fail_persistence("directory flush failed");
    }
    std::string journal;
    if (!ReadFile(journal_path, journal)) return fail_persistence("journal read failed");
    std::size_t start = 0;
    const uint64_t checkpoint = sequence_;
    uint64_t expected = 0;
    bool tail_started = false;
    while (start < journal.size()) {
        const auto newline = journal.find('\n', start);
        if (newline == std::string::npos) break; // Only an incomplete final record may be discarded.
        const std::string line = journal.substr(start, newline - start);
        std::vector<std::string> fields;
        Split(line, fields);
        if (fields.size() != 5 || fields[0] != "A") return fail_persistence("invalid complete journal record");
        uint64_t seq = 0, address64 = 0;
        std::string hostname;
        const auto checksum_pos = line.rfind('|');
        const std::string prefix_text = checksum_pos == std::string::npos ? std::string() : line.substr(0, checksum_pos + 1);
        if (!ParseUnsigned(fields[1], seq) || !ParseUnsigned(fields[2], address64) ||
            address64 > 0xffffffffu || !Decode(fields[3], hostname) ||
            fields[4] != Hex(Checksum(prefix_text)) || NormalizeHostname(hostname) != hostname || hostname.empty()) {
            return fail_persistence("journal checksum, sequence, or identity is invalid");
        }
        if (expected == 0) {
            if (checkpoint == 0) {
                if (seq != 1) return fail_persistence("journal sequence is invalid");
                tail_started = true;
            } else if (seq > checkpoint) {
                if (seq != checkpoint + 1) return fail_persistence("journal sequence is invalid");
                tail_started = true;
            }
            expected = seq + 1;
        } else if (!tail_started && expected == checkpoint + 1 && seq == checkpoint + 1) {
            tail_started = true;
            expected = seq + 1;
        } else if (seq == expected) {
            ++expected;
        } else {
            return fail_persistence("journal sequence is invalid");
        }
        const uint32_t address = static_cast<uint32_t>(address64);
        if (address < first_ || address > last_) {
            return fail_persistence("journal mapping violates pool or uniqueness constraints");
        }
        if (seq <= checkpoint) {
            const auto prior = by_hostname_.find(hostname);
            if (prior == by_hostname_.end() || prior->second != address) {
                return fail_persistence("journal record conflicts with snapshot");
            }
        } else {
            if (seq != sequence_ + 1 || by_hostname_.count(hostname) || by_address_.count(address)) {
                return fail_persistence("journal mapping violates sequence or uniqueness constraints");
            }
            by_hostname_[hostname] = address;
            by_address_[address] = hostname;
            sequence_ = seq;
        }
        start = newline + 1;
    }
    if (start < journal.size()) {
        if (!StageAllowed(Stage::JournalRepair)) return fail_persistence("torn journal repair failed");
#if defined(_WIN32)
        HANDLE handle = CreateFileW(journal_path.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        LARGE_INTEGER position;
        position.QuadPart = static_cast<LONGLONG>(start);
        bool repaired = handle != INVALID_HANDLE_VALUE && SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) &&
            SetEndOfFile(handle);
        if (repaired && StageAllowed(Stage::JournalRepairFlush)) repaired = FlushFileBuffers(handle) != 0;
        else repaired = false;
        if (handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle);
#else
        int fd = ::open(journal_path.c_str(), O_WRONLY);
        bool repaired = fd >= 0 && ::ftruncate(fd, static_cast<off_t>(start)) == 0;
        if (repaired && StageAllowed(Stage::JournalRepairFlush)) repaired = ::fsync(fd) == 0;
        else repaired = false;
        if (fd >= 0 && ::close(fd) != 0) repaired = false;
#endif
        if (!repaired) return fail_persistence("torn journal repair flush failed");
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        mapping_count_ = by_hostname_.size();
        open_ = true;
        healthy_ = true;
    }
    return true;
}

void DurableFakeIpStore::Close() noexcept {
    std::lock_guard<std::mutex> io_lock(io_mutex_);
    CloseWithIoLock();
}

void DurableFakeIpStore::CloseWithIoLock() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        by_hostname_.clear();
        by_address_.clear();
        open_ = false;
        healthy_ = false;
    }
#if defined(_WIN32)
    if (lock_handle_ != -1) ::CloseHandle(reinterpret_cast<HANDLE>(lock_handle_));
#else
    if (lock_handle_ != -1) { ::flock(static_cast<int>(lock_handle_), LOCK_UN); ::close(static_cast<int>(lock_handle_)); }
#endif
    lock_handle_ = -1;
}

bool DurableFakeIpStore::AppendRecord(uint64_t sequence, uint32_t address,
                                      const std::string& hostname, std::string* error) {
    const std::string record = "A|" + std::to_string(sequence) + "|" + std::to_string(address) + "|" +
        Encode(hostname) + "|";
    const std::string line = record + Hex(Checksum(record)) + "\n";
    const fs::path path = fs::path(directory_) / "fake-ip.journal";
    if (!StageAllowed(Stage::JournalAppend)) { SetError(error, "journal append failed"); return false; }
#if defined(_WIN32)
    HANDLE handle = CreateFileW(path.wstring().c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { SetError(error, "journal open failed"); return false; }
    DWORD written = 0;
    const bool ok = WriteFile(handle, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) && written == line.size();
    if (!ok || !StageAllowed(Stage::JournalFlush) || !FlushFileBuffers(handle)) {
        ::CloseHandle(handle); SetError(error, "journal durable flush failed"); return false;
    }
    ::CloseHandle(handle);
#else
    int fd = ::open(path.c_str(), O_WRONLY | O_APPEND);
    if (fd < 0) { SetError(error, "journal open failed"); return false; }
    bool ok = WriteAll(fd, line.data(), line.size());
    if (!StageAllowed(Stage::JournalFlush)) ok = false;
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    if (!ok) { SetError(error, "journal durable flush failed"); return false; }
#endif
    return true;
}

bool DurableFakeIpStore::Allocate(const std::string& hostname, uint32_t& fake_ip_host,
                                  std::string* error) {
    std::lock_guard<std::mutex> io_lock(io_mutex_);
    fake_ip_host = 0;
    const std::string normalized = NormalizeHostname(hostname);
    if (normalized.empty()) { SetError(error, "invalid hostname"); return false; }
    uint32_t candidate = 0;
    uint64_t next_sequence = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!open_ || !healthy_) { SetError(error, "durable fake-ip store is unavailable"); return false; }
        auto found = by_hostname_.find(normalized);
        if (found != by_hostname_.end()) { fake_ip_host = found->second; return true; }
        candidate = first_;
        while (candidate <= last_ && by_address_.count(candidate)) {
            if (candidate == std::numeric_limits<uint32_t>::max()) break;
            ++candidate;
        }
        if (candidate > last_ || by_address_.count(candidate)) {
            ++pool_exhaustions_;
            SetError(error, "fake-ip pool exhausted");
            return false;
        }
        if (sequence_ == std::numeric_limits<uint64_t>::max()) {
            healthy_ = false;
            SetError(error, "fake-ip journal sequence exhausted");
            return false;
        }
        next_sequence = sequence_ + 1;
    }
    if (!AppendRecord(next_sequence, candidate, normalized, error)) {
        std::lock_guard<std::mutex> lock(mutex_);
        healthy_ = false;
        ++persistence_errors_;
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++sequence_;
        by_hostname_[normalized] = candidate;
        by_address_[candidate] = normalized;
        mapping_count_ = by_hostname_.size();
    }
    fake_ip_host = candidate;
    return true;
}

bool DurableFakeIpStore::LookupHostname(uint32_t fake_ip_host, std::string& hostname) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) { hostname.clear(); return false; }
    const auto found = by_address_.find(fake_ip_host);
    if (found == by_address_.end()) { hostname.clear(); return false; }
    hostname = found->second;
    return true;
}

bool DurableFakeIpStore::LookupAddress(const std::string& hostname, uint32_t& fake_ip_host) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) { fake_ip_host = 0; return false; }
    const std::string normalized = NormalizeHostname(hostname);
    const auto found = by_hostname_.find(normalized);
    if (normalized.empty() || found == by_hostname_.end()) { fake_ip_host = 0; return false; }
    fake_ip_host = found->second;
    return true;
}

bool DurableFakeIpStore::Contains(uint32_t address) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return open_ && (address & mask_) == network_;
}

bool DurableFakeIpStore::IsOpen() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return open_ && healthy_;
}

bool DurableFakeIpStore::GetRoute(uint32_t& route_network, int& route_prefix) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_ || !healthy_) {
        route_network = 0;
        route_prefix = 0;
        return false;
    }
    unsigned prefix = 0;
    uint32_t network = 0, mask = 0, first = 0, last = 0;
    if (!ParseCidr(cidr_, network, mask, first, last, prefix)) {
        route_network = 0;
        route_prefix = 0;
        return false;
    }
    route_network = htonl(network_);
    route_prefix = static_cast<int>(prefix);
    return true;
}

DurableFakeIpStore::Stats DurableFakeIpStore::SnapshotStats() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats stats;
    stats.fake_ip_mappings = mapping_count_;
    stats.fake_ip_exhaustions = pool_exhaustions_;
    stats.fake_ip_persistence_errors = persistence_errors_;
    return stats;
}

bool DurableFakeIpStore::Compact(std::string* error) {
    std::lock_guard<std::mutex> io_lock(io_mutex_);
    std::string identity;
    uint32_t network = 0;
    uint64_t sequence = 0;
    std::map<uint32_t, std::string> entries;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!open_ || !healthy_) { SetError(error, "durable fake-ip store is unavailable"); return false; }
        identity = identity_;
        network = network_;
        sequence = sequence_;
        entries = by_address_;
    }
    unsigned prefix = 0;
    uint32_t parsed_network = 0, mask = 0, first = 0, last = 0;
    if (!ParseCidr(cidr_, parsed_network, mask, first, last, prefix)) return false;
    auto poison = [this]() {
        std::lock_guard<std::mutex> lock(mutex_);
        healthy_ = false;
        ++persistence_errors_;
    };
    const auto bytes = SnapshotBytes(identity, network, prefix, sequence, entries);
    const fs::path snapshot = fs::path(directory_) / "fake-ip.snapshot";
    if (!AtomicWrite(directory_, snapshot, bytes, options_, error)) { poison(); return false; }
    const fs::path journal = fs::path(directory_) / "fake-ip.journal";
    if (!StageAllowed(Stage::JournalTruncate)) {
        poison();
        SetError(error, "journal truncate failed");
        return false;
    }
#if defined(_WIN32)
    HANDLE handle = CreateFileW(journal.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool ok = handle != INVALID_HANDLE_VALUE && StageAllowed(Stage::JournalTruncateFlush) && FlushFileBuffers(handle) != 0;
    if (handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle);
#else
    int fd = ::open(journal.c_str(), O_WRONLY | O_TRUNC);
    const bool ok = fd >= 0 && StageAllowed(Stage::JournalTruncateFlush) && ::fsync(fd) == 0;
    if (fd >= 0 && ::close(fd) != 0) { poison(); SetError(error, "journal truncate flush failed"); return false; }
#endif
    if (!ok || !DurableFlushDirectory(directory_)) { poison(); SetError(error, "journal truncate flush failed"); return false; }
    return true;
}

} // namespace ppp::app::client::dns
