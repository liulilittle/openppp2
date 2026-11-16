#include "NetworkRecoveryJournal.h"

#include <ppp/Filesystem.h>
#include <ppp/net/IPEndPoint.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>

#if defined(_WIN32)
#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/tap/WintunAdapter.h>
#include <windows/ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/app/client/WindowsIPv6Snapshot.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>
#elif defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
#include <ppp/app/client/route/LinuxRoutePlatform.h>
#elif defined(_MACOS)
#include <ppp/app/client/route/DarwinRoutePlatform.h>
#endif

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ppp::app::client {
namespace {
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;
constexpr std::size_t kMaxBytes = 4u * 1024u * 1024u;
constexpr std::size_t kMaxFieldBytes = 1024u * 1024u;

void Error(std::string* out, const char* value) { if (out) *out = value; }

uint64_t Checksum(const std::string& value) {
    uint64_t hash = 14695981039346656037ull;
    for (unsigned char ch : value) { hash ^= ch; hash *= 1099511628211ull; }
    return hash;
}

std::string Hex(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    std::string result(16, '0');
    for (int i = 15; i >= 0; --i) { result[static_cast<std::size_t>(i)] = digits[value & 15u]; value >>= 4; }
    return result;
}

std::string Encode(const std::string& value) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (unsigned char ch : value) { result.push_back(digits[ch >> 4]); result.push_back(digits[ch & 15u]); }
    return result;
}

bool Decode(const std::string& value, std::string& result) {
    if ((value.size() & 1u) != 0 || value.size() > kMaxFieldBytes * 2) return false;
    auto digit = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
    };
    result.clear(); result.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int high = digit(value[i]), low = digit(value[i + 1]);
        if (high < 0 || low < 0) return false;
        result.push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}

bool Read(const fs::path& path, std::string& bytes) {
    error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxBytes) return false;
    std::ifstream stream(ppp::filesystem::StreamPath(path), std::ios::binary);
    if (!stream) return false;
    bytes.resize(static_cast<std::size_t>(size));
    if (!bytes.empty()) stream.read(&bytes[0], static_cast<std::streamsize>(bytes.size()));
    return stream.good() || (stream.eof() && static_cast<std::size_t>(stream.gcount()) == bytes.size());
}

bool FlushDirectory(const fs::path& path) {
#if defined(_WIN32)
    (void)path;
    return true;
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
#endif
}

#if defined(_WIN32)
struct AssignedIPv4Snapshot final {
    std::string guid;
    std::string luid;
    int interface_index = -1;
    boost::asio::ip::address address;
    boost::asio::ip::address mask;
    boost::asio::ip::address gateway;
};

bool ParseAssignedIPv4Snapshot(const std::string& value,
                               AssignedIPv4Snapshot& snapshot) noexcept {
    std::vector<std::string> fields;
    std::size_t begin = 0;
    for (;;) {
        const std::size_t end = value.find('|', begin);
        fields.emplace_back(value.substr(begin,
            end == std::string::npos ? end : end - begin));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    if (fields.size() != 7 || fields[0] != "ipv4-v2" ||
        fields[1].empty() || fields[2].empty()) {
        return false;
    }
    try {
        snapshot.interface_index = std::stoi(fields[3]);
    } catch (...) {
        return false;
    }
    if (snapshot.interface_index < 0) return false;
    snapshot.guid = fields[1];
    snapshot.luid = fields[2];
    boost::system::error_code ec;
    snapshot.address = boost::asio::ip::make_address(fields[4], ec);
    if (ec || !snapshot.address.is_v4()) return false;
    ec.clear();
    snapshot.mask = boost::asio::ip::make_address(fields[5], ec);
    if (ec || !snapshot.mask.is_v4()) return false;
    snapshot.gateway = boost::asio::ip::address();
    if (!fields[6].empty()) {
        ec.clear();
        snapshot.gateway = boost::asio::ip::make_address(fields[6], ec);
        if (ec || !snapshot.gateway.is_v4()) return false;
    }
    return true;
}

bool AssignedIPv4IdentityMatches(
    const ppp::win32::network::NetworkInterfacePtr& current,
    const AssignedIPv4Snapshot& snapshot) noexcept {
    return current && current->InterfaceIndex == snapshot.interface_index &&
        _stricmp(current->Guid.data(), snapshot.guid.data()) == 0 &&
        !current->InterfaceLuid.empty() && _stricmp(current->InterfaceLuid.data(), snapshot.luid.data()) == 0;
}

bool AssignedIPv4StateMatches(
    const ppp::win32::network::NetworkInterfacePtr& current,
    const AssignedIPv4Snapshot& snapshot) noexcept {
    if (!AssignedIPv4IdentityMatches(current, snapshot)) return false;

    std::vector<std::pair<std::string, std::string>> ipv4;
    for (std::size_t i = 0; i < current->IPAddresses.size(); ++i) {
        boost::system::error_code ec;
        const auto address = boost::asio::ip::make_address(
            current->IPAddresses[i].data(), ec);
        if (ec || !address.is_v4()) continue;
        std::string mask;
        if (i < current->IPSubnet.size()) {
            boost::system::error_code mask_ec;
            const auto parsed_mask = boost::asio::ip::make_address(
                current->IPSubnet[i].data(), mask_ec);
            if (!mask_ec && parsed_mask.is_v4()) mask = parsed_mask.to_string();
        }
        ipv4.emplace_back(address.to_string(), std::move(mask));
    }
    if (ipv4.size() != 1 ||
        ipv4.front().first != snapshot.address.to_string() ||
        ipv4.front().second != snapshot.mask.to_string()) {
        return false;
    }

    std::vector<std::string> gateways;
    for (const auto& value : current->DefaultIPGateway) {
        boost::system::error_code ec;
        const auto gateway = boost::asio::ip::make_address(value.data(), ec);
        if (!ec && gateway.is_v4()) gateways.emplace_back(gateway.to_string());
    }
    if (snapshot.gateway.is_v4()) {
        return gateways.size() == 1 && gateways.front() == snapshot.gateway.to_string();
    }
    return gateways.empty();
}

bool RecoverAssignedIPv4(const NetworkRecoveryJournal::Entry& entry) noexcept {
    AssignedIPv4Snapshot before;
    AssignedIPv4Snapshot after;
    if (!ParseAssignedIPv4Snapshot(entry.before, before) ||
        !ParseAssignedIPv4Snapshot(entry.after, after) ||
        _stricmp(before.guid.data(), after.guid.data()) != 0 ||
        before.luid != after.luid ||
        before.interface_index != after.interface_index ||
        _stricmp(entry.target.data(), before.guid.data()) != 0) {
        return false;
    }

    auto current = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(
        before.interface_index);
    if (!AssignedIPv4IdentityMatches(current, before)) return false;
    // A crash can leave the adapter untouched. Treat that as already cleaned.
    if (AssignedIPv4StateMatches(current, before)) return true;
    // Never overwrite a user or another VPN's update. Only the exact value
    // written by this journal entry may be rolled back.
    if (!AssignedIPv4StateMatches(current, after)) return false;

    const uint32_t ip = htonl(before.address.to_v4().to_uint());
    const uint32_t mask = htonl(before.mask.to_v4().to_uint());
    const uint32_t gateway = before.gateway.is_v4()
        ? htonl(before.gateway.to_v4().to_uint())
        : ppp::net::IPEndPoint::NoneAddress;
    if (!ppp::tap::TapWindows::SetAddresses(before.interface_index, ip, mask, gateway)) {
        return false;
    }

    current = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(
        before.interface_index);
    return AssignedIPv4StateMatches(current, before);
}

bool RecoverWindowsFirewall(const NetworkRecoveryJournal::Entry& entry) noexcept {
    if (entry.resource != "windows-firewall") return false;
    ppp::win32::network::Fw::ApplicationOwnership before;
    ppp::win32::network::Fw::ApplicationOwnership after;
    if (!ppp::win32::network::Fw::DeserializeApplicationOwnership(
            entry.before, &before) ||
        !ppp::win32::network::Fw::DeserializeApplicationOwnership(
            entry.after, &after) ||
        before.name != after.name ||
        before.executable_path != after.executable_path ||
        entry.target != ppp::win32::network::Fw::ApplicationOwnershipTarget(after)) {
        return false;
    }
    // RestoreApplicationOwned performs the live COM compare and only removes
    // an exact rule created by this journal entry.  A missing rule is already
    // clean; a user or another VPN's edit remains pending for a later retry.
    return ppp::win32::network::Fw::RestoreApplicationOwned(after);
}
#endif

bool Split(const std::string& line, std::vector<std::string>& fields) {
    std::size_t start = 0;
    for (;;) {
        const auto bar = line.find('|', start);
        fields.emplace_back(line.substr(start, bar == std::string::npos ? bar : bar - start));
        if (bar == std::string::npos) return true;
        start = bar + 1;
    }
}

std::string Body(const std::vector<NetworkRecoveryJournal::Entry>& entries) {
    std::string body;
    for (const auto& entry : entries) {
        body += "E|" + Encode(entry.resource) + "|" + Encode(entry.target) + "|" +
            Encode(entry.before) + "|" + Encode(entry.after) + "|" +
            (entry.confirmed ? "confirmed" : "intent") + "\n";
    }
    return body;
}

bool Parse(const std::string& bytes, const std::string& owner,
           std::vector<NetworkRecoveryJournal::Entry>& entries) {
    const auto newline = bytes.find('\n');
    if (newline == std::string::npos) return false;
    std::vector<std::string> header;
    Split(bytes.substr(0, newline), header);
    if (header.size() != 4 || header[0] != "NWRJ" || header[1] != "1" ||
        header[2] != Encode(owner) || header[3] != Hex(Checksum(bytes.substr(newline + 1)))) return false;
    std::size_t start = newline + 1;
    while (start < bytes.size()) {
        const auto end = bytes.find('\n', start);
        if (end == std::string::npos) return false;
        std::vector<std::string> fields;
        Split(bytes.substr(start, end - start), fields);
        if (fields.size() != 6 || fields[0] != "E" ||
            (fields[5] != "intent" && fields[5] != "confirmed")) return false;
        NetworkRecoveryJournal::Entry entry;
        if (!Decode(fields[1], entry.resource) || !Decode(fields[2], entry.target) ||
            !Decode(fields[3], entry.before) || !Decode(fields[4], entry.after) ||
            entry.resource.empty() || entry.target.empty() || entry.before.size() > kMaxFieldBytes ||
            entry.after.size() > kMaxFieldBytes) return false;
        entry.confirmed = fields[5] == "confirmed";
        const auto duplicate = std::find_if(entries.begin(), entries.end(), [&](const auto& item) {
            return item.resource == entry.resource && item.target == entry.target;
        });
        if (duplicate != entries.end()) return false;
        entries.emplace_back(std::move(entry));
        start = end + 1;
    }
    return true;
}

bool WriteAtomic(const fs::path& directory, const fs::path& target, const std::string& bytes,
                 const NetworkRecoveryJournal::Options& options, std::string* error) {
    if (options.allow_stage && !options.allow_stage(NetworkRecoveryJournal::Stage::Write)) { Error(error, "journal write failed"); return false; }
    const fs::path temporary = target.string() + ".tmp";
#if defined(_WIN32)
    HANDLE handle = CreateFileW(temporary.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { Error(error, "journal open failed"); return false; }
    DWORD written = 0;
    const bool wrote = bytes.empty() || (WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size());
    bool flushed = wrote;
    if (options.allow_stage && !options.allow_stage(NetworkRecoveryJournal::Stage::Flush)) flushed = false;
    if (flushed) flushed = FlushFileBuffers(handle) != 0;
    ::CloseHandle(handle);
    if (!flushed) { Error(error, "journal flush failed"); return false; }
    if (options.allow_stage && !options.allow_stage(NetworkRecoveryJournal::Stage::Rename)) { Error(error, "journal rename failed"); return false; }
    if (!MoveFileExW(temporary.wstring().c_str(), target.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        // GetLastError=32 (sharing violation) means the journal file is held
        // by an unreleased handle; report the code so retry can distinguish
        // a transient lock from an unrecoverable path error.
        char buf[96];
        snprintf(buf, sizeof(buf), "journal rename failed (GetLastError=%lu)",
            static_cast<unsigned long>(GetLastError()));
        Error(error, buf);
        return false;
    }
#else
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { Error(error, "journal open failed"); return false; }
    bool wrote = true;
    const char* data = bytes.data();
    std::size_t left = bytes.size();
    while (left) { const ssize_t count = ::write(fd, data, left); if (count < 0 && errno == EINTR) continue; if (count <= 0) { wrote = false; break; } data += count; left -= static_cast<std::size_t>(count); }
    if (options.allow_stage && !options.allow_stage(NetworkRecoveryJournal::Stage::Flush)) wrote = false;
    if (wrote && ::fsync(fd) != 0) wrote = false;
    if (::close(fd) != 0) wrote = false;
    if (!wrote) { Error(error, "journal flush failed"); return false; }
    if (options.allow_stage && !options.allow_stage(NetworkRecoveryJournal::Stage::Rename)) { Error(error, "journal rename failed"); return false; }
    if (::rename(temporary.c_str(), target.c_str()) != 0) { Error(error, "journal rename failed"); return false; }
#endif
    if (options.allow_stage && !options.allow_stage(NetworkRecoveryJournal::Stage::DirectoryFlush)) { Error(error, "journal directory flush failed"); return false; }
    if (!FlushDirectory(directory)) { Error(error, "journal directory flush failed"); return false; }
    return true;
}
} // namespace

NetworkRecoveryJournal::~NetworkRecoveryJournal() { Close(); }

bool NetworkRecoveryJournal::StageAllowed(Stage stage) const { return !options_.allow_stage || options_.allow_stage(stage); }

bool NetworkRecoveryJournal::Open(const std::string& directory, const std::string& owner,
                                  const Options& options, std::string* error) {
    Close();
    if (directory.empty() || owner.empty() || owner.size() > kMaxFieldBytes) { Error(error, "invalid journal identity"); return false; }
    options_ = options; directory_ = directory; owner_ = owner;
    const fs::path path(directory_);
    error_code ec;
    if (!fs::exists(path, ec)) {
        if (!StageAllowed(Stage::DirectoryCreate) || !fs::create_directories(path, ec) || ec) { Error(error, "journal directory unavailable"); Close(); return false; }
#if !defined(_WIN32)
        ::chmod(path.c_str(), 0700);
#endif
    }
    if (ec || !fs::is_directory(path, ec) || ec) { Error(error, "journal directory unavailable"); Close(); return false; }
#if !defined(_WIN32)
    ::chmod(path.c_str(), 0700);
#endif
    const fs::path lock = path / "network-recovery.lock";
#if defined(_WIN32)
    if (!StageAllowed(Stage::Lock)) { Error(error, "journal lock failed"); Close(); return false; }
    HANDLE handle = CreateFileW(lock.wstring().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) { Error(error, "journal lock failed"); Close(); return false; }
    lock_handle_ = reinterpret_cast<std::intptr_t>(handle);
#else
    if (!StageAllowed(Stage::Lock)) { Error(error, "journal lock failed"); Close(); return false; }
    const int fd = ::open(lock.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0 || ::flock(fd, LOCK_EX | LOCK_NB) != 0) { if (fd >= 0) ::close(fd); Error(error, "journal lock failed"); Close(); return false; }
    ::fchmod(fd, 0600); lock_handle_ = fd;
#endif
    const fs::path journal = path / "network-recovery.journal";
    if (fs::exists(journal, ec)) {
        std::string bytes;
        if (ec || !Read(journal, bytes) || !Parse(bytes, owner_, entries_)) { Error(error, "journal is corrupt or has a different owner"); Close(); return false; }
#if !defined(_WIN32)
        // Recovery state can contain interface configuration; do not leave it
        // readable by unrelated local users after an existing file is reused.
        ::chmod(journal.c_str(), 0600);
#endif
    } else if (ec) { Error(error, "journal metadata unavailable"); Close(); return false; }
    open_ = true;
    return true;
}

void NetworkRecoveryJournal::CloseWithLock() noexcept {
#if defined(_WIN32)
    if (lock_handle_ != -1) ::CloseHandle(reinterpret_cast<HANDLE>(lock_handle_));
#else
    if (lock_handle_ != -1) { flock(static_cast<int>(lock_handle_), LOCK_UN); ::close(static_cast<int>(lock_handle_)); }
#endif
    lock_handle_ = -1;
}

void NetworkRecoveryJournal::Close() noexcept { open_ = false; entries_.clear(); CloseWithLock(); directory_.clear(); owner_.clear(); }

bool NetworkRecoveryJournal::Rewrite(std::string* error) {
    if (!open_) { Error(error, "journal is not open"); return false; }
    const std::string body = Body(entries_);
    const std::string bytes = "NWRJ|1|" + Encode(owner_) + "|" + Hex(Checksum(body)) + "\n" + body;
    return WriteAtomic(fs::path(directory_), fs::path(directory_) / "network-recovery.journal", bytes, options_, error);
}

bool NetworkRecoveryJournal::RecordIntent(const std::string& resource, const std::string& target,
                                          const std::string& before, const std::string& after,
                                          std::string* error) {
    if (resource.empty() || target.empty() || before.size() > kMaxFieldBytes || after.size() > kMaxFieldBytes) { Error(error, "invalid journal entry"); return false; }
    auto it = std::find_if(entries_.begin(), entries_.end(), [&](const auto& item) { return item.resource == resource && item.target == target; });
    const bool inserted = it == entries_.end();
    Entry previous;
    if (!inserted) previous = *it;
    if (inserted) entries_.push_back({resource, target, before, after, false});
    else { it->before = before; it->after = after; it->confirmed = false; }
    if (!Rewrite(error)) {
        if (inserted) entries_.pop_back();
        else *it = std::move(previous);
        return false;
    }
    return true;
}

bool NetworkRecoveryJournal::Confirm(const std::string& resource, const std::string& target, std::string* error) {
    auto it = std::find_if(entries_.begin(), entries_.end(), [&](const auto& item) { return item.resource == resource && item.target == target; });
    if (it == entries_.end()) { Error(error, "journal entry not found"); return false; }
    const bool previous = it->confirmed; it->confirmed = true;
    if (!Rewrite(error)) { it->confirmed = previous; return false; }
    return true;
}

bool NetworkRecoveryJournal::ReplaceTarget(
    const std::string& resource, const std::string& old_target,
    const std::string& new_target, const std::string& after,
    std::string* error) {
    if (resource.empty() || old_target.empty() || new_target.empty() ||
        after.size() > kMaxFieldBytes) {
        Error(error, "invalid journal entry");
        return false;
    }
    auto old = std::find_if(entries_.begin(), entries_.end(),
        [&](const auto& item) {
            return item.resource == resource && item.target == old_target;
        });
    if (old == entries_.end()) {
        Error(error, "journal entry not found");
        return false;
    }
    const auto collision = std::find_if(entries_.begin(), entries_.end(),
        [&](const auto& item) {
            return item.resource == resource && item.target == new_target;
        });
    if (collision != entries_.end() && collision != old) {
        Error(error, "journal entry already exists");
        return false;
    }
    Entry previous = *old;
    old->target = new_target;
    old->after = after;
    old->confirmed = false;
    if (!Rewrite(error)) {
        *old = std::move(previous);
        return false;
    }
    return true;
}

bool NetworkRecoveryJournal::Remove(const std::string& resource, const std::string& target, std::string* error) {
    const auto it = std::find_if(entries_.begin(), entries_.end(), [&](const auto& item) { return item.resource == resource && item.target == target; });
    if (it == entries_.end()) { Error(error, "journal entry not found"); return false; }
    const Entry backup = *it; entries_.erase(it);
    if (!Rewrite(error)) { entries_.push_back(backup); return false; }
    return true;
}

bool NetworkRecoveryJournal::RecoverPending(const RecoveryHandler& handler, std::string* error) {
    return RecoverPending(
        [](const Entry&) noexcept { return true; }, handler, error);
}

bool NetworkRecoveryJournal::RecoverPending(
    const ResourceFilter& filter,
    const RecoveryHandler& handler,
    std::string* error) {
    if (!open_ || !filter || !handler) {
        Error(error, "invalid recovery handler");
        return false;
    }

    // Work on a snapshot because a successful callback removes the current
    // entry and rewrites the journal.  Never let a failed callback or remove
    // erase state needed by the next retry.
    std::vector<Entry> pending;
    pending.reserve(entries_.size());
    for (const Entry& entry : entries_) {
        if (filter(entry)) {
            pending.emplace_back(entry);
        }
    }
    bool complete = true;
    for (const Entry& entry : pending) {
        if (!handler(entry)) {
            complete = false;
            continue;
        }
        std::string remove_error;
        if (!Remove(entry.resource, entry.target, &remove_error)) {
            complete = false;
            if (error && error->empty()) *error = remove_error;
        }
    }
    // A resource-scoped pass is complete when all selected entries have been
    // restored. Entries belonging to other handlers intentionally remain.
    return complete;
}

bool NetworkRecoveryJournal::RecoverPendingFor(
    const std::string& resource,
    const RecoveryHandler& handler,
    std::string* error) {
    if (resource.empty()) {
        Error(error, "invalid recovery resource");
        return false;
    }
    return RecoverPending(
        [&resource](const Entry& entry) noexcept {
            return entry.resource == resource;
        }, handler, error);
}

bool NetworkRecoveryJournal::IsRecoveryCommand(int argc, const char* const* argv) noexcept {
    if (argc <= 0 || argv == nullptr) return false;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            (std::strcmp(argv[i], "--network-recovery") == 0 ||
             std::strncmp(argv[i], "--network-recovery-dir=", 23) == 0)) return true;
    }
    return false;
}

int NetworkRecoveryJournal::RunRecoveryCommand(int argc, const char* const* argv) noexcept {
    if (!IsRecoveryCommand(argc, argv)) return -1;

    fs::path directory;
    constexpr const char* prefix = "--network-recovery-dir=";
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == nullptr || std::strncmp(argv[i], prefix, std::strlen(prefix)) != 0) continue;
        const char* value = argv[i] + std::strlen(prefix);
        if (*value == '\0') return 2;
        directory = fs::path(value);
        break;
    }
    if (directory.empty()) return 2;
    NetworkRecoveryJournal journal;
    std::string error;
    if (!journal.Open(directory.string(), "openppp2-core-network-v1", {}, &error)) return 2;

#if defined(_WIN32)
    // Wintun's bundled API cannot delete an adapter. Its independent marker
    // tracks only the owning process session, and recovery verifies the
    // adapter LUID/index before closing a stale session handle.
    const bool wintun_recovered = WintunAdapter::RecoverPending();
#else
    const bool wintun_recovered = true;
#endif

    const bool recovered = journal.RecoverPendingFor("windows-dns",
        [](const NetworkRecoveryJournal::Entry& entry) noexcept {
#if defined(_WIN32)
            if (entry.resource != "windows-dns") return false;
            ppp::win32::network::NetworkDnsSnapshot before;
            ppp::win32::network::NetworkDnsSnapshot after;
            auto parse = [](const std::string& value,
                            ppp::win32::network::NetworkDnsSnapshot& snapshot) noexcept {
                std::vector<std::string> fields;
                std::size_t start = 0;
                for (;;) {
                    const std::size_t end = value.find('|', start);
                    fields.emplace_back(value.substr(start, end == std::string::npos ? end : end - start));
                    if (end == std::string::npos) break;
                    start = end + 1;
                }
                if (fields.size() != 7 || fields[0] != "dns-v1" || fields[4].size() != 1 ||
                    (fields[4] != "0" && fields[4] != "1")) return false;
                try { snapshot.InterfaceIndex = std::stoi(fields[1]); }
                catch (...) { return false; }
                snapshot.InterfaceLuid = fields[2];
                snapshot.Guid = fields[3];
                if (snapshot.InterfaceIndex < 0 || snapshot.Guid.empty()) return false;
                snapshot.DnsAutomatic = fields[4] == "1";
                auto parse_addresses = [](const std::string& text, auto& output) noexcept {
                    if (text.empty()) return true;
                    std::size_t begin = 0;
                    while (begin <= text.size()) {
                        const std::size_t end = text.find(',', begin);
                        const std::string item = text.substr(begin, end == std::string::npos ? end : end - begin);
                        boost::system::error_code ec;
                        const auto address = boost::asio::ip::make_address(item, ec);
                        if (ec || address.is_unspecified() || address.is_multicast()) return false;
                        output.emplace_back(address);
                        if (end == std::string::npos) break;
                        begin = end + 1;
                    }
                    return true;
                };
                return parse_addresses(fields[5], snapshot.DnsAddresses) &&
                    parse_addresses(fields[6], snapshot.AppliedDnsAddresses);
            };
            if (!parse(entry.before, before) || !parse(entry.after, after)) return false;
            before.AppliedDnsAddresses = after.AppliedDnsAddresses;
            // An intent may have been persisted immediately before the OS
            // write. Restore accepts unchanged original state and otherwise
            // compares against the values OpenPPP2 intended to write.
            before.DnsApplyAttempted = true;
            before.DnsApplied = entry.confirmed;
            return ppp::win32::network::RestoreDnsSnapshot(before);
#else
            (void)entry;
            return false;
#endif
        }, &error);
    // Route entries carry a platform-specific, ownership-bearing snapshot.
    // Replay them in the recovery worker so a Core restart does not leave
    // route records pending merely because no live connection exists.
    bool routes_recovered = journal.RecoverPendingFor("route",
        [](const NetworkRecoveryJournal::Entry& entry) noexcept {
#if defined(_WIN32)
            return ppp::app::client::route::WindowsRoutePlatform::
                RecoverRouteJournalEntry(entry.target);
#elif defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
            return ppp::app::client::route::LinuxRoutePlatform::
                RecoverRouteJournalEntry(entry.target);
#elif defined(_MACOS)
            return ppp::app::client::route::DarwinRoutePlatform::
                RecoverRouteJournalEntry(entry.target);
#else
            (void)entry;
            return false;
#endif
        }, &error);
    // Assigned TAP addresses use a durable GUID/LUID/index identity and
    // compare-and-restore. The handler returns true only when the adapter is
    // already at the captured before state or when the exact after state was
    // replaced and verified; conflicts remain in the journal for inspection.
    const bool assigned_addresses_recovered = journal.RecoverPendingFor(
        "assigned-ipv4",
        [](const NetworkRecoveryJournal::Entry& entry) noexcept {
#if defined(_WIN32)
            return RecoverAssignedIPv4(entry);
#else
            (void)entry;
            return false;
#endif
        },
        &error);
    // IPv6 address, neighbor, route, and resolver records use the same stable
    // TAP identity and compare-before-delete rules as the in-process teardown.
    const bool assigned_ipv6_recovered = journal.RecoverPendingFor(
        "assigned-ipv6",
        [](const NetworkRecoveryJournal::Entry& entry) noexcept {
#if defined(_WIN32)
            WindowsIPv6Snapshot snapshot;
            if (!DeserializeWindowsIPv6Snapshot(entry.before, snapshot)) return false;
            return ppp::win32::ipv6::auxiliary::RecoverClientSnapshot(snapshot);
#else
            (void)entry;
            return false;
#endif
        },
        &error);
#if defined(_WIN32)
    const bool firewall_recovered = journal.RecoverPendingFor(
        "windows-firewall",
        [](const NetworkRecoveryJournal::Entry& entry) noexcept {
            return RecoverWindowsFirewall(entry);
        },
        &error);
#else
    const bool firewall_recovered = true;
#endif
#if defined(_WIN32)
    // Core's WinINet implementation stores its snapshot in HKCU rather than
    // the portable journal.  Replay it in this independent worker so a Core
    // crash does not leave the system proxy modified until the next process
    // happens to touch it.  The implementation is compare-and-restore and is
    // a no-op when no OpenPPP2 snapshot exists.
    const bool system_proxy_recovered =
        ppp::net::proxies::HttpProxy::RecoverSystemProxy();
#else
    const bool system_proxy_recovered = true;
#endif
    // Unsupported resources remain retryable. Check all residual entries
    // after the independent DNS pass before reporting complete recovery.
    if (journal.HasPending()) return 2;
    return recovered && routes_recovered && assigned_addresses_recovered &&
        assigned_ipv6_recovered && firewall_recovered && system_proxy_recovered &&
        wintun_recovered ? 0 : 2;
}


std::vector<NetworkRecoveryJournal::Entry> NetworkRecoveryJournal::Pending() const { return entries_; }

std::vector<NetworkRecoveryJournal::Entry> NetworkRecoveryJournal::PendingFor(
    const std::string& resource) const {
    std::vector<Entry> result;
    if (resource.empty()) {
        return result;
    }
    for (const Entry& entry : entries_) {
        if (entry.resource == resource) {
            result.emplace_back(entry);
        }
    }
    return result;
}

bool NetworkRecoveryJournal::HasPending() const { return !entries_.empty(); }

bool NetworkRecoveryJournal::HasPendingFor(const std::string& resource) const {
    if (resource.empty()) {
        return false;
    }
    return std::any_of(entries_.begin(), entries_.end(),
        [&resource](const Entry& entry) noexcept {
            return entry.resource == resource;
        });
}

} // namespace ppp::app::client
