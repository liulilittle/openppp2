#include <ppp/app/client/route/NetworkOwnership.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <sstream>
#include <functional>
#include <thread>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace ppp::app::client::route {
namespace {

std::string MakeToken(const std::string& lease_id) noexcept {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t n = sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::ostringstream out;
    out << lease_id << '-' << static_cast<unsigned long long>(now) << '-'
        << static_cast<unsigned long long>(n) << '-'
        << static_cast<unsigned long long>(
            std::hash<std::thread::id>{}(std::this_thread::get_id()));
    return out.str();
}

#if defined(_WIN32)
HANDLE AcquireNativeHandle() noexcept {
    // The presence of the named object is the lease. Creation and the
    // ERROR_ALREADY_EXISTS check are atomic across threads and processes.
    // Do not use wait/reset: those are separate operations for manual-reset
    // events, and mutex ownership cannot safely move between worker threads.
    // An unsignaled event also prevents older wait-based clients from entering.
    SetLastError(ERROR_SUCCESS);
    HANDLE handle = CreateEventW(nullptr, TRUE, FALSE,
        L"Global\\OpenPPP2.NetworkControlPlane.v1");
    const DWORD error = GetLastError();
    if (!handle) return nullptr;
    if (error == ERROR_ALREADY_EXISTS) {
        ::CloseHandle(handle);
        return nullptr;
    }
    return handle;
}

void ReleaseNativeHandle(HANDLE handle) noexcept {
    // Closing the last handle removes the kernel object, including on process
    // death. No thread-affine release or separately signaled state is needed.
    if (handle) ::CloseHandle(handle);
}
#else
int AcquireNativeHandle() noexcept {
    // Keep this path independent of a running daemon.  flock releases the
    // lease on process death, allowing a later startup recovery attempt.
    constexpr const char* path = "/tmp/openppp2-network-control-plane-v1.lock";
    // Linux protected_regular rejects O_CREAT in sticky /tmp when an earlier
    // unprivileged proxy client owns this file, even for a later root client.
    // Open existing files without O_CREAT; create exclusively only if absent.
    constexpr int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW;
    int fd = ::open(path, flags);
    if (fd < 0 && errno == ENOENT) {
        fd = ::open(path, flags | O_CREAT | O_EXCL, 0600);
        if (fd < 0 && errno == EEXIST) {
            fd = ::open(path, flags);
        }
    }
    if (fd < 0 || ::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (fd >= 0) {
            ::close(fd);
        }
        return -1;
    }
    return fd;
}

void ReleaseNativeHandle(int fd) noexcept {
    if (fd < 0) {
        return;
    }
    ::flock(fd, LOCK_UN);
    ::close(fd);
}
#endif

} // namespace

NetworkOwnershipLease::NetworkOwnershipLease(
    std::string lease_id,
    std::string token,
    uintptr_t native_handle) noexcept
    : lease_id_(std::move(lease_id)),
      token_(std::move(token)),
      native_handle_(native_handle) {
}

NetworkOwnershipLease::~NetworkOwnershipLease() noexcept {
    Release();
}

NetworkOwnershipLease::NetworkOwnershipLease(
    NetworkOwnershipLease&& other) noexcept
    : lease_id_(std::move(other.lease_id_)),
      token_(std::move(other.token_)),
      native_handle_(other.native_handle_) {
    other.native_handle_ = 0;
}

NetworkOwnershipLease& NetworkOwnershipLease::operator=(
    NetworkOwnershipLease&& other) noexcept {
    if (this != &other) {
        Release();
        lease_id_ = std::move(other.lease_id_);
        token_ = std::move(other.token_);
        native_handle_ = other.native_handle_;
        other.native_handle_ = 0;
    }
    return *this;
}

std::optional<NetworkOwnershipLease> NetworkOwnershipLease::Acquire(
    std::string lease_id) noexcept {
    if (lease_id.empty()) {
        return std::nullopt;
    }
#if defined(_WIN32)
    HANDLE handle = AcquireNativeHandle();
    if (!handle) {
        return std::nullopt;
    }
    const uintptr_t native_handle = reinterpret_cast<uintptr_t>(handle);
#else
    const int fd = AcquireNativeHandle();
    if (fd < 0) {
        return std::nullopt;
    }
    const uintptr_t native_handle = static_cast<uintptr_t>(fd + 1);
#endif
    const std::string token = MakeToken(lease_id);
    NetworkOwnershipLease lease(
        std::move(lease_id), token, native_handle);
    return std::optional<NetworkOwnershipLease>(std::move(lease));
}

bool NetworkOwnershipLease::IsHeld() const noexcept {
    return native_handle_ != 0;
}

void NetworkOwnershipLease::Release() noexcept {
    if (!IsHeld()) {
        return;
    }
#if defined(_WIN32)
    ReleaseNativeHandle(reinterpret_cast<HANDLE>(native_handle_));
#else
    ReleaseNativeHandle(static_cast<int>(native_handle_ - 1));
#endif
    native_handle_ = 0;
}

} // namespace ppp::app::client::route
