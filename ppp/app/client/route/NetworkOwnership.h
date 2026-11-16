#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace ppp::app::client::route {

// A process-wide lease for mutations of the host network control plane.
//
// The lease is deliberately system scoped: two OpenPPP2 processes must not
// capture and restore the same default routes concurrently.  Callers should
// keep the lease alive for the complete apply/rollback lifecycle.
class NetworkOwnershipLease final {
public:
    NetworkOwnershipLease() noexcept = default;
    ~NetworkOwnershipLease() noexcept;

    NetworkOwnershipLease(const NetworkOwnershipLease&) = delete;
    NetworkOwnershipLease& operator=(const NetworkOwnershipLease&) = delete;
    NetworkOwnershipLease(NetworkOwnershipLease&& other) noexcept;
    NetworkOwnershipLease& operator=(NetworkOwnershipLease&& other) noexcept;

    static std::optional<NetworkOwnershipLease> Acquire(
        std::string lease_id) noexcept;

    bool IsHeld() const noexcept;
    const std::string& OwnerId() const noexcept { return lease_id_; }
    const std::string& Token() const noexcept { return token_; }

private:
    friend class NetworkOwnershipLeaseFactory;

    NetworkOwnershipLease(
        std::string lease_id,
        std::string token,
        uintptr_t native_handle) noexcept;
    void Release() noexcept;

    std::string lease_id_;
    std::string token_;
    uintptr_t native_handle_ = 0;
};

} // namespace ppp::app::client::route
