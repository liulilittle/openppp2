#include <ppp/app/client/xtcp/XtcpPoolLease.h>

#include <mutex>
#include <new>

#if defined(PPP_ENABLE_XTCP)
#include <xtcp/buf/bufref.h>
#endif

namespace ppp::app::client::xtcp {
namespace {
std::mutex pool_sync;
std::size_t pool_leases = 0;
}

std::unique_ptr<XtcpPoolLease> XtcpPoolLease::Acquire() noexcept {
#if defined(PPP_ENABLE_XTCP)
    std::unique_ptr<XtcpPoolLease> lease(
        new (std::nothrow) XtcpPoolLease(false));
    if (!lease) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(pool_sync);
    if (pool_leases == 0) {
        ::xtcp::buf::InitPools();
    }
    ++pool_leases;
    lease->acquired_ = true;
    return lease;
#else
    return nullptr;
#endif
}

XtcpPoolLease::~XtcpPoolLease() noexcept {
#if defined(PPP_ENABLE_XTCP)
    if (!acquired_) {
        return;
    }
    std::lock_guard<std::mutex> lock(pool_sync);
    acquired_ = false;
    if (pool_leases > 0 && --pool_leases == 0) {
        ::xtcp::buf::ShutdownPools();
    }
#endif
}

} // namespace ppp::app::client::xtcp
