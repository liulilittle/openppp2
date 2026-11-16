#include "PolicyFakeIpAsync.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <atomic>
#include <utility>

namespace ppp::app::client::dns {
namespace {
constexpr std::size_t kMaxPendingAllocations = 256;
std::atomic_size_t pending_allocations{0};

boost::asio::thread_pool& DiskWorker() {
    static boost::asio::thread_pool worker(1);
    return worker;
}

bool IsActive(const PolicyFakeIpAsync::ActiveCheck& active) noexcept {
    if (!active) return true;
    try { return active(); }
    catch (...) { return false; }
}

void NotifyPending(const PolicyFakeIpAsync::PendingObserver& observer, std::ptrdiff_t delta) noexcept {
    if (!observer) return;
    try { observer(delta); }
    catch (...) {}
}
}

bool PolicyFakeIpAsync::Allocate(const std::shared_ptr<DurableFakeIpStore>& store,
    const std::shared_ptr<boost::asio::io_context>& return_context,
    const std::string& hostname, ActiveCheck active, Completion completion,
    PendingObserver pending_observer) noexcept {
    if (!store || !store->IsOpen() || !return_context || hostname.empty() || !completion) return false;
    std::size_t pending = pending_allocations.load(std::memory_order_relaxed);
    do {
        if (pending >= kMaxPendingAllocations) return false;
    } while (!pending_allocations.compare_exchange_weak(
        pending, pending + 1, std::memory_order_acq_rel, std::memory_order_relaxed));

    NotifyPending(pending_observer, 1);
    try {
        boost::asio::post(DiskWorker(), [store, return_context, hostname,
                active = std::move(active), completion = std::move(completion), pending_observer]() mutable {
            bool ok = false;
            uint32_t address = 0;
            if (IsActive(active)) ok = store->Allocate(hostname, address);
            pending_allocations.fetch_sub(1, std::memory_order_acq_rel);
            NotifyPending(pending_observer, -1);
            // The durable identity remains useful after shutdown, but a closed
            // request or stopped io_context must not retain its output handler.
            if (!IsActive(active) || return_context->stopped()) return;
            try {
                boost::asio::post(*return_context, [active = std::move(active),
                        completion = std::move(completion), ok, address]() mutable {
                    if (IsActive(active)) completion(ok, ok ? address : 0);
                });
            } catch (...) {
            }
        });
    } catch (...) {
        pending_allocations.fetch_sub(1, std::memory_order_acq_rel);
        NotifyPending(pending_observer, -1);
        return false;
    }
    return true;
}

}
