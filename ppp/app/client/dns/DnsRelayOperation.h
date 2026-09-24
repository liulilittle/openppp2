#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <utility>

namespace ppp::app::client::dns {

class DnsRelayOperation final {
public:
    enum class Completion : unsigned char {
        Pending,
        Response,
        Fallback,
    };

    using Action = std::function<void()>;
    using ActiveCheck = std::function<bool()>;

    DnsRelayOperation(Action cleanup, Action fallback, ActiveCheck active) noexcept
        : token_(next_token_.fetch_add(1, std::memory_order_relaxed) + 1),
          cleanup_(std::move(cleanup)),
          fallback_(std::move(fallback)),
          active_(std::move(active)) {
    }

    bool CompleteResponse(const Action& response) noexcept {
        return Complete(Completion::Response, response);
    }

    bool CompleteFallback() noexcept {
        return Complete(Completion::Fallback, fallback_);
    }

    Completion GetCompletion() const noexcept {
        return completion_.load(std::memory_order_acquire);
    }

    uint64_t Token() const noexcept {
        return token_;
    }

    void* RegistryHandle() noexcept {
        return &token_;
    }

private:
    bool Complete(Completion desired, const Action& action) noexcept {
        Completion expected = Completion::Pending;
        if (!completion_.compare_exchange_strong(
                expected, desired, std::memory_order_acq_rel, std::memory_order_acquire)) {
            return false;
        }

        if (cleanup_) {
            cleanup_();
        }
        if ((!active_ || active_()) && action) {
            action();
        }
        return true;
    }

    inline static std::atomic<uint64_t> next_token_{0};
    std::atomic<Completion> completion_{Completion::Pending};
    uint64_t token_;
    const Action cleanup_;
    const Action fallback_;
    const ActiveCheck active_;
};

}  // namespace ppp::app::client::dns
