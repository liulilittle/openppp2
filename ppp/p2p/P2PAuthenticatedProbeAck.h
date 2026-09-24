#pragma once

#include <utility>

namespace ppp::p2p {

class P2PControlStateMachine;

namespace detail {
class P2PAuthenticatedProbeAckFactory;
}

class P2PAuthenticatedProbeAck final {
public:
    P2PAuthenticatedProbeAck(P2PAuthenticatedProbeAck&& other) noexcept
        : valid_(std::exchange(other.valid_, false)) {}
    P2PAuthenticatedProbeAck& operator=(P2PAuthenticatedProbeAck&& other) noexcept {
        if (this != &other) valid_ = std::exchange(other.valid_, false);
        return *this;
    }
    P2PAuthenticatedProbeAck(const P2PAuthenticatedProbeAck&) = delete;
    P2PAuthenticatedProbeAck& operator=(const P2PAuthenticatedProbeAck&) = delete;

private:
    P2PAuthenticatedProbeAck() noexcept = default;
    bool Consume() noexcept { return std::exchange(valid_, false); }

    friend class detail::P2PAuthenticatedProbeAckFactory;
    friend class P2PControlStateMachine;

    bool valid_ = true;
};

namespace detail {
class P2PAuthenticatedProbeAckFactory final {
public:
    static P2PAuthenticatedProbeAck Create() noexcept {
        return P2PAuthenticatedProbeAck{};
    }
};
}

}
