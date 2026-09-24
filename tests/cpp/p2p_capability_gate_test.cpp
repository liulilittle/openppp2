#define BOOST_TEST_MODULE p2p_capability_gate_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/p2p/P2PDefs.h>
#include <ppp/p2p/P2PSocketProtector.h>
#include <ppp/transmissions/IAuthenticatedCarrierBinding.h>
#include <ppp/transmissions/ITransmission.h>

#include <type_traits>

using namespace ppp::p2p;

namespace {

class RecordingProtector final : public ISocketProtector {
public:
    explicit RecordingProtector(bool ready, bool protected_result) noexcept
        : ready_(ready), protected_result_(protected_result) {}

    bool IsReady() const noexcept override {
        ++ready_calls;
        return ready_;
    }

    bool Protect(int) noexcept override {
        ++protect_calls;
        return protected_result_;
    }

    mutable int ready_calls = 0;
    int protect_calls = 0;

private:
    bool ready_;
    bool protected_result_;
};

} // namespace

BOOST_AUTO_TEST_CASE(default_and_relay_modes_are_not_advertised) {
    const auto disabled = P2PCapabilityGate::Evaluate(false, "direct-preferred", true, true, true);
    BOOST_TEST(!disabled.allowed);
    BOOST_TEST(static_cast<int>(disabled.state) == static_cast<int>(P2PState::Disabled));
    BOOST_TEST(std::string(disabled.reason) == "p2p-disabled");

    const auto relay = P2PCapabilityGate::Evaluate(true, "relay", true, true, true);
    BOOST_TEST(!relay.allowed);
    BOOST_TEST(static_cast<int>(relay.state) == static_cast<int>(P2PState::Relay));
    BOOST_TEST(std::string(relay.reason) == "relay-only");
}

BOOST_AUTO_TEST_CASE(direct_requires_authenticated_exporter_and_socket_protection) {
    const auto raw_tcp = P2PCapabilityGate::Evaluate(true, "direct-preferred", false, true, true);
    BOOST_TEST(!raw_tcp.allowed);
    BOOST_TEST(std::string(raw_tcp.reason) == "authenticated-exporter-unavailable");

    const auto unprotected_platform = P2PCapabilityGate::Evaluate(true, "direct-preferred", true, false, true);
    BOOST_TEST(!unprotected_platform.allowed);
    BOOST_TEST(std::string(unprotected_platform.reason) == "socket-protection-unavailable");

    const auto missing_control_v1 = P2PCapabilityGate::Evaluate(
        true, "direct-preferred", true, true, false);
    BOOST_TEST(!missing_control_v1.allowed);
    BOOST_TEST(std::string(missing_control_v1.reason) ==
        "authenticated-control-v1-unavailable");

    const auto eligible = P2PCapabilityGate::Evaluate(true, "direct-preferred", true, true, true);
    BOOST_TEST(eligible.allowed);
    BOOST_TEST(static_cast<int>(eligible.state) == static_cast<int>(P2PState::Eligible));
    BOOST_TEST(std::string(eligible.reason) == "eligible");
}

BOOST_AUTO_TEST_CASE(transmission_exporter_contract_is_explicit) {
    using Binding = ppp::transmissions::IAuthenticatedCarrierBinding;
    using Transmission = ppp::transmissions::ITransmission;
    static_assert(std::has_virtual_destructor_v<Binding>);
    static_assert(std::is_same_v<decltype(&Binding::HasAuthenticatedSessionExporter),
        bool (Binding::*)() const noexcept>);
    static_assert(std::is_same_v<decltype(&Binding::ExportAuthenticatedSessionKey),
        bool (Binding::*)(const char*, const std::uint8_t*, std::size_t,
            std::uint8_t*, std::size_t) noexcept>);
    static_assert(std::is_base_of_v<Binding, Transmission>);
    static_assert(std::is_convertible_v<Transmission*, Binding*>);
    static_assert(std::is_same_v<decltype(&Transmission::HasAuthenticatedSessionExporter),
        bool (Transmission::*)() const noexcept>);
    static_assert(std::is_same_v<decltype(&Transmission::ExportAuthenticatedSessionKey),
        bool (Transmission::*)(const char*, const std::uint8_t*, std::size_t,
            std::uint8_t*, std::size_t) noexcept>);
    static_assert(std::is_same_v<decltype(&Transmission::IsHandshakeComplete),
        bool (Transmission::*)() const noexcept>);
}

BOOST_AUTO_TEST_CASE(socket_protection_checks_readiness_before_protecting) {
    auto unavailable = std::make_shared<RecordingProtector>(false, true);
    BOOST_TEST(!ProtectP2PSocket(unavailable, 7));
    BOOST_TEST(unavailable->ready_calls == 1);
    BOOST_TEST(unavailable->protect_calls == 0);

    auto failure = std::make_shared<RecordingProtector>(true, false);
    BOOST_TEST(!ProtectP2PSocket(failure, 7));
    BOOST_TEST(failure->ready_calls == 1);
    BOOST_TEST(failure->protect_calls == 1);

    auto success = std::make_shared<RecordingProtector>(true, true);
    BOOST_TEST(ProtectP2PSocket(success, 7));
    BOOST_TEST(success->ready_calls == 1);
    BOOST_TEST(success->protect_calls == 1);
}

BOOST_AUTO_TEST_CASE(suspect_processes_authenticated_control_without_forwarding_payload) {
    BOOST_TEST(CanProcessAuthenticatedP2PTier2(P2PChannelState::Direct));
    BOOST_TEST(CanProcessAuthenticatedP2PTier2(P2PChannelState::Suspect));
    BOOST_TEST(!CanProcessAuthenticatedP2PTier2(P2PChannelState::Probing));
    BOOST_TEST(!CanProcessAuthenticatedP2PTier2(P2PChannelState::Relay));

    BOOST_TEST(CanForwardP2PPayload(P2PChannelState::Direct));
    BOOST_TEST(!CanForwardP2PPayload(P2PChannelState::Suspect));
    BOOST_TEST(!CanForwardP2PPayload(P2PChannelState::Probing));
    BOOST_TEST(!CanForwardP2PPayload(P2PChannelState::Relay));
}
