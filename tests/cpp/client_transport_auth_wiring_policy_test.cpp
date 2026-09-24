#define BOOST_TEST_MODULE client_transport_auth_wiring_policy_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/VEthernetExchanger.h>

namespace client = ppp::app::client;
namespace transmissions = ppp::transmissions;

using Kind = transmissions::AuthenticatedCarrierKind;
using Method = transmissions::AuthenticatedCarrierMethod;

BOOST_AUTO_TEST_CASE(legacy_or_disabled_peers_do_not_start_transport_auth) {
    BOOST_TEST(!client::ShouldRunClientTransportAuth(
        Kind::Tcp, false, true, true));
    BOOST_TEST(!client::ShouldRunClientTransportAuth(
        Kind::Tcp, true, false, false));
    BOOST_TEST(!client::ShouldRunClientTransportAuth(
        Kind::Tcp, true, true, false));
    BOOST_TEST(!client::ShouldRunClientTransportAuth(
        Kind::TlsWebSocket, true, true, true));
    BOOST_TEST(!client::ShouldRunClientTransportAuth(
        Kind::None, true, true, true));

    BOOST_TEST(client::ShouldRunClientTransportAuth(
        Kind::Tcp, true, true, true));
    BOOST_TEST(client::ShouldRunClientTransportAuth(
        Kind::WebSocket, true, true, true));
}

BOOST_AUTO_TEST_CASE(recovery_requires_exact_active_method_carrier_pair) {
    BOOST_TEST(client::IsClientSessionRecoveryCarrierEligible(
        Kind::TlsWebSocket, Method::TlsExporterV1, true, true));
    BOOST_TEST(client::IsClientSessionRecoveryCarrierEligible(
        Kind::Tcp, Method::NoisePskV1, true, true));
    BOOST_TEST(client::IsClientSessionRecoveryCarrierEligible(
        Kind::WebSocket, Method::NoisePskV1, true, true));

    BOOST_TEST(!client::IsClientSessionRecoveryCarrierEligible(
        Kind::TlsWebSocket, Method::NoisePskV1, true, true));
    BOOST_TEST(!client::IsClientSessionRecoveryCarrierEligible(
        Kind::Tcp, Method::TlsExporterV1, true, true));
    BOOST_TEST(!client::IsClientSessionRecoveryCarrierEligible(
        Kind::WebSocket, Method::TlsExporterV1, true, true));
    BOOST_TEST(!client::IsClientSessionRecoveryCarrierEligible(
        Kind::None, Method::NoisePskV1, true, true));
    BOOST_TEST(!client::IsClientSessionRecoveryCarrierEligible(
        Kind::Tcp, Method::NoisePskV1, false, true));
    BOOST_TEST(!client::IsClientSessionRecoveryCarrierEligible(
        Kind::Tcp, Method::NoisePskV1, true, false));
}
