#define BOOST_TEST_MODULE p2p_datagram_transport_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PDatagramTransport.h>

using namespace ppp::p2p;

BOOST_AUTO_TEST_CASE(ios_requires_provider_owned_datagram_transport) {
    BOOST_TEST(RequiresProviderOwnedP2PDatagramTransport(
        P2PDatagramPlatform::IosPacketTunnel));
    BOOST_TEST(!AllowsNativeSocketP2PDatagramTransport(
        P2PDatagramPlatform::IosPacketTunnel));
}

BOOST_AUTO_TEST_CASE(desktop_and_android_allow_protected_native_socket_transport) {
    BOOST_TEST(!RequiresProviderOwnedP2PDatagramTransport(
        P2PDatagramPlatform::Linux));
    BOOST_TEST(AllowsNativeSocketP2PDatagramTransport(
        P2PDatagramPlatform::Linux));
    BOOST_TEST(AllowsNativeSocketP2PDatagramTransport(
        P2PDatagramPlatform::Android));
}
