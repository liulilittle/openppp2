#define BOOST_TEST_MODULE p2p_v2_noise_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/cryptography/noise/NoisePsk.h>
#include <algorithm>
#include <cstring>
using namespace ppp::cryptography::noise;

BOOST_AUTO_TEST_CASE(v2_exporter_requires_typed_purpose_and_145_byte_context) {
    Bytes32 psk{}; psk.fill(7);
    std::vector<std::uint8_t> prologue; SessionId session{}; session.fill(3);
    const std::uint8_t id[]={'t','e','s','t'};
    BOOST_REQUIRE(BuildCanonicalPrologue(Carrier::Tcp,session,id,sizeof(id),prologue));
    auto server_psk=psk;
    NoisePskHandshake client(HandshakeRole::NetworkClientInitiator,Secret32(std::move(psk)),prologue);
    NoisePskHandshake server(HandshakeRole::NetworkServerResponder,Secret32(std::move(server_psk)),prologue);
    std::vector<std::uint8_t> first,second;
    BOOST_REQUIRE(client.WriteMessage1(first)); BOOST_REQUIRE(server.ReadMessage1(first.data(),first.size()));
    BOOST_REQUIRE(server.WriteMessage2(second)); BOOST_REQUIRE(client.ReadMessage2(second.data(),second.size()));
    NoisePskHandshakeResult ci,sr; BOOST_REQUIRE(client.TakeResult(ci)); BOOST_REQUIRE(server.TakeResult(sr));
    std::array<std::uint8_t,145> context{}; context.fill(0x51);
    Secret32 ck,sk,wrong,changed,v1;
    BOOST_CHECK(!ci.DeriveBinding(BindingPurpose::P2PWrapV2,context.data(),113,wrong));
    BOOST_CHECK(!ci.DeriveBinding(BindingPurpose::P2PWrapV1,context.data(),145,wrong));
    BOOST_REQUIRE(ci.DeriveBinding(BindingPurpose::P2PWrapV2,context.data(),145,ck));
    BOOST_REQUIRE(sr.DeriveBinding(BindingPurpose::P2PWrapV2,context.data(),145,sk));
    BOOST_CHECK(std::memcmp(ck.data(),sk.data(),32)==0);
    BOOST_REQUIRE(ci.DeriveBinding(BindingPurpose::P2PWrapV1,context.data(),113,v1));
    BOOST_CHECK(std::memcmp(ck.data(),v1.data(),32)!=0);
    context.back()^=1;
    BOOST_REQUIRE(ci.DeriveBinding(BindingPurpose::P2PWrapV2,context.data(),145,changed));
    BOOST_CHECK(std::memcmp(ck.data(),changed.data(),32)!=0);
    BOOST_CHECK(!ci.DeriveBinding(BindingPurpose::P2PWrapV2,context.data(),145,ck));
    ci.Clear(); BOOST_CHECK(!ci.DeriveBinding(BindingPurpose::P2PWrapV2,context.data(),145,wrong));
}
