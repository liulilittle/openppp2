#define BOOST_TEST_MODULE p2p_v2_channel_test
#include <boost/test/included/unit_test.hpp>
#include "support/p2p_v2_fixture.h"
#include <limits>
using namespace p2p_v2_test;

BOOST_AUTO_TEST_CASE(bilateral_ready_promotes_and_data_replay_is_rejected) {
    Pair pair; pair.Offer(); pair.Connect();
    BOOST_CHECK(pair.channels[0].Snapshot().state==P2PState::Direct);
    BOOST_CHECK(pair.channels[1].Snapshot().state==P2PState::Direct);
    std::vector<std::uint8_t> packet,plain;
    BOOST_REQUIRE(pair.channels[0].SealData(std::vector<std::uint8_t>{1,2,3},1001,7,packet));
    auto damaged=packet; damaged.back()^=1;
    BOOST_CHECK(!pair.channels[1].OpenData(damaged,Endpoint(1),1001,7,plain));
    BOOST_REQUIRE(pair.channels[1].OpenData(packet,Endpoint(1),1001,7,plain));
    BOOST_CHECK(plain==std::vector<std::uint8_t>({1,2,3}));
    BOOST_CHECK(!pair.channels[1].OpenData(packet,Endpoint(1),1002,7,plain));
}
BOOST_AUTO_TEST_CASE(duplicate_offer_and_exact_probe_retry_preserve_budget) {
    Pair pair; pair.Offer(); auto first=pair.Probe(0);
    BOOST_REQUIRE(pair.channels[0].AcceptOffer(pair.encoded[0],pair.contexts[0],pair.exporters[0],9000,7));
    BOOST_TEST(pair.channels[0].Snapshot().setup_deadline_ms==11000u);
    std::vector<std::uint8_t> retry;
    BOOST_CHECK(!pair.channels[0].CreateProbe(Endpoint(1),Endpoint(2),2999,7,retry));
    BOOST_REQUIRE(pair.channels[0].CreateProbe(Endpoint(1),Endpoint(2),3000,7,retry)); BOOST_CHECK(first==retry);
    BOOST_CHECK(!pair.channels[0].CreateProbe(Endpoint(1),Endpoint(2),5000,7,retry));
    BOOST_CHECK(pair.channels[0].Tick(11000,7).fallback);
}
BOOST_AUTO_TEST_CASE(commit_ack_loss_requires_ready_then_new_key_data_confirms) {
    Pair pair; pair.Offer(); pair.Connect(1000,true);
    BOOST_CHECK(!pair.channels[0].Snapshot().has_current);
    BOOST_CHECK(pair.channels[0].Snapshot().pending_ready);
    std::vector<std::uint8_t> packet,plain;
    BOOST_REQUIRE(pair.channels[1].SealData(std::vector<std::uint8_t>{9},1001,7,packet));
    BOOST_REQUIRE(pair.channels[0].OpenData(packet,Endpoint(2),1001,7,plain));
    BOOST_CHECK(pair.channels[0].Snapshot().has_current);
}
BOOST_AUTO_TEST_CASE(refresh_keeps_three_slots_and_old_receive_has_hard_expiry) {
    Pair pair; pair.Offer(); pair.Connect();
    std::vector<std::uint8_t> old,plain;
    BOOST_REQUIRE(pair.channels[0].SealData(std::vector<std::uint8_t>{8},59000,7,old));
    pair.Offer(59000,2); pair.Connect(59000);
    BOOST_CHECK(pair.channels[1].Snapshot().has_previous);
    BOOST_TEST(pair.channels[1].Snapshot().previous_deadline_ms==61000u);
    BOOST_REQUIRE(pair.channels[1].OpenData(old,Endpoint(1),60999,7,plain));
    BOOST_CHECK(!pair.channels[1].OpenData(old,Endpoint(1),61000,7,plain));
    pair.channels[1].Tick(61000,7); BOOST_CHECK(!pair.channels[1].Snapshot().has_previous);
}
BOOST_AUTO_TEST_CASE(sequence_refresh_and_exhaustion_never_reuse_old_key_nonce) {
    Pair pair; pair.Offer(); pair.Connect();
    const auto max=std::numeric_limits<std::uint32_t>::max();
    BOOST_REQUIRE(pair.channels[0].AdvanceTxSequenceForTesting(max-4096));
    BOOST_CHECK(pair.channels[0].Tick(1001,7).renew);
    BOOST_CHECK(!pair.channels[0].AdvanceTxSequenceForTesting(0));
    BOOST_REQUIRE(pair.channels[0].AdvanceTxSequenceForTesting(max));
    std::vector<std::uint8_t> packet;
    BOOST_CHECK(!pair.channels[0].SealData(std::vector<std::uint8_t>{1},1002,7,packet));
    BOOST_CHECK(pair.channels[0].Snapshot().state==P2PState::Relay);
}
BOOST_AUTO_TEST_CASE(stale_generation_cannot_clear_or_authenticate_new_channel) {
    Pair pair; pair.Offer(); pair.Connect(); pair.channels[0].Reset(6);
    BOOST_CHECK(pair.channels[0].Snapshot().has_current);
    pair.channels[0].Reset(8); BOOST_CHECK(!pair.channels[0].Snapshot().has_current);
    BOOST_CHECK(!pair.channels[0].AcceptOffer(pair.encoded[0],pair.contexts[0],pair.exporters[0],1001,7));
}
BOOST_AUTO_TEST_CASE(same_generation_reset_allows_fresh_registration) {
    Pair pair; pair.Offer();
    pair.channels[0].Reset(7); pair.channels[1].Reset(7);
    pair.Offer(2000, 1);
    BOOST_CHECK(pair.channels[0].Snapshot().has_pending);
    BOOST_CHECK(pair.channels[1].Snapshot().has_pending);
}
BOOST_AUTO_TEST_CASE(new_pair_cannot_restart_probing_after_original_four_second_window) {
    Pair pair; pair.Offer(); std::vector<std::uint8_t> packet;
    BOOST_CHECK(!pair.channels[0].CreateProbe(Endpoint(1),Endpoint(2),5000,7,packet));
    BOOST_CHECK(pair.channels[0].Snapshot().has_pending);
    BOOST_TEST(pair.channels[0].Snapshot().setup_deadline_ms==11000u);
}
BOOST_AUTO_TEST_CASE(control_codec_authenticates_transcripts_and_rejects_padding_and_lengths) {
    Pair pair; pair.Offer(); auto bytes=pair.Probe(0);
    P2PV2ControlPacket packet; BOOST_REQUIRE(ParseP2PV2Control(bytes,packet));
    BOOST_TEST(bytes.size()==158u);
    auto padded=bytes; padded.back()=1; BOOST_CHECK(!ParseP2PV2Control(padded,packet));
    auto truncated=bytes; truncated.pop_back(); BOOST_CHECK(!ParseP2PV2Control(truncated,packet));
    auto altered=bytes; altered[110]^=1; P2PV2ControlResult result;
    BOOST_CHECK(!pair.channels[1].HandleControl(altered,Endpoint(1),1000,7,result));
    BOOST_REQUIRE(pair.channels[1].HandleControl(bytes,Endpoint(1),1000,7,result));
    BOOST_REQUIRE_EQUAL(result.outbound.size(),1u); auto original_ack=result.outbound[0].datagram;
    BOOST_REQUIRE(pair.channels[1].HandleControl(bytes,Endpoint(1),1001,7,result));
    BOOST_CHECK(result.outbound[0].datagram==original_ack);
    P2PExporterKey key=Bytes<32>(7); P2POfferHash binding=Bytes<32>(21);
    BOOST_REQUIRE(ParseP2PV2Control(bytes,packet)); packet.type=P2PV2ControlType::MigrateAck;
    BOOST_REQUIRE(SignP2PV2Control(packet,key,&binding)); BOOST_REQUIRE(SerializeP2PV2Control(packet,bytes));
    BOOST_TEST(bytes.size()==126u); BOOST_CHECK(VerifyP2PV2Control(packet,key,&binding));
    BOOST_CHECK(!VerifyP2PV2Control(packet,key)); binding.back()^=1;
    BOOST_CHECK(!VerifyP2PV2Control(packet,key,&binding));
}
BOOST_AUTO_TEST_CASE(receiver_accepts_large_numeric_advance_but_never_sequence_wrap) {
    Pair pair; pair.Offer(); pair.Connect();
    std::vector<std::uint8_t> old,high,last,plain;
    BOOST_REQUIRE(pair.channels[0].SealData(std::vector<std::uint8_t>{1},1001,7,old));
    const auto maximum=std::numeric_limits<std::uint32_t>::max();
    BOOST_REQUIRE(pair.channels[0].AdvanceTxSequenceForTesting(maximum-4096));
    BOOST_REQUIRE(pair.channels[0].SealData(std::vector<std::uint8_t>{2},1001,7,high));
    auto tampered=high; tampered.back()^=1;
    BOOST_CHECK(!pair.channels[1].OpenData(tampered,Endpoint(1),1001,7,plain));
    BOOST_REQUIRE(pair.channels[1].OpenData(high,Endpoint(1),1001,7,plain));
    BOOST_CHECK(plain==std::vector<std::uint8_t>({2}));
    BOOST_CHECK(!pair.channels[1].OpenData(high,Endpoint(1),1001,7,plain));
    BOOST_CHECK(!pair.channels[1].OpenData(old,Endpoint(1),1001,7,plain));
    BOOST_REQUIRE(pair.channels[0].AdvanceTxSequenceForTesting(maximum-1));
    BOOST_REQUIRE(pair.channels[0].SealData(std::vector<std::uint8_t>{3},1001,7,last));
    BOOST_REQUIRE(pair.channels[1].OpenData(last,Endpoint(1),1001,7,plain));
    BOOST_CHECK(plain==std::vector<std::uint8_t>({3}));
}
