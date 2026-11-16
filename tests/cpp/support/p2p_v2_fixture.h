#pragma once
#include <ppp/p2p/P2PV2Channel.h>
#include <ppp/p2p/P2PV2Codec.h>
#include <algorithm>
#include <cstring>

namespace p2p_v2_test {
using namespace ppp::p2p;
template<std::size_t N> std::array<std::uint8_t,N> Bytes(std::uint8_t start) {
    std::array<std::uint8_t,N> out{};
    for (std::size_t i=0;i<N;++i) out[i]=static_cast<std::uint8_t>(start+i);
    return out;
}
inline P2PCandidateEndpoint Endpoint(std::uint8_t host) {
    P2PCandidateEndpoint out; out.address_family=4;
    out.address[10]=out.address[11]=0xff; out.address[12]=192;
    out.address[14]=2; out.address[15]=host; out.port=4000+host; return out;
}
inline P2PSessionExporter Exporter(std::uint8_t start) {
    return [key=Bytes<32>(start)](const char* label,const std::uint8_t*,std::size_t size,
        std::uint8_t* out,std::size_t length) {
        if (!label || std::strcmp(label,P2PWrapExporterLabelV2) || size!=145 || length!=32) return false;
        std::copy(key.begin(),key.end(),out); return true;
    };
}
struct Pair {
    P2PV2Channel channels[2];
    P2PV2RecipientContext contexts[2];
    P2PSessionExporter exporters[2]{Exporter(7),Exporter(47)};
    P2PRelayOfferV2Bundle bundle;
    std::string encoded[2];
    Pair() {
        for (unsigned i=0;i<2;++i) {
            contexts[i].local_session_id=Bytes<16>(1+20*i);
            contexts[i].local_peer_id=Bytes<16>(41+20*i);
            contexts[i].local_candidate_revision=contexts[i].peer_candidate_revision=1;
            contexts[i].local_candidates={Endpoint(1+i)};
            contexts[i].peer_candidates={Endpoint(2-i)};
            channels[i].ConfigureLiveness(5000,10,10000,5000);
        }
    }
    void Offer(std::uint64_t now=1000,std::uint64_t key_generation=1) {
        P2PRelayOfferV2Input input;
        input.initiator_session_id=contexts[0].local_session_id; input.responder_session_id=contexts[1].local_session_id;
        input.initiator_peer_id=contexts[0].local_peer_id; input.responder_peer_id=contexts[1].local_peer_id;
        input.initiator_candidate_revision=input.responder_candidate_revision=1;
        input.key_generation=key_generation; input.previous_offer_hash=channels[0].Snapshot().current_offer_hash;
        BOOST_REQUIRE(HashP2PV2CandidateSet(input.initiator_session_id,input.responder_session_id,1,1,
            contexts[0].local_candidates,contexts[1].local_candidates,input.candidate_set_hash));
        BOOST_REQUIRE(CreateP2PRelayOfferV2Bundle(input,exporters[0],exporters[1],bundle));
        BOOST_REQUIRE(EncodeP2PRelayOfferRecipientV2Hex(bundle.offer,bundle.initiator_envelope,encoded[0]));
        BOOST_REQUIRE(EncodeP2PRelayOfferRecipientV2Hex(bundle.offer,bundle.responder_envelope,encoded[1]));
        for (unsigned i=0;i<2;++i) BOOST_REQUIRE(channels[i].AcceptOffer(encoded[i],contexts[i],exporters[i],now,7));
    }
    std::vector<std::uint8_t> Probe(unsigned i,std::uint64_t now=1000) {
        std::vector<std::uint8_t> packet;
        BOOST_REQUIRE(channels[i].CreateProbe(Endpoint(1+i),Endpoint(2-i),now,7,packet)); return packet;
    }
    P2PV2ControlResult Deliver(unsigned sender,const std::vector<std::uint8_t>& packet,std::uint64_t now=1000) {
        P2PV2ControlResult result;
        BOOST_REQUIRE(channels[1-sender].HandleControl(packet,Endpoint(1+sender),now,7,result)); return result;
    }
    void Connect(std::uint64_t now=1000,bool drop_commit_ack=false) {
        auto ip=Probe(0,now),rp=Probe(1,now);
        auto ra=Deliver(0,ip,now),ia=Deliver(1,rp,now);
        BOOST_REQUIRE_EQUAL(ra.outbound.size(),1u); BOOST_REQUIRE_EQUAL(ia.outbound.size(),1u);
        auto commit=Deliver(1,ra.outbound[0].datagram,now);
        BOOST_REQUIRE_EQUAL(commit.outbound.size(),1u);
        Deliver(0,ia.outbound[0].datagram,now);
        auto ack=Deliver(0,commit.outbound[0].datagram,now);
        BOOST_REQUIRE_EQUAL(ack.outbound.size(),1u);
        if (!drop_commit_ack) Deliver(1,ack.outbound[0].datagram,now);
    }
};
}
