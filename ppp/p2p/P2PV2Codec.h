#pragma once
#include <ppp/p2p/P2PControlPacket.h>
#include <ppp/p2p/P2PDataDatagram.h>
#include <ppp/p2p/P2PRelayOfferV2.h>

namespace ppp::p2p {
enum class P2PV2ControlType : std::uint8_t {
    Probe=1, ProbeAck=2, MigrateChallenge=3, MigrateAck=4,
    KeyCommit=6, KeyCommitAck=7
};
struct P2PV2ControlPacket {
    P2PV2ControlType type=P2PV2ControlType::Probe;
    P2POfferHash offer_hash{}, previous_offer_hash{}, probe_transcript_hash{}, commit_transcript_hash{};
    std::uint8_t sender_role=0, receiver_role=1, direction=0;
    P2PId connection_epoch{};
    P2PCandidateEndpoint source,destination;
    std::uint32_t sequence=0;
    std::array<std::uint8_t,12> nonce{};
    std::uint8_t setup_ttl_seconds=10;
    std::array<std::uint8_t,16> token{};
};
std::size_t P2PV2ControlWireSize(P2PV2ControlType) noexcept;
bool ParseP2PV2Control(const std::vector<std::uint8_t>&,P2PV2ControlPacket&) noexcept;
bool SerializeP2PV2Control(const P2PV2ControlPacket&,std::vector<std::uint8_t>&) noexcept;
bool SignP2PV2Control(P2PV2ControlPacket&,const P2PExporterKey&,
    const P2POfferHash* challenge_binding=nullptr) noexcept;
bool VerifyP2PV2Control(const P2PV2ControlPacket&,const P2PExporterKey&,
    const P2POfferHash* challenge_binding=nullptr) noexcept;
bool HashP2PV2Control(const P2PV2ControlPacket&,P2POfferHash&) noexcept;
using P2PV2DataPacketHeader=P2PDataPacketHeader;
bool ParseP2PV2DataPacketHeader(const std::vector<std::uint8_t>&,P2PV2DataPacketHeader&) noexcept;
bool SealP2PV2DataDatagram(const P2PV2DataPacketHeader&,const std::array<std::uint8_t,32>&,
    const std::array<std::uint8_t,12>&,const std::uint8_t*,std::size_t,std::vector<std::uint8_t>&) noexcept;
bool OpenP2PV2DataDatagram(const std::vector<std::uint8_t>&,const P2PV2DataPacketHeader&,
    const std::array<std::uint8_t,32>&,const std::array<std::uint8_t,12>&,std::vector<std::uint8_t>&) noexcept;
}
