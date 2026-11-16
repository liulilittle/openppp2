#define BOOST_TEST_MODULE p2p_v2_exchanger_recovery_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/ClientFrpRegistry.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/threading/Executors.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/checksum.h>
#include "support/p2p_v2_fixture.h"
#include <boost/crc.hpp>

struct IsolatedRuntime {
    IsolatedRuntime() { ppp::global::cctor(); }
    ~IsolatedRuntime() { ppp::threading::Executors::Exit(); }
};
BOOST_GLOBAL_FIXTURE(IsolatedRuntime);

namespace ppp::app::client {
namespace {
class Relay final : public ppp::transmissions::ITransmission {
public:
    unsigned disposals = 0;
    std::vector<std::vector<uint8_t>> writes;
    ppp::p2p::P2PSessionExporter exporter = p2p_v2_test::Exporter(7);
    Relay(const ContextPtr& c, const AppConfigurationPtr& config)
        : ITransmission(c, std::make_shared<boost::asio::strand<boost::asio::io_context::executor_type>>(c->get_executor()), config) {}
    bool ShiftToScheduler() noexcept override { return false; }
    void Dispose() noexcept override { ++disposals; ITransmission::Dispose(); }
    boost::asio::ip::tcp::endpoint GetRemoteEndPoint() noexcept override { return {}; }
    std::shared_ptr<Byte> DoReadBytes(YieldContext&, int) noexcept override { return {}; }
    bool DoWriteBytes(std::shared_ptr<Byte> bytes, int offset, int size, const AsynchronousWriteBytesCallback& cb) noexcept override {
        if (!bytes || offset < 0 || size < 0) { cb(false); return false; }
        writes.emplace_back(bytes.get() + offset, bytes.get() + offset + size);
        cb(true); return true;
    }
    bool ExportAuthenticatedSessionKey(const char* label, const uint8_t* ctx, std::size_t n,
        uint8_t* out, std::size_t size) noexcept override { return exporter(label, ctx, n, out, size); }
};
class Datagram final : public ppp::p2p::IP2PDatagramTransport {
public:
    bool ready = true;
    unsigned closes = 0;
    ppp::p2p::P2PDatagramReceiveCallback receive;
    std::vector<std::vector<uint8_t>> sent;
    std::vector<boost::asio::ip::udp::endpoint> destinations;
    bool IsReady() const noexcept override { return ready; }
    bool Start(const ppp::p2p::P2PDatagramReceiveCallback& cb) noexcept override { receive = cb; return ready; }
    boost::asio::ip::udp::endpoint LocalEndpoint() const noexcept override {
        return {boost::asio::ip::make_address("192.0.2.1"), 4001};
    }
    bool SendTo(const uint8_t* bytes, int n, const boost::asio::ip::udp::endpoint& destination) noexcept override {
        if (!ready) return false;
        sent.emplace_back(bytes, bytes + n); destinations.push_back(destination); return true;
    }
    void Close() noexcept override { ready = false; ++closes; }
};
class Mapping final : public ppp::app::protocol::VirtualEthernetMappingPort {
public:
    unsigned ticks = 0;
    Mapping(const std::shared_ptr<ppp::app::protocol::VirtualEthernetLinklayer>& e,
        const std::shared_ptr<Relay>& tx) : VirtualEthernetMappingPort(e, tx, true, true, 4321) {}
    bool Update(UInt64) noexcept override { ++ticks; return true; }
};
class PacketSink final : public VEthernetExchanger {
public:
    using VEthernetExchanger::VEthernetExchanger;
    std::vector<std::vector<uint8_t>> inbound;
    bool OnNat(const ITransmissionPtr&, Byte* packet, int size) noexcept override {
        inbound.emplace_back(packet, packet + size); return true;
    }
};
std::vector<uint8_t> IPv4Packet(uint32_t source, uint32_t destination) {
    using namespace ppp::net::native;
    std::vector<uint8_t> packet(sizeof(ip_hdr) + sizeof(udp_hdr), 0);
    auto* ip = reinterpret_cast<ip_hdr*>(packet.data());
    ip->v_hl = 0x45; ip->len = htons(static_cast<uint16_t>(packet.size()));
    ip->ttl = 64; ip->proto = ip_hdr::IP_PROTO_UDP; ip->src = source; ip->dest = destination;
    ip->chksum = inet_chksum(ip, sizeof(ip_hdr));
    auto* udp = reinterpret_cast<udp_hdr*>(packet.data() + sizeof(ip_hdr));
    udp->src = htons(12000); udp->dest = htons(13000); udp->len = htons(sizeof(udp_hdr));
    return packet;
}
boost::asio::ip::udp::endpoint NativeCandidate(const ppp::p2p::P2PCandidateEndpoint& candidate) {
    boost::asio::ip::address_v4::bytes_type address{};
    std::copy(candidate.address.begin() + 12, candidate.address.end(), address.begin());
    return {boost::asio::ip::address_v4(address), candidate.port};
}
}

// Only dependency boundaries are replaced; recovery and callback validation run
// on the actual exchanger compiled from the production translation units.
struct P2PExchangerRecoveryTestAccess {
    using Exchanger = VEthernetExchanger;
    std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
    std::shared_ptr<ppp::configurations::AppConfiguration> config = std::make_shared<ppp::configurations::AppConfiguration>();
    std::shared_ptr<Relay> tx = std::make_shared<Relay>(context, config);
    std::shared_ptr<PacketSink> exchanger = std::make_shared<PacketSink>(nullptr, config, context, Int128(1));
    std::shared_ptr<Datagram> socket;
    uint64_t now = ppp::threading::Executors::GetTickCount();
    unsigned registrations = 0, renews = 0;
    bool registration_ok = true, install_socket = true;
    ppp::coroutines::YieldContext::Anchor suspended;
    bool suspend_registration = false;
    std::map<uint32_t, std::shared_ptr<p2p_v2_test::Pair>> peers;
    std::size_t sent_cursor = 0;
    P2PExchangerRecoveryTestAccess() {
        BOOST_REQUIRE(config->Normalize());
        auto& e = *exchanger;
        e.transmission_ = tx;
        e.p2p_offer_generation_ = 7;
        e.p2p_v2_selected_ = true;
        e.p2p_registered_virtual_ip_ = 1;
        e.p2p_peer_virtual_ip_ = 2;
        ppp::app::protocol::P2PEndpointCandidate host;
        host.endpoint = "192.0.2.1:4001"; host.source = "host";
        e.p2p_registered_candidates_ = {host};
        e.p2p_candidate_revision_ = 1;
        e.p2p_candidate_history_[1] = {host};
        e.recovery_test_hooks_.enabled = true;
        e.recovery_test_hooks_.now = [this] { return now; };
        e.recovery_test_hooks_.control = [this](const char* action) { if (std::string(action) == "renew") ++renews; };
        e.recovery_test_hooks_.register_candidates = [this](const Exchanger::ITransmissionPtr&, Exchanger::YieldContext& y) {
            ++registrations;
            if (install_socket) Install();
            if (suspend_registration) { suspended = y.Arm(); y.Suspend(suspended); }
            return registration_ok;
        };
        Install();
    }
    ~P2PExchangerRecoveryTestAccess() {
        exchanger->Finalize();
        Pump();
    }
    void Pump() { context->restart(); context->poll(); context->restart(); }
    void Install() {
        auto& e = *exchanger;
        ppp::app::protocol::P2PEndpointCandidate host;
        host.endpoint = "192.0.2.1:4001"; host.source = "host";
        e.p2p_registered_candidates_ = {host};
        e.p2p_candidate_history_[e.p2p_candidate_revision_] = {host};
        socket = std::make_shared<Datagram>();
        sent_cursor = 0;
        e.p2p_candidate_transport_ = socket;
        e.p2p_registered_transmission_ = tx;
        e.p2p_transport_registration_id_ = ++e.p2p_transport_registration_sequence_;
        const auto registration = e.p2p_transport_registration_id_;
        socket->Start([this, registration](ppp::p2p::P2PDatagramReceiveStatus status,
            const boost::asio::ip::udp::endpoint& sender, const uint8_t* bytes, int n) {
            exchanger->HandleP2PDatagram(tx, 7, registration, status, sender, bytes, n);
        });
    }
    void Error() { socket->receive(ppp::p2p::P2PDatagramReceiveStatus::Error, {}, nullptr, 0); }
    void Retry() { exchanger->RecoverP2PTransport(tx, 7, exchanger->p2p_transport_registration_id_); }
    uint64_t Deadline() const { return exchanger->p2p_retry_at_ms_; }
    bool Running() const { return exchanger->p2p_recovery_running_; }
    uint64_t Registration() const { return exchanger->p2p_transport_registration_id_; }
    bool Selected() const { return exchanger->p2p_v2_selected_; }
    void CheckRelay() {
        BOOST_TEST(exchanger->GetTransmission() == tx);
        BOOST_TEST(Selected());
        BOOST_TEST(!exchanger->disposed_.load());
    }
    void DisableGate() { exchanger->recovery_test_hooks_.enabled = false; }
    void FailPost() { exchanger->recovery_test_hooks_.post = [](ppp::function<void()>) { return false; }; }
    void FailSpawn() { exchanger->recovery_test_hooks_.spawn = [](ppp::coroutines::YieldContext::SpawnHander) { return false; }; }
    void ReplaceAttempt() {
        exchanger->p2p_recovery_running_ = false;
        ++exchanger->p2p_recovery_attempt_;
    }
    void CheckEmptyChannel() {
        for (const auto& peer : exchanger->p2p_v2_peers_) {
            const auto snapshot = peer.second->channel.Snapshot();
            BOOST_TEST(!snapshot.has_current);
            BOOST_TEST(!snapshot.has_pending);
            BOOST_TEST(!snapshot.has_previous);
        }
    }
    std::size_t PeerCount() const { return exchanger->p2p_v2_peers_.size(); }
    ppp::p2p::P2PV2Snapshot Snapshot(uint32_t vip) const {
        BOOST_REQUIRE(exchanger->p2p_v2_peers_.count(vip));
        return exchanger->p2p_v2_peers_.at(vip)->channel.Snapshot();
    }
    void Tick() { exchanger->TickP2PV2(tx, now, 7); Pump(); }
    void Inject(const std::vector<uint8_t>& bytes,
        const boost::asio::ip::udp::endpoint& source = {boost::asio::ip::make_address("192.0.2.2"), 4002}) {
        socket->receive(ppp::p2p::P2PDatagramReceiveStatus::Packet,
            source, bytes.data(), static_cast<int>(bytes.size()));
        Pump();
    }
    void Application(uint32_t vip, uint32_t claimed_source, uint32_t destination = 1) {
        const auto packet = IPv4Packet(claimed_source, destination);
        std::vector<uint8_t> encrypted;
        BOOST_REQUIRE(peers.at(vip)->channels[1].SealData(packet, now, 7, encrypted));
        Inject(encrypted, NativeCandidate(peers.at(vip)->contexts[1].local_candidates.back()));
    }
    void ConfigureStun(const char* profile = "standard") {
        config->p2p.stun_servers = {"192.0.2.100:3478"};
        config->p2p.stun_request_profile = profile;
    }
    void StartStun(const char* profile = "standard") {
        ConfigureStun(profile);
        exchanger->StartP2PStunGatherAsync(tx, 7, Registration(), 1, config->p2p.stun_servers);
        Pump();
    }
    void RefreshStun() { exchanger->TickP2PStunRefresh(tx, now); Pump(); }
    bool StunRunning() const {
        return exchanger->p2p_stun_gatherer_ && exchanger->p2p_stun_gatherer_->IsRunning();
    }
    uint64_t StunDeadline() const { return exchanger->p2p_next_stun_refresh_ms_; }
    uint64_t Revision() const { return exchanger->p2p_candidate_revision_; }
    std::size_t CandidateCount() const { return exchanger->p2p_registered_candidates_.size(); }
    std::vector<uint8_t> StunRequest() const {
        for (auto it = socket->sent.rbegin(); it != socket->sent.rend(); ++it) {
            if ((it->size() == 20 || it->size() == 40) && (*it)[0] == 0 && (*it)[1] == 1) return *it;
        }
        BOOST_FAIL("Expected a production STUN binding request");
        return {};
    }
    void CompleteStun(const boost::asio::ip::udp::endpoint& mapped) {
        const auto request = StunRequest();
        std::vector<uint8_t> reply(32, 0);
        const auto write16 = [](uint8_t* bytes, uint16_t value) {
            bytes[0] = static_cast<uint8_t>(value >> 8); bytes[1] = static_cast<uint8_t>(value);
        };
        write16(reply.data(), 0x0101); write16(reply.data() + 2, 12);
        std::copy(request.begin() + 4, request.begin() + 20, reply.begin() + 4);
        write16(reply.data() + 20, 0x0020); write16(reply.data() + 22, 8);
        reply[25] = 1; write16(reply.data() + 26, mapped.port() ^ 0x2112);
        const auto address = mapped.address().to_v4().to_uint() ^ 0x2112a442u;
        for (unsigned index = 0; index < 4; ++index) reply[28 + index] = static_cast<uint8_t>(address >> (24 - index * 8));
        socket->receive(ppp::p2p::P2PDatagramReceiveStatus::Packet,
            {boost::asio::ip::make_address("192.0.2.100"), 3478}, reply.data(), static_cast<int>(reply.size()));
        Pump();
    }
    void ApplyMapping(const boost::asio::ip::udp::endpoint& mapped,
        uint64_t generation, uint64_t registration, const std::shared_ptr<Relay>& relay, bool pump = true) {
        exchanger->ApplyP2PStunMappedCandidate(relay, generation, registration, 1, mapped);
        if (pump) Pump();
    }
    std::shared_ptr<p2p_v2_test::Pair> Offer(uint32_t vip, bool tamper = false,
        uint32_t claimed_vip = 0, uint64_t key_generation = 1, bool dual_candidates = false) {
        using namespace ppp::p2p;
        auto peer = key_generation > 1 ? peers.at(vip) : std::make_shared<p2p_v2_test::Pair>();
        auto& e = *exchanger;
        Int128ToBytes(e.GetId(), peer->contexts[0].local_session_id.data());
        peer->contexts[0].local_peer_id = {};
        std::memcpy(peer->contexts[0].local_peer_id.data() + 12, &e.p2p_registered_virtual_ip_, 4);
        peer->contexts[1].local_session_id = p2p_v2_test::Bytes<16>(static_cast<uint8_t>(vip + 20));
        peer->contexts[1].local_peer_id = {};
        std::memcpy(peer->contexts[1].local_peer_id.data() + 12, &vip, 4);
        if (dual_candidates && key_generation == 1) {
            peer->contexts[0].local_candidates.push_back(p2p_v2_test::Endpoint(10));
            peer->contexts[1].local_candidates.push_back(p2p_v2_test::Endpoint(static_cast<uint8_t>(20 + vip)));
            peer->contexts[0].peer_candidates = peer->contexts[1].local_candidates;
            peer->contexts[1].peer_candidates = peer->contexts[0].local_candidates;
        }
        if (key_generation == 1) peer->Offer(now);
        else {
            if (!Snapshot(vip).has_current) peer->channels[1].Reset(7);
            P2PRelayOfferV2Input input;
            input.initiator_session_id = peer->contexts[0].local_session_id;
            input.responder_session_id = peer->contexts[1].local_session_id;
            input.initiator_peer_id = peer->contexts[0].local_peer_id;
            input.responder_peer_id = peer->contexts[1].local_peer_id;
            input.initiator_candidate_revision = input.responder_candidate_revision = 1;
            input.key_generation = key_generation;
            input.previous_offer_hash = Snapshot(vip).current_offer_hash;
            BOOST_REQUIRE(HashP2PV2CandidateSet(input.initiator_session_id, input.responder_session_id,
                1, 1, peer->contexts[0].local_candidates, peer->contexts[1].local_candidates, input.candidate_set_hash));
            BOOST_REQUIRE(CreateP2PRelayOfferV2Bundle(input, peer->exporters[0], peer->exporters[1], peer->bundle));
            BOOST_REQUIRE(EncodeP2PRelayOfferRecipientV2Hex(peer->bundle.offer, peer->bundle.initiator_envelope, peer->encoded[0]));
            BOOST_REQUIRE(EncodeP2PRelayOfferRecipientV2Hex(peer->bundle.offer, peer->bundle.responder_envelope, peer->encoded[1]));
            BOOST_REQUIRE(peer->channels[1].AcceptOffer(peer->encoded[1], peer->contexts[1], peer->exporters[1], now, 7));
        }
        ppp::app::protocol::P2PControlMessage offer;
        offer.enabled = true; offer.action = "offer-v2";
        offer.virtual_ip = e.p2p_registered_virtual_ip_; offer.peer_virtual_ip = claimed_vip ? claimed_vip : vip;
        offer.supported_versions = {1, 2}; offer.candidate_revision = offer.peer_candidate_revision = 1;
        for (const auto& candidate : peer->contexts[0].local_candidates) {
            ppp::app::protocol::P2PEndpointCandidate value;
            const auto endpoint = NativeCandidate(candidate);
            value.endpoint = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
            offer.local_candidates.push_back(value);
        }
        for (const auto& candidate : peer->contexts[1].local_candidates) {
            ppp::app::protocol::P2PEndpointCandidate value;
            const auto endpoint = NativeCandidate(candidate);
            value.endpoint = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
            offer.candidates.push_back(value);
        }
        auto encoded = peer->encoded[0];
        if (tamper) encoded.back() = encoded.back() == '0' ? '1' : '0';
        offer.authenticated_offer_v2 = encoded.c_str();
        e.p2p_candidate_history_[1] = offer.local_candidates;
        e.HandleP2PV2RelayOffer(tx, offer); Pump();
        if (!tamper) peers[vip] = peer;
        return peer;
    }
    void DeliverReplies() {
        using namespace ppp::p2p;
        while (sent_cursor < socket->sent.size()) {
            BOOST_REQUIRE(sent_cursor < 1000u);
            const auto packet = socket->sent[sent_cursor++];
            P2PV2DataPacketHeader header;
            P2PV2ControlPacket control;
            const bool data = ParseP2PV2DataPacketHeader(packet, header);
            BOOST_REQUIRE(data || ParseP2PV2Control(packet, control));
            const auto hash = data ? header.offer_hash : control.offer_hash;
            std::shared_ptr<p2p_v2_test::Pair> peer;
            for (const auto& entry : peers) {
                const auto snapshot = entry.second->channels[1].Snapshot();
                if (snapshot.current_offer_hash == hash || snapshot.pending_offer_hash == hash) {
                    BOOST_REQUIRE(!peer);
                    peer = entry.second;
                }
            }
            BOOST_REQUIRE(peer);
            const auto source = peer->contexts[0].local_candidates.back();
            if (peer->contexts[1].local_candidates.size() > 1 &&
                socket->destinations[sent_cursor - 1] != NativeCandidate(peer->contexts[1].local_candidates.back())) continue;
            if (data) {
                std::vector<uint8_t> plaintext;
                BOOST_REQUIRE(peer->channels[1].OpenData(packet, source, now, 7, plaintext));
                continue;
            }
            P2PV2ControlResult result;
            const bool accepted = peer->channels[1].HandleControl(packet, source, now, 7, result);
            if (peer->contexts[0].local_candidates.size() > 1 && !(control.source == source)) {
                BOOST_TEST(!accepted); continue;
            }
            BOOST_REQUIRE(accepted);
            for (const auto& reply : result.outbound) {
                socket->receive(P2PDatagramReceiveStatus::Packet,
                    NativeCandidate(peer->contexts[1].local_candidates.back()),
                    reply.datagram.data(), static_cast<int>(reply.datagram.size()));
                Pump();
            }
        }
    }
    void PrimeRemote(uint32_t vip) {
        auto& peer = *peers.at(vip);
        for (const auto& local : peer.contexts[1].local_candidates) {
            for (const auto& destination : peer.contexts[0].local_candidates) {
                std::vector<uint8_t> packet;
                BOOST_REQUIRE(peer.channels[1].CreateProbe(local, destination, now, 7, packet));
                if (destination == peer.contexts[0].local_candidates.back())
                    Inject(packet, NativeCandidate(peer.contexts[1].local_candidates.back()));
            }
        }
    }
    void Handshake(uint32_t vip = 2, uint64_t key_generation = 1) {
        using namespace ppp::p2p;
        auto peer = Offer(vip, false, 0, key_generation);
        auto& e = *exchanger;
        BOOST_REQUIRE(e.p2p_v2_peers_.count(vip));
        BOOST_REQUIRE(e.p2p_v2_peers_.at(vip)->channel.Snapshot().has_pending);
        auto reverse = peer->Probe(1, now);
        const boost::asio::ip::udp::endpoint endpoint(boost::asio::ip::make_address("192.0.2.2"), 4002);
        socket->receive(P2PDatagramReceiveStatus::Packet, endpoint, reverse.data(), static_cast<int>(reverse.size()));
        Pump();
        DeliverReplies();
        BOOST_TEST(e.p2p_v2_peers_.at(vip)->channel.Snapshot().has_current);
        BOOST_TEST(peer->channels[1].Snapshot().has_current);
        BOOST_TEST(static_cast<int>(e.p2p_state_.load()) == static_cast<int>(P2PState::Direct));
        std::vector<uint8_t> legacy(158);
        legacy[0] = 1; legacy[1] = 1;
        const auto sent_before = socket->sent.size();
        socket->receive(P2PDatagramReceiveStatus::Packet, endpoint, legacy.data(), static_cast<int>(legacy.size()));
        Pump();
        BOOST_TEST(socket->sent.size() == sent_before);
        BOOST_TEST(e.p2p_v2_peers_.at(vip)->channel.Snapshot().has_current); BOOST_TEST(Selected());
    }
    void UpdateWithFrp() {
        auto& e = *exchanger;
        e.switcher_ = std::make_shared<VEthernetNetworkSwitcher>(context, false, false, false, config);
        e.network_state_ = Exchanger::NetworkState_Established;
        e.keepalive_policy_.OnConnected(ppp::threading::Executors::GetTickCount(), 50000);
        auto mapping = std::make_shared<Mapping>(exchanger, tx);
        BOOST_REQUIRE(e.frp_registry_->Add(true, true, 4321, mapping));
        BOOST_REQUIRE(e.Update()); Pump();
        BOOST_TEST(mapping->ticks == 1u);
        BOOST_TEST(tx->disposals == 0u);
        CheckRelay();
    }
    void AliasPeerForAmbiguousHash(uint32_t source, uint32_t alias) {
        exchanger->p2p_v2_peers_[alias] = exchanger->p2p_v2_peers_.at(source);
    }
    bool SendQueued(const std::vector<uint8_t>& datagram, uint64_t registration) {
        return exchanger->SendP2PV2Packets(tx,
            {{datagram, p2p_v2_test::Endpoint(2)}}, 7, registration);
    }
    void ExhaustEgress(uint32_t vip) {
        ppp::p2p::P2PId session{};
        ppp::p2p::Int128ToBytes(exchanger->GetId(), session.data());
        unsigned consumed = 0;
        auto& limiter = exchanger->p2p_v2_peers_.at(vip)->egress_limiter;
        while (limiter.AllowSession(session, now)) ++consumed;
        BOOST_TEST(consumed <= ppp::p2p::P2PIngressLimiter::SessionBurst);
    }
    std::size_t DeferredCount(uint32_t vip) const {
        const auto peer = exchanger->p2p_v2_peers_.find(vip);
        return peer == exchanger->p2p_v2_peers_.end() ? 0 : peer->second->deferred_packets.size();
    }
    std::vector<uint8_t> DeferredBytes(uint32_t vip) const {
        BOOST_REQUIRE(DeferredCount(vip));
        return exchanger->p2p_v2_peers_.at(vip)->deferred_packets.front().packet.datagram;
    }
    bool FlushDeferred(uint64_t registration) {
        return exchanger->SendP2PV2Packets(tx, {}, 7, registration);
    }
};
}

using Fixture = ppp::app::client::P2PExchangerRecoveryTestAccess;

BOOST_AUTO_TEST_CASE(socket_error_closes_immediately_and_invalidates_registration) {
    Fixture f;
    f.Handshake();
    auto old = f.socket;
    f.Error();
    BOOST_TEST(old->closes == 1u);
    BOOST_TEST(f.Registration() == 0u);
    BOOST_TEST(f.Deadline() == f.now + 1000);
    f.CheckEmptyChannel(); f.CheckRelay();
    old->receive(ppp::p2p::P2PDatagramReceiveStatus::Error, {}, nullptr, 0);
    BOOST_TEST(old->closes == 1u);
    f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_TEST(f.registrations == 1u);
    BOOST_TEST(f.Registration() != 0u);
    BOOST_TEST(!f.Running()); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(idle_peer_context_is_reclaimed_after_channel_liveness_timeout) {
    Fixture f;
    f.Handshake();
    BOOST_TEST(f.PeerCount() == 1u);

    // The direct channel has already lost liveness by this point.  Tick must
    // clear its channel and release the map entry so a later peer can reuse
    // the bounded table slot.
    f.now += 30000;
    f.Tick();
    BOOST_TEST(f.PeerCount() == 0u);
}

BOOST_AUTO_TEST_CASE(failed_registration_obeys_one_two_four_eight_ten_second_backoff) {
    Fixture f; f.registration_ok = false;
    f.Error();
    const uint64_t expected[] = {1000, 2000, 4000, 8000, 10000, 10000};
    for (auto delay : expected) {
        BOOST_TEST(f.Deadline() == f.now + delay);
        f.now = f.Deadline() - 1; f.Retry(); f.Pump();
        const auto before = f.registrations;
        ++f.now; f.Retry(); f.Pump();
        BOOST_TEST(f.registrations == before + 1);
        BOOST_TEST(f.Registration() == 0u); f.CheckRelay();
    }
}

BOOST_AUTO_TEST_CASE(production_gate_stays_closed_and_test_capability_is_explicit) {
    BOOST_TEST(ppp::p2p::ProductionAuthenticatedControlV1Ready);
    Fixture f; f.DisableGate(); f.Error();
    f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_TEST(f.registrations == 0u); BOOST_TEST(!f.Running());
}

BOOST_AUTO_TEST_CASE(production_gate_allows_recovery_when_enabled) {
    BOOST_TEST(ppp::p2p::ProductionAuthenticatedControlV1Ready);
    Fixture f; f.Error();
    f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_TEST(f.registrations == 1u); BOOST_TEST(!f.Running());
}

BOOST_AUTO_TEST_CASE(registration_failure_without_socket_waits_and_does_not_send_renew) {
    Fixture f; f.registration_ok = false; f.install_socket = false;
    f.Error(); f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_TEST(f.registrations == 1u); BOOST_TEST(!f.Running());
    BOOST_TEST(f.Deadline() == f.now + 2000);
    BOOST_TEST(f.renews == 0u); BOOST_TEST(f.Registration() == 0u); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(post_and_spawn_failure_release_running_and_retry) {
    for (bool post : {false, true}) {
        Fixture f; f.Error(); f.now = f.Deadline();
        if (post) f.FailPost(); else f.FailSpawn();
        f.Retry(); f.Pump();
        BOOST_TEST(!f.Running()); BOOST_TEST(f.Deadline() == f.now + 1000);
        BOOST_TEST(f.registrations == 0u); f.CheckRelay();
    }
}

BOOST_AUTO_TEST_CASE(same_generation_old_queued_callback_cannot_rebuild) {
    Fixture f; f.Error(); f.now = f.Deadline();
    f.Retry(); f.ReplaceAttempt(); f.Pump();
    BOOST_TEST(f.registrations == 0u); BOOST_TEST(f.Registration() == 0u);
}

BOOST_AUTO_TEST_CASE(same_generation_old_coroutine_completion_cannot_overwrite_new_socket) {
    Fixture f; f.suspend_registration = true; f.Error(); f.now = f.Deadline();
    f.Retry(); f.Pump();
    BOOST_REQUIRE(f.suspended);
    auto old = f.socket; f.Error();
    f.suspend_registration = false; f.now = f.Deadline(); f.Retry(); f.Pump();
    const auto current = f.socket;
    const auto registration = f.Registration();
    const auto renews = f.renews;
    BOOST_REQUIRE(f.suspended.R()); f.Pump();
    BOOST_TEST(f.socket == current); BOOST_TEST(f.Registration() == registration);
    BOOST_TEST(f.renews == renews); BOOST_TEST(old->closes == 1u); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(rebuilt_transport_completes_authenticated_v2_handshake_and_rejects_v1) {
    Fixture f; f.Offer(2); f.Error(); f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_TEST(f.renews == 1u); f.Handshake(2, 2);
}

BOOST_AUTO_TEST_CASE(actual_update_keeps_frp_maintenance_during_recovery_and_v2_selection) {
    {
        Fixture f; f.Error(); f.UpdateWithFrp();
        BOOST_TEST(f.registrations == 0u);
    }
    {
        Fixture f; f.UpdateWithFrp();
    }
}

BOOST_AUTO_TEST_CASE(two_authenticated_peers_share_endpoint_and_remain_independent) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    BOOST_REQUIRE_EQUAL(f.PeerCount(), 2u);
    const auto first = f.Snapshot(2), second = f.Snapshot(3);
    BOOST_TEST(first.has_current); BOOST_TEST(second.has_current);
    BOOST_CHECK(first.current_offer_hash != second.current_offer_hash);
    BOOST_CHECK(first.peer_candidate == second.peer_candidate);
    f.Application(2, 2); f.Application(3, 3);
    BOOST_REQUIRE_EQUAL(f.exchanger->inbound.size(), 2u);
    BOOST_CHECK(f.exchanger->inbound[0] == ppp::app::client::IPv4Packet(2, 1));
    BOOST_CHECK(f.exchanger->inbound[1] == ppp::app::client::IPv4Packet(3, 1));
    BOOST_CHECK(f.Snapshot(2).current_offer_hash == first.current_offer_hash);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == second.current_offer_hash);
    f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(actual_update_preserves_two_active_peers_and_frp_maintenance) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    const auto first = f.Snapshot(2).current_offer_hash;
    const auto second = f.Snapshot(3).current_offer_hash;
    f.UpdateWithFrp();
    BOOST_TEST(f.Snapshot(2).has_current); BOOST_TEST(f.Snapshot(3).has_current);
    BOOST_CHECK(f.Snapshot(2).current_offer_hash == first);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == second);
}

BOOST_AUTO_TEST_CASE(three_dual_candidate_peers_complete_without_erasing_control_budgets) {
    Fixture f;
    for (uint32_t vip = 2; vip <= 4; ++vip) f.Offer(vip, false, 0, 1, true);
    for (uint32_t vip = 2; vip <= 4; ++vip) f.PrimeRemote(vip);
    f.DeliverReplies();
    for (uint32_t vip = 2; vip <= 4; ++vip) {
        const auto snapshot = f.Snapshot(vip);
        BOOST_REQUIRE_MESSAGE(snapshot.has_current, "Each authenticated peer must get its own bounded setup budget");
        BOOST_TEST(f.peers.at(vip)->channels[1].Snapshot().has_current);
        BOOST_CHECK(snapshot.local_candidate == f.peers.at(vip)->contexts[0].local_candidates.back());
        BOOST_CHECK(snapshot.peer_candidate == f.peers.at(vip)->contexts[1].local_candidates.back());
        f.Application(vip, vip);
    }
    BOOST_REQUIRE_EQUAL(f.exchanger->inbound.size(), 3u);
    BOOST_TEST(f.PeerCount() == 3u); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(authenticated_peer_cannot_deliver_other_peer_or_other_destination_ipv4) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    f.Application(2, 3); f.Application(2, 2, 3);
    BOOST_TEST(f.exchanger->inbound.empty());
    f.Application(2, 2); f.Application(3, 3);
    BOOST_REQUIRE_EQUAL(f.exchanger->inbound.size(), 2u);
    BOOST_TEST(f.Snapshot(2).has_current); BOOST_TEST(f.Snapshot(3).has_current);
}

BOOST_AUTO_TEST_CASE(one_peer_key_rotation_preserves_other_peer_current_and_nonce_state) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    const auto old = f.Snapshot(2).current_offer_hash;
    const auto independent = f.Snapshot(3).current_offer_hash;
    f.now += 1000;
    f.Handshake(2, 2);
    BOOST_CHECK(f.Snapshot(2).current_offer_hash != old);
    BOOST_TEST(f.Snapshot(2).key_generation == 2u);
    BOOST_TEST(f.Snapshot(2).has_previous);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == independent);
    BOOST_TEST(f.Snapshot(3).key_generation == 1u);
    f.Application(2, 2); f.Application(3, 3);
    BOOST_REQUIRE_EQUAL(f.exchanger->inbound.size(), 2u);
}

BOOST_AUTO_TEST_CASE(ambiguous_offer_hash_fails_closed_before_decryption_and_delivery) {
    Fixture f;
    f.Handshake(2);
    f.AliasPeerForAmbiguousHash(2, 3);
    const auto sent = f.socket->sent.size();
    f.Application(2, 2);
    BOOST_TEST(f.exchanger->inbound.empty());
    BOOST_TEST(f.socket->sent.size() == sent);
    BOOST_TEST(f.Snapshot(2).has_current);
}

BOOST_AUTO_TEST_CASE(unknown_hash_invalid_offer_and_mislabeled_vip_cannot_allocate_peer_slot) {
    Fixture f;
    f.Offer(2, false, 3);
    BOOST_TEST(f.PeerCount() == 0u);
    for (uint32_t vip = 2; vip < 24; ++vip) f.Offer(vip, true);
    BOOST_TEST(f.PeerCount() == 0u);
    f.Handshake(2);
    std::vector<uint8_t> packet;
    BOOST_REQUIRE(f.peers.at(2)->channels[1].SealData(std::vector<uint8_t>{0}, f.now, 7, packet));
    packet[4] ^= 1;
    const auto sent = f.socket->sent.size();
    f.Inject(packet);
    BOOST_TEST(f.socket->sent.size() == sent);
    BOOST_TEST(f.PeerCount() == 1u);
    BOOST_TEST(f.Snapshot(2).has_current);
}

BOOST_AUTO_TEST_CASE(authenticated_peer_capacity_is_bounded_without_evicting_existing_pending) {
    Fixture f;
    for (uint32_t vip = 2; vip < 18; ++vip) f.Offer(vip);
    BOOST_REQUIRE_EQUAL(f.PeerCount(), 16u);
    const auto first = f.Snapshot(2).pending_offer_hash;
    const auto last = f.Snapshot(17).pending_offer_hash;
    f.Offer(18);
    BOOST_TEST(f.PeerCount() == 16u);
    BOOST_CHECK(f.Snapshot(2).pending_offer_hash == first);
    BOOST_CHECK(f.Snapshot(17).pending_offer_hash == last);
}

BOOST_AUTO_TEST_CASE(one_peer_liveness_failure_preserves_other_direct_peer_and_relay) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    const auto healthy = f.Snapshot(3).current_offer_hash;
    f.now += 10000;
    f.Application(3, 3);
    BOOST_TEST(!f.Snapshot(2).has_current);
    BOOST_TEST(!f.Snapshot(2).has_pending);
    BOOST_TEST(f.Snapshot(3).has_current);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == healthy);
    BOOST_REQUIRE_EQUAL(f.exchanger->inbound.size(), 1u);
    f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(shared_socket_error_invalidates_all_peer_keys_and_stale_callbacks) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    auto old = f.socket;
    std::vector<uint8_t> stale;
    BOOST_REQUIRE(f.peers.at(3)->channels[1].SealData(std::vector<uint8_t>{0}, f.now, 7, stale));
    f.Error();
    f.CheckEmptyChannel(); f.CheckRelay();
    BOOST_TEST(old->closes == 1u);
    old->receive(ppp::p2p::P2PDatagramReceiveStatus::Packet,
        {boost::asio::ip::make_address("192.0.2.2"), 4002}, stale.data(), static_cast<int>(stale.size()));
    f.Pump(); f.CheckEmptyChannel();
    f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_TEST(f.registrations == 1u);
    f.CheckEmptyChannel(); f.CheckRelay();
    f.Handshake(2, 2); f.Handshake(3, 2);
    BOOST_TEST(f.Snapshot(2).has_current); BOOST_TEST(f.Snapshot(3).has_current);
}

BOOST_AUTO_TEST_CASE(old_registration_queued_outbound_cannot_send_on_rebuilt_socket) {
    Fixture f;
    f.Handshake(2);
    const auto registration = f.Registration();
    const auto stale = f.socket->sent.back();
    f.Error(); f.now = f.Deadline(); f.Retry(); f.Pump();
    f.Handshake(2, 2);
    BOOST_REQUIRE(f.Registration() != registration);
    const auto sent = f.socket->sent.size();
    BOOST_TEST(!f.SendQueued(stale, registration));
    BOOST_TEST(f.socket->sent.size() == sent);
    BOOST_TEST(f.socket->ready); BOOST_TEST(f.socket->closes == 0u);
    const auto current = f.socket->sent.back();
    BOOST_TEST(f.SendQueued(current, f.Registration()));
    BOOST_TEST(f.socket->sent.size() == sent + 1);
    BOOST_TEST(f.Snapshot(2).has_current); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(exhausted_peer_budget_defers_exact_authenticated_ack_until_refill) {
    Fixture f;
    auto peer = f.Offer(2);
    f.ExhaustEgress(2);
    const auto probe = peer->Probe(1, f.now);
    const auto sent = f.socket->sent.size();
    f.Inject(probe);
    BOOST_REQUIRE_EQUAL(f.DeferredCount(2), 1u);
    const auto ack = f.DeferredBytes(2);
    ppp::p2p::P2PV2ControlPacket decoded;
    BOOST_REQUIRE(ppp::p2p::ParseP2PV2Control(ack, decoded));
    BOOST_TEST(static_cast<unsigned>(decoded.type) == static_cast<unsigned>(ppp::p2p::P2PV2ControlType::ProbeAck));
    f.Inject(probe); // Cached authenticated response is deduplicated in the queue.
    BOOST_TEST(f.DeferredCount(2) == 1u);
    BOOST_TEST(f.socket->sent.size() == sent);
    f.now += 124; BOOST_TEST(f.FlushDeferred(f.Registration()));
    BOOST_TEST(f.socket->sent.size() == sent);
    ++f.now; BOOST_TEST(f.FlushDeferred(f.Registration()));
    BOOST_TEST(f.socket->sent.size() == sent + 1);
    BOOST_CHECK(f.socket->sent.back() == ack);
    BOOST_TEST(f.DeferredCount(2) == 0u);
    BOOST_CHECK(f.socket->destinations.back() == ppp::app::client::NativeCandidate(decoded.destination));
}

BOOST_AUTO_TEST_CASE(socket_rebuild_clears_deferred_authenticated_control_before_new_registration) {
    Fixture f;
    auto peer = f.Offer(2);
    f.ExhaustEgress(2);
    f.Inject(peer->Probe(1, f.now));
    BOOST_REQUIRE_EQUAL(f.DeferredCount(2), 1u);
    const auto old_registration = f.Registration();
    f.Error();
    BOOST_TEST(f.DeferredCount(2) == 0u);
    f.now = f.Deadline(); f.Retry(); f.Pump();
    BOOST_REQUIRE(f.Registration() != old_registration);
    const auto sent = f.socket->sent.size();
    BOOST_TEST(!f.FlushDeferred(old_registration));
    BOOST_TEST(f.FlushDeferred(f.Registration()));
    BOOST_TEST(f.socket->sent.size() == sent);
    BOOST_TEST(f.DeferredCount(2) == 0u); f.CheckEmptyChannel(); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(expired_unsent_control_cannot_leave_optimistic_pending_setup) {
    Fixture f;
    auto peer = f.Offer(2);
    f.ExhaustEgress(2);
    f.Inject(peer->Probe(1, f.now));
    BOOST_REQUIRE_EQUAL(f.DeferredCount(2), 1u);
    f.now += 2000;
    BOOST_TEST(f.FlushDeferred(f.Registration()));
    BOOST_TEST(f.DeferredCount(2) == 0u);
    BOOST_TEST(!f.Snapshot(2).has_pending);
    BOOST_TEST(!f.Snapshot(2).has_current); f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(expired_unsent_refresh_preserves_current_until_original_pending_deadline) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    const auto first = f.Snapshot(2).current_offer_hash;
    const auto second = f.Snapshot(3).current_offer_hash;
    f.ExhaustEgress(2);
    f.Offer(2, false, 0, 2);
    BOOST_REQUIRE(f.Snapshot(2).has_pending);
    BOOST_TEST(!f.Snapshot(2).commit_started);
    const auto deadline = f.Snapshot(2).setup_deadline_ms;
    BOOST_REQUIRE(f.DeferredCount(2) > 0u);
    f.now += 2000;
    BOOST_TEST(f.FlushDeferred(f.Registration()));
    BOOST_TEST(f.DeferredCount(2) == 0u);
    BOOST_TEST(f.Snapshot(2).has_pending);
    BOOST_TEST(f.Snapshot(2).setup_deadline_ms == deadline);
    BOOST_TEST(f.Snapshot(2).has_current);
    BOOST_CHECK(f.Snapshot(2).current_offer_hash == first);
    BOOST_TEST(f.Snapshot(3).has_current);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == second);
    f.Application(2, 2); f.Application(3, 3);
    while (f.now < deadline) {
        f.now = std::min(f.now + 1000, deadline);
        f.Application(2, 2); f.Application(3, 3);
        f.DeliverReplies();
    }
    BOOST_TEST(!f.Snapshot(2).has_pending);
    BOOST_TEST(f.Snapshot(2).has_current);
    BOOST_CHECK(f.Snapshot(2).current_offer_hash == first);
    BOOST_TEST(f.Snapshot(3).has_current);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == second);
    BOOST_TEST(f.exchanger->inbound.size() > 0u);
    f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(periodic_stun_uses_same_transport_and_does_not_restart_running_transaction) {
    Fixture f;
    BOOST_TEST(f.config->p2p.stun_request_profile == "standard");
    f.StartStun();
    BOOST_REQUIRE(f.StunRunning());
    const auto socket = f.socket;
    const auto registration = f.Registration();
    const auto request = f.StunRequest();
    BOOST_REQUIRE(request.size() == 20u);
    BOOST_TEST(f.StunDeadline() == f.now + 15000);
    f.now += 14999; f.RefreshStun();
    BOOST_CHECK(f.StunRequest() == request);
    ++f.now; f.RefreshStun(); f.RefreshStun();
    BOOST_CHECK(f.StunRequest() == request);
    BOOST_TEST(f.socket->sent.size() == 1u);
    f.CompleteStun({boost::asio::ip::make_address("203.0.113.9"), 54321});
    BOOST_TEST(!f.StunRunning());
    f.RefreshStun();
    BOOST_REQUIRE(f.StunRunning());
    BOOST_CHECK(f.StunRequest() != request);
    BOOST_TEST(f.socket == socket); BOOST_TEST(f.Registration() == registration);
    BOOST_TEST(socket->LocalEndpoint().port() == 4001u); BOOST_TEST(socket->closes == 0u);
    BOOST_TEST(f.StunDeadline() == f.now + 15000);
}

BOOST_AUTO_TEST_CASE(stun_request_profile_configuration_roundtrips_and_defaults_to_standard) {
    ppp::configurations::AppConfiguration config;
    BOOST_TEST(config.p2p.stun_request_profile == "standard");
    auto json = config.ToJson();
    BOOST_TEST(json["p2p"]["stun"]["request-profile"].asString() == "standard");
    json["p2p"]["stun"]["request-profile"] = "  TAILNODE  ";
    BOOST_REQUIRE(config.Load(json));
    BOOST_TEST(config.p2p.stun_request_profile == "tailnode");
    auto exported = config.ToJson();
    BOOST_TEST(exported["p2p"]["stun"]["request-profile"].asString() == "tailnode");
    ppp::configurations::AppConfiguration roundtrip;
    BOOST_REQUIRE(roundtrip.Load(exported));
    BOOST_TEST(roundtrip.p2p.stun_request_profile == "tailnode");
    roundtrip.p2p.stun_request_profile = "unsupported-test-profile";
    BOOST_REQUIRE(roundtrip.Normalize());
    BOOST_TEST(roundtrip.p2p.stun_request_profile == "standard");
    BOOST_TEST(roundtrip.ToJson()["p2p"]["stun"]["request-profile"].asString() == "standard");
}

BOOST_AUTO_TEST_CASE(tailnode_stun_profile_sends_fingerprinted_40_byte_requests_on_shared_transport) {
    Fixture f;
    f.StartStun("tailnode");
    BOOST_REQUIRE(f.StunRunning());
    const auto socket = f.socket;
    const auto registration = f.Registration();
    const auto request = f.StunRequest();
    const auto check_request = [](const std::vector<uint8_t>& packet) {
        BOOST_REQUIRE(packet.size() == 40u);
        BOOST_TEST(packet[2] == 0u); BOOST_TEST(packet[3] == 20u);
        BOOST_TEST(packet[20] == 0x80u); BOOST_TEST(packet[21] == 0x22u);
        BOOST_TEST(packet[22] == 0u); BOOST_TEST(packet[23] == 8u);
        BOOST_CHECK(std::memcmp(packet.data() + 24, "tailnode", 8) == 0);
        BOOST_TEST(packet[32] == 0x80u); BOOST_TEST(packet[33] == 0x28u);
        BOOST_TEST(packet[34] == 0u); BOOST_TEST(packet[35] == 4u);
        boost::crc_32_type crc;
        crc.process_bytes(packet.data(), 32);
        const uint32_t fingerprint = (uint32_t(packet[36]) << 24) | (uint32_t(packet[37]) << 16) |
            (uint32_t(packet[38]) << 8) | uint32_t(packet[39]);
        BOOST_TEST(fingerprint == (crc.checksum() ^ 0x5354554eu));
    };
    check_request(request);
    f.CompleteStun({boost::asio::ip::make_address("203.0.113.9"), 54321});
    BOOST_TEST(!f.StunRunning());
    BOOST_TEST(f.Revision() == 2u);
    f.now = f.StunDeadline(); f.RefreshStun();
    BOOST_REQUIRE(f.StunRunning());
    const auto refreshed = f.StunRequest();
    check_request(refreshed);
    BOOST_CHECK(std::memcmp(request.data() + 8, refreshed.data() + 8, 12) != 0);
    BOOST_TEST(f.socket == socket); BOOST_TEST(f.Registration() == registration);
    BOOST_TEST(socket->LocalEndpoint().port() == 4001u); BOOST_TEST(socket->closes == 0u);
    BOOST_TEST(f.config->p2p.stun_request_profile == "tailnode");
    f.CheckRelay();
}

BOOST_AUTO_TEST_CASE(stun_latest_updates_preserve_both_active_peers_and_duplicate_revision) {
    Fixture f;
    f.Handshake(2); f.Handshake(3);
    const auto first = f.Snapshot(2), second = f.Snapshot(3);
    f.Offer(4);
    const auto pending = f.Snapshot(4).pending_offer_hash;
    BOOST_REQUIRE(f.Snapshot(4).has_pending);
    f.StartStun();
    const auto writes = f.tx->writes.size();
    f.CompleteStun({boost::asio::ip::make_address("203.0.113.9"), 54321});
    BOOST_TEST(f.Revision() == 2u); BOOST_TEST(f.CandidateCount() == 2u);
    BOOST_TEST(f.tx->writes.size() > writes);
    BOOST_CHECK(f.Snapshot(2).current_offer_hash == first.current_offer_hash);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == second.current_offer_hash);
    BOOST_CHECK(f.Snapshot(2).local_candidate == first.local_candidate);
    BOOST_CHECK(f.Snapshot(3).local_candidate == second.local_candidate);
    BOOST_CHECK(f.Snapshot(4).pending_offer_hash == pending);
    BOOST_TEST(f.Snapshot(4).has_pending);
    f.now = f.StunDeadline(); f.RefreshStun();
    f.CompleteStun({boost::asio::ip::make_address("203.0.113.9"), 54321});
    BOOST_TEST(f.Revision() == 2u);
    f.ApplyMapping(f.socket->LocalEndpoint(), 7, f.Registration(), f.tx);
    BOOST_TEST(f.Revision() == 3u); BOOST_TEST(f.CandidateCount() == 1u);
    f.ApplyMapping(f.socket->LocalEndpoint(), 7, f.Registration(), f.tx);
    BOOST_TEST(f.Revision() == 3u);
    BOOST_CHECK(f.Snapshot(2).current_offer_hash == first.current_offer_hash);
    BOOST_CHECK(f.Snapshot(3).current_offer_hash == second.current_offer_hash);
    BOOST_CHECK(f.Snapshot(4).pending_offer_hash == pending);
}

BOOST_AUTO_TEST_CASE(stale_stun_generation_registration_and_carrier_cannot_reregister) {
    Fixture f;
    const auto mapped = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("203.0.113.9"), 54321);
    const auto writes = f.tx->writes.size();
    f.ApplyMapping(mapped, 6, f.Registration(), f.tx);
    f.ApplyMapping(mapped, 7, f.Registration() + 1, f.tx);
    f.ApplyMapping(mapped, 7, f.Registration(), std::make_shared<ppp::app::client::Relay>(f.context, f.config));
    BOOST_TEST(f.Revision() == 1u); BOOST_TEST(f.CandidateCount() == 1u);
    BOOST_TEST(f.tx->writes.size() == writes);
    f.ApplyMapping(mapped, 7, f.Registration(), f.tx, false);
    BOOST_TEST(f.Revision() == 2u);
    BOOST_TEST(f.tx->writes.size() == writes);
    f.Error();
    f.Pump();
    f.ApplyMapping(mapped, 7, 1, f.tx);
    BOOST_TEST(f.tx->writes.size() == writes);
    f.CheckEmptyChannel(); f.CheckRelay();
}
