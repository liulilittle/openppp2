#define BOOST_TEST_MODULE p2p_v2_integration_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PV2Channel.h>
#include <ppp/p2p/P2PV2Codec.h>
#include <ppp/p2p/P2PProbeCoordinator.h>
#include <ppp/p2p/P2PIngressLimiter.h>
#include <ppp/p2p/P2PDirectDataPath.h>
#include <ppp/p2p/P2PDatagramTransport.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>

#include <array>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <tuple>

namespace {

using namespace ppp::p2p;

template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t seed) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t index = 0; index < N; ++index) result[index] = seed + index;
    return result;
}

P2PCandidateEndpoint Endpoint(const char* host, std::uint16_t port) {
    P2PCandidateEndpoint result;
    result.address_family = 4;
    result.address[10] = result.address[11] = 0xff;
    const auto bytes = boost::asio::ip::make_address_v4(host).to_bytes();
    std::copy(bytes.begin(), bytes.end(), result.address.begin() + 12);
    result.port = port;
    return result;
}

boost::asio::ip::udp::endpoint NativeEndpoint(const P2PCandidateEndpoint& endpoint) {
    BOOST_REQUIRE(endpoint.address_family == 4);
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::copy(endpoint.address.begin() + 12, endpoint.address.end(), bytes.begin());
    return {boost::asio::ip::address_v4(bytes), endpoint.port};
}

P2PCandidateEndpoint Candidate(const boost::asio::ip::udp::endpoint& endpoint) {
    P2PCandidateEndpoint result;
    result.address_family = 4;
    result.address[10] = result.address[11] = 0xff;
    const auto bytes = endpoint.address().to_v4().to_bytes();
    std::copy(bytes.begin(), bytes.end(), result.address.begin() + 12);
    result.port = endpoint.port();
    return result;
}

P2PSessionExporter Exporter(std::uint8_t seed) {
    const auto key = Bytes<32>(seed);
    return [key](const char* label, const std::uint8_t*, std::size_t context_length,
        std::uint8_t* output, std::size_t size) noexcept {
        if (!label || std::strcmp(label, P2PWrapExporterLabelV2) != 0 ||
            context_length != P2PExporterContextV2{}.size() || size != key.size()) {
            return false;
        }
        std::copy(key.begin(), key.end(), output);
        return true;
    };
}

std::vector<std::uint8_t> IPv4Udp(unsigned sender, std::uint32_t marker) {
    using namespace ppp::net::native;
    std::vector<std::uint8_t> packet(sizeof(ip_hdr) + sizeof(udp_hdr) + 4, 0);
    auto* ip = reinterpret_cast<ip_hdr*>(packet.data());
    ip->v_hl = 0x45;
    ip->len = htons(static_cast<std::uint16_t>(packet.size()));
    ip->ttl = 64;
    ip->proto = ip_hdr::IP_PROTO_UDP;
    ip->src = htonl(sender == 0 ? 0x0a4d0001u : 0x0a4d0002u);
    ip->dest = htonl(sender == 0 ? 0x0a4d0002u : 0x0a4d0001u);
    ip->chksum = inet_chksum(ip, sizeof(ip_hdr));
    auto* udp = reinterpret_cast<udp_hdr*>(packet.data() + sizeof(ip_hdr));
    udp->src = htons(12000);
    udp->dest = htons(13000);
    udp->len = htons(static_cast<std::uint16_t>(sizeof(udp_hdr) + 4));
    std::memcpy(packet.data() + sizeof(ip_hdr) + sizeof(udp_hdr), &marker, 4);
    return packet;
}

struct VirtualClock {
    std::uint64_t now = 1000;
    void Advance(std::uint64_t milliseconds) { now += milliseconds; }
};

// The harness fakes only packet delivery/NAT filters, relay delivery and the
// clock. Every offer, ACK proof, commit, key, replay and IPv4 parser is real.
class V2Lab {
public:
    struct Trace {
        std::uint64_t tick = 0, registration = 0;
        unsigned sender = 0;
        P2PCandidateEndpoint source, destination;
        std::vector<std::uint8_t> packet;
        std::uint8_t Type() const { return packet.size() > 1 ? packet[1] : 0; }
    };

    class NatTransport final : public IP2PDatagramTransport {
    public:
        NatTransport(V2Lab& lab, unsigned owner, std::uint64_t registration)
            : lab_(lab), owner_(owner), registration_(registration) {}
        bool IsReady() const noexcept override { return !closed_; }
        bool Start(const P2PDatagramReceiveCallback& callback) noexcept override {
            if (closed_ || callback_) return false;
            callback_ = callback;
            return true;
        }
        boost::asio::ip::udp::endpoint LocalEndpoint() const noexcept override {
            return NativeEndpoint(lab_.peers[owner_].context.local_candidates.front());
        }
        bool SendTo(const std::uint8_t* packet, int size,
            const boost::asio::ip::udp::endpoint& destination) noexcept override {
            if (closed_ || !packet || size < 1 || fail_send) return false;
            lab_.Route({lab_.clock.now, registration_, owner_,
                lab_.peers[owner_].mapped, Candidate(destination),
                std::vector<std::uint8_t>(packet, packet + size)});
            return true;
        }
        void Close() noexcept override { closed_ = true; }
        void Deliver(const Trace& trace) {
            if (!closed_ && callback_) callback_(P2PDatagramReceiveStatus::Packet,
                NativeEndpoint(trace.source), trace.packet.data(), trace.packet.size());
        }
        bool fail_send = false;
        std::uint64_t Registration() const { return registration_; }
    private:
        V2Lab& lab_;
        unsigned owner_;
        std::uint64_t registration_;
        bool closed_ = false;
        P2PDatagramReceiveCallback callback_;
    };

    struct Peer {
        P2PV2Channel channel;
        P2PProbeCoordinator probes;
        P2PIngressLimiter ingress;
        P2PV2RecipientContext context;
        P2PCandidateEndpoint mapped;
        P2PSessionExporter exporter;
        std::shared_ptr<NatTransport> transport;
        std::vector<std::vector<std::uint8_t>> received;
        std::set<std::pair<std::uint32_t, std::uint16_t>> filter;
        std::uint64_t generation = 7;
        bool renew = false;
        unsigned invalid = 0, limited = 0;
    };

    V2Lab() {
        peers[0].mapped = Endpoint("203.0.113.1", 51000);
        peers[1].mapped = Endpoint("198.51.100.2", 52000);
        peers[0].context.local_session_id = Bytes<16>(1);
        peers[1].context.local_session_id = Bytes<16>(21);
        peers[0].context.local_peer_id = Bytes<16>(41);
        peers[1].context.local_peer_id = Bytes<16>(61);
        peers[0].context.local_candidates = {Endpoint("10.0.0.1", 41000), peers[0].mapped};
        peers[1].context.local_candidates = {Endpoint("10.0.0.2", 42000), peers[1].mapped};
        for (unsigned index = 0; index < 2; ++index) {
            peers[index].context.peer_candidates = peers[1 - index].context.local_candidates;
            peers[index].context.local_candidate_revision = 1;
            peers[index].context.peer_candidate_revision = 1;
            peers[index].exporter = Exporter(index == 0 ? 7 : 47);
            InstallTransport(index);
        }
    }

    void InstallTransport(unsigned index) {
        Peer& peer = peers[index];
        peer.transport = std::make_shared<NatTransport>(*this, index, ++registration);
        const auto generation = peer.generation;
        BOOST_REQUIRE(peer.transport->Start([this, index, generation](
            P2PDatagramReceiveStatus status, const boost::asio::ip::udp::endpoint& sender,
            const std::uint8_t* packet, int size) {
            if (status != P2PDatagramReceiveStatus::Packet || !packet || size < 1) return;
            Receive(index, Candidate(sender),
                std::vector<std::uint8_t>(packet, packet + size), generation);
        }));
    }

    void Offer(std::uint64_t key_generation = 1) {
        P2PRelayOfferV2Input input;
        input.initiator_session_id = peers[0].context.local_session_id;
        input.responder_session_id = peers[1].context.local_session_id;
        input.initiator_peer_id = peers[0].context.local_peer_id;
        input.responder_peer_id = peers[1].context.local_peer_id;
        input.initiator_candidate_revision = 1;
        input.responder_candidate_revision = 1;
        input.key_generation = key_generation;
        if (key_generation > 1) input.previous_offer_hash = peers[0].channel.Snapshot().current_offer_hash;
        BOOST_REQUIRE(HashP2PV2CandidateSet(input.initiator_session_id,
            input.responder_session_id, 1, 1,
            peers[0].context.local_candidates, peers[1].context.local_candidates,
            input.candidate_set_hash));
        P2PRelayOfferV2Bundle bundle;
        BOOST_REQUIRE(CreateP2PRelayOfferV2Bundle(input,
            peers[0].exporter, peers[1].exporter, bundle));
        for (unsigned index = 0; index < 2; ++index) {
            std::string encoded;
            BOOST_REQUIRE(EncodeP2PRelayOfferRecipientV2Hex(bundle.offer,
                index == 0 ? bundle.initiator_envelope : bundle.responder_envelope, encoded));
            last_offer[index] = encoded;
            BOOST_REQUIRE(peers[index].channel.AcceptOffer(encoded, peers[index].context,
                peers[index].exporter, clock.now, peers[index].generation));
            BOOST_REQUIRE(peers[index].probes.Begin(index == 0
                    ? P2PProbeRole::Controlling : P2PProbeRole::Controlled,
                peers[index].context.local_candidates, peers[index].context.peer_candidates,
                clock.now, peers[index].generation));
            peers[index].renew = false;
        }
        ++offers;
    }

    void Schedule() {
        // Prime both cold NAT filters before processing any delivery. This is
        // essential for address/port-restricted NAT and uses the real scheduler.
        for (unsigned index = 0; index < 2; ++index) {
            Peer& peer = peers[index];
            const auto tasks = peer.probes.Poll(clock.now, peer.generation);
            for (std::size_t slot = 0; slot < tasks.size; ++slot) {
                const auto& task = tasks.tasks[slot];
                std::vector<std::uint8_t> packet;
                if (peer.channel.CreateProbe(task.pair.local, task.pair.peer,
                    clock.now, peer.generation, packet)) Send(index, packet, task.pair.peer);
            }
        }
    }

    void Tick() {
        for (unsigned index = 0; index < 2; ++index) {
            Peer& peer = peers[index];
            const auto result = peer.channel.Tick(clock.now, peer.generation);
            peer.renew = peer.renew || result.renew;
            for (const auto& outgoing : result.outbound) Send(index, outgoing.datagram, outgoing.destination);
        }
        Schedule();
    }

    void Step(std::uint64_t milliseconds, bool auto_renew = false) {
        clock.Advance(milliseconds);
        Tick();
        if (auto_renew && peers[0].renew) {
            const auto generation = peers[0].channel.Snapshot().key_generation + 1;
            BOOST_REQUIRE(generation > 1);
            Offer(generation);
            Schedule();
        }
        Pump();
    }

    void Connect() {
        Offer();
        Schedule();
        Pump();
        if (!peers[0].channel.Snapshot().has_current ||
            !peers[1].channel.Snapshot().has_current) Step(2000);
        RequireDirect();
    }

    void RequireDirect() const {
        for (const auto& peer : peers) {
            BOOST_REQUIRE(peer.channel.Snapshot().has_current);
            BOOST_REQUIRE_EQUAL(static_cast<int>(peer.channel.Snapshot().state), static_cast<int>(P2PState::Direct));
            BOOST_REQUIRE_EQUAL(std::string(peer.channel.Snapshot().effective_path), "direct");
        }
    }

    void Send(unsigned owner, const std::vector<std::uint8_t>& packet,
        const P2PCandidateEndpoint& destination) {
        BOOST_REQUIRE(peers[owner].transport->SendTo(packet.data(), packet.size(), NativeEndpoint(destination)));
    }

    std::vector<std::uint8_t> SealApplication(unsigned owner, std::uint32_t marker) {
        const auto plaintext = IPv4Udp(owner, marker);
        const auto local = htonl(owner == 0 ? 0x0a4d0001u : 0x0a4d0002u);
        const auto remote = htonl(owner == 0 ? 0x0a4d0002u : 0x0a4d0001u);
        BOOST_REQUIRE(P2PDirectDataPath::AllowsOutboundPacket(
            plaintext.data(), plaintext.size(), local, remote));
        std::vector<std::uint8_t> packet;
        BOOST_REQUIRE(peers[owner].channel.SealData(plaintext,
            clock.now, peers[owner].generation, packet));
        return packet;
    }

    void Application(unsigned owner, std::uint32_t marker) {
        const auto packet = SealApplication(owner, marker);
        Send(owner, packet, peers[owner].channel.Snapshot().peer_candidate);
    }

    void Route(Trace trace) {
        const unsigned recipient = 1 - trace.sender;
        const auto native = NativeEndpoint(trace.destination);
        peers[trace.sender].filter.emplace(native.address().to_v4().to_uint(), native.port());
        traces.push_back(trace);
        if (blocked || !(trace.destination == peers[recipient].mapped)) return;
        if (restricted_nat) {
            const auto source = NativeEndpoint(trace.source);
            if (!peers[recipient].filter.count({source.address().to_v4().to_uint(), source.port()})) {
                ++filter_drops;
                return;
            }
        }
        if (drop && drop(trace)) return;
        deliveries.push_back({peers[recipient].transport, std::move(trace)});
    }

    void Pump() {
        std::size_t count = 0;
        while (!deliveries.empty()) {
            BOOST_REQUIRE_MESSAGE(++count < 1000, "control reply loop is bounded");
            auto delivery = std::move(deliveries.front());
            deliveries.pop_front();
            delivery.first->Deliver(delivery.second);
        }
    }

    void Receive(unsigned owner, const P2PCandidateEndpoint& source,
        const std::vector<std::uint8_t>& packet, std::uint64_t generation) {
        Peer& peer = peers[owner];
        if (generation != peer.generation || packet.size() < 2 || packet[0] != 2) {
            ++peer.invalid;
            return;
        }
        if (packet[1] == 5) {
            std::vector<std::uint8_t> plaintext;
            if (!peer.channel.OpenData(packet, source, clock.now, generation, plaintext)) {
                ++peer.invalid;
                return;
            }
            // Real channel's authenticated heartbeat carries no IPv4 packet.
            if (plaintext.size() == 1 && plaintext[0] == 0) return;
            const auto local = htonl(owner == 0 ? 0x0a4d0001u : 0x0a4d0002u);
            const auto remote = htonl(owner == 0 ? 0x0a4d0002u : 0x0a4d0001u);
            BOOST_REQUIRE(P2PDirectDataPath::AllowsInboundPacket(
                plaintext.data(), plaintext.size(), local, remote));
            peer.received.push_back(std::move(plaintext));
            return;
        }
        if (!peer.ingress.AllowSource(NativeEndpoint(source).address(), clock.now) ||
            !peer.ingress.AllowSession(peer.context.local_session_id, clock.now)) {
            ++peer.limited;
            return;
        }
        P2PV2ControlResult result;
        if (!peer.channel.HandleControl(packet, source, clock.now, generation, result)) {
            ++peer.invalid;
            return;
        }
        const auto pair = P2PProbeCandidatePair{result.local_candidate, result.peer_candidate};
        if (result.event == P2PV2ControlEvent::ProbeAck) {
            const auto slot = peer.probes.FindPair(pair);
            BOOST_REQUIRE(slot.has_value());
            // This scheduling event follows real Channel authentication only.
            peer.probes.OnAuthenticatedAck(*slot, clock.now, generation);
        }
        if (result.event == P2PV2ControlEvent::ReverseProbeNeeded) {
            BOOST_REQUIRE(peer.probes.NominateResponderPair(pair, clock.now, generation));
        }
        for (const auto& outgoing : result.outbound) Send(owner, outgoing.datagram, outgoing.destination);
    }

    void AssertNonceAndAmplificationBounds() const {
        using NonceKey = std::tuple<P2POfferHash, std::uint8_t, std::uint32_t>;
        std::map<NonceKey, std::vector<std::uint8_t>> seen;
        std::map<P2POfferHash, std::size_t> probes, commits;
        for (const auto& trace : traces) {
            if (trace.Type() == 5) {
                P2PV2DataPacketHeader header;
                BOOST_REQUIRE(ParseP2PV2DataPacketHeader(trace.packet, header));
                const NonceKey key{header.offer_hash, header.direction, header.sequence};
                const auto found = seen.find(key);
                if (found != seen.end()) BOOST_CHECK(found->second == trace.packet);
                else seen.emplace(key, trace.packet);
            }
            else {
                P2PV2ControlPacket packet;
                BOOST_REQUIRE(ParseP2PV2Control(trace.packet, packet));
                const NonceKey key{packet.offer_hash, packet.direction, packet.sequence};
                const auto found = seen.find(key);
                if (found != seen.end()) BOOST_CHECK(found->second == trace.packet);
                else seen.emplace(key, trace.packet);
                if (packet.type == P2PV2ControlType::Probe) probes[packet.offer_hash] = trace.packet.size();
                if (packet.type == P2PV2ControlType::KeyCommit) commits[packet.offer_hash] = trace.packet.size();
                if (packet.type == P2PV2ControlType::ProbeAck) {
                    BOOST_REQUIRE(probes.count(packet.offer_hash));
                    BOOST_TEST(trace.packet.size() <= probes.at(packet.offer_hash));
                }
                if (packet.type == P2PV2ControlType::KeyCommitAck) {
                    // ACK is for the cached authenticated Commit, not the
                    // later reverse ProbeACK that made the responder ready.
                    BOOST_REQUIRE(commits.count(packet.offer_hash));
                    BOOST_TEST(trace.packet.size() <= commits.at(packet.offer_hash));
                }
            }
        }
    }

    VirtualClock clock;
    std::array<Peer, 2> peers;
    std::array<std::string, 2> last_offer;
    std::vector<Trace> traces;
    std::deque<std::pair<std::shared_ptr<NatTransport>, Trace>> deliveries;
    std::function<bool(const Trace&)> drop;
    bool blocked = false, restricted_nat = false;
    unsigned offers = 0, filter_drops = 0;
    std::uint64_t registration = 0;
};

}

BOOST_AUTO_TEST_CASE(real_channel_selects_public_pair_and_primes_cold_restricted_nat) {
    V2Lab lab;
    lab.restricted_nat = true;
    lab.Connect();
    for (unsigned owner = 0; owner < 2; ++owner) {
        BOOST_CHECK(lab.peers[owner].channel.Snapshot().local_candidate == lab.peers[owner].mapped);
        BOOST_CHECK(lab.peers[owner].channel.Snapshot().peer_candidate == lab.peers[1 - owner].mapped);
        lab.Application(owner, owner + 1);
    }
    lab.Pump();
    BOOST_REQUIRE_EQUAL(lab.peers[0].received.size(), 1u);
    BOOST_REQUIRE_EQUAL(lab.peers[1].received.size(), 1u);
    BOOST_CHECK(lab.peers[0].received.front() == IPv4Udp(1, 2));
    BOOST_CHECK(lab.peers[1].received.front() == IPv4Udp(0, 1));
    BOOST_TEST(lab.filter_drops > 0u); // The first one-way send really was blocked.
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(one_lost_public_probe_is_retried_without_new_transaction_or_budget) {
    V2Lab lab;
    unsigned lost = 0;
    std::vector<std::uint8_t> lost_packet;
    lab.drop = [&lost, &lost_packet, &lab](const V2Lab::Trace& trace) {
        P2PV2ControlPacket packet;
        if (trace.sender == 0 && trace.Type() == 1 && lost == 0 &&
            ParseP2PV2Control(trace.packet, packet) &&
            packet.source == lab.peers[0].mapped && packet.destination == lab.peers[1].mapped) {
            ++lost; lost_packet = trace.packet; return true;
        }
        return false;
    };
    lab.Offer();
    lab.Schedule();
    lab.Pump();
    BOOST_REQUIRE_EQUAL(lost, 1u);
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    lab.Step(1999);
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    lab.Step(1);
    lab.RequireDirect();
    lab.AssertNonceAndAmplificationBounds();
    unsigned identical_sends = 0;
    for (const auto& trace : lab.traces) if (trace.sender == 0 && trace.packet == lost_packet) ++identical_sends;
    BOOST_TEST(identical_sends == 2u);
}

BOOST_AUTO_TEST_CASE(two_peers_remain_direct_for_180_seconds_and_multiple_key_rotations) {
    V2Lab lab;
    lab.restricted_nat = true;
    lab.Connect();
    const auto registration_a = lab.peers[0].transport->Registration();
    const auto registration_b = lab.peers[1].transport->Registration();
    for (std::uint32_t second = 1; second <= 180; ++second) {
        lab.Step(1000, true);
        lab.RequireDirect();
        lab.Application(0, second);
        lab.Application(1, second + 1000);
        lab.Pump();
        BOOST_REQUIRE_EQUAL(lab.peers[0].received.size(), second);
        BOOST_REQUIRE_EQUAL(lab.peers[1].received.size(), second);
        BOOST_CHECK(lab.peers[0].received.back() == IPv4Udp(1, second + 1000));
        BOOST_CHECK(lab.peers[1].received.back() == IPv4Udp(0, second));
    }
    BOOST_TEST(lab.offers >= 5u);
    BOOST_TEST(lab.peers[0].channel.Snapshot().key_generation >= 5u);
    BOOST_TEST(lab.peers[1].channel.Snapshot().key_generation >= 5u);
    BOOST_TEST(lab.peers[0].transport->Registration() == registration_a);
    BOOST_TEST(lab.peers[1].transport->Registration() == registration_b);
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(refresh_pending_preserves_direct_and_old_receive_expires_at_five_seconds) {
    V2Lab lab;
    lab.Connect();
    const auto old_a = lab.SealApplication(0, 1);
    const auto old_b = lab.SealApplication(1, 2);
    for (unsigned second = 0; second < 40; ++second) lab.Step(1000);
    lab.Offer(2);
    lab.RequireDirect(); // Accepting a fresh offer does not replace current.
    BOOST_TEST(lab.peers[0].channel.Snapshot().has_pending);
    BOOST_TEST(lab.peers[1].channel.Snapshot().has_pending);
    lab.Schedule();
    lab.Pump();
    lab.RequireDirect();
    BOOST_TEST(lab.peers[0].channel.Snapshot().key_generation == 2u);
    BOOST_TEST(lab.peers[1].channel.Snapshot().key_generation == 2u);
    lab.clock.Advance(4999);
    lab.Receive(1, lab.peers[0].mapped, old_a, lab.peers[1].generation);
    lab.Receive(0, lab.peers[1].mapped, old_b, lab.peers[0].generation);
    BOOST_TEST(lab.peers[0].received.size() == 1u);
    BOOST_TEST(lab.peers[1].received.size() == 1u);
    lab.Receive(1, lab.peers[0].mapped, old_a, lab.peers[1].generation); // replay
    BOOST_TEST(lab.peers[1].received.size() == 1u);
    lab.clock.Advance(1);
    std::vector<std::uint8_t> output{9};
    BOOST_TEST(!lab.peers[1].channel.OpenData(old_a, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, output));
    BOOST_CHECK(output == std::vector<std::uint8_t>{9});
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(unconfirmed_commit_is_bounded_by_setup_deadline_and_relay_fallback) {
    V2Lab lab;
    lab.drop = [](const V2Lab::Trace& trace) {
        return trace.sender == 1 && (trace.Type() == 7 || trace.Type() == 5);
    };
    lab.Offer();
    lab.Schedule();
    lab.Pump();
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    lab.Step(9999);
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    lab.Step(1);
    for (const auto& peer : lab.peers) {
        BOOST_TEST(!peer.channel.Snapshot().has_current);
        BOOST_TEST(!peer.channel.Snapshot().has_pending);
        BOOST_TEST(std::string(peer.channel.Snapshot().effective_path) == "relay");
    }
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(new_key_data_confirms_ready_commit_when_commit_ack_is_lost) {
    V2Lab lab;
    lab.drop = [](const V2Lab::Trace& trace) { return trace.Type() == 7; };
    lab.Offer();
    lab.Schedule();
    lab.Pump();
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    BOOST_REQUIRE(lab.peers[0].channel.Snapshot().pending_ready);
    BOOST_REQUIRE(lab.peers[0].channel.Snapshot().commit_started);
    BOOST_REQUIRE(lab.peers[1].channel.Snapshot().has_current);
    lab.Application(1, 27);
    lab.Pump();
    lab.RequireDirect();
    BOOST_REQUIRE_EQUAL(lab.peers[0].received.size(), 1u);
    BOOST_CHECK(lab.peers[0].received.front() == IPv4Udp(1, 27));
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(previous_receive_grace_is_cut_off_at_original_key_hard_deadline) {
    V2Lab lab;
    lab.Connect();
    const auto deadline = lab.peers[0].channel.Snapshot().key_deadline_ms;
    while (lab.clock.now + 1000 < deadline - 2000) lab.Step(1000);
    lab.Step(deadline - 2000 - lab.clock.now);
    const auto old_packet = lab.SealApplication(0, 19);
    const auto old_packet_late = lab.SealApplication(0, 20);
    lab.Offer(2);
    lab.Schedule();
    lab.Pump();
    lab.RequireDirect();
    BOOST_REQUIRE(lab.peers[1].channel.Snapshot().has_previous);
    BOOST_TEST(lab.peers[1].channel.Snapshot().previous_deadline_ms == deadline);
    lab.clock.Advance(1999);
    std::vector<std::uint8_t> output;
    const auto last_current_rx = lab.peers[1].channel.Snapshot().last_receive_ms;
    BOOST_REQUIRE(lab.peers[1].channel.OpenData(old_packet, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, output));
    BOOST_CHECK(output == IPv4Udp(0, 19));
    BOOST_TEST(lab.peers[1].channel.Snapshot().last_receive_ms == last_current_rx);
    lab.clock.Advance(1);
    output = {9};
    BOOST_TEST(!lab.peers[1].channel.OpenData(old_packet_late, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, output));
    BOOST_CHECK(output == std::vector<std::uint8_t>{9});
}

BOOST_AUTO_TEST_CASE(sequence_boundary_requests_refresh_and_exhaustion_never_wraps) {
    V2Lab lab;
    lab.Connect();
    const auto maximum = std::numeric_limits<std::uint32_t>::max();
    BOOST_REQUIRE(lab.peers[0].channel.AdvanceTxSequenceForTesting(maximum - 4096));
    lab.Tick();
    lab.Pump();
    BOOST_TEST(lab.peers[0].renew);
    BOOST_TEST(!lab.peers[0].channel.AdvanceTxSequenceForTesting(1));
    BOOST_REQUIRE(lab.peers[0].channel.AdvanceTxSequenceForTesting(maximum - 1));
    const auto last = lab.SealApplication(0, 71);
    P2PV2DataPacketHeader header;
    BOOST_REQUIRE(ParseP2PV2DataPacketHeader(last, header));
    BOOST_TEST(header.sequence == maximum - 1);
    std::vector<std::uint8_t> output{9};
    BOOST_TEST(!lab.peers[0].channel.SealData(IPv4Udp(0, 72),
        lab.clock.now, lab.peers[0].generation, output));
    BOOST_CHECK(output == std::vector<std::uint8_t>{9});
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    BOOST_TEST(std::string(lab.peers[0].channel.Snapshot().effective_path) == "relay");
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(udp_blocked_has_eight_probe_sends_per_peer_then_clean_relay) {
    V2Lab lab;
    lab.blocked = true;
    lab.Offer();
    lab.Schedule();
    lab.Step(2000);
    lab.Step(2000);
    lab.Step(6000);
    std::array<unsigned, 2> counts{};
    for (const auto& trace : lab.traces) if (trace.Type() == 1) ++counts[trace.sender];
    BOOST_TEST(counts[0] == 8u);
    BOOST_TEST(counts[1] == 8u);
    for (const auto& peer : lab.peers) {
        BOOST_TEST(!peer.channel.Snapshot().has_current);
        BOOST_TEST(!peer.channel.Snapshot().has_pending);
        BOOST_TEST(std::string(peer.channel.Snapshot().effective_path) == "relay");
    }
}

BOOST_AUTO_TEST_CASE(tampered_and_wrong_endpoint_packets_never_deliver_or_consume_valid_replay) {
    V2Lab lab;
    lab.Connect();
    const auto valid = lab.SealApplication(0, 123);
    const auto baseline = lab.peers[1].channel.Snapshot();
    auto tampered = valid;
    tampered.back() ^= 1;
    std::vector<std::uint8_t> output{9, 8};
    BOOST_TEST(!lab.peers[1].channel.OpenData(tampered, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, output));
    BOOST_CHECK(output == std::vector<std::uint8_t>({9, 8}));
    BOOST_TEST(!lab.peers[1].channel.OpenData(valid, Endpoint("203.0.113.200", 51000),
        lab.clock.now, lab.peers[1].generation, output));
    BOOST_CHECK(output == std::vector<std::uint8_t>({9, 8}));
    BOOST_TEST(lab.peers[1].channel.Snapshot().last_receive_ms == baseline.last_receive_ms);
    BOOST_REQUIRE(lab.peers[1].channel.OpenData(valid, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, output));
    BOOST_CHECK(output == IPv4Udp(0, 123));
    BOOST_TEST(!lab.peers[1].channel.OpenData(valid, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, output));
    lab.RequireDirect();
}

BOOST_AUTO_TEST_CASE(real_parser_rejects_ipv6_unrelated_peer_and_unsupported_ipv4_protocol) {
    const auto packet = IPv4Udp(0, 1);
    const auto local = htonl(0x0a4d0001u), remote = htonl(0x0a4d0002u);
    BOOST_TEST(P2PDirectDataPath::AllowsOutboundPacket(packet.data(), packet.size(), local, remote));
    BOOST_TEST(!P2PDirectDataPath::AllowsOutboundPacket(packet.data(), packet.size(), local, htonl(0x0a4d0003u)));
    auto wrong_protocol = packet;
    reinterpret_cast<ppp::net::native::ip_hdr*>(wrong_protocol.data())->proto = 0;
    BOOST_TEST(!P2PDirectDataPath::AllowsOutboundPacket(wrong_protocol.data(), wrong_protocol.size(), local, remote));
    auto ipv6 = packet;
    ipv6[0] = 0x60;
    BOOST_TEST(!P2PDirectDataPath::AllowsOutboundPacket(ipv6.data(), ipv6.size(), local, remote));
}

BOOST_AUTO_TEST_CASE(authenticated_migration_to_unlisted_endpoint_validates_before_replay_commit) {
    V2Lab lab;
    lab.Connect();
    const auto original = lab.peers[1].mapped;
    const auto changed = Endpoint("198.51.100.29", 53000);
    const auto valid = lab.SealApplication(1, 81);
    auto forged = valid;
    forged.back() ^= 1;
    P2PV2ControlResult result;
    BOOST_TEST(!lab.peers[0].channel.HandleNewEndpointData(forged, changed,
        lab.clock.now, lab.peers[0].generation, result));
    BOOST_TEST(!lab.peers[0].channel.Snapshot().migration_pending);
    BOOST_REQUIRE(lab.peers[0].channel.HandleNewEndpointData(valid, changed,
        lab.clock.now, lab.peers[0].generation, result));
    BOOST_REQUIRE_EQUAL(result.outbound.size(), 1u);
    BOOST_TEST(lab.peers[0].channel.Snapshot().migration_pending);
    BOOST_CHECK(lab.peers[0].channel.Snapshot().peer_candidate == original);
    lab.peers[1].mapped = changed;
    lab.Send(0, result.outbound.front().datagram, result.outbound.front().destination);
    lab.Pump();
    lab.RequireDirect();
    BOOST_CHECK(lab.peers[0].channel.Snapshot().peer_candidate == changed);
    BOOST_CHECK(lab.peers[1].channel.Snapshot().local_candidate == changed);
    BOOST_TEST(!lab.peers[0].channel.Snapshot().migration_pending);
    std::vector<std::uint8_t> plaintext;
    BOOST_REQUIRE(lab.peers[0].channel.OpenData(valid, changed,
        lab.clock.now, lab.peers[0].generation, plaintext));
    BOOST_CHECK(plaintext == IPv4Udp(1, 81));
    BOOST_TEST(!lab.peers[0].channel.OpenData(valid, changed,
        lab.clock.now, lab.peers[0].generation, plaintext));
    lab.Tick();
    BOOST_TEST(lab.peers[0].renew);
    BOOST_TEST(lab.peers[1].renew);
}

BOOST_AUTO_TEST_CASE(migration_cancels_uncommitted_refresh_and_renews_after_ack) {
    V2Lab lab;
    lab.Connect();
    lab.Step(1000);
    const auto valid = lab.SealApplication(1, 82);
    lab.Offer(2);
    const auto pending = lab.peers[0].channel.Snapshot().pending_offer_hash;
    P2PV2ControlResult result;
    const auto changed = Endpoint("198.51.100.29", 53000);
    BOOST_REQUIRE(lab.peers[0].channel.HandleNewEndpointData(valid, changed,
        lab.clock.now, lab.peers[0].generation, result));
    BOOST_CHECK(result.cancelled_offer_hash == pending);
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_pending);
    lab.peers[1].mapped = changed;
    for (const auto& outgoing : result.outbound) lab.Send(0, outgoing.datagram, outgoing.destination);
    lab.Pump();
    lab.RequireDirect();
    BOOST_TEST(!lab.peers[1].channel.Snapshot().has_pending);
    lab.Tick();
    BOOST_TEST(lab.peers[0].renew);
}

BOOST_AUTO_TEST_CASE(endpoint_change_after_commit_is_bounded_relay_fallback) {
    V2Lab lab;
    lab.Connect();
    lab.Step(1000);
    const auto old = lab.SealApplication(1, 83);
    lab.drop = [](const V2Lab::Trace& trace) { return trace.Type() == 7; };
    lab.Offer(2);
    lab.Schedule();
    lab.Pump();
    BOOST_REQUIRE(lab.peers[0].channel.Snapshot().commit_started);
    P2PV2ControlResult result;
    BOOST_REQUIRE(lab.peers[0].channel.HandleNewEndpointData(old,
        Endpoint("198.51.100.29", 53000), lab.clock.now, lab.peers[0].generation, result));
    BOOST_TEST(static_cast<int>(result.event) == static_cast<int>(P2PV2ControlEvent::Fallback));
    BOOST_TEST(result.outbound.empty());
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_current);
    BOOST_TEST(!lab.peers[0].channel.Snapshot().has_pending);
    BOOST_TEST(std::string(lab.peers[0].channel.Snapshot().effective_path) == "relay");
}

BOOST_AUTO_TEST_CASE(one_hundred_start_refresh_stop_cycles_ignore_old_registered_deliveries) {
    V2Lab lab;
    for (unsigned cycle = 0; cycle < 100; ++cycle) {
        lab.Connect();
        lab.Step(2000);
        lab.Offer(2);
        lab.Schedule();
        lab.Pump();
        lab.RequireDirect();
        BOOST_TEST(lab.peers[0].channel.Snapshot().key_generation == 2u);
        BOOST_TEST(lab.peers[1].channel.Snapshot().key_generation == 2u);
        const auto queued = lab.SealApplication(0, cycle);
        lab.Send(0, queued, lab.peers[1].mapped);
        const auto received = lab.peers[1].received.size();
        for (unsigned owner = 0; owner < 2; ++owner) {
            auto& peer = lab.peers[owner];
            ++peer.generation;
            peer.channel.Reset(peer.generation);
            peer.probes.Cancel(peer.generation - 1);
            peer.ingress.Clear();
            lab.InstallTransport(owner);
        }
        lab.Pump(); // old callback captures the old generation, still real bytes
        BOOST_TEST(lab.peers[1].received.size() == received);
        for (const auto& peer : lab.peers) {
            BOOST_TEST(!peer.channel.Snapshot().has_current);
            BOOST_TEST(!peer.channel.Snapshot().has_pending);
            BOOST_TEST(!peer.channel.Snapshot().has_previous);
        }
        lab.clock.Advance(1000);
    }
    BOOST_TEST(lab.offers == 200u);
    lab.AssertNonceAndAmplificationBounds();
}

BOOST_AUTO_TEST_CASE(socket_failure_rebuilds_registration_and_rejects_stale_receive_callback) {
    V2Lab lab;
    lab.Connect();
    const auto stale = lab.SealApplication(0, 101);
    lab.Send(0, stale, lab.peers[1].mapped);
    const auto old_registration = lab.peers[0].transport->Registration();
    const auto old_generation = lab.peers[0].generation;
    auto old_transport = lab.peers[0].transport;
    old_transport->fail_send = true;
    BOOST_TEST(!old_transport->SendTo(stale.data(), stale.size(), NativeEndpoint(lab.peers[1].mapped)));
    old_transport->Close();
    BOOST_TEST(!old_transport->IsReady());
    BOOST_TEST(!old_transport->SendTo(stale.data(), stale.size(), NativeEndpoint(lab.peers[1].mapped)));
    for (auto& peer : lab.peers) {
        ++peer.generation;
        peer.channel.Reset(peer.generation);
        peer.probes.Cancel(peer.generation - 1);
        peer.ingress.Clear();
    }
    lab.InstallTransport(0);
    lab.InstallTransport(1);
    BOOST_TEST(lab.peers[0].transport->Registration() != old_registration);
    BOOST_TEST(lab.peers[0].generation != old_generation);
    lab.Pump(); // Recipient's old callback captured the old generation.
    BOOST_TEST(lab.peers[1].received.empty());
    for (const auto& peer : lab.peers) {
        BOOST_TEST(!peer.channel.Snapshot().has_current);
        BOOST_TEST(!peer.channel.Snapshot().has_pending);
        BOOST_TEST(!peer.channel.Snapshot().has_previous);
    }
    lab.clock.Advance(1000);
    lab.Connect();
    lab.Application(0, 102);
    lab.Pump();
    BOOST_REQUIRE_EQUAL(lab.peers[1].received.size(), 1u);
    BOOST_CHECK(lab.peers[1].received.front() == IPv4Udp(0, 102));
    std::vector<std::uint8_t> plaintext;
    BOOST_TEST(!lab.peers[1].channel.OpenData(stale, lab.peers[0].mapped,
        lab.clock.now, lab.peers[1].generation, plaintext));
}
