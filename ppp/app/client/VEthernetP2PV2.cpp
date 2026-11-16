#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/P2PCandidateAdapter.h>
#include <ppp/p2p/P2PV2Codec.h>
#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/p2p/P2PSocketProtector.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>

namespace ppp::app::client {
namespace {
using namespace ppp::p2p;
using ppp::threading::Executors;
using ppp::net::Ipep;

P2PCandidateEndpoint Candidate(const boost::asio::ip::udp::endpoint& endpoint) {
    P2PCandidateEndpoint result;
    if (endpoint.port() == 0 || endpoint.address().is_unspecified()) return result;
    result.address_family = endpoint.address().is_v4() ? 4 : 6;
    result.port = endpoint.port();
    if (endpoint.address().is_v4()) {
        result.address[10] = result.address[11] = 0xff;
        const auto bytes = endpoint.address().to_v4().to_bytes();
        std::copy(bytes.begin(), bytes.end(), result.address.begin() + 12);
    } else if (endpoint.address().is_v6()) {
        const auto bytes = endpoint.address().to_v6().to_bytes();
        std::copy(bytes.begin(), bytes.end(), result.address.begin());
    } else {
        result = {};
    }
    return result;
}
boost::asio::ip::udp::endpoint Endpoint(const P2PCandidateEndpoint& candidate) {
    if (!IsCanonicalP2PCandidate(candidate)) return {};
    if (candidate.address_family == 4) {
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy(candidate.address.begin() + 12, candidate.address.end(), bytes.begin());
        return {boost::asio::ip::address_v4(bytes), candidate.port};
    }
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::copy(candidate.address.begin(), candidate.address.end(), bytes.begin());
    return {boost::asio::ip::address_v6(bytes), candidate.port};
}
bool Candidates(const ppp::vector<ppp::app::protocol::P2PEndpointCandidate>& values,
    std::vector<P2PCandidateEndpoint>& out) {
    if (values.empty() || values.size() > 2) return false;
    for (const auto& value : values) {
        auto ep = Ipep::ParseEndPoint(value.endpoint);
        if ((!(ep.address().is_v4() || ep.address().is_v6())) ||
            ep.address().is_unspecified() || ep.address().is_multicast() || !ep.port()) return false;
        auto candidate = Candidate(ep);
        if (!IsCanonicalP2PCandidate(candidate)) return false;
        if (std::find(out.begin(), out.end(), candidate) != out.end()) return false;
        out.push_back(candidate);
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        // Prefer globally routable IPv6 before IPv4 while retaining stable
        // ordering within each family for deterministic offer hashes.
        return a.address_family != b.address_family
            ? a.address_family == 6
            : (a.address < b.address || (a.address == b.address && a.port < b.port));
    });
    return true;
}
std::string Hex(const P2POfferHash& hash) {
    static const char digits[] = "0123456789abcdef";
    std::string value(64, '0');
    for (std::size_t i = 0; i < hash.size(); ++i) {
        value[i*2] = digits[hash[i] >> 4]; value[i*2+1] = digits[hash[i] & 15];
    }
    return value;
}
}

void VEthernetExchanger::ResetP2PV2Peers(uint64_t generation, bool clear) noexcept {
    for (auto& item : p2p_v2_peers_) {
        auto& peer = *item.second;
        peer.channel.Reset(generation); peer.probes.Cancel(generation);
        peer.local_candidate = {}; peer.peer_candidate = {};
        peer.reported_key_hash = {}; peer.last_key_report_ms = peer.last_renew_ms = 0;
        peer.deferred_packets.clear();
        peer.ingress_limiter.Clear(); peer.egress_limiter.Clear();
    }
    if (clear) p2p_v2_peers_.clear();
}

void VEthernetExchanger::PruneP2PV2Peers(uint64_t now, uint64_t generation) noexcept {
    for (auto it = p2p_v2_peers_.begin(); it != p2p_v2_peers_.end();) {
        const auto snapshot = it->second->channel.Snapshot();
        const auto last_activity = it->second->last_activity_ms;
        const bool idle = last_activity != 0 && now >= last_activity &&
            now - last_activity >= P2PV2PeerIdleTimeoutMs;
        if (idle && !snapshot.has_current && !snapshot.has_pending && !snapshot.has_previous) {
            it->second->probes.Cancel(generation);
            it = p2p_v2_peers_.erase(it);
            continue;
        }
        ++it;
    }
}

std::shared_ptr<VEthernetExchanger::P2PV2PeerContext> VEthernetExchanger::FindP2PV2Peer(const P2POfferHash& hash) noexcept {
    if (hash == P2POfferHash{}) return {};
    std::shared_ptr<P2PV2PeerContext> result;
    for (auto& item : p2p_v2_peers_) {
        const auto snapshot = item.second->channel.Snapshot();
        if ((snapshot.has_current && snapshot.current_offer_hash == hash) ||
            (snapshot.has_pending && snapshot.pending_offer_hash == hash) ||
            (snapshot.has_previous && snapshot.previous_offer_hash == hash)) {
            if (result) return {};
            result = item.second;
        }
    }
    return result;
}

void VEthernetExchanger::PublishP2PV2State() noexcept {
    P2PState state = P2PState::Relay;
    for (const auto& item : p2p_v2_peers_) {
        const auto peer_state = item.second->channel.Snapshot().state;
        if (peer_state == P2PState::Direct) { state = peer_state; break; }
        if (peer_state == P2PState::Probing) state = peer_state;
    }
    p2p_state_.store(state);
}

void VEthernetExchanger::HandleP2PV2RelayOffer(const ITransmissionPtr& tx,
    const ppp::app::protocol::P2PControlMessage& message) noexcept {
    if (!tx || !tx->GetContext() || !tx->GetStrand()) return;
    const auto generation = p2p_offer_generation_.load();
    uint64_t registration = 0;
    {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        registration = p2p_transport_registration_id_;
    }
    auto self = shared_from_this();
    Executors::Post(tx->GetContext(), tx->GetStrand(), [self, this, tx, message, generation, registration]() noexcept {
        const auto now = P2PRecoveryNow();
        {
            std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
            if (disposed_.load() || generation != p2p_offer_generation_.load() ||
                registration != p2p_transport_registration_id_ ||
                p2p_registered_transmission_.lock() != tx || !p2p_candidate_transport_ ||
                !p2p_candidate_transport_->IsReady() || message.virtual_ip != p2p_registered_virtual_ip_) return;
            if (message.action == "status") {
                auto peer = p2p_v2_peers_.find(message.peer_virtual_ip);
                if (peer != p2p_v2_peers_.end()) {
                    const auto current = peer->second->channel.Snapshot();
                    if (current.has_current && message.enabled && message.reason == "key-active-current" &&
                        message.current_offer_hash == Hex(current.current_offer_hash).c_str()) {
                        peer->second->reported_key_hash = current.current_offer_hash;
                        peer->second->last_activity_ms = now;
                    }
                }
                return;
            }
            if (!P2PRecoveryAllowed() || !message.enabled || message.action != "offer-v2" ||
                !message.peer_virtual_ip || message.peer_virtual_ip == message.virtual_ip ||
                std::find(message.supported_versions.begin(), message.supported_versions.end(), 2) == message.supported_versions.end()) return;
            PruneP2PV2Peers(now, generation);
            auto found = p2p_v2_peers_.find(message.peer_virtual_ip);
            if (found == p2p_v2_peers_.end() && p2p_v2_peers_.size() >= P2PV2MaxPeers) return;
            auto frozen = p2p_candidate_history_.find(message.candidate_revision);
            if (frozen == p2p_candidate_history_.end()) return;
            P2PV2RecipientContext recipient;
            if (!Candidates(message.local_candidates, recipient.local_candidates) ||
                !Candidates(message.candidates, recipient.peer_candidates)) return;
            std::vector<P2PCandidateEndpoint> registered;
            if (!Candidates(frozen->second, registered) || registered != recipient.local_candidates) return;
            Int128ToBytes(GetId(), recipient.local_session_id.data());
            std::memcpy(recipient.local_peer_id.data() + 12, &message.virtual_ip, 4);
            recipient.local_candidate_revision = message.candidate_revision;
            recipient.peer_candidate_revision = message.peer_candidate_revision;
            P2PRelayOfferV2 offered;
            P2PWrappedPairSeed wrapped;
            const std::string encoded(message.authenticated_offer_v2.data(), message.authenticated_offer_v2.size());
            if (!ParseP2PRelayOfferRecipientV2Hex(encoded, offered, wrapped)) return;
            P2PId expected_peer{};
            std::memcpy(expected_peer.data() + 12, &message.peer_virtual_ip, 4);
            if (offered.initiator_session_id == recipient.local_session_id) {
                if (offered.responder_peer_id != expected_peer) return;
            } else if (offered.responder_session_id == recipient.local_session_id) {
                if (offered.initiator_peer_id != expected_peer) return;
            } else return;
            auto peer = found == p2p_v2_peers_.end() ? std::make_shared<P2PV2PeerContext>() : found->second;
            const auto before = peer->channel.Snapshot();
            const auto exporter = [tx](const char* label, const uint8_t* context, std::size_t n, uint8_t* out, std::size_t size) {
                return tx->ExportAuthenticatedSessionKey(label, context, n, out, size);
            };
            if (!peer->channel.AcceptOffer(encoded,
                recipient, exporter, now, generation)) return;
            if (found == p2p_v2_peers_.end()) {
                peer->virtual_ip = message.peer_virtual_ip;
                p2p_v2_peers_.emplace(message.peer_virtual_ip, peer);
            }
            peer->last_activity_ms = now;
            const auto after = peer->channel.Snapshot();
            // Keep the configured strategy bound to the authenticated remote
            // UUID, even when the peer context is recreated.
            peer->peer_uuid = after.peer_uuid;
            peer->candidates = recipient.peer_candidates;
            p2p_v2_selected_ = true;
            auto config = GetConfiguration();
            if (config) peer->channel.ConfigureLiveness(config->p2p.heartbeat_interval_ms,
                config->p2p.heartbeat_miss_max, config->p2p.suspect_timeout_ms, config->p2p.migration_grace_ms);
            if (after.has_pending && (!before.has_pending || before.pending_offer_hash != after.pending_offer_hash)) {
                const auto configured = p2p_peer_priorities_.find(peer->peer_uuid);
                const auto priority = configured == p2p_peer_priorities_.end()
                    ? p2p_peer_priority_.load(std::memory_order_acquire)
                    : configured->second;
                peer->probes.SetPriority(priority);
                peer->channel.SetRelayOnly(priority == P2PPeerPriority::RelayFirst);
                peer->probes.Begin(after.local_role == P2PPeerRole::Initiator ? P2PProbeRole::Controlling : P2PProbeRole::Controlled,
                    recipient.local_candidates, recipient.peer_candidates, now, generation);
            }
            PublishP2PV2State();
        }
        TickP2PV2(tx, now, generation);
    });
}

bool VEthernetExchanger::SendP2PV2Packets(const ITransmissionPtr& tx,
    const std::vector<P2PV2Outbound>& packets, uint64_t generation, uint64_t expected_registration) noexcept {
    uint64_t registration = 0;
    bool failed = false;
    {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        if (disposed_.load() || generation != p2p_offer_generation_.load() || p2p_registered_transmission_.lock() != tx ||
            (expected_registration && expected_registration != p2p_transport_registration_id_)) return false;
        auto transport = p2p_candidate_transport_; registration = p2p_transport_registration_id_;
        if (!transport) return false;
        const auto now = P2PRecoveryNow();
        P2PId session{}; Int128ToBytes(GetId(), session.data());
        const auto abandon_output = [generation](P2PV2PeerContext& peer) {
            const auto state = peer.channel.Snapshot();
            if (!state.has_current || state.commit_started) {
                peer.channel.Reset(generation); peer.reported_key_hash = {}; peer.last_renew_ms = 0;
            }
            peer.probes.Cancel(generation); peer.deferred_packets.clear();
            ppp::telemetry::Count("p2p.control.queue.fallback", 1);
        };
        for (const auto& packet : packets) {
            P2PV2DataPacketHeader data;
            const bool is_data = ParseP2PV2DataPacketHeader(packet.datagram, data);
            P2PV2ControlPacket control;
            if (!is_data && !ParseP2PV2Control(packet.datagram, control)) continue;
            auto peer = FindP2PV2Peer(is_data ? data.offer_hash : control.offer_hash);
            if (!peer) continue;
            if (is_data) {
                if (!transport->SendTo(packet.datagram.data(), static_cast<int>(packet.datagram.size()), Endpoint(packet.destination))) {
                    failed = true; break;
                }
                continue;
            }
            const auto duplicate = std::find_if(peer->deferred_packets.begin(), peer->deferred_packets.end(),
                [&packet](const auto& queued) {
                    return queued.packet.destination == packet.destination && queued.packet.datagram == packet.datagram;
                });
            if (duplicate != peer->deferred_packets.end()) continue;
            if (peer->deferred_packets.size() == 32) {
                abandon_output(*peer);
                continue;
            }
            const auto state = peer->channel.Snapshot();
            uint64_t expires = now + 2000;
            if (state.has_pending && state.pending_offer_hash == control.offer_hash) {
                expires = std::min(expires, state.setup_deadline_ms);
                if (control.type == P2PV2ControlType::Probe && state.setup_deadline_ms >= 10000)
                    expires = std::min(expires, state.setup_deadline_ms - 6000);
            }
            if (state.has_current && state.current_offer_hash == control.offer_hash)
                expires = std::min(expires, state.key_deadline_ms);
            if (state.has_previous && state.previous_offer_hash == control.offer_hash)
                expires = std::min(expires, state.previous_deadline_ms);
            peer->deferred_packets.push_back({packet, expires});
        }
        for (auto& item : p2p_v2_peers_) {
            if (failed) break;
            auto& peer = *item.second;
            while (!peer.deferred_packets.empty()) {
                auto& queued = peer.deferred_packets.front();
                P2PV2ControlPacket control;
                if (!ParseP2PV2Control(queued.packet.datagram, control) || FindP2PV2Peer(control.offer_hash) != item.second) {
                    peer.deferred_packets.pop_front(); continue;
                }
                if (now >= queued.expires_ms) {
                    // Preserve a healthy predecessor if an uncommitted refresh stalls.
                    abandon_output(peer);
                    break;
                }
                if (!peer.egress_limiter.AllowSession(session, now)) break;
                if (!transport->SendTo(queued.packet.datagram.data(), static_cast<int>(queued.packet.datagram.size()),
                    Endpoint(queued.packet.destination))) { failed = true; break; }
                peer.deferred_packets.pop_front();
            }
        }
        PublishP2PV2State();
    }
    if (failed) { RecoverP2PTransport(tx, generation, registration); return false; }
    return true;
}

void VEthernetExchanger::SendP2PV2Control(const ITransmissionPtr& tx, uint32_t peer_ip, const char* action,
    const P2POfferHash& current, const P2POfferHash& cancel) noexcept {
    if (!tx || !tx->GetContext() || !tx->GetStrand()) return;
    InformationEnvelope envelope;
    envelope.Base.Clear();
    auto& message = envelope.Extensions.P2P;
    uint64_t generation = 0, registration = 0;
    {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        if (disposed_.load() || p2p_registered_transmission_.lock() != tx || !p2p_v2_selected_ ||
            !p2p_v2_peers_.count(peer_ip)) return;
        const auto state = p2p_v2_peers_.at(peer_ip)->channel.Snapshot();
        if (state.current_offer_hash != current || (std::strcmp(action, "key-active") == 0 && !state.has_current)) return;
        generation = p2p_offer_generation_.load(); registration = p2p_transport_registration_id_;
        message.enabled = true; message.mode = "direct-preferred"; message.action = action;
        message.virtual_ip = p2p_registered_virtual_ip_; message.peer_virtual_ip = peer_ip;
        message.supported_versions = {1, 2}; message.current_offer_hash = Hex(current).c_str();
        if (cancel != P2POfferHash{}) message.cancel_offer_hash = Hex(cancel).c_str();
    }
#if defined(OPENPPP2_P2P_RECOVERY_TESTING)
    if (recovery_test_hooks_.control) { recovery_test_hooks_.control(action); return; }
#endif
    envelope.ExtendedJson = envelope.Extensions.ToJson();
    auto self = shared_from_this();
    ppp::coroutines::YieldContext::Spawn(tx->BufferAllocator.get(), *tx->GetContext(), tx->GetStrand().get(),
        [self, this, tx, envelope, generation, registration](ppp::coroutines::YieldContext& y) noexcept {
            {
                std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
                if (disposed_.load() || generation != p2p_offer_generation_.load() ||
                    registration != p2p_transport_registration_id_ || p2p_registered_transmission_.lock() != tx) return;
                const auto peer = p2p_v2_peers_.find(envelope.Extensions.P2P.peer_virtual_ip);
                if (peer == p2p_v2_peers_.end() ||
                    envelope.Extensions.P2P.current_offer_hash != Hex(peer->second->channel.Snapshot().current_offer_hash).c_str()) return;
            }
            DoInformation(tx, envelope, y);
        });
}

void VEthernetExchanger::HandleP2PV2Datagram(const ITransmissionPtr& tx, uint64_t generation,
    uint64_t registration, const boost::asio::ip::udp::endpoint& sender,
    const std::vector<uint8_t>& datagram) noexcept {
    P2PV2ControlResult result;
    std::vector<uint8_t> plaintext;
    uint32_t local_ip = 0, peer_ip = 0;
    bool accepted = false;
    {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        if (disposed_.load() || !p2p_v2_selected_ || generation != p2p_offer_generation_.load() ||
            registration != p2p_transport_registration_id_ || p2p_registered_transmission_.lock() != tx) return;
        const auto source = Candidate(sender);
        const auto now = P2PRecoveryNow();
        P2PV2DataPacketHeader header;
        const bool data = ParseP2PV2DataPacketHeader(datagram, header);
        P2PV2ControlPacket control;
        if (!data && !ParseP2PV2Control(datagram, control)) return;
        auto peer = FindP2PV2Peer(data ? header.offer_hash : control.offer_hash);
        if (!peer) return;
        if (data) {
            accepted = peer->channel.OpenData(datagram, source, now, generation, plaintext);
            if (!accepted) peer->channel.HandleNewEndpointData(datagram, source, now, generation, result);
        } else {
            if (!peer->channel.HandleControl(datagram, source, now, generation, result)) return;
            P2PProbeCandidatePair pair{result.local_candidate, result.peer_candidate};
            if (result.event == P2PV2ControlEvent::ProbeAck) {
                const auto index = peer->probes.FindPair(pair);
                if (index) peer->probes.OnAuthenticatedAck(*index, now, generation);
            } else if (result.event == P2PV2ControlEvent::ReverseProbeNeeded) {
                peer->probes.NominateResponderPair(pair, now, generation);
            }
        }
        if (accepted || result.event != P2PV2ControlEvent::None)
            peer->last_activity_ms = now;
        auto snapshot = peer->channel.Snapshot();
        if (snapshot.has_current) {
            peer->local_candidate = Endpoint(snapshot.local_candidate);
            peer->peer_candidate = Endpoint(snapshot.peer_candidate);
        }
        PublishP2PV2State();
        local_ip = p2p_registered_virtual_ip_; peer_ip = peer->virtual_ip;
    }
    SendP2PV2Packets(tx, result.outbound, generation, registration);
    if (accepted && !plaintext.empty() && P2PDirectDataPath::AllowsInboundPacket(plaintext.data(),
        static_cast<int>(plaintext.size()), local_ip, peer_ip))
        OnNat(tx, plaintext.data(), static_cast<int>(plaintext.size()));
    TickP2PV2(tx, P2PRecoveryNow(), generation);
}

void VEthernetExchanger::TickP2PV2(const ITransmissionPtr& tx, uint64_t now, uint64_t generation) noexcept {
    if (!tx) return;
    struct Work {
        uint32_t peer_ip;
        P2PV2TickResult tick;
        P2POfferHash report{};
        bool report_key = false;
    };
    std::vector<Work> work;
    bool retry = false;
    uint64_t registration = 0;
    {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        if (disposed_.load() || generation != p2p_offer_generation_.load() || !p2p_v2_selected_ ||
            p2p_registered_transmission_.lock() != tx) return;
        registration = p2p_transport_registration_id_;
        PruneP2PV2Peers(now, generation);
        for (auto& item : p2p_v2_peers_) {
        auto& peer = *item.second;
        Work action; action.peer_ip = item.first;
        auto& tick = action.tick;
        const auto before = peer.channel.Snapshot();
        tick = peer.channel.Tick(now, generation);
        if (tick.fallback && before.has_pending && tick.cancelled_offer_hash == P2POfferHash{})
            tick.cancelled_offer_hash = before.pending_offer_hash;
        auto batch = peer.probes.Poll(now, generation);
        for (std::size_t i = 0; i < batch.size; ++i) {
            P2PV2Outbound outbound; outbound.destination = batch.tasks[i].pair.peer;
            if (peer.channel.CreateProbe(batch.tasks[i].pair.local, batch.tasks[i].pair.peer, now, generation, outbound.datagram))
                tick.outbound.push_back(std::move(outbound));
        }
        auto snapshot = peer.channel.Snapshot();
        if (snapshot.has_current) {
            peer.local_candidate = Endpoint(snapshot.local_candidate); peer.peer_candidate = Endpoint(snapshot.peer_candidate);
            if (snapshot.current_offer_hash != peer.reported_key_hash &&
                (!peer.last_key_report_ms || now - peer.last_key_report_ms >= 1000)) {
                action.report_key = true; action.report = snapshot.current_offer_hash; peer.last_key_report_ms = now;
            }
        } else if (!snapshot.has_pending && (tick.fallback || !peer.last_renew_ms || now - peer.last_renew_ms >= 10000)) {
            // A failed probe/commit already invalidated the authenticated
            // offer.  Re-register immediately instead of waiting for the
            // normal ten-second keepalive interval; this keeps relay/direct
            // policy changes bounded by one control tick while retaining the
            // authenticated renew path.
            tick.renew = true; peer.last_renew_ms = now;
        }
        if (!snapshot.has_pending) peer.probes.Cancel(generation);
        work.push_back(std::move(action));
        }
        // A liveness timeout can clear a channel during the loop above. Drop
        // its now-empty context before the next renew/capacity decision.
        PruneP2PV2Peers(now, generation);
        PublishP2PV2State();
        retry = (!p2p_candidate_transport_ || !p2p_candidate_transport_->IsReady()) && now >= p2p_retry_at_ms_;
    }
    if (retry) { RecoverP2PTransport(tx, generation, registration); return; }
    for (const auto& action : work) {
        if (!SendP2PV2Packets(tx, action.tick.outbound, generation, registration)) return;
        if (action.report_key) SendP2PV2Control(tx, action.peer_ip, "key-active", action.report);
        if (action.tick.renew || action.tick.cancelled_offer_hash != P2POfferHash{})
            SendP2PV2Control(tx, action.peer_ip, "renew", action.tick.current_offer_hash, action.tick.cancelled_offer_hash);
    }
}

uint64_t VEthernetExchanger::P2PRecoveryNow() noexcept {
#if defined(OPENPPP2_P2P_RECOVERY_TESTING)
    if (recovery_test_hooks_.now) return recovery_test_hooks_.now();
#endif
    return Executors::GetTickCount();
}
bool VEthernetExchanger::P2PRecoveryAllowed() noexcept {
#if defined(OPENPPP2_P2P_RECOVERY_TESTING)
    if (recovery_test_hooks_.enabled) return true;
#endif
    return ProductionAuthenticatedControlV1Ready;
}
bool VEthernetExchanger::PostP2PRecovery(const ITransmissionPtr& tx, ppp::function<void()> callback) noexcept {
#if defined(OPENPPP2_P2P_RECOVERY_TESTING)
    if (recovery_test_hooks_.post) return recovery_test_hooks_.post(std::move(callback));
#endif
    return Executors::Post(tx->GetContext(), tx->GetStrand(), std::move(callback));
}
bool VEthernetExchanger::SpawnP2PRecovery(const ITransmissionPtr& tx, ppp::coroutines::YieldContext::SpawnHander callback) noexcept {
#if defined(OPENPPP2_P2P_RECOVERY_TESTING)
    if (recovery_test_hooks_.spawn) return recovery_test_hooks_.spawn(std::move(callback));
#endif
    return ppp::coroutines::YieldContext::Spawn(tx->BufferAllocator.get(), *tx->GetContext(), tx->GetStrand().get(), std::move(callback));
}

void VEthernetExchanger::RecoverP2PTransport(const ITransmissionPtr& tx, uint64_t generation, uint64_t registration) noexcept {
    if (!tx || !tx->GetContext() || !tx->GetStrand()) return;
    std::shared_ptr<IP2PDatagramTransport> failed;
    uint32_t local_ip = 0, peer_ip = 0;
    bool selected = false;
    uint64_t attempt = 0;
    {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        if (disposed_.load() || generation != p2p_offer_generation_.load() ||
            p2p_registered_transmission_.lock() != tx || registration != p2p_transport_registration_id_) return;
        local_ip = p2p_registered_virtual_ip_; peer_ip = p2p_peer_virtual_ip_;
        selected = p2p_v2_selected_;
        failed = std::move(p2p_candidate_transport_);
        if (failed) {
            ++p2p_recovery_attempt_;
            // Invalidate callbacks before Close; rebuilding is deferred to the owner strand.
            p2p_transport_registration_id_ = 0;
            if (p2p_stun_gatherer_) p2p_stun_gatherer_->Cancel();
            p2p_stun_gatherer_.reset();
            ResetP2PV2Peers(generation);
            p2p_next_stun_refresh_ms_ = 0;
            p2p_offer_session_.ResetGeneration(generation);
            p2p_direct_data_path_.Reset(generation);
            p2p_candidate_history_.clear(); p2p_registered_candidates_.clear();
            p2p_local_candidate_ = {}; p2p_peer_candidate_ = {};
            p2p_last_heartbeat_tx_ms_ = p2p_suspect_since_ms_ = p2p_migrate_started_ms_ = 0;
            p2p_heartbeat_misses_ = 0;
            static constexpr uint64_t delays[] = {1000, 2000, 4000, 8000, 10000};
            p2p_retry_at_ms_ = P2PRecoveryNow() + delays[std::min(p2p_retry_step_, 4u)];
            p2p_retry_step_ = std::min(p2p_retry_step_ + 1, 5u);
            p2p_recovery_running_ = false;
            p2p_state_.store(P2PState::Relay);
        } else {
            if (p2p_recovery_running_ || P2PRecoveryNow() < p2p_retry_at_ms_ ||
                !P2PRecoveryAllowed()) return;
            p2p_recovery_running_ = true;
            attempt = ++p2p_recovery_attempt_;
        }
    }
    if (failed) { failed->Close(); return; }
    auto self = shared_from_this();
    const bool scheduled = PostP2PRecovery(tx, [self, this, tx, generation, registration, attempt, local_ip, peer_ip, selected]() noexcept {
        {
            std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
            if (disposed_.load() || generation != p2p_offer_generation_.load() ||
                p2p_registered_transmission_.lock() != tx || p2p_candidate_transport_ ||
                p2p_transport_registration_id_ != registration || !p2p_recovery_running_ ||
                attempt != p2p_recovery_attempt_) return;
        }
        const bool spawned = SpawnP2PRecovery(tx,
            [self, this, tx, generation, registration, attempt, local_ip, peer_ip, selected](ppp::coroutines::YieldContext& y) noexcept {
                {
                    std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
                    if (disposed_.load() || generation != p2p_offer_generation_.load() ||
                        p2p_registered_transmission_.lock() != tx ||
                        registration != p2p_transport_registration_id_ ||
                        attempt != p2p_recovery_attempt_ || !p2p_recovery_running_) return;
                }
                const bool registered = SendRequestedIPv6Configuration(tx, y, true);
                if (!registered) {
                    uint64_t failed_registration = 0;
                    {
                        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
                        if (disposed_.load() || generation != p2p_offer_generation_.load() || GetTransmission() != tx ||
                            attempt != p2p_recovery_attempt_) return;
                        failed_registration = p2p_transport_registration_id_;
                    }
                    if (failed_registration) {
                        RecoverP2PTransport(tx, generation, failed_registration);
                        return;
                    }
                }
                bool ready = false;
                std::vector<uint32_t> renew_peers;
                {
                    std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
                    if (disposed_.load() || generation != p2p_offer_generation_.load() || GetTransmission() != tx ||
                        attempt != p2p_recovery_attempt_) return;
                    p2p_v2_selected_ = selected; p2p_peer_virtual_ip_ = peer_ip;
                    p2p_registered_transmission_ = tx;
                    if (!p2p_registered_virtual_ip_) p2p_registered_virtual_ip_ = local_ip;
                    p2p_recovery_running_ = false;
                    if (p2p_candidate_transport_ && p2p_candidate_transport_->IsReady()) {
                        p2p_retry_step_ = 0; p2p_retry_at_ms_ = 0;
                        ready = true;
                    } else {
                        static constexpr uint64_t delays[] = {1000, 2000, 4000, 8000, 10000};
                        p2p_retry_at_ms_ = P2PRecoveryNow() + delays[std::min(p2p_retry_step_, 4u)];
                        p2p_retry_step_ = std::min(p2p_retry_step_ + 1, 5u);
                    }
                    for (auto& item : p2p_v2_peers_) {
                        item.second->last_renew_ms = 0;
                        renew_peers.push_back(item.first);
                    }
                }
                if (ready) for (auto peer : renew_peers) SendP2PV2Control(tx, peer, "renew", {});
            });
        if (!spawned) {
            std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
            if (!disposed_.load() && generation == p2p_offer_generation_.load() &&
                p2p_transport_registration_id_ == registration &&
                p2p_recovery_attempt_ == attempt &&
                p2p_registered_transmission_.lock() == tx && !p2p_candidate_transport_) {
                p2p_recovery_running_ = false;
                p2p_retry_at_ms_ = P2PRecoveryNow() + 1000;
            }
        }
    });
    if (!scheduled) {
        std::lock_guard<std::mutex> lock(p2p_offer_mutex_);
        if (!disposed_.load() && generation == p2p_offer_generation_.load() &&
            p2p_transport_registration_id_ == registration &&
            p2p_recovery_attempt_ == attempt &&
            p2p_registered_transmission_.lock() == tx && !p2p_candidate_transport_) {
            p2p_recovery_running_ = false;
            p2p_retry_at_ms_ = P2PRecoveryNow() + 1000;
        }
    }
}
}
