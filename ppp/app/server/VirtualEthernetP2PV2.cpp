#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/p2p/P2PRelayOfferV2.h>
#include <ppp/net/Ipep.h>
#include <ppp/threading/Executors.h>

namespace ppp::app::server {
namespace {
using namespace ppp::p2p;
using ppp::threading::Executors;

template<std::size_t N> std::string Hex(const std::array<std::uint8_t, N>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(N * 2, '0');
    for (std::size_t i = 0; i < N; ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return result;
}
bool DecodeHash(const ppp::string& text, P2POfferHash& out) {
    if (text.size() != 64) return false;
    auto nibble = [](char ch) { return ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1; };
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int a = nibble(text[2*i]), b = nibble(text[2*i+1]);
        if (a < 0 || b < 0) return false;
        out[i] = static_cast<std::uint8_t>((a << 4) | b);
    }
    return true;
}
P2PId SessionId(const Int128& session) {
    P2PId id{}; Int128ToBytes(session, id.data()); return id;
}
P2PId PeerId(uint32_t vip) {
    P2PId id{}; std::memcpy(id.data() + 12, &vip, sizeof(vip)); return id;
}
std::string PairKey(const Int128& a, const Int128& b) {
    auto x = SessionId(a), y = SessionId(b);
    if (y < x) std::swap(x, y);
    return Hex(x) + Hex(y);
}
bool SupportsV2(const VirtualEthernetSwitcher::P2PPeerRecord& record) {
    return record.CandidateRevision && std::find(record.SupportedVersions.begin(), record.SupportedVersions.end(), 2) != record.SupportedVersions.end();
}
bool Candidates(const VirtualEthernetSwitcher::P2PPeerRecord& record,
    std::vector<P2PCandidateEndpoint>& out) {
    if (record.Candidates.empty() || record.Candidates.size() > 2) return false;
    for (const auto& candidate : record.Candidates) {
        auto endpoint = ppp::net::Ipep::ParseEndPoint(candidate.endpoint);
        if (!(endpoint.address().is_v4() || endpoint.address().is_v6()) ||
            endpoint.address().is_unspecified() || endpoint.address().is_multicast() || !endpoint.port()) return false;
        P2PCandidateEndpoint value;
        value.address_family = endpoint.address().is_v4() ? 4 : 6;
        value.port = endpoint.port();
        if (endpoint.address().is_v4()) {
            const auto bytes = endpoint.address().to_v4().to_bytes();
            value.address[10] = value.address[11] = 0xff;
            std::copy(bytes.begin(), bytes.end(), value.address.begin() + 12);
        } else {
            const auto bytes = endpoint.address().to_v6().to_bytes();
            std::copy(bytes.begin(), bytes.end(), value.address.begin());
        }
        if (!IsCanonicalP2PCandidate(value)) return false;
        if (std::find(out.begin(), out.end(), value) == out.end()) out.push_back(value);
    }
    return !out.empty();
}
}

bool VirtualEthernetSwitcher::SendP2PV2Offer(const P2PPeerRecord& record,
    const ITransmissionPtr& transmission, const ppp::app::protocol::P2PControlMessage& message,
    const std::string& key, std::uint64_t generation) noexcept {
    auto exchanger = record.Exchanger.lock();
    if (!exchanger || !transmission) return false;
    auto context = transmission->GetContext(); auto strand = transmission->GetStrand();
    if (!context || !strand) return false;
    InformationEnvelope envelope;
    envelope.Base.Clear();
    envelope.Base.IncomingTraffic = envelope.Base.OutgoingTraffic = std::numeric_limits<UInt64>::max();
    envelope.Base.ExpiredTime = std::numeric_limits<UInt32>::max();
    envelope.Extensions.P2P = message;
    envelope.ExtendedJson = envelope.Extensions.ToJson();
    P2PRelayOfferV2 offer;
    P2PWrappedPairSeed recipient;
    P2POfferHash expected_hash{};
    if (!ParseP2PRelayOfferRecipientV2Hex(std::string(message.authenticated_offer_v2.data(),
        message.authenticated_offer_v2.size()), offer, recipient) ||
        !HashP2PRelayOfferV2(offer, expected_hash)) return false;
    auto self = shared_from_this();
    return ppp::coroutines::YieldContext::Spawn(transmission->BufferAllocator.get(),
        *context, strand.get(), [self, exchanger, transmission, envelope, key, generation, record, expected_hash]
        (ppp::coroutines::YieldContext& y) noexcept {
            auto owner = self->FindNatInformation(record.VirtualIP);
            if (!owner || owner->Exchanger != exchanger) return;
            {
                SynchronizedObjectScope lock(self->syncobj_);
                auto pair = self->p2p_v2_pairs_.find(key);
                auto peer = self->p2p_peers_.find(record.SessionId);
                if (self->disposed_ || pair == self->p2p_v2_pairs_.end() ||
                    !pair->second.CanSend(generation, expected_hash, Executors::GetTickCount()) ||
                    peer == self->p2p_peers_.end() ||
                    peer->second.VirtualIP != record.VirtualIP ||
                    peer->second.Exchanger.lock() != exchanger) return;
            }
            if (exchanger->IsDisposed() || exchanger->GetTransmission() != transmission) return;
            exchanger->DoInformation(transmission, envelope, y);
        });
}

bool VirtualEthernetSwitcher::OfferP2PPeerHintsV2(const P2PPeerRecord& source,
    const P2PPeerRecord& destination, const ITransmissionPtr& source_tx,
    const ITransmissionPtr& destination_tx, UInt64 now, bool renew, const P2POfferHash& predecessor) noexcept {
    if (!SupportsV2(source) || !SupportsV2(destination) || !source_tx || !destination_tx ||
        !configuration_ || !ppp::p2p::ProductionAuthenticatedControlV1Ready ||
        !source_tx->HasAuthenticatedSessionExporter() || !destination_tx->HasAuthenticatedSessionExporter()) return false;
    auto initiator = source, responder = destination;
    auto itx = source_tx, rtx = destination_tx;
    if (PeerId(responder.VirtualIP) < PeerId(initiator.VirtualIP)) {
        std::swap(initiator, responder); std::swap(itx, rtx);
    }
    auto iex = initiator.Exchanger.lock(), rex = responder.Exchanger.lock();
    if (!iex || !rex) return false;
    std::vector<P2PCandidateEndpoint> locals, peers;
    if (!Candidates(initiator, locals) || !Candidates(responder, peers)) return false;
    P2PRelayOfferV2Input input;
    input.initiator_session_id = SessionId(initiator.SessionId);
    input.responder_session_id = SessionId(responder.SessionId);
    input.initiator_peer_id = PeerId(initiator.VirtualIP);
    input.responder_peer_id = PeerId(responder.VirtualIP);
    input.initiator_candidate_revision = initiator.CandidateRevision;
    input.responder_candidate_revision = responder.CandidateRevision;
    if (!HashP2PV2CandidateSet(input.initiator_session_id, input.responder_session_id,
        initiator.CandidateRevision, responder.CandidateRevision, locals, peers, input.candidate_set_hash)) return false;
    const auto key = PairKey(initiator.SessionId, responder.SessionId);
    ppp::app::protocol::P2PControlMessage cached_i, cached_r;
    bool cached = false;
    {
        SynchronizedObjectScope lock(syncobj_);
        if (disposed_) return false;
        auto registered_i = p2p_peers_.find(initiator.SessionId);
        auto registered_r = p2p_peers_.find(responder.SessionId);
        if (registered_i == p2p_peers_.end() || registered_r == p2p_peers_.end() ||
            registered_i->second.VirtualIP != initiator.VirtualIP ||
            registered_r->second.VirtualIP != responder.VirtualIP ||
            registered_i->second.Exchanger.lock() != initiator.Exchanger.lock() ||
            registered_r->second.Exchanger.lock() != responder.Exchanger.lock() ||
            iex->GetTransmission() != itx || rex->GetTransmission() != rtx) return false;
        for (auto old = p2p_v2_pairs_.begin(); old != p2p_v2_pairs_.end();) {
            auto i = p2p_peers_.find(old->second.InitiatorSession);
            auto r = p2p_peers_.find(old->second.ResponderSession);
            auto old_i = i == p2p_peers_.end() ? nullptr : i->second.Exchanger.lock();
            auto old_r = r == p2p_peers_.end() ? nullptr : r->second.Exchanger.lock();
            if (i == p2p_peers_.end() || r == p2p_peers_.end() ||
                !old_i || !old_r || old_i->IsDisposed() || old_r->IsDisposed() ||
                old_i->GetTransmission() != old->second.InitiatorTransmission.lock() ||
                old_r->GetTransmission() != old->second.ResponderTransmission.lock() ||
                i->second.VirtualIP != old->second.InitiatorIP || r->second.VirtualIP != old->second.ResponderIP)
                old = p2p_v2_pairs_.erase(old);
            else ++old;
        }
        if (!p2p_v2_pairs_.count(key) && p2p_v2_pairs_.size() >= 256) return false;
        auto& pair = p2p_v2_pairs_[key];
        if (renew && !pair.MatchesPredecessor(predecessor, now)) return false;
        if (pair.ExpirePending(now)) {
            pair.InitiatorOffer.Clear(); pair.ResponderOffer.Clear();
        }
        if (pair.Generating) return true;
        if (pair.PendingHash != P2POfferHash{}) {
            cached = true; cached_i = pair.InitiatorOffer; cached_r = pair.ResponderOffer;
        } else {
            if (!pair.PrepareOffer(now, renew)) return true;
            if (p2p_v2_generation_ == UINT64_MAX ||
                !pair.Begin(now, p2p_v2_generation_ + 1, renew)) return false;
            ++p2p_v2_generation_;
            pair.InitiatorSession = initiator.SessionId; pair.ResponderSession = responder.SessionId;
            pair.InitiatorIP = initiator.VirtualIP; pair.ResponderIP = responder.VirtualIP;
            pair.InitiatorTransmission = itx; pair.ResponderTransmission = rtx;
            input.key_generation = pair.Generation;
            input.previous_offer_hash = pair.CurrentHash;
        }
        if (cached) input.key_generation = pair.Generation;
    }
    if (cached) {
        const bool a = SendP2PV2Offer(initiator, itx, cached_i, key, input.key_generation);
        const bool b = SendP2PV2Offer(responder, rtx, cached_r, key, input.key_generation);
        return a && b;
    }
    auto export_for = [](const ITransmissionPtr& tx) {
        return ScheduleP2PSessionExporterV2(
            [tx](const P2PTask& task) { return Executors::Post(tx->GetContext(), tx->GetStrand(), task); },
            [tx](const char* label, const uint8_t* context, std::size_t length, uint8_t* output, std::size_t n) {
                return tx->ExportAuthenticatedSessionKey(label, context, length, output, n);
            });
    };
    auto self = shared_from_this();
    const auto finish = [self, key, input, initiator, responder, itx, rtx, iex, rex]
        (bool ok, const P2PRelayOfferV2Bundle& bundle) noexcept {
        ppp::app::protocol::P2PControlMessage im, rm;
        P2POfferHash hash{};
        std::string ih, rh;
        auto io = self->FindNatInformation(initiator.VirtualIP);
        auto ro = self->FindNatInformation(responder.VirtualIP);
        ok = ok && io && ro && io->Exchanger == iex && ro->Exchanger == rex;
        ok = ok && HashP2PRelayOfferV2(bundle.offer, hash) &&
            EncodeP2PRelayOfferRecipientV2Hex(bundle.offer, bundle.initiator_envelope, ih) &&
            EncodeP2PRelayOfferRecipientV2Hex(bundle.offer, bundle.responder_envelope, rh);
        if (ok) {
            im.enabled = rm.enabled = true; im.mode = rm.mode = "direct-preferred";
            im.action = rm.action = "offer-v2"; im.supported_versions = rm.supported_versions = {1, 2};
            im.virtual_ip = initiator.VirtualIP; im.peer_virtual_ip = responder.VirtualIP;
            rm.virtual_ip = responder.VirtualIP; rm.peer_virtual_ip = initiator.VirtualIP;
            im.authenticated_offer_v2.assign(ih.data(), ih.size()); rm.authenticated_offer_v2.assign(rh.data(), rh.size());
            im.local_candidates = initiator.Candidates; im.candidates = responder.Candidates;
            rm.local_candidates = responder.Candidates; rm.candidates = initiator.Candidates;
            im.candidate_revision = rm.peer_candidate_revision = initiator.CandidateRevision;
            rm.candidate_revision = im.peer_candidate_revision = responder.CandidateRevision;
        }
        {
            SynchronizedObjectScope lock(self->syncobj_);
            auto pair = self->p2p_v2_pairs_.find(key);
            auto i = self->p2p_peers_.find(initiator.SessionId), r = self->p2p_peers_.find(responder.SessionId);
            if (self->disposed_ || pair == self->p2p_v2_pairs_.end() || !pair->second.Generating ||
                pair->second.Generation != input.key_generation) return;
            ok = ok && i != self->p2p_peers_.end() && r != self->p2p_peers_.end() &&
                i->second.VirtualIP == initiator.VirtualIP && r->second.VirtualIP == responder.VirtualIP &&
                SupportsV2(i->second) && SupportsV2(r->second) &&
                i->second.Exchanger.lock() == initiator.Exchanger.lock() &&
                r->second.Exchanger.lock() == responder.Exchanger.lock() &&
                !iex->IsDisposed() && !rex->IsDisposed() &&
                iex->GetTransmission() == itx && rex->GetTransmission() == rtx &&
                Executors::GetTickCount() - pair->second.StartedAt < 10000;
            if (!ok || !pair->second.Complete(input.key_generation, hash, Executors::GetTickCount())) {
                pair->second.ClearPending(); return;
            }
            pair->second.InitiatorOffer = im; pair->second.ResponderOffer = rm;
        }
        self->SendP2PV2Offer(initiator, itx, im, key, input.key_generation);
        self->SendP2PV2Offer(responder, rtx, rm, key, input.key_generation);
    };
    const bool scheduled = CreateP2PRelayOfferV2BundleAsync(input, export_for(itx), export_for(rtx), finish);
    if (!scheduled) finish(false, {});
    return scheduled;
}

bool VirtualEthernetSwitcher::UpdateP2PV2Control(const std::shared_ptr<VirtualEthernetExchanger>& exchanger,
    const ITransmissionPtr& transmission, const ppp::app::protocol::P2PControlMessage& request,
    ppp::app::protocol::P2PControlMessage& response) noexcept {
    response.action = "status";
    if (!exchanger || !transmission || !configuration_ ||
        exchanger->GetTransmission() != transmission) return false;
    const auto capability = P2PCapabilityGate::Evaluate(configuration_->p2p.enabled,
        configuration_->p2p.mode.c_str(), transmission->HasAuthenticatedSessionExporter(),
        request.enabled, ProductionAuthenticatedControlV1Ready);
    if (!capability.allowed) { response.reason = capability.reason; return false; }
    auto owner = FindNatInformation(request.virtual_ip);
    if (!owner || owner->Exchanger != exchanger || request.peer_virtual_ip == 0) return false;
    P2POfferHash current{}, cancel{};
    if (!DecodeHash(request.current_offer_hash, current)) return false;
    const UInt64 now = Executors::GetTickCount();
    P2PPeerRecord source, destination;
    {
        SynchronizedObjectScope lock(syncobj_);
        auto src = p2p_peers_.find(exchanger->GetId());
        auto vip = p2p_virtual_ips_.find(request.peer_virtual_ip);
        if (src == p2p_peers_.end() || src->second.VirtualIP != request.virtual_ip ||
            src->second.Exchanger.lock() != exchanger || vip == p2p_virtual_ips_.end()) return false;
        auto dst = p2p_peers_.find(vip->second);
        if (dst == p2p_peers_.end() || !SupportsV2(src->second) || !SupportsV2(dst->second)) return false;
        source = src->second; destination = dst->second;
        response.virtual_ip = source.VirtualIP;
        response.peer_virtual_ip = destination.VirtualIP;
        const auto key = PairKey(source.SessionId, destination.SessionId);
        auto found = p2p_v2_pairs_.find(key);
        if (found == p2p_v2_pairs_.end()) return false;
        auto& pair = found->second;
        if (source.SessionId != pair.InitiatorSession && source.SessionId != pair.ResponderSession) return false;
        if ((source.SessionId == pair.InitiatorSession ? pair.InitiatorTransmission.lock() :
            pair.ResponderTransmission.lock()) != transmission) return false;
        if (request.action == "key-active") {
            const auto result = pair.Activate(current, source.SessionId == pair.InitiatorSession, now);
            if (!result) return false;
            response.reason = result == 2 ? "key-active-current" : "key-active-pending";
            response.enabled = true; response.current_offer_hash = request.current_offer_hash;
            return true;
        }
        // A client may intentionally drop its local channel when switching to
        // relay-first. Its authenticated renew with an empty predecessor is
        // an explicit restart request; clear the stale server key immediately
        // so direct probing can converge without waiting for key expiry.
        if (current == P2POfferHash{} && request.cancel_offer_hash.empty()) {
            pair.ResetForExplicitRenew();
        } else if (!pair.MatchesPredecessor(current, now)) {
            return false;
        }
        if (!request.cancel_offer_hash.empty()) {
            if (!DecodeHash(request.cancel_offer_hash, cancel) || !pair.Cancel(current, cancel)) return false;
            pair.InitiatorOffer.Clear(); pair.ResponderOffer.Clear();
        }
    }
    auto peer = destination.Exchanger.lock();
    auto peer_tx = peer ? peer->GetTransmission() : nullptr;
    if (!peer || !peer_tx) return false;
    auto peer_owner = FindNatInformation(destination.VirtualIP);
    if (!peer_owner || peer_owner->Exchanger != peer) return false;
    response.enabled = true;
    const bool ok = OfferP2PPeerHintsV2(source, destination, transmission, peer_tx, now, true, current);
    response.reason = ok ? "renew-pending" : "renew-throttled";
    return ok;
}
}
