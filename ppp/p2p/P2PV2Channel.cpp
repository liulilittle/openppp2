#include <ppp/p2p/P2PV2Channel.h>
#include <ppp/p2p/P2PV2Codec.h>
#include <ppp/p2p/P2PReplayWindow.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <limits>
#include <mutex>

namespace ppp::p2p {
namespace {
constexpr auto MaxSequence=std::numeric_limits<std::uint32_t>::max();
constexpr auto RefreshSequence=MaxSequence-4096;
constexpr std::uint64_t RetryMs=2000;
bool Member(const std::vector<P2PCandidateEndpoint>& values,const P2PCandidateEndpoint& e) noexcept {
    return std::find(values.begin(),values.end(),e)!=values.end();
}
bool Replay(P2PReplayWindow& r,std::uint32_t sequence) noexcept {
    if (sequence==MaxSequence) return false;
    // v1 is modular. v2 never admits a numerical wrap within one key/epoch.
    if (r.initialized_ && sequence<static_cast<std::uint32_t>(r.base_) &&
        static_cast<std::uint32_t>(r.base_)-sequence>=REPLAY_WINDOW_SIZE) return false;
    if (r.initialized_ && sequence>static_cast<std::uint32_t>(r.base_) &&
        sequence-static_cast<std::uint32_t>(r.base_)>=REPLAY_WINDOW_SIZE) {
        // Any older entries are outside the new numeric window. Reset before
        // v1's half-range comparison can misclassify a large forward advance.
        r.Reset();
    }
    return r.Accept(sequence);
}
struct Transaction {
    P2PV2ControlPacket request;
    P2POfferHash hash{};
    std::vector<std::uint8_t> request_bytes,ack_bytes;
    std::uint64_t first_ms=0;
    unsigned sends=0;
    bool acked=false;
};
struct Migration {
    bool active=false;
    P2PCandidateEndpoint peer;
    P2PV2ControlPacket challenge;
    P2POfferHash hash{};
    std::vector<std::uint8_t> bytes;
    std::uint64_t started_ms=0,deadline_ms=0;
    unsigned sends=0;
};
struct Slot {
    P2PRelayOfferV2 offer;
    P2POfferHash hash{};
    P2PV1KeyMaterial keys;
    P2PPeerRole role=P2PPeerRole::Initiator;
    P2PV2RecipientContext context;
    std::uint64_t received_ms=0,setup_ms=0,key_ms=0,refresh_ms=0,previous_ms=0;
    std::uint64_t last_rx_ms=0,last_heartbeat_ms=0;
    std::uint64_t last_renew_ms=0;
    unsigned renew_attempts=0;
    std::uint32_t next_sequence=0;
    P2PReplayWindow replay;
    std::array<Transaction,4> tx{},rx{};
    std::size_t tx_count=0,rx_count=0;
    bool nominated=false,commit_sent=false,commit_received=false,renew_requested=false;
    P2PCandidateEndpoint local,peer;
    P2PV2ControlPacket commit;
    P2POfferHash commit_hash{};
    std::vector<std::uint8_t> commit_bytes,commit_ack_bytes;
    std::uint64_t commit_started_ms=0;
    unsigned commit_sends=0,migration_attempts=0,received_migrations=0;
    Migration migration;
    P2POfferHash received_migration_hash{};
    std::vector<std::uint8_t> migration_ack_bytes;
    ~Slot() { OPENSSL_cleanse(&keys,sizeof(keys)); }
};
Transaction* Tx(Slot& s,const P2PCandidateEndpoint& local,const P2PCandidateEndpoint& peer) noexcept {
    for(std::size_t n=0;n<s.tx_count;++n)
        if (s.tx[n].request.source==local && s.tx[n].request.destination==peer) return &s.tx[n];
    return nullptr;
}
Transaction* Rx(Slot& s,const P2PCandidateEndpoint& peer,const P2PCandidateEndpoint& local) noexcept {
    for(std::size_t n=0;n<s.rx_count;++n)
        if (s.rx[n].request.source==peer && s.rx[n].request.destination==local) return &s.rx[n];
    return nullptr;
}
bool Ready(Slot& s) noexcept {
    if (!s.nominated) return false;
    const auto* tx=Tx(s,s.local,s.peer);
    const auto* rx=Rx(s,s.peer,s.local);
    return tx && tx->acked && rx && !rx->ack_bytes.empty();
}
bool Alive(const Slot& s,std::uint64_t now) noexcept { return now>=s.received_ms && now<s.key_ms; }
bool Setup(const Slot& s,std::uint64_t now) noexcept { return Alive(s,now) && now<s.setup_ms; }
bool MakeControl(Slot& s,P2PV2ControlType type,const P2PCandidateEndpoint& local,
    const P2PCandidateEndpoint& peer,P2PV2ControlPacket& p) noexcept {
    if (s.next_sequence==MaxSequence) return false;
    p={}; p.type=type; p.offer_hash=s.hash; p.connection_epoch=s.offer.connection_epoch;
    p.sender_role=static_cast<std::uint8_t>(s.role); p.receiver_role=1-p.sender_role; p.direction=p.sender_role;
    p.source=local; p.destination=peer; p.sequence=s.next_sequence;
    const auto& prefix=s.role==P2PPeerRole::Initiator?s.keys.initiator_to_responder_nonce:s.keys.responder_to_initiator_nonce;
    p.nonce=BuildP2PV1Nonce(prefix,p.sequence); return true;
}
bool FinishControl(Slot& s,P2PV2ControlPacket& p,std::vector<std::uint8_t>& bytes,
    const P2POfferHash* binding=nullptr) noexcept {
    if (!SignP2PV2Control(p,s.keys.offer_token_key,binding) || !SerializeP2PV2Control(p,bytes)) return false;
    ++s.next_sequence; return true;
}
bool Authenticate(Slot& s,const P2PV2ControlPacket& p,const P2PCandidateEndpoint& sender,
    const P2POfferHash* binding=nullptr) noexcept {
    const auto& prefix=s.role==P2PPeerRole::Initiator?s.keys.responder_to_initiator_nonce:s.keys.initiator_to_responder_nonce;
    return p.offer_hash==s.hash && p.connection_epoch==s.offer.connection_epoch &&
        p.receiver_role==static_cast<std::uint8_t>(s.role) && p.sender_role==1-p.receiver_role &&
        p.source==sender && p.nonce==BuildP2PV1Nonce(prefix,p.sequence) &&
        VerifyP2PV2Control(p,s.keys.offer_token_key,binding);
}
bool Open(Slot& s,const std::vector<std::uint8_t>& bytes,std::vector<std::uint8_t>& out,
    P2PReplayWindow& replay) noexcept {
    P2PV2DataPacketHeader p;
    if (!ParseP2PV2DataPacketHeader(bytes,p) || p.offer_hash!=s.hash || p.connection_epoch!=s.offer.connection_epoch ||
        p.receiver_role!=static_cast<std::uint8_t>(s.role) || p.sender_role!=1-p.receiver_role || !Replay(replay,p.sequence)) return false;
    auto direction=SelectP2PV1Direction(s.keys,s.role);
    const bool ok=OpenP2PV2DataDatagram(bytes,p,direction.rx_key,BuildP2PV1Nonce(direction.rx_nonce_prefix,p.sequence),out);
    OPENSSL_cleanse(&direction,sizeof(direction)); return ok;
}
bool Seal(Slot& s,const std::uint8_t* data,std::size_t size,std::vector<std::uint8_t>& out) noexcept {
    if (s.next_sequence==MaxSequence) return false;
    auto direction=SelectP2PV1Direction(s.keys,s.role); P2PV2DataPacketHeader p;
    p.offer_hash=s.hash; p.connection_epoch=s.offer.connection_epoch; p.sequence=s.next_sequence;
    p.sender_role=static_cast<std::uint8_t>(s.role); p.receiver_role=1-p.sender_role; p.direction=p.sender_role;
    const bool ok=SealP2PV2DataDatagram(p,direction.tx_key,BuildP2PV1Nonce(direction.tx_nonce_prefix,p.sequence),data,size,out);
    OPENSSL_cleanse(&direction,sizeof(direction)); if (ok) ++s.next_sequence; return ok;
}
}

struct P2PV2Channel::Impl {
    mutable std::mutex mutex;
    std::unique_ptr<Slot> current,pending,previous;
    std::uint64_t generation=0,high_water=0;
    P2PState state=P2PState::Relay;
    P2POfferHash cancelled{};
    bool needs_renew=false,fallback_event=false,activation_event=false;
    bool relay_only=false;
    std::uint64_t heartbeat_ms=1000,suspect_after_ms=2000,failure_after_ms=4000,migration_grace_ms=5000;
    bool Generation(std::uint64_t value) const noexcept { return generation==value; }
    void Clear() noexcept {
        current.reset(); pending.reset(); previous.reset(); state=P2PState::Relay;
        needs_renew=false; activation_event=false;
    }
    void Fallback() noexcept { Clear(); fallback_event=true; }
    void CancelPending() noexcept {
        if (pending) cancelled=pending->hash;
        pending.reset(); needs_renew=current!=nullptr;
        if (current) { current->renew_requested=false; current->renew_attempts=0; }
    }
    void Promote(std::uint64_t now) noexcept {
        previous.reset();
        if (current) {
            current->previous_ms=std::min(current->key_ms,now+pending->offer.previous_receive_grace_ms);
            previous=std::move(current);
        }
        current=std::move(pending); state=relay_only ? P2PState::Relay : P2PState::Direct;
        current->last_rx_ms=now; current->last_heartbeat_ms=0;
        activation_event=true; needs_renew=false;
    }
    void Details(P2PV2ControlResult& out,const Slot& slot) const noexcept {
        out.local_candidate=slot.local; out.peer_candidate=slot.peer; out.offer_hash=slot.hash;
    }
    bool CommitAck(Slot& slot,std::uint64_t now,P2PV2ControlResult& result) {
        if (!slot.commit_received || !Ready(slot) || !Setup(slot,now)) return false;
        P2PV2ControlPacket ack;
        if (!MakeControl(slot,P2PV2ControlType::KeyCommitAck,slot.local,slot.peer,ack)) return false;
        ack.commit_transcript_hash=slot.commit_hash;
        ack.probe_transcript_hash=Tx(slot,slot.local,slot.peer)->hash;
        std::vector<std::uint8_t> bytes;
        if (!FinishControl(slot,ack,bytes) || bytes.size()>slot.commit_bytes.size()) return false;
        slot.commit_ack_bytes=bytes;
        result.outbound.push_back({std::move(bytes),slot.peer});
        Promote(now); result.event=P2PV2ControlEvent::Activated; Details(result,*current); return true;
    }
    bool Handle(const std::vector<std::uint8_t>& bytes,const P2PCandidateEndpoint& sender,
        std::uint64_t now,P2PV2ControlResult& result) {
        P2PV2ControlPacket p; if (!ParseP2PV2Control(bytes,p)) return false;
        Slot* slot=nullptr;
        if (pending && p.offer_hash==pending->hash) slot=pending.get();
        else if (current && p.offer_hash==current->hash) slot=current.get();
        if (!slot || !Alive(*slot,now)) return false;
        auto& s=*slot;
        const bool migration=p.type==P2PV2ControlType::MigrateChallenge || p.type==P2PV2ControlType::MigrateAck;
        if (!migration && !Setup(s,now)) return false;
        const P2POfferHash* binding=nullptr;
        if (p.type==P2PV2ControlType::MigrateAck) {
            if (slot!=current.get() || !s.migration.active || now>=s.migration.deadline_ms ||
                !(sender==s.migration.peer) || !(p.destination==s.local)) return false;
            binding=&s.migration.hash;
        }
        if (!Authenticate(s,p,sender,binding)) return false;

        P2POfferHash request_hash{}; if (!HashP2PV2Control(p,request_hash)) return false;
        // Exact duplicate requests may only receive their original authenticated reply.
        if (p.type==P2PV2ControlType::Probe) {
            if (!Member(s.context.peer_candidates,p.source) || !Member(s.context.local_candidates,p.destination)) return false;
            if (auto* cached=Rx(s,p.source,p.destination)) {
                if (cached->hash!=request_hash) return false;
                result.outbound.push_back({cached->ack_bytes,p.source}); return true;
            }
        }
        if (p.type==P2PV2ControlType::KeyCommit && s.commit_received) {
            if (s.commit_hash!=request_hash) return false;
            if (!s.commit_ack_bytes.empty()) result.outbound.push_back({s.commit_ack_bytes,p.source});
            return true;
        }
        if (p.type==P2PV2ControlType::MigrateChallenge && !s.migration_ack_bytes.empty() && s.received_migration_hash==request_hash) {
            result.outbound.push_back({s.migration_ack_bytes,p.source}); return true;
        }
        auto replay=s.replay; if (!Replay(replay,p.sequence)) return false;
        if (p.type==P2PV2ControlType::Probe) {
            if (s.rx_count==s.rx.size()) return false;
            P2PV2ControlPacket ack;
            if (!MakeControl(s,P2PV2ControlType::ProbeAck,p.destination,p.source,ack)) return false;
            ack.probe_transcript_hash=request_hash; std::vector<std::uint8_t> reply;
            if (!FinishControl(s,ack,reply) || reply.size()>bytes.size()) return false;
            Transaction tx; tx.request=p; tx.hash=request_hash; tx.request_bytes=bytes; tx.ack_bytes=reply;
            s.rx[s.rx_count++]=std::move(tx); s.replay=replay;
            result.outbound.push_back({std::move(reply),p.source}); return true;
        }
        if (p.type==P2PV2ControlType::ProbeAck) {
            auto* tx=Tx(s,p.destination,p.source);
            if (!tx || tx->acked || tx->hash!=p.probe_transcript_hash || !Member(s.context.local_candidates,p.destination) ||
                !Member(s.context.peer_candidates,p.source)) return false;
            tx->acked=true; s.replay=replay;
            result.event=P2PV2ControlEvent::ProbeAck;
            result.local_candidate=p.destination; result.peer_candidate=p.source; result.probe_sequence=tx->request.sequence;
            result.offer_hash=s.hash;
            if (s.role==P2PPeerRole::Initiator && !s.nominated) {
                s.nominated=true; s.local=p.destination; s.peer=p.source;
                P2PV2ControlPacket commit;
                if (!MakeControl(s,P2PV2ControlType::KeyCommit,s.local,s.peer,commit)) return false;
                commit.previous_offer_hash=s.offer.previous_offer_hash; commit.probe_transcript_hash=tx->hash;
                std::vector<std::uint8_t> packet;
                if (!FinishControl(s,commit,packet) || !HashP2PV2Control(commit,s.commit_hash)) return false;
                s.commit=commit; s.commit_bytes=packet; s.commit_sent=true;
                s.commit_started_ms=now; s.commit_sends=1;
                result.outbound.push_back({std::move(packet),s.peer});
            }
            else if (s.role==P2PPeerRole::Responder && s.nominated && p.destination==s.local && p.source==s.peer) {
                return CommitAck(s,now,result);
            }
            return true;
        }
        if (p.type==P2PV2ControlType::KeyCommit) {
            if (slot!=pending.get() || s.role!=P2PPeerRole::Responder || p.previous_offer_hash!=s.offer.previous_offer_hash ||
                !Member(s.context.peer_candidates,p.source) || !Member(s.context.local_candidates,p.destination)) return false;
            const auto* rx=Rx(s,p.source,p.destination);
            if (!rx || rx->hash!=p.probe_transcript_hash) return false;
            s.nominated=true; s.local=p.destination; s.peer=p.source; s.commit_received=true;
            s.commit=p; s.commit_hash=request_hash; s.commit_bytes=bytes; s.replay=replay;
            Details(result,s);
            if (Ready(s)) return CommitAck(s,now,result);
            result.event=P2PV2ControlEvent::ReverseProbeNeeded; return true;
        }
        if (p.type==P2PV2ControlType::KeyCommitAck) {
            if (slot!=pending.get() || s.role!=P2PPeerRole::Initiator || !s.commit_sent || !Ready(s) ||
                !(p.source==s.peer) || !(p.destination==s.local) || p.commit_transcript_hash!=s.commit_hash) return false;
            const auto* rx=Rx(s,s.peer,s.local);
            if (!rx || rx->hash!=p.probe_transcript_hash) return false;
            s.replay=replay; Promote(now); result.event=P2PV2ControlEvent::Activated; Details(result,*current); return true;
        }
        if (p.type==P2PV2ControlType::MigrateChallenge) {
            if (slot!=current.get() || !(p.source==s.peer) || s.received_migrations>=2 || s.migration.active) return false;
            if (pending && (pending->commit_sent || pending->commit_received)) {
                Fallback(); result.event=P2PV2ControlEvent::Fallback; return true;
            }
            P2PV2ControlPacket ack;
            if (!MakeControl(s,P2PV2ControlType::MigrateAck,p.destination,p.source,ack)) return false;
            std::vector<std::uint8_t> packet;
            if (!FinishControl(s,ack,packet,&request_hash) || packet.size()>bytes.size()) return false;
            if (pending) { CancelPending(); result.cancelled_offer_hash=cancelled; }
            s.migration_ack_bytes=packet; s.received_migration_hash=request_hash; ++s.received_migrations;
            s.local=p.destination; s.replay=replay; s.last_rx_ms=now;
            needs_renew=true;
            result.outbound.push_back({std::move(packet),p.source}); result.event=P2PV2ControlEvent::Migrated;
            Details(result,s); return true;
        }
        if (p.type==P2PV2ControlType::MigrateAck) {
            s.peer=s.migration.peer; s.migration={}; s.replay=replay; s.last_rx_ms=now; state=P2PState::Direct;
            needs_renew=true;
            result.event=P2PV2ControlEvent::Migrated; Details(result,s); return true;
        }
        return false;
    }
};

P2PV2Channel::P2PV2Channel() noexcept { try { impl_=std::make_unique<Impl>(); } catch (...) {} }
P2PV2Channel::~P2PV2Channel() noexcept=default;
bool P2PV2Channel::AcceptOffer(const std::string& encoded,const P2PV2RecipientContext& context,
    const P2PSessionExporter& exporter,std::uint64_t now,std::uint64_t generation) noexcept {
    if (!impl_ || now>std::numeric_limits<std::uint64_t>::max()-60000) return false;
    P2PRelayOfferV2 offer; P2PPeerRole role; P2PPairSeed seed{};
    if (!OpenP2PRelayOfferRecipientV2(encoded,context.local_session_id,context.local_peer_id,exporter,offer,role,seed)) return false;
    P2PV1KeyMaterial keys{}; const bool derived=DeriveP2PV2KeyMaterial(seed, [&]() {
        P2POfferHash h{}; HashP2PRelayOfferV2(offer,h); return h; }(),keys);
    OPENSSL_cleanse(seed.data(),seed.size());
    if (!derived) { OPENSSL_cleanse(&keys,sizeof(keys)); return false; }
    try {
        auto slot=std::make_unique<Slot>(); slot->keys=keys; OPENSSL_cleanse(&keys,sizeof(keys));
        slot->offer=offer; slot->role=role; slot->context=context;
        if (!HashP2PRelayOfferV2(offer,slot->hash)) return false;
        const bool initiator=role==P2PPeerRole::Initiator;
        P2POfferHash candidate_hash{};
        if (context.local_candidate_revision!=(initiator?offer.initiator_candidate_revision:offer.responder_candidate_revision) ||
            context.peer_candidate_revision!=(initiator?offer.responder_candidate_revision:offer.initiator_candidate_revision) ||
            !HashP2PV2CandidateSet(offer.initiator_session_id,offer.responder_session_id,
                offer.initiator_candidate_revision,offer.responder_candidate_revision,
                initiator?context.local_candidates:context.peer_candidates,
                initiator?context.peer_candidates:context.local_candidates,candidate_hash) || candidate_hash!=offer.candidate_set_hash) return false;
        slot->received_ms=now; slot->setup_ms=now+10000; slot->key_ms=now+60000; slot->refresh_ms=now+40000;
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (generation<impl_->generation) return false;
        if (generation>impl_->generation) {
            impl_->Clear(); impl_->high_water=0; impl_->generation=generation; impl_->cancelled={}; impl_->fallback_event=false;
        }
        if (impl_->pending && impl_->pending->hash==slot->hash) return true; // no new deadline
        if (offer.key_generation<=impl_->high_water || impl_->pending ||
            (impl_->current && (!Alive(*impl_->current,now) || impl_->current->migration.active)) ||
            offer.previous_offer_hash!=(impl_->current?impl_->current->hash:P2POfferHash{})) return false;
        impl_->high_water=offer.key_generation; impl_->pending=std::move(slot);
        if (!impl_->current && !impl_->relay_only) impl_->state=P2PState::Probing;
        return true;
    } catch (...) { OPENSSL_cleanse(&keys,sizeof(keys)); return false; }
}
bool P2PV2Channel::CreateProbe(const P2PCandidateEndpoint& local,const P2PCandidateEndpoint& peer,
    std::uint64_t now,std::uint64_t generation,std::vector<std::uint8_t>& out) noexcept {
    if (!impl_) return false;
    try {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->Generation(generation) || !impl_->pending || !Setup(*impl_->pending,now)) return false;
        auto& s=*impl_->pending;
        if (now-s.received_ms>=4000) return false;
        if (!Member(s.context.local_candidates,local) || !Member(s.context.peer_candidates,peer)) return false;
        if (s.nominated && (!(s.local==local) || !(s.peer==peer))) return false;
        if (auto* cached=Tx(s,local,peer)) {
            if (cached->acked || cached->sends>=2 || now-cached->first_ms<RetryMs) return false;
            out=cached->request_bytes; ++cached->sends; return true;
        }
        if (s.tx_count==s.tx.size()) return false;
        P2PV2ControlPacket packet; Transaction tx;
        if (!MakeControl(s,P2PV2ControlType::Probe,local,peer,packet) || !FinishControl(s,packet,tx.request_bytes) ||
            !HashP2PV2Control(packet,tx.hash)) return false;
        tx.request=packet; tx.first_ms=now; tx.sends=1; out=tx.request_bytes;
        s.tx[s.tx_count++]=std::move(tx); return true;
    } catch (...) { return false; }
}
bool P2PV2Channel::HandleControl(const std::vector<std::uint8_t>& packet,
    const P2PCandidateEndpoint& sender,std::uint64_t now,std::uint64_t generation,P2PV2ControlResult& out) noexcept {
    if (!impl_) return false;
    try { std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->Generation(generation)) return false;
        P2PV2ControlResult result; if (!impl_->Handle(packet,sender,now,result)) return false;
        out=std::move(result); return true;
    } catch (...) { return false; }
}
bool P2PV2Channel::SealData(const std::uint8_t* data,std::size_t size,std::uint64_t now,
    std::uint64_t generation,std::vector<std::uint8_t>& out) noexcept {
    if (!impl_) return false;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->Generation(generation) || !impl_->current || impl_->state!=P2PState::Direct || impl_->relay_only) return false;
    if (!Alive(*impl_->current,now) || impl_->current->next_sequence==MaxSequence) { impl_->Fallback(); return false; }
    return Seal(*impl_->current,data,size,out);
}
bool P2PV2Channel::OpenData(const std::vector<std::uint8_t>& packet,const P2PCandidateEndpoint& sender,
    std::uint64_t now,std::uint64_t generation,std::vector<std::uint8_t>& out) noexcept {
    if (!impl_) return false;
    try { std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->Generation(generation)) return false;
        P2PV2DataPacketHeader header; if (!ParseP2PV2DataPacketHeader(packet,header)) return false;
        Slot* s=nullptr; bool previous=false,promote=false;
        if (impl_->current && impl_->current->hash==header.offer_hash) s=impl_->current.get();
        else if (impl_->previous && impl_->previous->hash==header.offer_hash) { s=impl_->previous.get(); previous=true; }
        else if (impl_->pending && impl_->pending->hash==header.offer_hash) {
            s=impl_->pending.get(); if (!Setup(*s,now) || s->role!=P2PPeerRole::Initiator || !s->commit_sent || !Ready(*s)) return false;
            promote=true;
        }
        if (!s || !Alive(*s,now) || !(sender==s->peer) || (previous && now>=s->previous_ms)) return false;
        std::vector<std::uint8_t> plaintext; auto replay=s->replay;
        if (!Open(*s,packet,plaintext,replay)) return false;
        s->replay=replay;
        if (!previous) s->last_rx_ms=now;
        if (promote) impl_->Promote(now);
        else if (!previous && impl_->state==P2PState::Suspect && !s->migration.active) impl_->state=P2PState::Direct;
        out.swap(plaintext); return true;
    } catch (...) { return false; }
}
bool P2PV2Channel::HandleNewEndpointData(const std::vector<std::uint8_t>& packet,
    const P2PCandidateEndpoint& sender,std::uint64_t now,std::uint64_t generation,P2PV2ControlResult& out) noexcept {
    if (!impl_) return false;
    try { std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->Generation(generation) || !impl_->current || !Alive(*impl_->current,now) ||
            !IsCanonicalP2PCandidate(sender)) return false;
        auto& s=*impl_->current;
        if (sender==s.peer || s.migration.active || s.migration_attempts>=2) return false;
        auto replay=s.replay; std::vector<std::uint8_t> plaintext;
        if (!Open(s,packet,plaintext,replay)) return false;
        OPENSSL_cleanse(plaintext.data(),plaintext.size());
        P2PV2ControlResult result;
        if (impl_->pending && (impl_->pending->commit_sent || impl_->pending->commit_received)) {
            impl_->Fallback(); result.event=P2PV2ControlEvent::Fallback; out=std::move(result); return true;
        }
        Migration migration;
        if (!MakeControl(s,P2PV2ControlType::MigrateChallenge,s.local,sender,migration.challenge) ||
            !FinishControl(s,migration.challenge,migration.bytes) || !HashP2PV2Control(migration.challenge,migration.hash)) return false;
        migration.active=true; migration.peer=sender; migration.started_ms=now;
        migration.deadline_ms=std::min(s.key_ms,now+impl_->migration_grace_ms); migration.sends=1;
        result.outbound.push_back({migration.bytes,sender});
        if (impl_->pending) { impl_->CancelPending(); result.cancelled_offer_hash=impl_->cancelled; }
        s.migration=std::move(migration); ++s.migration_attempts; impl_->state=P2PState::Suspect;
        impl_->Details(result,s); out=std::move(result); return true;
    } catch (...) { return false; }
}
P2PV2TickResult P2PV2Channel::Tick(std::uint64_t now,std::uint64_t generation) noexcept {
    P2PV2TickResult result; if (!impl_) return result;
    try { std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->Generation(generation)) return result;
        if (impl_->previous && (!Alive(*impl_->previous,now) || now>=impl_->previous->previous_ms)) impl_->previous.reset();
        if (impl_->current && (!Alive(*impl_->current,now) || impl_->current->next_sequence==MaxSequence)) impl_->Fallback();
        if (impl_->pending && !Setup(*impl_->pending,now)) {
            if (impl_->pending->commit_sent || impl_->pending->commit_received || !impl_->current) impl_->Fallback();
            else impl_->CancelPending();
        }
        if (impl_->pending && impl_->pending->commit_sent && impl_->pending->commit_sends<2 &&
            now-impl_->pending->commit_started_ms>=RetryMs) {
            result.outbound.push_back({impl_->pending->commit_bytes,impl_->pending->peer}); ++impl_->pending->commit_sends;
        }
        if (impl_->current) {
            auto& s=*impl_->current;
            result.current_offer_hash=s.hash;
            if (s.migration.active && now>=s.migration.deadline_ms) impl_->Fallback();
            else if (now>=s.last_rx_ms && now-s.last_rx_ms>=impl_->failure_after_ms) impl_->Fallback();
            else {
                if (!s.migration.active && now>=s.last_rx_ms && now-s.last_rx_ms>=impl_->suspect_after_ms) impl_->state=P2PState::Suspect;
                if (s.migration.active && s.migration.sends<2 && now-s.migration.started_ms>=RetryMs) {
                    result.outbound.push_back({s.migration.bytes,s.migration.peer}); ++s.migration.sends;
                }
                if (s.last_heartbeat_ms==0 || (now>=s.last_heartbeat_ms && now-s.last_heartbeat_ms>=impl_->heartbeat_ms)) {
                    static constexpr std::uint8_t heartbeat=0; std::vector<std::uint8_t> bytes;
                    if (!Seal(s,&heartbeat,1,bytes)) impl_->Fallback();
                    else { result.outbound.push_back({std::move(bytes),s.peer}); s.last_heartbeat_ms=now; }
                }
                static constexpr std::uint64_t retry_delays[]{1000,2000,4000,8000,10000};
                if (impl_->current && !impl_->pending && !s.migration.active &&
                    (now>=s.refresh_ms || s.next_sequence>=RefreshSequence || impl_->needs_renew || s.renew_requested) &&
                    (!s.renew_requested || (now>=s.last_renew_ms &&
                     now-s.last_renew_ms>=retry_delays[std::min(s.renew_attempts-1,4u)]))) {
                    s.renew_requested=true; s.last_renew_ms=now; s.renew_attempts=std::min(s.renew_attempts+1,5u);
                    result.renew=true; impl_->needs_renew=false;
                }
            }
        }
        result.activated=std::exchange(impl_->activation_event,false);
        result.fallback=std::exchange(impl_->fallback_event,false);
        result.cancelled_offer_hash=std::exchange(impl_->cancelled,P2POfferHash{});
        if (result.fallback) { result.outbound.clear(); result.renew=false; }
        return result;
    } catch (...) { result={}; return result; }
}
void P2PV2Channel::RequestRenew(std::uint64_t generation) noexcept {
    if (!impl_) return;
    try {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->Generation(generation)) return;
        if (impl_->pending) {
            impl_->cancelled = impl_->pending->hash;
            impl_->pending.reset();
        }
        if (impl_->current) {
            impl_->current->renew_requested = false;
            impl_->current->renew_attempts = 0;
        }
        impl_->needs_renew = true;
        if (!impl_->current) impl_->state = P2PState::Relay;
    } catch (...) {}
}
P2PV2Snapshot P2PV2Channel::Snapshot() const noexcept {
    P2PV2Snapshot out; if (!impl_) return out;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    out.generation=impl_->generation; out.state=impl_->state;
    out.effective_path=impl_->state==P2PState::Direct?"direct":"relay";
    out.has_current=static_cast<bool>(impl_->current); out.has_pending=static_cast<bool>(impl_->pending);
    out.has_previous=static_cast<bool>(impl_->previous);
    if (impl_->current) {
        const auto& s=*impl_->current; out.current_offer_hash=s.hash; out.local_role=s.role;
        out.peer_uuid = s.role == P2PPeerRole::Initiator
            ? s.offer.responder_session_id : s.offer.initiator_session_id;
        out.local_candidate=s.local; out.peer_candidate=s.peer; out.key_generation=s.offer.key_generation;
        out.key_deadline_ms=s.key_ms; out.last_receive_ms=s.last_rx_ms; out.migration_pending=s.migration.active;
    }
    if (impl_->pending) {
        auto& s=*impl_->pending; out.pending_offer_hash=s.hash; out.setup_deadline_ms=s.setup_ms;
        if (out.peer_uuid == P2PId{}) {
            out.peer_uuid = s.role == P2PPeerRole::Initiator
                ? s.offer.responder_session_id : s.offer.initiator_session_id;
        }
        out.pending_ready=Ready(s); out.commit_started=s.commit_sent || s.commit_received;
        if (!impl_->current) out.local_role=s.role;
    }
    if (impl_->previous) { out.previous_offer_hash=impl_->previous->hash; out.previous_deadline_ms=impl_->previous->previous_ms; }
    return out;
}
void P2PV2Channel::Reset(std::uint64_t generation) noexcept {
    if (!impl_) return;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (generation<impl_->generation) return;
    impl_->Clear(); impl_->fallback_event=false; impl_->cancelled={};
    // A same-generation reset is also a fresh registration boundary.
    impl_->high_water=0;
    impl_->generation=generation;
}
void P2PV2Channel::RequestRenew() noexcept {
    if (!impl_) return;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->needs_renew=true;
    if (impl_->current) {
        impl_->current->renew_requested=false;
        impl_->current->renew_attempts=0;
    }
}
void P2PV2Channel::SetRelayOnly(bool enabled) noexcept {
    if (!impl_) return;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->relay_only=enabled;
    if (enabled) impl_->state=P2PState::Relay;
    else if (!impl_->current && impl_->pending) impl_->state=P2PState::Probing;
}
void P2PV2Channel::ConfigureLiveness(int interval,int misses,int suspect,int migration) noexcept {
    if (!impl_) return;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->heartbeat_ms=static_cast<std::uint64_t>(std::clamp(interval,500,5000));
    impl_->suspect_after_ms=impl_->heartbeat_ms*static_cast<std::uint64_t>(std::clamp(misses,1,10));
    impl_->failure_after_ms=impl_->suspect_after_ms+static_cast<std::uint64_t>(std::clamp(suspect,500,10000));
    impl_->migration_grace_ms=static_cast<std::uint64_t>(std::clamp(migration,1,5000));
}
bool P2PV2Channel::AdvanceTxSequenceForTesting(std::uint32_t next) noexcept {
    if (!impl_) return false;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->current || next<impl_->current->next_sequence) return false;
    impl_->current->next_sequence=next; return true;
}
}
