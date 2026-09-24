#include <ppp/p2p/P2PClientOfferSession.h>

#include <openssl/crypto.h>

#include <limits>

namespace ppp::p2p {
namespace {

constexpr std::uint8_t MaxProbeRounds = 2;

template <typename T>
void Cleanse(T& value) noexcept {
    OPENSSL_cleanse(&value, sizeof(value));
}

P2POfferBinding BuildBinding(
    const P2PRelayOfferV1& offer,
    const P2PControlPacket& packet) noexcept {
    P2POfferBinding binding;
    binding.version = packet.version;
    binding.offer_id = offer.offer_id;
    binding.initiator_session_id = offer.initiator_session_id;
    binding.responder_session_id = offer.responder_session_id;
    binding.initiator_peer_id = offer.initiator_peer_id;
    binding.responder_peer_id = offer.responder_peer_id;
    binding.connection_epoch = packet.connection_epoch;
    binding.message_type = packet.type;
    binding.offer_hash = packet.offer_hash;
    binding.sender_role = packet.sender_role;
    binding.receiver_role = packet.receiver_role;
    binding.direction = packet.direction;
    binding.source = packet.source;
    binding.destination = packet.destination;
    binding.sequence = packet.sequence;
    binding.nonce = packet.nonce;
    binding.ttl_seconds = packet.ttl_seconds;
    binding.probe_transcript_hash = packet.probe_transcript_hash;
    return binding;
}

}

P2PClientOfferSession::~P2PClientOfferSession() noexcept {
    Reset();
}

bool P2PClientOfferSession::Accept(
    const std::string& encoded,
    const P2PRelayOfferRecipientContext& context,
    const P2PRelayOfferExporter& exporter,
    std::uint64_t received_at_ms,
    std::uint64_t generation) noexcept {
    P2PRelayOfferRecipientResult opened;
    if (!OpenP2PRelayOfferRecipient(encoded, context, exporter, opened)) {
        return false;
    }

    P2POfferHash offer_hash{};
    P2PV1KeyMaterial key_material{};
    const bool derived = HashP2PRelayOffer(opened.offer, offer_hash) &&
        DeriveP2PV1KeyMaterial(opened.pair_seed, offer_hash, key_material);
    OPENSSL_cleanse(opened.pair_seed.data(), opened.pair_seed.size());
    if (!derived) {
        Cleanse(offer_hash);
        Cleanse(key_material);
        return false;
    }

    const std::uint64_t ttl_ms =
        static_cast<std::uint64_t>(opened.ttl_seconds) * 1000;
    if (received_at_ms > std::numeric_limits<std::uint64_t>::max() - ttl_ms) {
        Cleanse(offer_hash);
        Cleanse(key_material);
        return false;
    }
    const std::uint64_t deadline_ms = received_at_ms + ttl_ms;

    bool accepted = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation < generation_floor_) {
            Cleanse(offer_hash);
            Cleanse(key_material);
            return false;
        }
        if (generation > generation_floor_) {
            ClearActiveLocked();
            ClearReplayLocked();
            generation_floor_ = generation;
        }
        if (!SeenLocked(opened.offer.offer_id)) {
            ClearActiveLocked();
            active_ = true;
            state_ = P2PState::Eligible;
            offer_ = opened.offer;
            offer_hash_ = offer_hash;
            key_material_ = key_material;
            local_role_ = opened.local_role;
            peer_session_id_ = opened.peer_session_id;
            peer_id_ = opened.peer_id;
            received_at_ms_ = received_at_ms;
            deadline_ms_ = deadline_ms;
            generation_ = generation;
            last_receive_activity_ms_ = received_at_ms;
            RememberLocked(opened.offer.offer_id);
            accepted = true;
        }
    }
    Cleanse(offer_hash);
    Cleanse(key_material);
    return accepted;
}

bool P2PClientOfferSession::CreateSignedControlLocked(
    P2PControlType type,
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    bool track_outstanding,
    P2PControlPacket& output) noexcept {
    if (!active_ || generation_ != generation ||
        now_ms < received_at_ms_ || now_ms >= deadline_ms_ ||
        next_tx_sequence_ == std::numeric_limits<std::uint32_t>::max() ||
        !IsCanonicalP2PCandidate(source) ||
        !IsCanonicalP2PCandidate(destination)) {
        return false;
    }
    if (type == P2PControlType::Probe) {
        if (has_outstanding_probe_ || probe_rounds_ >= MaxProbeRounds) {
            return false;
        }
    }
    else if (type == P2PControlType::MigrateChallenge) {
        if (!data_authorized_ || has_outstanding_migrate_ ||
            migrate_rounds_ >= MaxProbeRounds) {
            return false;
        }
    }
    else {
        return false;
    }

    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    P2PControlPacket packet;
    packet.version = 1;
    packet.type = type;
    packet.offer_hash = offer_hash_;
    packet.sender_role = static_cast<std::uint8_t>(local_role_);
    packet.receiver_role = packet.sender_role == 0 ? 1 : 0;
    packet.direction = packet.sender_role;
    packet.connection_epoch = offer_.connection_epoch;
    packet.source = source;
    packet.destination = destination;
    packet.sequence = next_tx_sequence_;
    packet.nonce = BuildP2PV1Nonce(
        directional.tx_nonce_prefix, packet.sequence);
    packet.ttl_seconds = offer_.ttl_seconds;

    auto binding = BuildBinding(offer_, packet);
    if (!CreateP2POfferToken(
            key_material_.offer_token_key, binding, packet.token)) {
        Cleanse(directional);
        return false;
    }

    if (track_outstanding) {
        if (type == P2PControlType::Probe) {
            outstanding_probe_ = binding;
            has_outstanding_probe_ = true;
            ++probe_rounds_;
        }
        else {
            outstanding_migrate_ = binding;
            has_outstanding_migrate_ = true;
            ++migrate_rounds_;
        }
    }
    ++next_tx_sequence_;
    output = packet;
    Cleanse(directional);
    return true;
}

bool P2PClientOfferSession::CreateAuthenticatedProbe(
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlPacket& output) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return CreateSignedControlLocked(
        P2PControlType::Probe, source, destination,
        now_ms, generation, true, output);
}

bool P2PClientOfferSession::CreateAuthenticatedMigrateChallenge(
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlPacket& output) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return CreateSignedControlLocked(
        P2PControlType::MigrateChallenge, source, destination,
        now_ms, generation, true, output);
}

bool P2PClientOfferSession::CreateAuthenticatedProbeAck(
    const P2PControlPacket& probe,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlPacket& output) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || generation_ != generation || now_ms < received_at_ms_ ||
        now_ms >= deadline_ms_ ||
        next_tx_sequence_ == std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    const auto received = BuildBinding(offer_, probe);
    if (has_cached_probe_ack_ && received == cached_received_probe_ &&
        probe.token == cached_received_probe_token_ &&
        received.source == observed_source &&
        received.destination == observed_destination) {
        output = cached_probe_ack_;
        return true;
    }
    if (received_probe_rounds_ >= MaxProbeRounds) {
        return false;
    }

    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    auto expected_packet = probe;
    expected_packet.version = 1;
    expected_packet.type = P2PControlType::Probe;
    expected_packet.offer_hash = offer_hash_;
    expected_packet.sender_role = local_role_ == P2PPeerRole::Initiator ? 1 : 0;
    expected_packet.receiver_role = static_cast<std::uint8_t>(local_role_);
    expected_packet.direction = expected_packet.sender_role;
    expected_packet.connection_epoch = offer_.connection_epoch;
    expected_packet.source = observed_source;
    expected_packet.destination = observed_destination;
    expected_packet.ttl_seconds = offer_.ttl_seconds;
    expected_packet.probe_transcript_hash = {};

    auto replay = rx_replay_window_;
    if (!ValidateP2POfferToken(
            key_material_.offer_token_key, received,
            BuildBinding(offer_, expected_packet),
            observed_source, observed_destination,
            now_ms - received_at_ms_, probe.token,
            directional.rx_nonce_prefix, replay)) {
        Cleanse(directional);
        return false;
    }

    P2PControlPacket ack;
    ack.version = 1;
    ack.type = P2PControlType::ProbeAck;
    ack.offer_hash = offer_hash_;
    ack.sender_role = static_cast<std::uint8_t>(local_role_);
    ack.receiver_role = ack.sender_role == 0 ? 1 : 0;
    ack.direction = ack.sender_role;
    ack.connection_epoch = offer_.connection_epoch;
    ack.source = observed_destination;
    ack.destination = observed_source;
    ack.sequence = next_tx_sequence_;
    ack.nonce = BuildP2PV1Nonce(
        directional.tx_nonce_prefix, ack.sequence);
    ack.ttl_seconds = offer_.ttl_seconds;
    auto ack_binding = BuildBinding(offer_, ack);
    if (!CreateP2PProbeTranscriptHash(
            received, ack.probe_transcript_hash)) {
        Cleanse(directional);
        return false;
    }
    ack_binding.probe_transcript_hash = ack.probe_transcript_hash;
    if (!CreateP2POfferToken(
            key_material_.offer_token_key, ack_binding, ack.token)) {
        Cleanse(directional);
        return false;
    }

    rx_replay_window_ = replay;
    cached_received_probe_ = received;
    cached_received_probe_token_ = probe.token;
    cached_probe_ack_ = ack;
    has_cached_probe_ack_ = true;
    ++received_probe_rounds_;
    ++next_tx_sequence_;
    data_authorized_ = true;
    last_receive_activity_ms_ = now_ms;
    output = ack;
    Cleanse(directional);
    return true;
}

std::optional<P2PAuthenticatedProbeAck>
P2PClientOfferSession::AuthenticateProbeAck(
    const P2PControlPacket& packet,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || !has_outstanding_probe_ || generation_ != generation ||
        now_ms < received_at_ms_ || now_ms >= deadline_ms_) {
        return std::nullopt;
    }

    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    auto replay = rx_replay_window_;
    auto proof = AuthenticateP2PProbeAck(
        key_material_.offer_token_key,
        BuildBinding(offer_, packet),
        outstanding_probe_, observed_source, observed_destination,
        now_ms - received_at_ms_, packet.token,
        directional.rx_nonce_prefix, replay);
    if (proof) {
        rx_replay_window_ = replay;
        outstanding_probe_ = {};
        has_outstanding_probe_ = false;
        data_authorized_ = true;
        last_receive_activity_ms_ = now_ms;
    }
    Cleanse(directional);
    return proof;
}

bool P2PClientOfferSession::CreateAuthenticatedMigrateAck(
    const P2PControlPacket& challenge,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlPacket& output) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || !data_authorized_ || generation_ != generation ||
        now_ms < received_at_ms_ || now_ms >= deadline_ms_ ||
        next_tx_sequence_ == std::numeric_limits<std::uint32_t>::max() ||
        received_migrate_rounds_ >= MaxProbeRounds) {
        return false;
    }

    const auto received = BuildBinding(offer_, challenge);
    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    auto expected_packet = challenge;
    expected_packet.version = 1;
    expected_packet.type = P2PControlType::MigrateChallenge;
    expected_packet.offer_hash = offer_hash_;
    expected_packet.sender_role = local_role_ == P2PPeerRole::Initiator ? 1 : 0;
    expected_packet.receiver_role = static_cast<std::uint8_t>(local_role_);
    expected_packet.direction = expected_packet.sender_role;
    expected_packet.connection_epoch = offer_.connection_epoch;
    expected_packet.source = observed_source;
    expected_packet.destination = observed_destination;
    expected_packet.ttl_seconds = offer_.ttl_seconds;
    expected_packet.probe_transcript_hash = {};

    auto replay = rx_replay_window_;
    if (!ValidateP2POfferToken(
            key_material_.offer_token_key, received,
            BuildBinding(offer_, expected_packet),
            observed_source, observed_destination,
            now_ms - received_at_ms_, challenge.token,
            directional.rx_nonce_prefix, replay)) {
        Cleanse(directional);
        return false;
    }

    P2PControlPacket ack;
    ack.version = 1;
    ack.type = P2PControlType::MigrateAck;
    ack.offer_hash = offer_hash_;
    ack.sender_role = static_cast<std::uint8_t>(local_role_);
    ack.receiver_role = ack.sender_role == 0 ? 1 : 0;
    ack.direction = ack.sender_role;
    ack.connection_epoch = offer_.connection_epoch;
    ack.source = observed_destination;
    ack.destination = observed_source;
    ack.sequence = next_tx_sequence_;
    ack.nonce = BuildP2PV1Nonce(directional.tx_nonce_prefix, ack.sequence);
    ack.ttl_seconds = offer_.ttl_seconds;
    auto ack_binding = BuildBinding(offer_, ack);
    if (!CreateP2POfferToken(
            key_material_.offer_token_key, ack_binding, ack.token)) {
        Cleanse(directional);
        return false;
    }

    rx_replay_window_ = replay;
    ++received_migrate_rounds_;
    ++next_tx_sequence_;
    last_receive_activity_ms_ = now_ms;
    output = ack;
    Cleanse(directional);
    return true;
}

std::optional<P2PAuthenticatedProbeAck>
P2PClientOfferSession::AuthenticateMigrateAck(
    const P2PControlPacket& packet,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || !has_outstanding_migrate_ || generation_ != generation ||
        now_ms < received_at_ms_ || now_ms >= deadline_ms_) {
        return std::nullopt;
    }

    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    auto replay = rx_replay_window_;
    auto proof = AuthenticateP2PMigrateAck(
        key_material_.offer_token_key,
        BuildBinding(offer_, packet),
        outstanding_migrate_, observed_source, observed_destination,
        now_ms - received_at_ms_, packet.token,
        directional.rx_nonce_prefix, replay);
    if (proof) {
        rx_replay_window_ = replay;
        outstanding_migrate_ = {};
        has_outstanding_migrate_ = false;
        last_receive_activity_ms_ = now_ms;
    }
    Cleanse(directional);
    return proof;
}

bool P2PClientOfferSession::SealData(
    const std::uint8_t* payload,
    std::size_t payload_length,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || !data_authorized_ || generation_ != generation ||
        now_ms < received_at_ms_ || now_ms >= deadline_ms_ ||
        next_tx_sequence_ == std::numeric_limits<std::uint32_t>::max() ||
        !payload || payload_length == 0 ||
        payload_length > P2PDataPacketHeader::MaxPayloadSize) {
        return false;
    }

    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    P2PDataPacketHeader header;
    header.offer_hash = offer_hash_;
    header.sender_role = static_cast<std::uint8_t>(local_role_);
    header.receiver_role = header.sender_role == 0 ? 1 : 0;
    header.direction = header.sender_role;
    header.connection_epoch = offer_.connection_epoch;
    header.sequence = next_tx_sequence_;
    const auto nonce = BuildP2PV1Nonce(
        directional.tx_nonce_prefix, header.sequence);
    const bool sealed = SealP2PDataDatagram(
        header, directional.tx_key, nonce,
        payload, payload_length, output);
    if (sealed) {
        ++next_tx_sequence_;
    }
    Cleanse(directional);
    return sealed;
}

bool P2PClientOfferSession::OpenData(
    const std::vector<std::uint8_t>& datagram,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || !data_authorized_ || generation_ != generation ||
        now_ms < received_at_ms_ || now_ms >= deadline_ms_) {
        return false;
    }

    P2PDataPacketHeader parsed;
    if (!ParseP2PDataPacketHeader(datagram, parsed)) return false;

    P2PDataPacketHeader expected;
    expected.offer_hash = offer_hash_;
    expected.sender_role = local_role_ == P2PPeerRole::Initiator ? 1 : 0;
    expected.receiver_role = static_cast<std::uint8_t>(local_role_);
    expected.direction = expected.sender_role;
    expected.connection_epoch = offer_.connection_epoch;
    expected.sequence = parsed.sequence;

    auto replay = rx_replay_window_;
    if (!replay.Accept(parsed.sequence)) return false;
    auto directional = SelectP2PV1Direction(key_material_, local_role_);
    const auto nonce = BuildP2PV1Nonce(
        directional.rx_nonce_prefix, parsed.sequence);
    const bool opened = OpenP2PDataDatagram(
        datagram, expected, directional.rx_key, nonce, output);
    if (opened) {
        rx_replay_window_ = replay;
        last_receive_activity_ms_ = now_ms;
    }
    Cleanse(directional);
    return opened;
}

bool P2PClientOfferSession::SealHeartbeat(
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    static constexpr std::uint8_t kHeartbeatPayload[1] = {0};
    return SealData(kHeartbeatPayload, sizeof(kHeartbeatPayload),
        now_ms, generation, output);
}

std::uint64_t P2PClientOfferSession::LastReceiveActivityMs() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_receive_activity_ms_;
}

bool P2PClientOfferSession::Expire(
    std::uint64_t now_ms,
    std::uint64_t* expired_generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || now_ms < deadline_ms_) {
        return false;
    }
    const std::uint64_t generation = generation_;
    ClearActiveLocked();
    if (expired_generation) {
        *expired_generation = generation;
    }
    return true;
}

void P2PClientOfferSession::AdvanceGeneration(
    std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation <= generation_floor_) {
        return;
    }
    ClearActiveLocked();
    ClearReplayLocked();
    generation_floor_ = generation;
}

bool P2PClientOfferSession::IsActiveGeneration(
    std::uint64_t generation) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_ && generation_ == generation;
}

bool P2PClientOfferSession::ResetGeneration(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || generation_ != generation) {
        return false;
    }
    ClearActiveLocked();
    return true;
}

void P2PClientOfferSession::Reset() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    ClearActiveLocked();
    ClearReplayLocked();
    generation_floor_ = 0;
}

void P2PClientOfferSession::ClearReplayLocked() noexcept {
    for (auto& offer_id : seen_offer_ids_) {
        Cleanse(offer_id);
    }
    seen_count_ = 0;
    seen_next_ = 0;
}

P2PClientOfferSnapshot P2PClientOfferSession::Snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    P2PClientOfferSnapshot snapshot;
    snapshot.active = active_;
    snapshot.state = state_;
    if (active_) {
        snapshot.offer_id = offer_.offer_id;
        snapshot.connection_epoch = offer_.connection_epoch;
        snapshot.peer_session_id = peer_session_id_;
        snapshot.peer_id = peer_id_;
        snapshot.local_role = local_role_;
        snapshot.received_at_ms = received_at_ms_;
        snapshot.deadline_ms = deadline_ms_;
        snapshot.generation = generation_;
    }
    return snapshot;
}

bool P2PClientOfferSession::SeenLocked(const P2PId& offer_id) const noexcept {
    for (std::size_t i = 0; i < seen_count_; ++i) {
        if (seen_offer_ids_[i] == offer_id) {
            return true;
        }
    }
    return false;
}

void P2PClientOfferSession::RememberLocked(const P2PId& offer_id) noexcept {
    seen_offer_ids_[seen_next_] = offer_id;
    seen_next_ = (seen_next_ + 1) % ReplayCapacity;
    if (seen_count_ < ReplayCapacity) {
        ++seen_count_;
    }
}

void P2PClientOfferSession::ClearActiveLocked() noexcept {
    Cleanse(key_material_);
    active_ = false;
    state_ = P2PState::Relay;
    offer_ = {};
    offer_hash_ = {};
    peer_session_id_ = {};
    peer_id_ = {};
    local_role_ = P2PPeerRole::Initiator;
    received_at_ms_ = 0;
    deadline_ms_ = 0;
    generation_ = 0;
    last_receive_activity_ms_ = 0;
    outstanding_probe_ = {};
    outstanding_migrate_ = {};
    cached_received_probe_ = {};
    cached_received_probe_token_ = {};
    cached_probe_ack_ = {};
    rx_replay_window_.Reset();
    next_tx_sequence_ = 0;
    probe_rounds_ = 0;
    received_probe_rounds_ = 0;
    migrate_rounds_ = 0;
    received_migrate_rounds_ = 0;
    has_outstanding_probe_ = false;
    has_outstanding_migrate_ = false;
    has_cached_probe_ack_ = false;
    data_authorized_ = false;
}

}
