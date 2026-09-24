/**
 * @file P2PChannel.cpp
 * @brief P2P direct UDP channel implementation with state machine.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PChannel.h>
#include <ppp/Random.h>
#include <openssl/crypto.h>
#include <cstring>

#if defined(_LINUX) && !defined(_ANDROID)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#endif

namespace ppp {
    namespace p2p {

        // -------------------------------------------------------------------------
        // Construction / Destruction
        // -------------------------------------------------------------------------

        P2PChannel::P2PChannel(
                boost::asio::io_context& io_ctx,
                const std::shared_ptr<ISocketProtector>& protector,
                const Int128& session_id,
                const uint8_t base_session_key[SESSION_KEY_SIZE],
                const uint8_t token_key[SESSION_KEY_SIZE],
                const P2PConfig& config,
                P2PCipher cipher,
                const std::shared_ptr<IP2PDatagramTransportFactory>&
                    transport_factory) noexcept
            : io_ctx_(io_ctx)
            , protector_(protector)
            , transport_factory_(transport_factory)
            , session_id_(session_id)
            , peer_session_id_(0)
            , cipher_(cipher)
            , config_(config)
            , buffer_pool_(config.buffer_pool_count)
        {
            std::memcpy(base_session_key_, base_session_key, SESSION_KEY_SIZE);
            std::memcpy(token_key_, token_key, SESSION_KEY_SIZE);
            // H1: TX/RX keys are zeroed until StartProbing derives them.
            std::memset(tx_session_key_, 0, SESSION_KEY_SIZE);
            std::memset(rx_session_key_, 0, SESSION_KEY_SIZE);
        }

        P2PChannel::~P2PChannel() noexcept {
            Close();
        }

        // -------------------------------------------------------------------------
        // State management
        // -------------------------------------------------------------------------

        void P2PChannel::TransitionTo(P2PChannelState new_state) noexcept {
            P2PChannelState old = state_.load(std::memory_order_acquire);
            if (old == new_state) {
                return;
            }
            state_.store(new_state, std::memory_order_release);
            if (state_callback_) {
                state_callback_(old, new_state);
            }
        }

        void P2PChannel::Close() noexcept {
            if (closed_.exchange(true, std::memory_order_acq_rel)) {
                return;
            }

            if (probe_timer_) probe_timer_->cancel();
            if (heartbeat_timer_) heartbeat_timer_->cancel();
            if (suspect_timer_) suspect_timer_->cancel();

            if (transport_) {
                transport_->Close();
            }

            ResetAttemptState();
            TransitionTo(P2PChannelState::Relay);
        }

        void P2PChannel::FallbackToRelay(P2PFallbackReason reason) noexcept {
            P2PFallbackReason expected = P2PFallbackReason::None;
            fallback_reason_.compare_exchange_strong(expected, reason,
                std::memory_order_acq_rel, std::memory_order_acquire);
            Close();
        }

        void P2PChannel::ResetAttemptState() noexcept {
            if (probe_timer_) probe_timer_.reset();
            if (heartbeat_timer_) heartbeat_timer_.reset();
            if (suspect_timer_) suspect_timer_.reset();
            transport_.reset();

            OPENSSL_cleanse(base_session_key_, sizeof(base_session_key_));
            OPENSSL_cleanse(tx_session_key_, sizeof(tx_session_key_));
            OPENSSL_cleanse(rx_session_key_, sizeof(rx_session_key_));
            OPENSSL_cleanse(token_key_, sizeof(token_key_));
            if (!offer_token_.empty()) {
                OPENSSL_cleanse(offer_token_.data(), offer_token_.size());
            }
            offer_token_.clear();
            replay_window_.Reset();
            candidates_.clear();
            peer_session_id_ = 0;
            peer_endpoint_ = {};
            local_endpoint_ = {};
            nonce_counter_ = 0;
            sequence_counter_ = 0;
            probe_round_ = 0;
            last_heartbeat_recv_ms_ = 0;
            heartbeat_misses_ = 0;
            suspect_enter_ms_ = 0;
            pending_heartbeat_ack_ = false;
            std::memset(coalesced_frames_, 0, sizeof(coalesced_frames_));
        }

        // -------------------------------------------------------------------------
        // C1: Shared Tier-1 token input builder.
        //
        // Used by SendProbe, SendProbeAck, and VerifyTier1Token.
        // Serializes the header with the token field zeroed, then appends
        // the offer_token.  Fails closed if offer_token is missing or oversized.
        // -------------------------------------------------------------------------

        bool P2PChannel::BuildTier1TokenInput(P2PTier1Header header,
                                               uint8_t* out_buf, int buf_cap,
                                               int& out_len) const noexcept {
            out_len = 0;
            if (!out_buf || buf_cap < TIER1_HEADER_SIZE) {
                return false;
            }

            // C2: Fail closed if offer_token is missing or oversized.
            if (offer_token_.empty()) {
                return false;
            }
            int token_sz = static_cast<int>(offer_token_.size());
            if (token_sz > MAX_OFFER_TOKEN_SIZE) {
                return false;
            }

            // Zero the token field before serializing.
            std::memset(header.token, 0, TOKEN_SIZE);

            int hdr_len = header.Serialize(out_buf, buf_cap);
            if (hdr_len != TIER1_HEADER_SIZE) {
                return false;
            }

            // Append offer_token.
            if (hdr_len + token_sz > buf_cap) {
                return false;
            }
            std::memcpy(out_buf + hdr_len, offer_token_.data(), offer_token_.size());
            out_len = hdr_len + token_sz;
            return true;
        }

        // -------------------------------------------------------------------------
        // Probing phase
        // -------------------------------------------------------------------------

        void P2PChannel::StartProbing(const ppp::vector<P2PCandidate>& candidates,
                                       const Int128& peer_session_id,
                                       const ppp::string& offer_token) noexcept {
            if (closed_.load(std::memory_order_acquire)) {
                return;
            }

            // C2: Fail closed — require a non-empty, non-oversized offer token.
            if (offer_token.empty() ||
                static_cast<int>(offer_token.size()) > MAX_OFFER_TOKEN_SIZE) {
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return;
            }

            peer_session_id_ = peer_session_id;
            offer_token_ = offer_token;
            candidates_ = candidates;
            probe_round_ = 0;

            // H1: Derive directional TX/RX keys from base session key.
            // This ensures peer A's TX key == peer B's RX key and vice versa,
            // preventing AEAD nonce reuse when both peers start counters at 1.
            {
                uint8_t local_id_bytes[SESSION_ID_SIZE];
                uint8_t peer_id_bytes[SESSION_ID_SIZE];
                Int128ToBytes(session_id_, local_id_bytes);
                Int128ToBytes(peer_session_id, peer_id_bytes);

                if (!HKDFDeriveDirectionalKeys(base_session_key_,
                                               local_id_bytes, peer_id_bytes,
                                               tx_session_key_, rx_session_key_)) {
                    FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                    return;
                }
            }

            auto factory = transport_factory_;
            if (!factory) {
                factory = CreateNativeSocketP2PDatagramTransportFactory(protector_);
            }
            transport_ = factory ? factory->Create(io_ctx_) : nullptr;
            if (!transport_ || !transport_->IsReady()) {
                FallbackToRelay(P2PFallbackReason::SocketError);
                return;
            }

            std::weak_ptr<P2PChannel> weak = shared_from_this();
            if (!transport_->Start(
                    [weak](P2PDatagramReceiveStatus status,
                           const boost::asio::ip::udp::endpoint& sender,
                           const uint8_t* packet,
                           int packet_size) noexcept {
                        auto self = weak.lock();
                        if (!self || self->closed_.load(std::memory_order_acquire)) {
                            return;
                        }
                        if (status == P2PDatagramReceiveStatus::Error) {
                            self->FallbackToRelay(P2PFallbackReason::SocketError);
                            return;
                        }
                        self->OnReceive(sender, packet, packet_size);
                    })) {
                FallbackToRelay(P2PFallbackReason::SocketError);
                return;
            }
            local_endpoint_ = transport_->LocalEndpoint();

            TransitionTo(P2PChannelState::Probing);

            for (const auto& cand : candidates) {
                if (!SendProbe(cand.endpoint)) return;
            }
            if (closed_.load(std::memory_order_acquire)) return;

            probe_timer_ = std::make_shared<boost::asio::steady_timer>(io_ctx_);
            probe_timer_->expires_after(std::chrono::milliseconds(config_.probe_timeout_ms));
            probe_timer_->async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
                if (!ec && !self->closed_.load(std::memory_order_acquire)) {
                    self->OnProbeTimeout();
                }
            });
        }

        // -------------------------------------------------------------------------
        // SendProbe: PROBE_REQ with unified token binding (C1)
        // -------------------------------------------------------------------------

        bool P2PChannel::SendProbe(const boost::asio::ip::udp::endpoint& ep) noexcept {
            if (!transport_ || closed_.load(std::memory_order_acquire)) {
                return false;
            }

            uint8_t buf[TIER1_HEADER_SIZE + AUTH_TAG_SIZE + MAX_OFFER_TOKEN_SIZE];
            P2PTier1Header header;
            header.flags = P2P_FLAG_TIER | P2P_FLAG_PROBE_REQ;
            Int128ToBytes(session_id_, header.session_id);
            header.nonce = NextChannelNonce();
            header.sequence = 0;

            uint8_t token_input[TIER1_HEADER_SIZE + MAX_OFFER_TOKEN_SIZE];
            int token_input_len = 0;
            if (!BuildTier1TokenInput(header, token_input,
                                       static_cast<int>(sizeof(token_input)),
                                       token_input_len)) {
                OPENSSL_cleanse(token_input, sizeof(token_input));
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return false;
            }

            if (!TokenGenerate(token_key_, token_input, token_input_len, header.token)) {
                OPENSSL_cleanse(token_input, sizeof(token_input));
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return false;
            }
            OPENSSL_cleanse(token_input, sizeof(token_input));

            int written = header.Serialize(buf, sizeof(buf));
            if (written != TIER1_HEADER_SIZE) {
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return false;
            }

            if (!transport_ || !transport_->SendTo(buf, written, ep)) {
                FallbackToRelay(P2PFallbackReason::SocketError);
                return false;
            }
            return true;
        }

        // -------------------------------------------------------------------------
        // C1: SendProbeAck — PROBE_ACK with same unified token binding.
        // -------------------------------------------------------------------------

        void P2PChannel::SendProbeAck(const boost::asio::ip::udp::endpoint& ep) noexcept {
            if (!transport_ || closed_.load(std::memory_order_acquire)) {
                return;
            }

            uint8_t buf[TIER1_HEADER_SIZE + AUTH_TAG_SIZE + MAX_OFFER_TOKEN_SIZE];
            P2PTier1Header ack;
            ack.flags = P2P_FLAG_TIER | P2P_FLAG_PROBE_ACK;
            Int128ToBytes(session_id_, ack.session_id);
            ack.nonce = NextChannelNonce();
            ack.sequence = 0;

            uint8_t token_input[TIER1_HEADER_SIZE + MAX_OFFER_TOKEN_SIZE];
            int token_input_len = 0;
            if (!BuildTier1TokenInput(ack, token_input,
                                       static_cast<int>(sizeof(token_input)),
                                       token_input_len)) {
                OPENSSL_cleanse(token_input, sizeof(token_input));
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return;
            }

            if (!TokenGenerate(token_key_, token_input, token_input_len, ack.token)) {
                OPENSSL_cleanse(token_input, sizeof(token_input));
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return;
            }
            OPENSSL_cleanse(token_input, sizeof(token_input));

            int written = ack.Serialize(buf, sizeof(buf));
            if (written != TIER1_HEADER_SIZE) {
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return;
            }

            if (!transport_ || !transport_->SendTo(buf, written, ep)) {
                FallbackToRelay(P2PFallbackReason::SocketError);
            }
        }

        // -------------------------------------------------------------------------
        // C1: VerifyTier1Token — uses same unified BuildTier1TokenInput.
        // -------------------------------------------------------------------------

        bool P2PChannel::VerifyTier1Token(const P2PTier1Header& header) noexcept {
            uint8_t token_input[TIER1_HEADER_SIZE + MAX_OFFER_TOKEN_SIZE];
            int token_input_len = 0;
            if (!BuildTier1TokenInput(header, token_input,
                                       static_cast<int>(sizeof(token_input)),
                                       token_input_len)) {
                OPENSSL_cleanse(token_input, sizeof(token_input));
                return false;  // C2: fail closed — no unbound fallback.
            }
            bool verified = TokenVerify(token_key_, token_input, token_input_len, header.token);
            OPENSSL_cleanse(token_input, sizeof(token_input));
            return verified;
        }

        // -------------------------------------------------------------------------
        // Probe timeout / ACK
        // -------------------------------------------------------------------------

        void P2PChannel::OnProbeTimeout() noexcept {
            if (closed_.load(std::memory_order_acquire) ||
                state_.load(std::memory_order_acquire) != P2PChannelState::Probing) {
                return;
            }

            probe_round_++;
            if (probe_round_ >= config_.max_probes) {
                FallbackToRelay(P2PFallbackReason::Timeout);
                return;
            }

            for (const auto& cand : candidates_) {
                if (!SendProbe(cand.endpoint)) return;
            }
            if (closed_.load(std::memory_order_acquire)) return;

            if (probe_timer_) {
                probe_timer_->expires_after(std::chrono::milliseconds(config_.probe_timeout_ms));
                probe_timer_->async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
                    if (!ec && !self->closed_.load(std::memory_order_acquire)) {
                        self->OnProbeTimeout();
                    }
                });
            }
        }

        void P2PChannel::OnProbeAck(const boost::asio::ip::udp::endpoint& sender) noexcept {
            if (closed_.load(std::memory_order_acquire) ||
                state_.load(std::memory_order_acquire) != P2PChannelState::Probing) {
                return;
            }

            peer_endpoint_ = sender;
            TransitionTo(P2PChannelState::Direct);

            if (probe_timer_) {
                probe_timer_->cancel();
            }

            last_heartbeat_recv_ms_ = ppp::GetTickCount();
            heartbeat_timer_ = std::make_shared<boost::asio::steady_timer>(io_ctx_);
            heartbeat_timer_->expires_after(std::chrono::milliseconds(config_.heartbeat_interval_ms));
            heartbeat_timer_->async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
                if (!ec && !self->closed_.load(std::memory_order_acquire)) {
                    self->OnHeartbeatTimer();
                }
            });
        }

        // -------------------------------------------------------------------------
        // Receive path
        // -------------------------------------------------------------------------

        void P2PChannel::OnReceive(const boost::asio::ip::udp::endpoint& sender,
                                    const uint8_t* data, int data_len) noexcept {
            if (data_len < 1 || closed_.load(std::memory_order_acquire)) {
                return;
            }

            int tier = DetectTier(data, data_len);
            if (tier == 1) {
                HandleTier1(data, data_len, sender);
            } else if (tier == 2) {
                HandleTier2(data, data_len, sender);
            }
        }

        // -------------------------------------------------------------------------
        // Tier 1 control packet handling
        // -------------------------------------------------------------------------

        void P2PChannel::HandleTier1(const uint8_t* data, int data_len,
                                      const boost::asio::ip::udp::endpoint& sender) noexcept {
            P2PTier1Header header;
            if (!header.Parse(data, data_len)) {
                return;
            }

            if (!VerifyTier1Token(header)) {
                return;
            }

            {
                uint8_t peer_id_bytes[SESSION_ID_SIZE];
                Int128ToBytes(peer_session_id_, peer_id_bytes);
                if (!SessionIdEqual(header.session_id, peer_id_bytes)) {
                    return;
                }
            }

            P2PChannelState current_state = state_.load(std::memory_order_acquire);

            // PROBE_REQ: respond with PROBE_ACK using unified token (C1).
            if (IsProbeReq(header.flags) && current_state != P2PChannelState::Relay) {
                SendProbeAck(sender);
                return;
            }

            // PROBE_ACK: only valid in Probing state.
            if (IsProbeAck(header.flags)) {
                if (current_state == P2PChannelState::Probing) {
                    OnProbeAck(sender);
                }
                return;
            }

            // Heartbeat in Direct/Suspect states.
            if (current_state == P2PChannelState::Direct ||
                current_state == P2PChannelState::Suspect) {
                if (IsHeartbeatReq(header.flags)) {
                    pending_heartbeat_ack_ = true;
                }
                if (IsHeartbeatAck(header.flags)) {
                    last_heartbeat_recv_ms_ = ppp::GetTickCount();
                    heartbeat_misses_ = 0;
                    if (current_state == P2PChannelState::Suspect) {
                        TransitionTo(P2PChannelState::Direct);
                        if (suspect_timer_) {
                            suspect_timer_->cancel();
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------------------
        // Tier 2 data packet handling
        // -------------------------------------------------------------------------

        void P2PChannel::HandleTier2(const uint8_t* data, int data_len,
                                      const boost::asio::ip::udp::endpoint& sender) noexcept {
            P2PTier2Header header;
            if (!header.Parse(data, data_len)) {
                return;
            }

            P2PChannelState current_state = state_.load(std::memory_order_acquire);

            if (!CanProcessAuthenticatedP2PTier2(current_state)) {
                return;
            }

            if (sender != peer_endpoint_) {
                return;
            }

            // Replay check (M5: check Accept return value).
            if (replay_window_.IsDuplicate(header.sequence)) {
                return;
            }

            int header_size = TIER2_HEADER_SIZE;
            int payload_offset = header_size;
            int encrypted_len = data_len - payload_offset - AUTH_TAG_SIZE;
            if (encrypted_len < 0) {
                return;
            }

            auto dec_buf = buffer_pool_.Acquire();
            if (!dec_buf) {
                return;
            }

            const uint8_t* auth_tag = data + data_len - AUTH_TAG_SIZE;

            uint8_t nonce_bytes[NONCE_SIZE];
            NonceToBytes(header.nonce, nonce_bytes);

            P2PCryptoResult dec = AEADDecrypt(cipher_, rx_session_key_, nonce_bytes,
                                              data + payload_offset, encrypted_len,
                                              data, header_size,
                                              auth_tag, dec_buf.Data());
            if (!dec.success) {
                return;
            }

            // M5: Verify Accept succeeded; drop if duplicate raced past IsDuplicate.
            if (!replay_window_.Accept(header.sequence)) {
                return;
            }

            if (IsHeartbeatReq(header.flags)) {
                pending_heartbeat_ack_ = true;
            }
            if (IsHeartbeatAck(header.flags)) {
                last_heartbeat_recv_ms_ = ppp::GetTickCount();
                heartbeat_misses_ = 0;
                if (current_state == P2PChannelState::Suspect) {
                    TransitionTo(P2PChannelState::Direct);
                    if (suspect_timer_) {
                        suspect_timer_->cancel();
                    }
                }
            }

            if (!CanForwardP2PPayload(current_state)) {
                return;
            }

            if (IsCoalesced(header.flags)) {
                int n = DemuxCoalescedFrames(dec_buf.Data(), dec.output_length,
                                             coalesced_frames_, MAX_COALESCED_FRAMES);
                if (n > 0) {
                    for (int i = 0; i < n; ++i) {
                        if (frame_callback_) {
                            frame_callback_(dec_buf.Data() + coalesced_frames_[i].first,
                                            coalesced_frames_[i].second);
                        }
                    }
                }
            } else {
                if (frame_callback_ && dec.output_length > 0) {
                    frame_callback_(dec_buf.Data(), dec.output_length);
                }
            }

            last_heartbeat_recv_ms_ = ppp::GetTickCount();
        }

        // -------------------------------------------------------------------------
        // Data send path
        // -------------------------------------------------------------------------

        bool P2PChannel::SendFrame(const uint8_t* frame, int frame_len) noexcept {
            if (closed_.load(std::memory_order_acquire) ||
                state_.load(std::memory_order_acquire) != P2PChannelState::Direct) {
                return false;
            }
            if (!frame || frame_len <= 0 || frame_len > MAX_ETHERNET_FRAME_SIZE) {
                return false;
            }
            uint8_t flags = pending_heartbeat_ack_ ? P2P_FLAG_HEARTBEAT_ACK : 0;
            return EncryptAndSendTier2(frame, frame_len, flags);
        }

        bool P2PChannel::SendCoalesced(const std::pair<const uint8_t*, int>* frames,
                                        int frame_count) noexcept {
            if (closed_.load(std::memory_order_acquire) ||
                state_.load(std::memory_order_acquire) != P2PChannelState::Direct) {
                return false;
            }

            if (frame_count <= 0 || frame_count > MAX_COALESCED_FRAMES || !frames) {
                return false;
            }

            if (frame_count == 1) {
                return SendFrame(frames[0].first, frames[0].second);
            }

            auto coal_buf = buffer_pool_.Acquire();
            if (!coal_buf) {
                return false;
            }

            int coalesced_len = CoalesceFrames(coal_buf.Data(), coal_buf.Capacity(),
                                               frames, frame_count);
            if (coalesced_len <= 0) {
                return false;
            }

            uint8_t flags = P2P_FLAG_COALESCED;
            if (pending_heartbeat_ack_) {
                flags |= P2P_FLAG_HEARTBEAT_ACK;
            }
            return EncryptAndSendTier2(coal_buf.Data(), coalesced_len, flags);
        }

        bool P2PChannel::EncryptAndSendTier2(const uint8_t* payload, int payload_len,
                                              uint8_t flags) noexcept {
            if (!transport_) {
                FallbackToRelay(P2PFallbackReason::SocketError);
                return false;
            }

            bool is_heartbeat = (flags & (P2P_FLAG_HEARTBEAT_REQ | P2P_FLAG_HEARTBEAT_ACK)) != 0;
            if (payload_len < 0) {
                return false;
            }
            if (payload_len == 0 && !is_heartbeat) {
                return false;
            }
            if (payload_len > 0 && !payload) {
                return false;
            }
            if (TIER2_HEADER_SIZE + payload_len + AUTH_TAG_SIZE > P2P_MAX_PACKET_SIZE) {
                return false;
            }

            uint32_t seq = NextSequence();
            uint64_t nonce_val = NextChannelNonce();

            P2PTier2Header header;
            header.flags = flags;
            header.channel_id = 0;
            header.sequence = seq;
            header.nonce = nonce_val;

            uint8_t header_buf[TIER2_HEADER_SIZE];
            int hdr_len = header.Serialize(header_buf, sizeof(header_buf));
            if (hdr_len != TIER2_HEADER_SIZE) {
                return false;
            }

            auto cipher_buf = buffer_pool_.Acquire();
            if (!cipher_buf) {
                return false;
            }

            uint8_t auth_tag[AUTH_TAG_SIZE];
            uint8_t nonce_bytes[NONCE_SIZE];
            NonceToBytes(nonce_val, nonce_bytes);

            P2PCryptoResult enc = AEADEncrypt(cipher_, tx_session_key_, nonce_bytes,
                                              payload, payload_len,
                                              header_buf, hdr_len,
                                              cipher_buf.Data(), auth_tag);
            if (!enc.success) {
                FallbackToRelay(P2PFallbackReason::AuthenticationFailure);
                return false;
            }

            uint8_t packet[P2P_MAX_PACKET_SIZE];
            int packet_len = 0;
            std::memcpy(packet, header_buf, hdr_len);
            packet_len += hdr_len;
            std::memcpy(packet + packet_len, cipher_buf.Data(), enc.output_length);
            packet_len += enc.output_length;
            std::memcpy(packet + packet_len, auth_tag, AUTH_TAG_SIZE);
            packet_len += AUTH_TAG_SIZE;

            if (pending_heartbeat_ack_ && (flags & P2P_FLAG_HEARTBEAT_ACK)) {
                pending_heartbeat_ack_ = false;
            }

            if (!transport_->SendTo(packet, packet_len, peer_endpoint_)) {
                FallbackToRelay(P2PFallbackReason::SocketError);
                return false;
            }
            return true;
        }

        // -------------------------------------------------------------------------
        // Heartbeat
        // -------------------------------------------------------------------------

        void P2PChannel::OnHeartbeatTimer() noexcept {
            if (closed_.load(std::memory_order_acquire) ||
                state_.load(std::memory_order_acquire) != P2PChannelState::Direct) {
                return;
            }

            uint64_t now = ppp::GetTickCount();

            if (now - last_heartbeat_recv_ms_ >=
                static_cast<uint64_t>(config_.heartbeat_interval_ms * config_.heartbeat_miss_max)) {
                heartbeat_misses_ = config_.heartbeat_miss_max;
                TransitionTo(P2PChannelState::Suspect);
                suspect_enter_ms_ = now;

                suspect_timer_ = std::make_shared<boost::asio::steady_timer>(io_ctx_);
                suspect_timer_->expires_after(std::chrono::milliseconds(config_.suspect_timeout_ms));
                suspect_timer_->async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
                    if (!ec && !self->closed_.load(std::memory_order_acquire)) {
                        self->OnSuspectTimeout();
                    }
                });

                SendProbe(peer_endpoint_);
                return;
            }

            SendHeartbeat();

            if (heartbeat_timer_) {
                heartbeat_timer_->expires_after(std::chrono::milliseconds(config_.heartbeat_interval_ms));
                heartbeat_timer_->async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
                    if (!ec && !self->closed_.load(std::memory_order_acquire)) {
                        self->OnHeartbeatTimer();
                    }
                });
            }
        }

        void P2PChannel::SendHeartbeat() noexcept {
            EncryptAndSendTier2(nullptr, 0, P2P_FLAG_HEARTBEAT_REQ);
        }

        void P2PChannel::OnSuspectTimeout() noexcept {
            if (closed_.load(std::memory_order_acquire) ||
                state_.load(std::memory_order_acquire) != P2PChannelState::Suspect) {
                return;
            }

            FallbackToRelay(P2PFallbackReason::Timeout);
        }

        // -------------------------------------------------------------------------
        // Nonce / Sequence
        // -------------------------------------------------------------------------

        uint64_t P2PChannel::NextChannelNonce() noexcept {
            return ++nonce_counter_;
        }

        uint32_t P2PChannel::NextSequence() noexcept {
            return ++sequence_counter_;
        }

    }
}
