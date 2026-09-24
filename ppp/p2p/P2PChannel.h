#pragma once

/**
 * @file P2PChannel.h
 * @brief P2P direct UDP channel with state machine, heartbeat, and coalescing.
 *
 * Implements the Relay → Probing → Direct → Suspect → Relay lifecycle.
 * Manages the local UDP socket, candidate racing, heartbeat piggyback,
 * packet encryption/decryption, replay protection, and coalesced frames.
 *
 * Thread safety: all state mutations are performed on the owning io_context
 * strand. The `closed_` atomic allows async handlers to bail out safely.
 *
 * INTEGRATION STATUS: This channel class is a self-contained data-plane
 * component.  Production integration with VEthernetExchanger requires
 * wiring the frame callback into the TAP/TUN injection path, deriving
 * session keys from the TLS handshake, and obtaining channel_id from the
 * server hint offer.  When these hooks are not wired, the channel remains
 * in Relay state and all traffic uses the existing DoNat() relay path.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/p2p/P2PPacketHeader.h>
#include <ppp/p2p/P2PReplayWindow.h>
#include <ppp/p2p/P2PBufferPool.h>
#include <ppp/p2p/P2PCrypto.h>
#include <ppp/p2p/P2PDatagramTransport.h>
#include <ppp/p2p/P2PSocketProtector.h>
#include <ppp/p2p/P2PState.h>
#include <ppp/Int128.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>

#include <boost/asio.hpp>
#include <atomic>
#include <functional>

namespace ppp {
    namespace p2p {

        using P2PFrameReceivedCallback = ppp::function<void(const uint8_t* frame, int frame_len)>;
        using P2PStateChangedCallback = ppp::function<void(P2PChannelState old_state, P2PChannelState new_state)>;

        struct P2PCandidate {
            boost::asio::ip::udp::endpoint  endpoint;
            ppp::string                     source;
        };

        /**
         * @brief Core P2P direct UDP channel.
         */
        class P2PChannel final : public std::enable_shared_from_this<P2PChannel> {
        public:
            P2PChannel(
                boost::asio::io_context& io_ctx,
                const std::shared_ptr<ISocketProtector>& protector,
                const Int128& session_id,
                const uint8_t base_session_key[SESSION_KEY_SIZE],
                const uint8_t token_key[SESSION_KEY_SIZE],
                const P2PConfig& config,
                P2PCipher cipher,
                const std::shared_ptr<IP2PDatagramTransportFactory>&
                    transport_factory = nullptr) noexcept;

            ~P2PChannel() noexcept;

            P2PChannel(const P2PChannel&) = delete;
            P2PChannel& operator=(const P2PChannel&) = delete;

            /**
             * @brief Starts the probing phase.
             *
             * Fails closed if offer_token is empty or exceeds MAX_OFFER_TOKEN_SIZE.
             */
            void StartProbing(const ppp::vector<P2PCandidate>& candidates,
                              const Int128& peer_session_id,
                              const ppp::string& offer_token) noexcept;

            bool SendFrame(const uint8_t* frame, int frame_len) noexcept;
            bool SendCoalesced(const std::pair<const uint8_t*, int>* frames, int frame_count) noexcept;
            void Close() noexcept;

            P2PChannelState GetState() const noexcept {
                return state_.load(std::memory_order_acquire);
            }

            boost::asio::ip::udp::endpoint GetPeerEndpoint() const noexcept { return peer_endpoint_; }
            void SetFrameCallback(const P2PFrameReceivedCallback& cb) noexcept { frame_callback_ = cb; }
            void SetStateChangedCallback(const P2PStateChangedCallback& cb) noexcept { state_callback_ = cb; }
            bool IsClosed() const noexcept { return closed_.load(std::memory_order_acquire); }
            P2PFallbackReason GetFallbackReason() const noexcept {
                return fallback_reason_.load(std::memory_order_acquire);
            }

        private:
            void TransitionTo(P2PChannelState new_state) noexcept;
            void FallbackToRelay(P2PFallbackReason reason) noexcept;
            void ResetAttemptState() noexcept;
            void OnReceive(const boost::asio::ip::udp::endpoint& sender,
                           const uint8_t* data, int data_len) noexcept;

            void HandleTier1(const uint8_t* data, int data_len,
                             const boost::asio::ip::udp::endpoint& sender) noexcept;
            void HandleTier2(const uint8_t* data, int data_len,
                             const boost::asio::ip::udp::endpoint& sender) noexcept;

            bool SendProbe(const boost::asio::ip::udp::endpoint& ep) noexcept;
            void SendProbeAck(const boost::asio::ip::udp::endpoint& ep) noexcept;
            void SendHeartbeat() noexcept;
            void OnProbeAck(const boost::asio::ip::udp::endpoint& sender) noexcept;

            void OnProbeTimeout() noexcept;
            void OnHeartbeatTimer() noexcept;
            void OnSuspectTimeout() noexcept;

            uint64_t NextChannelNonce() noexcept;
            uint32_t NextSequence() noexcept;

            bool EncryptAndSendTier2(const uint8_t* payload, int payload_len, uint8_t flags) noexcept;

            /**
             * @brief Shared Tier-1 token input builder (C1).
             *
             * Builds the HMAC input for all Tier-1 token operations:
             * serialized header with token field zeroed, followed by offer_token.
             * Fails closed if offer_token is missing or oversized.
             *
             * @param[in]  header     Tier-1 header (token field need not be zeroed;
             *                        this method zeros it internally).
             * @param[out] out_buf    Output buffer (must be >= TIER1_HEADER_SIZE + MAX_OFFER_TOKEN_SIZE).
             * @param[out] out_len    Actual length written.
             * @return true on success, false if offer_token is missing/oversized.
             */
            bool BuildTier1TokenInput(P2PTier1Header header,
                                      uint8_t* out_buf, int buf_cap,
                                      int& out_len) const noexcept;

            /**
             * @brief Verifies a Tier-1 token using the unified token binding (C1).
             *
             * Reconstructs the HMAC input from the header (with token zeroed)
             * and the stored offer_token, then verifies the token field.
             *
             * @param[in] header Parsed Tier-1 header containing the token to verify.
             * @return true if the token is valid.
             */
            bool VerifyTier1Token(const P2PTier1Header& header) noexcept;

        private:
            boost::asio::io_context&                    io_ctx_;
            std::shared_ptr<ISocketProtector>           protector_;
            std::shared_ptr<IP2PDatagramTransportFactory> transport_factory_;
            std::shared_ptr<IP2PDatagramTransport>      transport_;

            Int128                                      session_id_;
            Int128                                      peer_session_id_;
            // H1: Directional AEAD keys prevent nonce reuse.
            // tx_session_key_ is used for encryption; rx_session_key_ for decryption.
            // Derived from the shared session key via HKDF with direction labels
            // based on deterministic peer ordering (lower session ID = "A").
            uint8_t                                     base_session_key_[SESSION_KEY_SIZE]; ///< Base key before directional derivation.
            uint8_t                                     tx_session_key_[SESSION_KEY_SIZE];
            uint8_t                                     rx_session_key_[SESSION_KEY_SIZE];
            uint8_t                                     token_key_[SESSION_KEY_SIZE];
            ppp::string                                 offer_token_;
            P2PCipher                                   cipher_;
            P2PConfig                                   config_;

            std::atomic<P2PChannelState>                state_{P2PChannelState::Relay};
            std::atomic<bool>                           closed_{false};
            std::atomic<P2PFallbackReason>              fallback_reason_{P2PFallbackReason::None};
            boost::asio::ip::udp::endpoint              peer_endpoint_;
            boost::asio::ip::udp::endpoint              local_endpoint_;

            P2PReplayWindow                             replay_window_;
            P2PBufferPool                               buffer_pool_;
            uint64_t                                    nonce_counter_ = 0;
            uint32_t                                    sequence_counter_ = 0;

            int                                         probe_round_ = 0;
            uint64_t                                    last_heartbeat_recv_ms_ = 0;
            int                                         heartbeat_misses_ = 0;
            uint64_t                                    suspect_enter_ms_ = 0;
            bool                                        pending_heartbeat_ack_ = false;

            ppp::vector<P2PCandidate>                   candidates_;

            P2PFrameReceivedCallback                    frame_callback_;
            P2PStateChangedCallback                     state_callback_;

            std::shared_ptr<boost::asio::steady_timer>  probe_timer_;
            std::shared_ptr<boost::asio::steady_timer>  heartbeat_timer_;
            std::shared_ptr<boost::asio::steady_timer>  suspect_timer_;

            std::pair<int, int>                         coalesced_frames_[MAX_COALESCED_FRAMES];
        };

    }
}
