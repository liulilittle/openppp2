#pragma once

/**
 * @file P2PStunClient.h
 * @brief Lightweight STUN Binding Request/Response client for mapped-endpoint detection.
 *
 * P2PStunGatherer sends through the existing protected datagram transport and
 * consumes responses supplied by its sole receive callback. The synchronous
 * Query helper is retained only for legacy callers; it cannot discover the
 * mapping of a different transport's socket.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/p2p/P2PDatagramTransport.h>
#include <boost/asio.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace ppp {
    namespace p2p {

        /**
         * @brief Minimal STUN Binding Request/Response implementation.
         *
         * Stateless STUN codec and legacy synchronous query helper.
         */
        class P2PStunClient final {
        public:
            enum class RequestProfile { Standard, Tailnode };
            static constexpr int StandardRequestSize = 20;
            static constexpr int TailnodeRequestSize = 40;

            struct StunResult {
                boost::asio::ip::udp::endpoint mapped_endpoint;
                bool success = false;
            };

            /**
             * @brief Sends a STUN Binding Request on a dedicated temporary socket.
             *
             * Creates a fresh UDP socket, sends the request, waits for the
             * response (blocking with timeout), and closes the socket.
             * Does not touch the P2P data socket.
             *
             * @param[in]  io_ctx       io_context for socket creation.
             * @param[in]  stun_server  STUN server endpoint.
             * @param[in]  timeout_ms   Timeout in milliseconds.
             * @return StunResult with mapped endpoint on success.
             */
            static StunResult Query(boost::asio::io_context& io_ctx,
                                    const boost::asio::ip::udp::endpoint& stun_server,
                                    int timeout_ms = 3000) noexcept;

            /**
             * @brief Parses a STUN Binding Response and extracts XOR-MAPPED-ADDRESS.
             *
             * Validates transaction ID against the expected value.
             *
             * @param[in]  response     Raw response buffer.
             * @param[in]  response_len Response length in bytes.
             * @param[in]  txn_id       Expected 12-byte transaction ID.
             * @param[out] mapped_ep    Parsed XOR-MAPPED-ADDRESS endpoint.
             * @return true if parsing succeeds and transaction ID matches.
             */
            static bool ParseResponse(const uint8_t* response, int response_len,
                                      const uint8_t txn_id[12],
                                      boost::asio::ip::udp::endpoint& mapped_ep) noexcept;

            static int BuildRequest(uint8_t* buf, int bufsz, uint8_t txn_id[12],
                RequestProfile profile = RequestProfile::Standard) noexcept;

            // Cheap receive demultiplexing; no allocation or field access beyond
            // the fixed header. Recognition alone does not authenticate a reply.
            static bool IsStunDatagram(const uint8_t* packet, int packet_size) noexcept;

            static constexpr int MaxResponseSize = 512;

        private:
            static constexpr uint16_t STUN_METHOD_BINDING             = 0x0001;
            static constexpr uint16_t STUN_TYPE_BINDING_SUCCESS_RESP  = 0x0101;  ///< L2: exact type.
            static constexpr uint32_t STUN_MAGIC_COOKIE               = 0x2112A442;
            static constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDR       = 0x0020;
        };

        /**
         * @brief One bounded asynchronous gather on an already started transport.
         *
         * Start and HandleDatagram must run on the supplied owner strand. The
         * transport's existing receive callback must supply STUN packets here;
         * this object never opens a socket, starts a receive, or closes the
         * shared transport. Create a new gatherer for another gather.
         *
         * Cancel is thread safe and suppresses queued completion callbacks.
         * A completion already executing may finish; its owner must still check
         * generation/registration before applying a candidate.
         */
        class P2PStunGatherer final
            : public std::enable_shared_from_this<P2PStunGatherer> {
        public:
            using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;
            using Completion = std::function<void(
                const P2PStunClient::StunResult& result,
                uint64_t generation,
                uint64_t transport_registration)>;

            static constexpr std::size_t MaxServers = 3;
            static constexpr int RetryDelayMs = 500;
            static constexpr int ServerTimeoutMs = 1000;

            static std::shared_ptr<P2PStunGatherer> Create(const Strand& owner) noexcept;
            ~P2PStunGatherer() noexcept;

            bool Start(
                const std::shared_ptr<IP2PDatagramTransport>& transport,
                const std::vector<boost::asio::ip::udp::endpoint>& servers,
                uint64_t generation,
                uint64_t transport_registration,
                const Completion& completion,
                P2PStunClient::RequestProfile profile = P2PStunClient::RequestProfile::Standard) noexcept;

            // Returns true for a recognized STUN datagram, including invalid,
            // stale, or unrelated responses, so it cannot reach the P2P parser.
            bool HandleDatagram(
                const boost::asio::ip::udp::endpoint& sender,
                const uint8_t* packet,
                int packet_size,
                uint64_t generation,
                uint64_t transport_registration) noexcept;

            void Cancel() noexcept;
            bool IsRunning() const noexcept;

        private:
            explicit P2PStunGatherer(const Strand& owner);
            bool BeginServerLocked() noexcept;
            bool ArmTimerLocked() noexcept;
            void HandleTimer(uint64_t transaction_serial) noexcept;
            void FinishLocked(const P2PStunClient::StunResult& result) noexcept;
            void ClearLocked() noexcept;

            Strand owner_;
            boost::asio::steady_timer timer_;
            // SendTo implementations may synchronously deliver a response. The
            // recursive lock also serializes Cancel with timer/socket operations.
            mutable std::recursive_mutex mutex_;
            std::shared_ptr<IP2PDatagramTransport> transport_;
            Completion completion_;
            std::array<boost::asio::ip::udp::endpoint, MaxServers> servers_{};
            std::size_t server_count_ = 0;
            std::size_t server_index_ = 0;
            std::array<uint8_t, P2PStunClient::TailnodeRequestSize> request_{};
            int request_length_ = 0;
            P2PStunClient::RequestProfile request_profile_ = P2PStunClient::RequestProfile::Standard;
            std::array<uint8_t, 12> transaction_id_{};
            std::chrono::steady_clock::time_point server_started_at_{};
            uint64_t generation_ = 0;
            uint64_t transport_registration_ = 0;
            uint64_t transaction_serial_ = 0;
            unsigned sends_ = 0;
            bool started_ = false;
            std::atomic<bool> running_{false};
            std::atomic<bool> cancelled_{false};
        };

    }
}
