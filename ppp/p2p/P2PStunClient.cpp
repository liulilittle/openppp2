/**
 * @file P2PStunClient.cpp
 * @brief STUN Binding Request/Response implementation per RFC 5389.
 *
 * The asynchronous gatherer shares the protected P2P transport and its receive
 * callback. Query remains a legacy helper with a separate temporary socket.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PStunClient.h>
#include <ppp/Random.h>
#include <openssl/rand.h>
#include <boost/crc.hpp>
#include <cstring>

namespace ppp {
    namespace p2p {

        int P2PStunClient::BuildRequest(uint8_t* buf, int bufsz, uint8_t txn_id[12],
                RequestProfile profile) noexcept {
            if (profile != RequestProfile::Standard && profile != RequestProfile::Tailnode) return 0;
            const int request_size = profile == RequestProfile::Tailnode ? TailnodeRequestSize : StandardRequestSize;
            if (bufsz < request_size || !buf || !txn_id) {
                return 0;
            }

            // H3: Use OpenSSL RAND_bytes for cryptographically strong transaction IDs.
            if (RAND_bytes(txn_id, 12) != 1) {
                return 0;  // Fail if secure random is unavailable.
            }

            buf[0] = (STUN_METHOD_BINDING >> 8) & 0xFF;
            buf[1] = STUN_METHOD_BINDING & 0xFF;
            buf[2] = 0;
            buf[3] = static_cast<uint8_t>(request_size - StandardRequestSize);

            buf[4] = (STUN_MAGIC_COOKIE >> 24) & 0xFF;
            buf[5] = (STUN_MAGIC_COOKIE >> 16) & 0xFF;
            buf[6] = (STUN_MAGIC_COOKIE >> 8) & 0xFF;
            buf[7] = STUN_MAGIC_COOKIE & 0xFF;

            std::memcpy(buf + 8, txn_id, 12);

            if (profile == RequestProfile::Tailnode) {
                buf[20] = 0x80; buf[21] = 0x22;
                buf[22] = 0; buf[23] = 8;
                std::memcpy(buf + 24, "tailnode", 8);
                // RFC 5389 fingerprint covers the header with the final message length.
                boost::crc_32_type crc;
                crc.process_bytes(buf, 32);
                const uint32_t fingerprint = crc.checksum() ^ 0x5354554eu;
                buf[32] = 0x80; buf[33] = 0x28;
                buf[34] = 0; buf[35] = 4;
                for (int i = 0; i < 4; ++i)
                    buf[36 + i] = static_cast<uint8_t>(fingerprint >> (24 - 8 * i));
            }
            return request_size;
        }

        bool P2PStunClient::ParseResponse(const uint8_t* response, int response_len,
                                           const uint8_t txn_id[12],
                                           boost::asio::ip::udp::endpoint& mapped_ep) noexcept {
            if (!response || response_len < 20 || response_len > MaxResponseSize || !txn_id) {
                return false;
            }

            uint32_t cookie = (static_cast<uint32_t>(response[4]) << 24) |
                              (static_cast<uint32_t>(response[5]) << 16) |
                              (static_cast<uint32_t>(response[6]) << 8) |
                               static_cast<uint32_t>(response[7]);
            if (cookie != STUN_MAGIC_COOKIE) {
                return false;
            }

            // Validate transaction ID (#13).
            if (std::memcmp(response + 8, txn_id, 12) != 0) {
                return false;
            }

            uint16_t type = (static_cast<uint16_t>(response[0]) << 8) |
                             static_cast<uint16_t>(response[1]);
            // L2: Require exact Binding Success Response type (0x0101),
            // not merely the success class bits.
            if (type != STUN_TYPE_BINDING_SUCCESS_RESP) {
                return false;
            }

            uint16_t msg_len = (static_cast<uint16_t>(response[2]) << 8) |
                                static_cast<uint16_t>(response[3]);
            // A UDP datagram contains exactly one message. Validate alignment,
            // padding and all attributes before publishing the mapped endpoint.
            if ((msg_len & 3) != 0 || msg_len + 20 != response_len) {
                return false;
            }

            boost::asio::ip::udp::endpoint mapped;
            bool found = false;
            int offset = 20;
            while (offset + 4 <= 20 + msg_len) {
                uint16_t attr_type = (static_cast<uint16_t>(response[offset]) << 8) |
                                      static_cast<uint16_t>(response[offset + 1]);
                uint16_t attr_len  = (static_cast<uint16_t>(response[offset + 2]) << 8) |
                                      static_cast<uint16_t>(response[offset + 3]);
                int attr_offset = offset + 4;

                int padded_len = (attr_len + 3) & ~3;
                if (attr_offset + padded_len > 20 + msg_len) {
                    return false;
                }

                if (attr_type == STUN_ATTR_XOR_MAPPED_ADDR) {
                    if (found || (attr_len != 8 && attr_len != 20) || response[attr_offset] != 0) {
                        return false;
                    }
                    uint8_t family = response[attr_offset + 1];
                    uint16_t xport = (static_cast<uint16_t>(response[attr_offset + 2]) << 8) |
                                      static_cast<uint16_t>(response[attr_offset + 3]);
                    uint16_t port = xport ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);

                    if (family == 0x01 && attr_len == 8) {
                        uint32_t xaddr = (static_cast<uint32_t>(response[attr_offset + 4]) << 24) |
                                         (static_cast<uint32_t>(response[attr_offset + 5]) << 16) |
                                         (static_cast<uint32_t>(response[attr_offset + 6]) << 8) |
                                          static_cast<uint32_t>(response[attr_offset + 7]);
                        uint32_t addr = xaddr ^ STUN_MAGIC_COOKIE;

                        boost::asio::ip::address_v4::bytes_type bytes = {
                            static_cast<uint8_t>((addr >> 24) & 0xFF),
                            static_cast<uint8_t>((addr >> 16) & 0xFF),
                            static_cast<uint8_t>((addr >> 8) & 0xFF),
                            static_cast<uint8_t>(addr & 0xFF)
                        };
                        const auto address = boost::asio::ip::address_v4(bytes);
                        if (port == 0 || address.is_unspecified() ||
                            address.is_multicast() || addr == 0xffffffffu) {
                            return false;
                        }
                        mapped = boost::asio::ip::udp::endpoint(address, port);
                        found = true;
                    } else if (family == 0x02 && attr_len == 20) {
                        boost::asio::ip::address_v6::bytes_type bytes{};
                        const std::uint32_t cookie = STUN_MAGIC_COOKIE;
                        bytes[0] = response[attr_offset + 4] ^ static_cast<std::uint8_t>(cookie >> 24);
                        bytes[1] = response[attr_offset + 5] ^ static_cast<std::uint8_t>(cookie >> 16);
                        bytes[2] = response[attr_offset + 6] ^ static_cast<std::uint8_t>(cookie >> 8);
                        bytes[3] = response[attr_offset + 7] ^ static_cast<std::uint8_t>(cookie);
                        for (std::size_t n = 4; n < bytes.size(); ++n)
                            bytes[n] = response[attr_offset + n] ^ txn_id[n - 4];
                        const auto address = boost::asio::ip::address_v6(bytes);
                        if (port == 0 || address.is_unspecified() || address.is_loopback() ||
                            address.is_multicast() || address.is_link_local() ||
                            (bytes[0] & 0xfe) == 0xfc) return false;
                        mapped = boost::asio::ip::udp::endpoint(address, port);
                        found = true;
                    } else {
                        return false;
                    }
                }

                offset = attr_offset + padded_len;
            }

            if (!found || offset != response_len) {
                return false;
            }
            mapped_ep = mapped;
            return true;
        }

        bool P2PStunClient::IsStunDatagram(
                const uint8_t* packet, int packet_size) noexcept {
            // Binding request/indication and success/error responses only. A
            // v2 P2P header can coincidentally start its offer hash with the STUN
            // cookie; the version byte must never let that packet be consumed.
            return packet && packet_size >= 20 && packet[0] <= 1 &&
                (packet[1] == 0x01 || packet[1] == 0x11) &&
                packet[4] == 0x21 && packet[5] == 0x12 &&
                packet[6] == 0xa4 && packet[7] == 0x42;
        }

        P2PStunGatherer::P2PStunGatherer(const Strand& owner)
            : owner_(owner), timer_(owner_) {}

        std::shared_ptr<P2PStunGatherer> P2PStunGatherer::Create(
                const Strand& owner) noexcept {
            try {
                return std::shared_ptr<P2PStunGatherer>(new P2PStunGatherer(owner));
            }
            catch (...) {
                return nullptr;
            }
        }

        P2PStunGatherer::~P2PStunGatherer() noexcept {
            Cancel();
        }

        bool P2PStunGatherer::Start(
                const std::shared_ptr<IP2PDatagramTransport>& transport,
                const std::vector<boost::asio::ip::udp::endpoint>& servers,
                uint64_t generation,
                uint64_t transport_registration,
                const Completion& completion,
                P2PStunClient::RequestProfile profile) noexcept {
            if (!owner_.running_in_this_thread() || !transport ||
                !transport->IsReady() || transport->LocalEndpoint().port() == 0 ||
                generation == 0 || transport_registration == 0 || !completion ||
                (profile != P2PStunClient::RequestProfile::Standard &&
                 profile != P2PStunClient::RequestProfile::Tailnode)) {
                return false;
            }
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (started_ || cancelled_.load(std::memory_order_acquire)) {
                return false;
            }
            try {
                for (const auto& server : servers) {
                    if (!(server.address().is_v4() || server.address().is_v6()) || server.address().is_unspecified() ||
                        server.address().is_multicast() || server.port() == 0 ||
                        server.address().to_v4().to_uint() == 0xffffffffu) {
                        continue;
                    }
                    bool duplicate = false;
                    for (std::size_t i = 0; i < server_count_; ++i) {
                        duplicate = duplicate || servers_[i] == server;
                    }
                    if (!duplicate) {
                        servers_[server_count_++] = server;
                    }
                    if (server_count_ == MaxServers) {
                        break;
                    }
                }
                if (server_count_ == 0) {
                    return false;
                }
                transport_ = transport;
                completion_ = completion;
                generation_ = generation;
                transport_registration_ = transport_registration;
                request_profile_ = profile;
                started_ = true;
                running_.store(true, std::memory_order_release);
                BeginServerLocked();
                return true;
            }
            catch (...) {
                ClearLocked();
                return false;
            }
        }

        bool P2PStunGatherer::BeginServerLocked() noexcept {
            try { timer_.cancel(); }
            catch (...) {}
            if (server_index_ >= server_count_ || !transport_ || !transport_->IsReady()) {
                FinishLocked({});
                return false;
            }
            request_length_ = P2PStunClient::BuildRequest(request_.data(),
                static_cast<int>(request_.size()), transaction_id_.data(), request_profile_);
            if (request_length_ == 0) {
                FinishLocked({});
                return false;
            }
            server_started_at_ = std::chrono::steady_clock::now();
            const auto serial = ++transaction_serial_;
            sends_ = 1;
            const auto transport = transport_;
            const auto request = request_;
            const auto request_length = request_length_;
            const auto destination = servers_[server_index_];
            // The synchronous send may cause a test/provider transport to invoke
            // HandleDatagram re-entrantly. Retain local copies across that call.
            transport->SendTo(request.data(), request_length,
                destination);
            if (!running_.load(std::memory_order_acquire) || serial != transaction_serial_) {
                return true;
            }
            return ArmTimerLocked();
        }

        bool P2PStunGatherer::ArmTimerLocked() noexcept {
            try {
                const auto serial = transaction_serial_;
                const auto delay = std::chrono::milliseconds(
                    sends_ == 1 ? RetryDelayMs : ServerTimeoutMs);
                timer_.expires_at(server_started_at_ + delay);
                const std::weak_ptr<P2PStunGatherer> weak = shared_from_this();
                timer_.async_wait([weak, serial](const boost::system::error_code& ec) noexcept {
                    if (!ec) {
                        if (const auto self = weak.lock()) {
                            self->HandleTimer(serial);
                        }
                    }
                });
                return true;
            }
            catch (...) {
                FinishLocked({});
                return false;
            }
        }

        void P2PStunGatherer::HandleTimer(uint64_t transaction_serial) noexcept {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!running_.load(std::memory_order_acquire) ||
                cancelled_.load(std::memory_order_acquire) ||
                transaction_serial != transaction_serial_) {
                return;
            }
            if (!transport_ || !transport_->IsReady()) {
                FinishLocked({});
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now >= server_started_at_ + std::chrono::milliseconds(ServerTimeoutMs)) {
                ++server_index_;
                BeginServerLocked();
                return;
            }
            if (sends_ == 1 &&
                now >= server_started_at_ + std::chrono::milliseconds(RetryDelayMs)) {
                sends_ = 2;
                const auto transport = transport_;
                const auto request = request_;
                const auto request_length = request_length_;
                const auto destination = servers_[server_index_];
                transport->SendTo(request.data(), request_length,
                    destination);
                if (!running_.load(std::memory_order_acquire) ||
                    transaction_serial != transaction_serial_) {
                    return;
                }
            }
            ArmTimerLocked();
        }

        bool P2PStunGatherer::HandleDatagram(
                const boost::asio::ip::udp::endpoint& sender,
                const uint8_t* packet,
                int packet_size,
                uint64_t generation,
                uint64_t transport_registration) noexcept {
            if (!P2PStunClient::IsStunDatagram(packet, packet_size)) {
                return false;
            }
            // Recognition is cheap and independent of mutable gather state.
            // Off-strand input is consumed but cannot alter the transaction.
            if (!owner_.running_in_this_thread() ||
                packet_size > P2PStunClient::MaxResponseSize) {
                return true;
            }
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!running_.load(std::memory_order_acquire) ||
                cancelled_.load(std::memory_order_acquire) ||
                generation != generation_ ||
                transport_registration != transport_registration_ ||
                sender != servers_[server_index_] || !transport_ ||
                !transport_->IsReady() ||
                std::chrono::steady_clock::now() >= server_started_at_ +
                    std::chrono::milliseconds(ServerTimeoutMs)) {
                return true;
            }
            P2PStunClient::StunResult result;
            if (P2PStunClient::ParseResponse(packet, packet_size,
                    transaction_id_.data(), result.mapped_endpoint)) {
                result.success = true;
                FinishLocked(result);
            }
            return true;
        }

        void P2PStunGatherer::FinishLocked(
                const P2PStunClient::StunResult& result) noexcept {
            const auto generation = generation_;
            const auto registration = transport_registration_;
            auto completion = std::move(completion_);
            ClearLocked();
            if (!completion || cancelled_.load(std::memory_order_acquire)) {
                return;
            }
            try {
                const std::weak_ptr<P2PStunGatherer> weak = shared_from_this();
                boost::asio::post(owner_,
                    [weak, completion = std::move(completion), result,
                        generation, registration]() noexcept {
                        const auto self = weak.lock();
                        if (self && !self->cancelled_.load(std::memory_order_acquire)) {
                            completion(result, generation, registration);
                        }
                    });
            }
            catch (...) {
                // Allocation failure cannot leave a retry or completion alive.
            }
        }

        void P2PStunGatherer::ClearLocked() noexcept {
            running_.store(false, std::memory_order_release);
            ++transaction_serial_;
            try { timer_.cancel(); }
            catch (...) {}
            transport_.reset();
            completion_ = nullptr;
            request_.fill(0);
            request_length_ = 0;
            request_profile_ = P2PStunClient::RequestProfile::Standard;
            transaction_id_.fill(0);
            servers_.fill({});
            server_count_ = 0;
            server_index_ = 0;
            sends_ = 0;
            generation_ = 0;
            transport_registration_ = 0;
        }

        void P2PStunGatherer::Cancel() noexcept {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            cancelled_.store(true, std::memory_order_release);
            ClearLocked();
        }

        bool P2PStunGatherer::IsRunning() const noexcept {
            return running_.load(std::memory_order_acquire);
        }

        P2PStunClient::StunResult P2PStunClient::Query(
                boost::asio::io_context& io_ctx,
                const boost::asio::ip::udp::endpoint& stun_server,
                int timeout_ms) noexcept {
            StunResult result;

            // Create a dedicated temporary socket (#13).
            boost::system::error_code ec;
            // open(protocol, ec) instead of the opening constructor: that overload
            // throws on failure (no IPv6 stack, descriptor exhaustion), which would
            // terminate the process from this noexcept function.
            boost::asio::ip::udp::socket tmp_socket(io_ctx);
            tmp_socket.open(stun_server.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4(), ec);
            if (ec || !tmp_socket.is_open()) {
                return result;
            }
            tmp_socket.bind(stun_server.address().is_v6()
                ? boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0)
                : boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0), ec);
            if (ec) {
                return result;
            }

            uint8_t request[28];
            uint8_t txn_id[12];
            int req_len = BuildRequest(request, sizeof(request), txn_id);
            if (req_len == 0) {
                return result;
            }

            tmp_socket.send_to(boost::asio::buffer(request, req_len), stun_server, 0, ec);
            if (ec) {
                return result;
            }

            // Non-blocking poll with timeout.
            uint8_t response[512];
            boost::asio::ip::udp::endpoint sender;

            tmp_socket.non_blocking(true, ec);
            uint64_t start = ppp::GetTickCount();

            for (;;) {
                ec.clear();
                size_t received = 0;
                try {
                    received = tmp_socket.receive_from(
                        boost::asio::buffer(response, sizeof(response)), sender, 0, ec);
                } catch (...) {
                    ec = boost::asio::error::eof;
                }

                if (!ec && received >= 20) {
                    // Validate sender is the STUN server we sent to (#13).
                    if (sender == stun_server) {
                        if (ParseResponse(response, static_cast<int>(received), txn_id, result.mapped_endpoint)) {
                            result.success = true;
                            break;
                        }
                    }
                }

                if (ppp::GetTickCount() - start >= static_cast<uint64_t>(timeout_ms)) {
                    break;
                }

                ppp::Sleep(10);
            }

            // Close temporary socket (does not affect P2P data socket).
            tmp_socket.close(ec);
            return result;
        }

    }
}
