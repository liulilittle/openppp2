// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetLinklayer.cpp
 * @brief Implementation of virtual Ethernet link-layer packet encoding/decoding.
 */

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/io/Stream.h>
#include <ppp/io/BinaryReader.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include <cstring>       // for std::memcpy

namespace ppp {
    namespace app {
            namespace protocol {
                using ppp::telemetry::Level;
                // Type aliases for convenience
            typedef ppp::io::Stream                                     Stream;
            typedef ppp::io::BinaryReader                               BinaryReader;
            typedef ppp::io::MemoryStream                               MemoryStream;
            typedef ppp::net::Ipep                                      Ipep;
            typedef ppp::net::AddressFamily                             AddressFamily;
            typedef ppp::net::IPEndPoint                                IPEndPoint;
            typedef VirtualEthernetLinklayer::ITransmissionPtr          ITransmissionPtr;
            typedef VirtualEthernetLinklayer::YieldContext              YieldContext;
            typedef VirtualEthernetLinklayer::PacketAction              PacketAction;
            typedef ppp::threading::Executors                           Executors;

            namespace checksum = ppp::net::native;
            namespace global {
                /** @brief Sets a diagnostic error code and returns false. */
                static bool PACKET_Fail(ppp::diagnostics::ErrorCode code) noexcept {
                    ppp::diagnostics::SetLastErrorCode(code);
                    return false;
                }

                /** @brief Applies a fallback diagnostic code when operation failed without one. */
                static bool PACKET_Result(bool ok, ppp::diagnostics::ErrorCode code) noexcept {
                    if (!ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(code);
                    }
                    return ok;
                }

                /** @brief Returns whether packet action is a defined protocol opcode. */
                static bool PACKET_IsKnownAction(PacketAction packet_action) noexcept {
                    switch (packet_action) {
                        case VirtualEthernetLinklayer::PacketAction_INFO:
                        case VirtualEthernetLinklayer::PacketAction_KEEPALIVED:
                        case VirtualEthernetLinklayer::PacketAction_FRP_ENTRY:
                        case VirtualEthernetLinklayer::PacketAction_FRP_CONNECT:
                        case VirtualEthernetLinklayer::PacketAction_FRP_CONNECTOK:
                        case VirtualEthernetLinklayer::PacketAction_FRP_PUSH:
                        case VirtualEthernetLinklayer::PacketAction_FRP_DISCONNECT:
                        case VirtualEthernetLinklayer::PacketAction_FRP_SENDTO:
                        case VirtualEthernetLinklayer::PacketAction_LAN:
                        case VirtualEthernetLinklayer::PacketAction_NAT:
                        case VirtualEthernetLinklayer::PacketAction_SYN:
                        case VirtualEthernetLinklayer::PacketAction_SYNOK:
                        case VirtualEthernetLinklayer::PacketAction_PSH:
                        case VirtualEthernetLinklayer::PacketAction_FIN:
                        case VirtualEthernetLinklayer::PacketAction_SENDTO:
                        case VirtualEthernetLinklayer::PacketAction_ECHO:
                        case VirtualEthernetLinklayer::PacketAction_ECHOACK:
                        case VirtualEthernetLinklayer::PacketAction_STATIC:
                        case VirtualEthernetLinklayer::PacketAction_STATICACK:
                        case VirtualEthernetLinklayer::PacketAction_MUX:
                        case VirtualEthernetLinklayer::PacketAction_MUXON:
                            return true;
                        default:
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                            return false;
                    }
                }

                /**
                 * @brief Parses endpoint fields from packet stream and resolves hostnames.
                 * @tparam TProtocol `boost::asio::ip::tcp` or `boost::asio::ip::udp`.
                 * @param firewall Optional firewall for segment/domain/port filtering.
                 * @param stream Input cursor advanced on success.
                 * @param packet_length Remaining packet bytes, updated after parsing.
                 * @param y Coroutine context used for async DNS resolve.
                 * @param hostname Output host text read from packet.
                 * @return Parsed endpoint or endpoint with port `0` on failure.
                 */
                // -----------------------------------------------------------------
                // Template: parse an endpoint (TCP/UDP) from a raw packet buffer.
                // Supports both IP addresses and domain names (with async DNS).
                // Returns an empty endpoint (port 0) on any failure.
                // -----------------------------------------------------------------
                template <class TProtocol>
                static boost::asio::ip::basic_endpoint<TProtocol>       PACKET_IPEndPoint(const std::shared_ptr<ppp::net::Firewall>& firewall, Byte*& stream, int& packet_length, YieldContext& y, ppp::string& hostname) noexcept
                {
                    /* Packet wire format:
                       ACTION(1) ADDR_LEN(1) HOSTNAME(ADDR_LEN) PORT_LEN(1) PORT_STRING(PORT_LEN) */

                    // Decrement packet_length to account for the address length field itself (1 byte)
                    if (--packet_length < 0) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    int address_length = *stream++;                         // length of hostname string
                    if (address_length > packet_length) {                   // hostname must fit in remaining data
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    // Build hostname string from the stream (no null terminator needed)
                    hostname = ppp::string((char*)stream, address_length);
                    if (hostname.empty()) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    stream += address_length;                               // move past hostname
                    packet_length -= address_length;                        // subtract hostname length

                    if (packet_length < 1) {                                // safety check
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    // read port length field
                    int port_length = *stream++;
                    if (--packet_length < 0) {                              // account for the port length byte
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    if (port_length > packet_length) {                      // port string must fit
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    // ----- safely convert port string to integer -----
                    int port = IPEndPoint::MinPort;
                    std::string_view port_str((char*)stream, port_length);

                    // invalid port -> treat as zero / invalid
                    if (!port_str.empty()) {
                        /**
                         * @brief Validate port number using strtol.
                         * @note Port must be in valid range [1, 65535].
                         */
                        ppp::string port_std_str(port_str);
                        char* endptr = NULLPTR;
                        long parsed_port = strtol(port_std_str.c_str(), &endptr, 10);
                        if (NULLPTR != endptr && endptr != port_std_str.c_str() && *endptr == '\x0' && parsed_port > IPEndPoint::MinPort && parsed_port <= IPEndPoint::MaxPort) {
                            port = static_cast<int>(parsed_port);
                        }

                        if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                            port = IPEndPoint::MinPort;
                        }
                    }

                    // apply firewall port filtering
                    if (NULLPTR != firewall) {
                        if (firewall->IsDropNetworkPort(port, std::is_same<TProtocol, boost::asio::ip::tcp>::value)) {
                            return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                        }
                    }

                    stream += port_length;                                  // move past port string
                    packet_length -= port_length;                           // subtract port string length

                    // ----- try to interpret hostname as IP address first -----
                    boost::system::error_code ec_ip;
                    boost::asio::ip::address address = StringToAddress(hostname.c_str(), ec_ip);
                    if (ec_ip) {                                            // not an IP -> domain name
                        if (NULLPTR != firewall) {
                            if (firewall->IsDropNetworkDomains(hostname)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        // async DNS resolution (only if coroutine context is available)
                        if (y) {
                            try {
                                const boost::asio::ip::basic_endpoint<TProtocol> endpoint =
                                    ppp::coroutines::asio::GetAddressByHostName<TProtocol>(hostname.data(), port, y);
                                // DNS-resolved hosts must obey the same segment rules as IP literals.
                                if (NULLPTR != firewall && firewall->IsDropNetworkSegment(endpoint.address())) {
                                    return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                                }

                                return endpoint;
                            } catch (...) {
                                // DNS resolution failed; record error and return empty endpoint.
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        } else {
                            return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                        }
                    } else {
                        // it's a valid IP address �?apply network segment filter
                        if (NULLPTR != firewall) {
                            if (firewall->IsDropNetworkSegment(address)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        return boost::asio::ip::basic_endpoint<TProtocol>(address, port);
                    }
                }

                // -----------------------------------------------------------------
                // Read a 4‑byte DWORD (big‑endian) from the stream, advance pointer.
                // Returns 0 if not enough bytes.
                // -----------------------------------------------------------------
                /** @brief Reads a big-endian 32-bit integer from packet stream. */
                static int PACKET_Dword(Byte*& stream, int& packet_length) noexcept {
                    int remainder_length = packet_length - 4;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    // assemble big‑endian 32‑bit integer
                    int value = (stream[0] << 24) | (stream[1] << 16) | (stream[2] << 8) | stream[3];
                    stream += 4;
                    packet_length -= 4;
                    return value;
                }

                // -----------------------------------------------------------------
                // Write a 4‑byte DWORD (big‑endian) to a stream.
                // -----------------------------------------------------------------
                /** @brief Writes a big-endian 32-bit integer to stream. */
                static bool PACKET_Dword(Stream& stream, int value) noexcept {
                    Byte buf[4] = {
                        static_cast<Byte>(value >> 24),
                        static_cast<Byte>(value >> 16),
                        static_cast<Byte>(value >> 8),
                        static_cast<Byte>(value)
                    };
                    return stream.Write(buf, 0, sizeof(buf));
                }

                // -----------------------------------------------------------------
                // Read a 2‑byte WORD (big‑endian) from the stream, advance pointer.
                // -----------------------------------------------------------------
                /** @brief Reads a big-endian 16-bit integer from packet stream. */
                static int PACKET_Word(Byte*& stream, int& packet_length) noexcept {
                    int remainder_length = packet_length - 2;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int value = (stream[0] << 8) | stream[1];
                    stream += 2;
                    packet_length -= 2;
                    return value;
                }

                // -----------------------------------------------------------------
                // Write a 2‑byte WORD (big‑endian) to a stream.
                // -----------------------------------------------------------------
                /** @brief Writes a big-endian 16-bit integer to stream. */
                static bool PACKET_Word(Stream& stream, int value) noexcept {
                    Byte buf[2] = {
                        static_cast<Byte>(value >> 8),
                        static_cast<Byte>(value)
                    };
                    return stream.Write(buf, 0, sizeof(buf));
                }

                // -----------------------------------------------------------------
                // Read a 3‑byte connection ID (big‑endian) �?used in SYN/PSH/FIN.
                // -----------------------------------------------------------------
                /** @brief Reads a 3-byte connection identifier from packet stream. */
                static int PACKET_ConnectId(Byte*& stream, int& packet_length) noexcept {
                    /* wire: ACTION(1) CONNECT_ID(3) */
                    int remainder_length = packet_length - 3;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int connect_id = (stream[0] << 16) | (stream[1] << 8) | stream[2];
                    stream += 3;
                    packet_length -= 3;
                    return connect_id;
                }

                // -----------------------------------------------------------------
                // Write a packet header (action + 3‑byte connection ID) followed by payload.
                // -----------------------------------------------------------------
                /** @brief Writes action + 3-byte connection ID header with payload. */
                static bool PACKET_ConnectId(Stream& stream, PacketAction packet_action,
                                             int connection_id, Byte* packet, int packet_length) noexcept
                {
                    if (packet_length < 0 || (NULLPTR == packet && packet_length != 0)) {
                        return PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    }

                    Byte packet_header[4] = {
                        static_cast<Byte>(packet_action),
                        static_cast<Byte>(connection_id >> 16),
                        static_cast<Byte>(connection_id >> 8),
                        static_cast<Byte>(connection_id)
                    };

                    bool ok = stream.Write(packet_header, 0, sizeof(packet_header));
                    if (ok) {
                        ok = stream.Write(packet, 0, packet_length);
                    }

                    return PACKET_Result(ok, ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                }

                // -----------------------------------------------------------------
                // Send a packet with a given action and connection ID.
                // -----------------------------------------------------------------
                /** @brief Sends connection-bound packet through transport. */
                static bool PACKET_Push(PacketAction packet_action, const ITransmissionPtr& transmission,
                                        int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept
                {
                    if (NULLPTR == transmission) {
                        return PACKET_Fail(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    MemoryStream ms;
                    if (!PACKET_ConnectId(ms, packet_action, connection_id, packet, packet_length)) {
                        return PACKET_Result(false, ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    }

                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return PACKET_Result(transmission->Write(y, buffer.get(), ms.GetPosition()), ppp::diagnostics::ErrorCode::SocketWriteFailed);
                }

                // -----------------------------------------------------------------
                // Validate an endpoint �?port range, address type, no multicast/broadcast.
                // -----------------------------------------------------------------
                template <class TProtocol>
                /** @brief Validates protocol endpoint for protocol-level constraints. */
                static bool PACKET_IPEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept
                {
                    int destinationPort = destinationEP.port();
                    if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
                    if (destinationIP.is_v4() || destinationIP.is_v6()) {
                        if (destinationIP.is_unspecified()) {
                            return false;
                        }

                        if (destinationIP.is_multicast()) {
                            return false;
                        }

                        if (std::is_same<TProtocol, boost::asio::ip::tcp>::value) {
                            IPEndPoint ep = IPEndPoint::ToEndPoint(destinationEP);
                            if (ep.IsBroadcast()) {
                                return false;
                            }
                        }

                        return true;
                    }

                    return false;
                }

                // -----------------------------------------------------------------
                // Write an endpoint as (address string length, address string,
                // port string length, port string).
                // -----------------------------------------------------------------
                template <class TString>
                /** @brief Writes endpoint host/port string tuple to packet stream. */
                static bool PACKET_IPEndPoint(Stream& stream, const TString& address_string, int address_port) noexcept
                {
                    if (address_port <= IPEndPoint::MinPort || address_port > IPEndPoint::MaxPort) {
                        return false;
                    }

                    if (address_string.empty()) {
                        return false;
                    }

                    if (stream.WriteByte(static_cast<Byte>(address_string.size()))) {
                        if (stream.Write(address_string.data(), 0, static_cast<int>(address_string.size()))) {
                            char address_port_string[16];
                            int address_port_string_size = snprintf(address_port_string, sizeof(address_port_string),
                                                                     "%d", address_port);
                            if (address_port_string_size < 1 || address_port_string_size >= static_cast<int>(sizeof(address_port_string))) {
                                return false;   // truncation or error
                            }

                            // port length must fit into a single Byte (0�?55)
                            if (address_port_string_size > 255) {
                                return false;
                            }

                            if (stream.WriteByte(static_cast<Byte>(address_port_string_size))) {
                                return stream.Write(address_port_string, 0, address_port_string_size);
                            }
                        }
                    }

                    return false;
                }

                // -----------------------------------------------------------------
                // Write an endpoint from a boost::asio endpoint.
                // -----------------------------------------------------------------
                template <class TProtocol>
                /** @brief Writes a validated endpoint to packet stream. */
                static bool PACKET_IPEndPoint(Stream& stream, const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept
                {
                    if (!PACKET_IPEndPoint<TProtocol>(destinationEP)) {
                        return false;
                    }

                    return PACKET_IPEndPoint(stream, Ipep::ToAddressString<ppp::string>(destinationEP), destinationEP.port());
                }

                // -----------------------------------------------------------------
                // Send a TCP SYN (connect) packet.
                // -----------------------------------------------------------------
                /** @brief Builds and sends TCP connect request packet. */
                static bool PACKET_DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint* destinationEP, const ppp::string& hostname, int port, YieldContext& y) noexcept
                {
                    typedef VirtualEthernetLinklayer PacketAction;   // bring enum into scope
                    if (NULLPTR == transmission) {
                        return PACKET_Fail(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    if (connection_id == 0) {
                        return PACKET_Fail(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                    }

                    MemoryStream ms;
                    if (NULLPTR != destinationEP) {
                        if (!PACKET_IPEndPoint(ms, *destinationEP)) {
                            return PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                        }
                    } else {
                        if (!PACKET_IPEndPoint(ms, hostname, port)) {
                            return PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                        }
                    }

                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return PACKET_Push(PacketAction::PacketAction_SYN, transmission, connection_id,
                                       buffer.get(), ms.GetPosition(), y);
                }

                // -----------------------------------------------------------------
                // Send a simple action packet with raw payload (no connection ID).
                // -----------------------------------------------------------------
                /** @brief Sends action packet with raw payload and no connection ID. */
                static bool PACKET_Push(PacketAction packet_action, const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept
                {
                    if (NULLPTR == packet || packet_length < 1) {
                        return PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    }

                    if (NULLPTR == transmission) {
                        return PACKET_Fail(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    MemoryStream ms;
                    if (ms.WriteByte(static_cast<Byte>(packet_action))) {
                        if (ms.Write(packet, 0, packet_length)) {
                            std::shared_ptr<Byte> buffer = ms.GetBuffer();
                            return PACKET_Result(transmission->Write(y, buffer.get(), ms.GetPosition()), ppp::diagnostics::ErrorCode::SocketWriteFailed);
                        }
                    }

                    return PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                }
            } // namespace global

            // ---------------------------------------------------------------------
            // Constructor: initialises the link layer with configuration, context, and ID.
            // ---------------------------------------------------------------------
            /** @brief Constructs the link-layer runtime object. */
            VirtualEthernetLinklayer::VirtualEthernetLinklayer(
                const AppConfigurationPtr&  configuration,
                const ContextPtr&           context,
                const Int128&               id) noexcept
                : context_(context)
                , id_(id)
                , last_(Executors::GetTickCount())          // initialise last activity timestamp
                , next_ka_(0)                               // no keep‑alive scheduled yet
                , configuration_(configuration) {
            }

            // ---------------------------------------------------------------------
            // Generate a new unique 24‑bit connection ID using a lock‑free atomic.
            // Fixed: unsigned type, modulo always yields [1 .. max_aid], no overflow UB.
            // ---------------------------------------------------------------------
            /** @brief Generates a non-zero 24-bit connection ID. */
            int VirtualEthernetLinklayer::NewId() noexcept {
                static std::atomic<unsigned int> aid = static_cast<unsigned int>(RandomNext()); // random base, non‑negative
                static constexpr unsigned int max_aid = (1U << 24) - 1U;   // 0xFFFFFF = 16,777,215

                // fetch and increment, then take modulo to stay in 1..max_aid
                unsigned int raw_id = aid.fetch_add(1, std::memory_order_relaxed);
                unsigned int id = (raw_id % max_aid) + 1;   // +1 ensures never 0
                return static_cast<int>(id);                // safe, max fits in int
            }

            // ---------------------------------------------------------------------
            // Returns the firewall instance (default null; override in derived class).
            // ---------------------------------------------------------------------
            /** @brief Returns firewall instance used by inbound parser. */
            std::shared_ptr<ppp::net::Firewall> VirtualEthernetLinklayer::GetFirewall() noexcept {
                return NULLPTR;
            }

            // ---------------------------------------------------------------------
            // Main run loop: reads packets from the transmission and processes them.
            // Returns true if at least one packet was successfully processed.
            // ---------------------------------------------------------------------
            /** @brief Runs receive loop and dispatches inbound packets. */
            bool VirtualEthernetLinklayer::Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULLPTR == transmission) {
                    return global::PACKET_Fail(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                bool ok = false;
                last_ = Executors::GetTickCount();          // reset activity timer
                next_ka_ = 0;                               // reset keep‑alive scheduler

                ppp::telemetry::Log(Level::kInfo, "protocol", "session established");
                ppp::telemetry::Count("protocol.session.established", 1);

                for (;;) {
                    int packet_length = 0;
                    std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (NULLPTR == packet || packet_length < 1) {
                        ppp::telemetry::Log(Level::kInfo, "protocol", "session read_end error=%d",
                            (int)ppp::diagnostics::GetLastErrorCode());
                        break;                              // no more data or read error
                    }

                    if (!PacketInput(transmission, packet, packet.get(), packet_length, y)) {
                        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                        }
                        break;                              // packet processing failed -> exit
                    } else {
                        ok = true;
                        last_ = Executors::GetTickCount();  // update last activity on success
                    }
                }
                ppp::telemetry::Log(Level::kInfo, "protocol", "session disposed ok=%d error=%d",
                    ok ? 1 : 0,
                    (int)ppp::diagnostics::GetLastErrorCode());
                ppp::telemetry::Count("protocol.session.disposed", 1);
                return ok;
            }

            /** @brief Reads one complete INFO frame for pre-data proof exchanges. */
            bool VirtualEthernetLinklayer::ReadInformation(const ITransmissionPtr& transmission, InformationEnvelope& information, YieldContext& y) noexcept {
                if (NULLPTR == transmission) {
                    return global::PACKET_Fail(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                int packet_length = 0;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                if (NULLPTR == packet) {
                    return false;
                }

                if (!DecodeInformation(packet.get(), packet_length, information)) {
                    return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                }

                return true;
            }

#pragma pack(push, 1)   // ensure packed structures for wire compatibility
            // MUX request structure (includes action byte)
            typedef struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            {
                Byte        il;                 // action byte (PacketAction_MUX)
                uint16_t    vlan;               // VLAN ID (network order)
                uint16_t    max_connections;    // max concurrent connections (network order)
                Byte        acceleration;       // acceleration flag (0/1)
                Byte        ordering_caps;       // receiver ordering capability bits (bit0 = FLOW_V2); optional trailing byte
            } VirtualEthernetLinklayer_MUX_IL;

            // MUXON acknowledgment structure (includes action byte)
            typedef struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            {
                Byte        il;                 // action byte (PacketAction_MUXON)
                uint16_t    vlan;               // VLAN ID (network order)
                uint32_t    seq;                // sequence number (network order)
                uint32_t    ack;                // acknowledgment number (network order)
            } VirtualEthernetLinklayer_MUXON_IL;
#pragma pack(pop)

            // ---------------------------------------------------------------------
            // Process a single incoming packet from the transmission.
            // Dispatches based on the action byte.
            // ---------------------------------------------------------------------
            /**
             * @brief Decodes and dispatches one inbound protocol packet.
             * @details The first byte selects action; remaining payload is parsed by
             * action-specific wire-format readers before calling `On*` handlers.
             */
            bool VirtualEthernetLinklayer::PacketInput(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* p, int packet_length, YieldContext& y) noexcept
            {
                if (NULLPTR == p || packet_length < 1) {
                    return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                }

                // extract action byte and advance
                PacketAction packet_action = static_cast<PacketAction>(*p);
                ++p;
                --packet_length;

                // ---------- dispatch based on action ----------
                if (packet_action == PacketAction_PSH) {                // TCP data push
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0 && packet_length > 0) {
                        return OnPush(transmission, connection_id, p, packet_length, y);
                    }
                }
                elif (packet_action == PacketAction_NAT) {           // NAT data
                    if (packet_length > 0) {
                        return OnNat(transmission, p, packet_length, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_SENDTO) {        // UDP send‑to
                    ppp::string destinationHost;
                    boost::asio::ip::udp::endpoint destinationEP =
                        global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, destinationHost);

                    int destinationPort = destinationEP.port();
                    if (destinationPort > IPEndPoint::MinPort && destinationPort <= IPEndPoint::MaxPort) {
                        ppp::string sourceHost;
                        boost::asio::ip::udp::endpoint sourceEP =
                            global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, sourceHost);
                        if (sourceEP.port() != 0 && packet_length >= 0) {
                            // call preparation hook and then the actual send handler
                            if (OnPreparedSendTo(transmission, sourceHost, sourceEP, destinationHost, destinationEP, p, packet_length, y)) {
                                return OnSendTo(transmission, sourceEP, destinationEP, owner, p, packet_length, y);
                            }
                        }
                    }
                    // fall through -> failure
                }
                elif (packet_action == PacketAction_FRP_PUSH) {      // FRP data push
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0 && packet_length > 0) {
                                return OnFrpPush(transmission, connection_id, in, remote_port, owner, p, packet_length);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_FRP_SENDTO) {    // FRP UDP send‑to
                    ppp::string destinationHost;
                    boost::asio::ip::udp::endpoint destinationEP =
                        global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, destinationHost);
                    if (destinationEP.port() != 0 && packet_length > 0) {
                        bool in = (*p != 0);
                        ++p;
                        --packet_length;

                        int remote_port = global::PACKET_Word(p, packet_length);
                        if (remote_port != 0 && packet_length > 0) {
                            return OnFrpSendTo(transmission, in, remote_port, destinationEP, owner, p, packet_length, y);
                        }
                    }
                }
                elif (packet_action == PacketAction_ECHO) {          // echo request
                    if (packet_length > 0) {
                        ppp::telemetry::Log(Level::kDebug, "protocol", "ECHO received");
                        ppp::telemetry::Count("protocol.echo.received", 1);
                        return OnEcho(transmission, owner, p, packet_length, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_ECHOACK) {       // echo reply
                    if (packet_length >= 3) {
                        int ack_id = global::PACKET_ConnectId(p, packet_length);
                        ppp::telemetry::Log(Level::kDebug, "protocol", "ECHOACK received ack_id=%d", ack_id);
                        ppp::telemetry::Count("protocol.echoack.received", 1);
                        return OnEcho(transmission, ack_id, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_SYN) {           // TCP connection request
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0) {
                        ppp::string destinationHost;
                        boost::asio::ip::tcp::endpoint destinationEP =
                            global::PACKET_IPEndPoint<boost::asio::ip::tcp>(GetFirewall(), p, packet_length, y, destinationHost);
                        if (destinationEP.port() != 0) {
                            if (OnPreparedConnect(transmission, connection_id, destinationHost, destinationEP, y)) {
                                return OnConnect(transmission, connection_id, destinationEP, y);
                            }
                        }
                    }
                }
                elif (packet_action == PacketAction_SYNOK) {         // TCP connection acknowledgment
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0 && packet_length > 0) {
                        Byte error_code = *p;
                        ++p;
                        return OnConnectOK(transmission, connection_id, error_code, y);
                    }
                }
                elif (packet_action == PacketAction_FIN) {           // TCP disconnection
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0) {
                        return OnDisconnect(transmission, connection_id, y);
                    }
                }
                elif (packet_action == PacketAction_LAN) {           // LAN advertisement
                    if (packet_length >= static_cast<int>(sizeof(uint32_t) * 2)) {
                        uint32_t address = 0;
                        uint32_t mask = 0;
                        std::memcpy(&address, p, sizeof(address));
                        std::memcpy(&mask, p + sizeof(address), sizeof(mask));
                        return OnLan(transmission, address, mask, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_FRP_DISCONNECT) { // FRP disconnection
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0) {
                                return OnFrpDisconnect(transmission, connection_id, in, remote_port);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_FRP_CONNECT) {    // FRP connection request
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            if (packet_length > 0) {
                                int remote_port = global::PACKET_Word(p, packet_length);
                                if (remote_port != 0) {
                                    return OnFrpConnect(transmission, connection_id, in, remote_port, y);
                                }
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_FRP_CONNECTOK) {  // FRP connection acknowledgment
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0 && packet_length > 0) {
                                Byte error_code = *p;
                                ++p;
                                --packet_length;
                                return OnFrpConnectOK(transmission, connection_id, in, remote_port, error_code, y);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_INFO) {           // Virtual Ethernet information
                    ppp::string session_guid = ppp::auxiliary::StringAuxiliary::Int128ToGuidString(id_);
                    ppp::telemetry::SpanScope span("protocol.auth", session_guid.c_str());

                    InformationEnvelope info;
                    if (!DecodeInformation(p - 1, packet_length + 1, info)) {
                        return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    }

                    ppp::telemetry::Log(Level::kDebug, "protocol", "INFO received bandwidth_qos=%lld incoming=%llu outgoing=%llu",
                                        static_cast<long long>(info.Base.BandwidthQoS),
                                        static_cast<unsigned long long>(info.Base.IncomingTraffic),
                                        static_cast<unsigned long long>(info.Base.OutgoingTraffic));
                    ppp::telemetry::Count("protocol.info.received", 1);
                    ppp::telemetry::Count("protocol.auth.success", 1);
                    ppp::telemetry::Count("protocol.bandwidth.received", 1);
                    return OnInformation(transmission, static_cast<const InformationEnvelope&>(info), y);
                }
                elif (packet_action == PacketAction_FRP_ENTRY) {      // FRP entry registration
                    if (packet_length > 0) {
                        bool tcp = (*p != 0);
                        ++p;
                        --packet_length;

                        if (packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0) {
                                return OnFrpEntry(transmission, tcp, in, remote_port, y);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_STATIC) {         // static route request
                    ppp::telemetry::Log(Level::kDebug, "protocol", "STATIC received");
                    ppp::telemetry::Count("protocol.static.received", 1);
                    return OnStatic(transmission, y);
                }
                elif (packet_action == PacketAction_STATICACK) {      // static route acknowledgment (single entry)
                    int session_id = global::PACKET_Dword(p, packet_length);
                    if (packet_length >= (2 + 16)) {    // need remote_port (2) + fsid (16)
                        int remote_port = global::PACKET_Word(p, packet_length);
                        if (packet_length >= 16) {      // ensure 16 bytes for fsid remain
                            // SAFE: copy via memcpy to avoid alignment issues
                            boost::uuids::uuid uuid_buf;
                            std::memcpy(&uuid_buf, p, sizeof(uuid_buf));

                            Int128 fsid = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(uuid_buf);
                            ppp::telemetry::Log(Level::kDebug, "protocol", "STATICACK received session_id=%d remote_port=%d", session_id, remote_port);
                            ppp::telemetry::Count("protocol.staticack.received", 1);
                            return OnStatic(transmission, fsid, session_id, remote_port, y);
                        }
                    }
                    return false;
                }
                elif (packet_action == PacketAction_MUX) {            // MUX setup request
                    // Required length covers every field except the action byte `il`
                    // AND except the optional trailing ordering_caps byte, so that
                    // older peers (which never send ordering_caps) still parse.
                    static constexpr int MUX_IL_REFT = sizeof(VirtualEthernetLinklayer_MUX_IL) - 1 - (int)sizeof(Byte);

                    if (packet_length >= MUX_IL_REFT) {
                        VirtualEthernetLinklayer_MUX_IL* pil = reinterpret_cast<VirtualEthernetLinklayer_MUX_IL*>(p - 1);

                        // ordering_caps is an optional trailing byte; absent (older peer) => 0 (=COMPAT).
                        // packet_length excludes the leading action byte, so the full struct on the
                        // wire is present only when packet_length >= sizeof(struct) - 1.
                        Byte ordering_caps = 0;
                        if (packet_length >= (int)(sizeof(VirtualEthernetLinklayer_MUX_IL) - 1)) {
                            ordering_caps = pil->ordering_caps;
                        }

                        ppp::telemetry::Log(Level::kDebug, "protocol", "MUX received vlan=%u max_connections=%u caps=%u",
                                            static_cast<unsigned int>(ntohs(pil->vlan)),
                                            static_cast<unsigned int>(ntohs(pil->max_connections)),
                                            static_cast<unsigned int>(ordering_caps));
                        ppp::telemetry::Count("protocol.mux.received", 1);
                        return global::PACKET_Result(OnMux(transmission, ntohs(pil->vlan), ntohs(pil->max_connections),
                                     pil->acceleration != 0, ordering_caps, y), ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_MUXON) {          // MUXON acknowledgment
                    static constexpr int MUXON_IL_REF = sizeof(VirtualEthernetLinklayer_MUXON_IL) - 1;

                    if (packet_length >= MUXON_IL_REF) {
                        VirtualEthernetLinklayer_MUXON_IL* pil = reinterpret_cast<VirtualEthernetLinklayer_MUXON_IL*>(p - 1);
                        ppp::telemetry::Log(Level::kDebug, "protocol", "MUXON received vlan=%u seq=%u ack=%u",
                                            static_cast<unsigned int>(ntohs(pil->vlan)),
                                            static_cast<unsigned int>(ntohl(pil->seq)),
                                            static_cast<unsigned int>(ntohl(pil->ack)));
                        ppp::telemetry::Count("protocol.muxon.received", 1);
                        return global::PACKET_Result(OnMuxON(transmission, ntohs(pil->vlan), ntohl(pil->seq), ntohl(pil->ack), y), ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                    } else {
                        return packet_length == 0;
                    }
                }
                elif (packet_action == PacketAction_KEEPALIVED) {     // keep‑alive heartbeat
                    last_ = Executors::GetTickCount();   // update last activity time
                    return true;
                }

                if (global::PACKET_IsKnownAction(packet_action)) {
                    return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                }

                return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
            }

            // ---------------------------------------------------------------------
            // Send a keep‑alive packet if the idle timeout has been reached.
            // Returns false only when the connection should be considered dead.
            // ---------------------------------------------------------------------
            /** @brief Schedules and sends keep-alive packets based on idle timing. */
            bool VirtualEthernetLinklayer::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                static constexpr int MAX_RANDOM_BUFFER_SIZE = ppp::tap::ITap::Mtu;
                static constexpr int MILLISECONDS_TO_SECONDS = 1000;
                static constexpr int MIN_TIMEOUT_SECONDS = 5;
                static constexpr int EXTRA_FAULT_TOLERANT_TIME = MIN_TIMEOUT_SECONDS * MILLISECONDS_TO_SECONDS;

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    return false;
                }

                // calculate maximum idle timeout in milliseconds
                const int max_timeout_sec = std::max(MIN_TIMEOUT_SECONDS,
                    std::min(configuration->tcp.connect.timeout << 1, configuration->tcp.inactive.timeout));
                const int max_timeout_ms = max_timeout_sec * MILLISECONDS_TO_SECONDS;

                uint64_t deadline = last_ + static_cast<uint64_t>(max_timeout_ms + EXTRA_FAULT_TOLERANT_TIME);
                if (now >= deadline) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketTimeout);
                    return false;   // idle timeout exceeded -> dead connection
                }

                uint64_t next_ka = next_ka_;
                if (next_ka == 0) {
                    // first time: schedule a random delay within [1s, max_timeout_ms]
                    int delay_ms = RandomNext(1000, max_timeout_ms);
                    next_ka = now + static_cast<uint64_t>(delay_ms);
                    next_ka_ = next_ka;
                }

                if (NULLPTR == transmission || now < next_ka) {
                    return true;    // not yet time to send keep‑alive
                }

                // generate random payload (printable ASCII) to avoid predictable patterns
                Byte packet[MAX_RANDOM_BUFFER_SIZE];
                int packet_size = RandomNext(1, MAX_RANDOM_BUFFER_SIZE);
                for (int i = 0; i < packet_size; ++i) {
                    packet[i] = static_cast<Byte>(RandomNext(0x20, 0x7E)); // printable range
                }

                YieldContext& y_null = nullof<YieldContext>();   // dummy yield context for synchronous send
                if (!global::PACKET_Push(PacketAction_KEEPALIVED, transmission, packet, packet_size,
                                         y_null /* no coroutine context */)) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    }
                    return false;   // failed to send keep‑alive
                }

                // schedule next keep‑alive with a new random interval
                int next_delay_ms = RandomNext(1000, max_timeout_ms);
                next_ka_ = now + static_cast<uint64_t>(next_delay_ms);
                return true;
            }

            // ---------------------------------------------------------------------
            // Send a LAN advertisement packet (IP + netmask).
            // ---------------------------------------------------------------------
            /** @brief Sends LAN advertisement payload. */
            bool VirtualEthernetLinklayer::DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept
            {
                uint32_t addresses[] = { ip, mask };
                return global::PACKET_Push(PacketAction_LAN, transmission,
                                           reinterpret_cast<Byte*>(addresses), sizeof(addresses), y);
            }

            // ---------------------------------------------------------------------
            // Send a NAT data packet.
            // ---------------------------------------------------------------------
            /** @brief Sends NAT packet payload. */
            bool VirtualEthernetLinklayer::DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_NAT, transmission, packet, packet_length, y);
            }

            // ---------------------------------------------------------------------
            // Send virtual Ethernet information structure (converted to network byte order).
            // ---------------------------------------------------------------------
            /** @brief Sends base information payload. */
            bool VirtualEthernetLinklayer::DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                InformationEnvelope envelope;
                envelope.Base = information;
                return DoInformation(transmission, envelope, y);
            }

            /** @brief Sends extended information envelope. */
            bool VirtualEthernetLinklayer::DoInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept {
                VirtualEthernetInformation info = information.Base;

                // convert host byte order to network byte order for transmission
                info.BandwidthQoS    = ppp::net::Ipep::HostToNetworkOrder(info.BandwidthQoS);
                info.ExpiredTime     = htonl(info.ExpiredTime);
                info.IncomingTraffic = ppp::net::Ipep::HostToNetworkOrder(info.IncomingTraffic);
                info.OutgoingTraffic = ppp::net::Ipep::HostToNetworkOrder(info.OutgoingTraffic);

                MemoryStream ms;
                if (!ms.Write(&info, 0, sizeof(info))) {
                    return false;
                }

                ppp::string extended = information.ExtendedJson;
                if (extended.empty() && information.Extensions.HasAny()) {
                    extended = information.Extensions.ToJson();
                }

                if (!extended.empty()) {
                    if (!ms.Write(extended.data(), 0, static_cast<int>(extended.size()))) {
                        return false;
                    }
                }

                ppp::telemetry::Log(Level::kDebug, "protocol", "INFO sent bandwidth_qos=%lld incoming=%llu outgoing=%llu",
                                    static_cast<long long>(info.BandwidthQoS),
                                    static_cast<unsigned long long>(info.IncomingTraffic),
                                    static_cast<unsigned long long>(info.OutgoingTraffic));
                ppp::telemetry::Count("protocol.info.sent", 1);
                ppp::telemetry::Count("protocol.bandwidth.sent", 1);

                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                return global::PACKET_Push(PacketAction_INFO, transmission, buffer.get(), ms.GetPosition(), y);
            }

            // ---------------------------------------------------------------------
            // Send a TCP connection request using an endpoint.
            // ---------------------------------------------------------------------
            /** @brief Sends connect request using destination endpoint. */
            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept
            {
                return global::PACKET_DoConnect(transmission, connection_id, &destinationEP,
                                                ppp::string(), IPEndPoint::MinPort, y);
            }

            // ---------------------------------------------------------------------
            // Send a TCP connection request using hostname and port.
            // ---------------------------------------------------------------------
            /** @brief Sends connect request using host text and port. */
            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept
            {
                return global::PACKET_DoConnect(transmission, connection_id, NULLPTR, hostname, port, y);
            }

            // ---------------------------------------------------------------------
            // Send a TCP connection acknowledgment with error code.
            // ---------------------------------------------------------------------
            /** @brief Sends connect acknowledgment with error code. */
            bool VirtualEthernetLinklayer::DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept
            {
                return global::PACKET_Push(PacketAction_SYNOK, transmission, connection_id,
                                           &error_code, sizeof(error_code), y);
            }

            // ---------------------------------------------------------------------
            // Send TCP data push on a connection.
            // ---------------------------------------------------------------------
            /** @brief Sends stream payload on established connection. */
            bool VirtualEthernetLinklayer::DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_PSH, transmission, connection_id,
                                           packet, packet_length, y);
            }

            // ---------------------------------------------------------------------
            // Send TCP disconnection notification (FIN).
            // ---------------------------------------------------------------------
            /** @brief Sends connection close notification. */
            bool VirtualEthernetLinklayer::DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept
            {
                return global::PACKET_Push(PacketAction_FIN, transmission, connection_id, NULLPTR, 0, y);
            }

            // Maximum binary frame size that is safe to emit when key.plaintext is enabled.
            //
            // In plaintext mode every transmission frame is wrapped in a base94 envelope
            // (see ITransmissionBridge::Encrypt).  ssea::base94_encode can expand the binary
            // payload by up to 2x in the worst case, so the binary frame must stay at or below
            // PPP_BUFFER_SIZE/2 (minus the small frame header) to guarantee the encoded frame
            // does not exceed PPP_BUFFER_SIZE on the receiver.  TCP and vmux read paths cap
            // their socket reads to the same bound; UDP datagrams cannot be split without
            // breaking datagram boundaries, so an oversized datagram is dropped instead.
            static constexpr int kPlaintextBase94MaxBinaryFrame = (PPP_BUFFER_SIZE / 2) - 3;

            // ---------------------------------------------------------------------
            // Send a UDP datagram with source and destination endpoints.
            // ---------------------------------------------------------------------
            /** @brief Sends UDP payload with source and destination endpoint metadata. */
            bool VirtualEthernetLinklayer::DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept
            {
                if (NULLPTR == packet && packet_length != 0) {
                    return false;
                }

                if (packet_length < 0) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_SENDTO))) {
                    if (global::PACKET_IPEndPoint(ms, destinationEP)) {
                        if (global::PACKET_IPEndPoint(ms, sourceEP)) {
                            if (ms.Write(packet, 0, packet_length)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                int frame_length = ms.GetPosition();

                                // In plaintext mode the frame is base94-wrapped before transport.
                                // A frame that would expand past PPP_BUFFER_SIZE on the receiver is
                                // rejected there with ProtocolFrameInvalid, which tears down the whole
                                // transmission (Read returns null -> Dispose).  UDP has no MTU contract
                                // here and cannot be split, so silently drop the oversized datagram and
                                // report success: a single lost datagram is normal UDP behaviour and far
                                // less harmful than collapsing the tunnel.
                                if (frame_length > kPlaintextBase94MaxBinaryFrame) {
                                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                                    if (NULLPTR != configuration && configuration->key.plaintext) {
                                        ppp::telemetry::Log(Level::kInfo,
                                            "linklayer",
                                            "drop oversized plaintext UDP datagram frame_length=%d max=%d",
                                            frame_length,
                                            kPlaintextBase94MaxBinaryFrame);
                                        return true;
                                    }
                                }

                                return transmission->Write(y, buffer.get(), frame_length);
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send an echo reply (acknowledgment).
            // ---------------------------------------------------------------------
            /** @brief Sends echo acknowledgment by connection-style ID field. */
            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept
            {
                ppp::telemetry::Log(Level::kDebug, "protocol", "ECHOACK sent ack_id=%d", ack_id);
                ppp::telemetry::Count("protocol.echoack.sent", 1);
                return global::PACKET_Push(PacketAction_ECHOACK, transmission, ack_id, NULLPTR, 0, y);
            }

            // ---------------------------------------------------------------------
            // Send an echo request with payload.
            // ---------------------------------------------------------------------
            /** @brief Sends echo payload packet. */
            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept
            {
                // In plaintext mode the frame is base94-wrapped before transport and may expand
                // by up to 2x.  An ICMP echo payload large enough to exceed PPP_BUFFER_SIZE after
                // encoding would be rejected by the peer and collapse the whole transmission.
                // Echo is a datagram-style message, so drop the oversized one (report success)
                // rather than tearing down the tunnel.  See DoSendTo for the same rationale.
                if (NULLPTR != packet && packet_length > kPlaintextBase94MaxBinaryFrame) {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    if (NULLPTR != configuration && configuration->key.plaintext) {
                        ppp::telemetry::Log(Level::kInfo,
                            "protocol",
                            "drop oversized plaintext ECHO packet packet_length=%d max=%d",
                            packet_length,
                            kPlaintextBase94MaxBinaryFrame);
                        return true;
                    }
                }

                ppp::telemetry::Log(Level::kDebug, "protocol", "ECHO sent");
                ppp::telemetry::Count("protocol.echo.sent", 1);
                return global::PACKET_Push(PacketAction_ECHO, transmission, packet, packet_length, y);
            }

            // ---------------------------------------------------------------------
            // Request static route information.
            // ---------------------------------------------------------------------
            /** @brief Sends static-route request packet. */
            bool VirtualEthernetLinklayer::DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_STATIC))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    ppp::telemetry::Log(Level::kDebug, "protocol", "STATIC sent");
                    ppp::telemetry::Count("protocol.static.sent", 1);
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Respond with static route information for a specific session.
            // Fixed: use memcpy for alignment‑safe UUID conversion.
            // ---------------------------------------------------------------------
            /** @brief Sends static-route acknowledgment payload. */
            bool VirtualEthernetLinklayer::DoStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_STATICACK))) {
                    if (global::PACKET_Dword(ms, session_id)) {
                        if (global::PACKET_Word(ms, remote_port)) {
                            // safely copy Int128 into a uuid buffer (avoids alignment UB)
                            boost::uuids::uuid uuid_buf;
                            std::memcpy(&uuid_buf, &fsid, sizeof(uuid_buf));

                            Int128 fsid_netbuf = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(uuid_buf);
                            if (ms.Write(&fsid_netbuf, 0, sizeof(fsid_netbuf))) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                ppp::telemetry::Log(Level::kDebug, "protocol", "STATICACK sent session_id=%d remote_port=%d", session_id, remote_port);
                                ppp::telemetry::Count("protocol.staticack.sent", 1);
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send MUX setup request.
            // ---------------------------------------------------------------------
            /** @brief Sends MUX setup request packet. */
            bool VirtualEthernetLinklayer::DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept
            {
                MemoryStream ms;
                VirtualEthernetLinklayer_MUX_IL data;
                data.il               = static_cast<Byte>(PacketAction_MUX);
                data.vlan             = htons(vlan);
                data.max_connections  = htons(max_connections);
                data.acceleration     = acceleration ? 1 : 0;
                data.ordering_caps    = ordering_caps;

                if (ms.Write(&data, 0, sizeof(data))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    ppp::telemetry::Log(Level::kDebug, "protocol", "MUX sent vlan=%u max_connections=%u caps=%u",
                                        static_cast<unsigned int>(vlan), static_cast<unsigned int>(max_connections),
                                        static_cast<unsigned int>(ordering_caps));
                    ppp::telemetry::Count("protocol.mux.sent", 1);
                    return global::PACKET_Result(transmission->Write(y, buffer.get(), ms.GetPosition()), ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                }

                return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
            }

            // ---------------------------------------------------------------------
            // Send MUXON acknowledgment.
            // ---------------------------------------------------------------------
            /** @brief Sends MUX setup acknowledgment packet. */
            bool VirtualEthernetLinklayer::DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept
            {
                MemoryStream ms;
                VirtualEthernetLinklayer_MUXON_IL data;
                data.il   = static_cast<Byte>(PacketAction_MUXON);
                data.vlan = htons(vlan);
                data.seq  = htonl(seq);
                data.ack  = htonl(ack);

                if (ms.Write(&data, 0, sizeof(data))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    ppp::telemetry::Log(Level::kDebug, "protocol", "MUXON sent vlan=%u seq=%u ack=%u",
                                        static_cast<unsigned int>(vlan), static_cast<unsigned int>(seq), static_cast<unsigned int>(ack));
                    ppp::telemetry::Count("protocol.muxon.sent", 1);
                    return global::PACKET_Result(transmission->Write(y, buffer.get(), ms.GetPosition()), ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                }

                return global::PACKET_Fail(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
            }

            // ---------------------------------------------------------------------
            // Send FRP entry registration.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP entry registration packet. */
            bool VirtualEthernetLinklayer::DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_ENTRY))) {
                    Byte b = tcp ? 1 : 0;
                    if (ms.WriteByte(b)) {
                        b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP UDP datagram.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP UDP payload packet. */
            bool VirtualEthernetLinklayer::DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_SENDTO))) {
                    if (global::PACKET_IPEndPoint(ms, sourceEP)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.Write(packet, 0, packet_length)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP connection request.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP connect request packet. */
            bool VirtualEthernetLinklayer::DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_CONNECT))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP connection acknowledgment.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP connect acknowledgment packet. */
            bool VirtualEthernetLinklayer::DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_CONNECTOK))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.WriteByte(error_code)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP disconnection notification.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP disconnect packet. */
            bool VirtualEthernetLinklayer::DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_DISCONNECT))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP data push.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP stream data packet. */
            bool VirtualEthernetLinklayer::DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet,  int packet_length, YieldContext& y) noexcept
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_PUSH))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.Write(packet, 0, packet_length)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }

                return false;
            }
        }
    }
}
