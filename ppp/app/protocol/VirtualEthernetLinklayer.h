// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetLinklayer.h
 * @brief Virtual Ethernet link-layer protocol definitions and dispatch interface.
 */

#pragma once

namespace ppp::configurations { class AppConfiguration; }

#include <ppp/Int128.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/Ipep.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

#include <cstring>

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Address encoding type used by packet endpoint fields.
             *
             * Identifies the wire format used to encode the remote host address
             * in connect and send-to protocol frames.
             */
            enum AddressType {
                None                                                        = 0,    ///< No address; endpoint is unspecified.
                IPv4                                                        = 1,    ///< 4-byte IPv4 address in network byte order.
                IPv6                                                        = 2,    ///< 16-byte IPv6 address in network byte order.
                Domain                                                      = 3,    ///< Length-prefixed ASCII/UTF-8 domain name.
            };

            /**
             * @brief Logical endpoint containing address type, host text, and port.
             *
             * Used as a decoded representation after parsing a connect or send-to
             * frame; carries the resolved address family together with host string
             * and port number before socket operations begin.
             */
            struct AddressEndPoint {
                AddressType                                                 Type = AddressType::None;   ///< Wire address format of the host field.
                ppp::string                                                 Host;                        ///< Host text: dotted-decimal, colon-hex, or domain string.
                int                                                         Port = 0;                   ///< Destination port in host byte order.
            };

            /**
             * @brief Virtual Ethernet packet codec and dispatcher.
             *
             * This class serializes outbound protocol frames and parses inbound frames,
             * then dispatches parsed events through overridable `On*` handlers.
             */
            class VirtualEthernetLinklayer : public std::enable_shared_from_this<VirtualEthernetLinklayer> {
            public:
                /** @brief Full information payload including optional extension JSON. */
                struct                                                    InformationEnvelope {
                    VirtualEthernetInformation                            Base;
                    VirtualEthernetInformationExtensions                  Extensions;
                    ppp::string                                           ExtendedJson;
                };

            public:
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                   ITransmission;
                typedef std::shared_ptr<ITransmission>                      ITransmissionPtr;
                typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
                typedef ppp::coroutines::YieldContext                       YieldContext;

            public:
                /** @brief Virtual Ethernet protocol action opcodes.
                 *
                 * Each value identifies one protocol message type in the link-layer
                 * frame header, driving the dispatch table inside `PacketInput`.
                 */
                typedef enum {
                    PacketAction_INFO                                       = 0x7E,   ///< Session information / quota exchange frame.
                    PacketAction_KEEPALIVED                                 = 0x7F,   ///< Periodic keep-alive heartbeat frame.
                    PacketAction_FRP_ENTRY                                  = 0x20,   ///< FRP: register a port mapping entry.
                    PacketAction_FRP_CONNECT                                = 0x21,   ///< FRP: open a new tunneled connection.
                    PacketAction_FRP_CONNECTOK                              = 0x22,   ///< FRP: acknowledgment for connection open.
                    PacketAction_FRP_PUSH                                   = 0x23,   ///< FRP: stream payload data.
                    PacketAction_FRP_DISCONNECT                             = 0x24,   ///< FRP: notify connection closure.
                    PacketAction_FRP_SENDTO                                 = 0x25,   ///< FRP: UDP datagram delivery.
                    PacketAction_LAN                                        = 0x28,   ///< LAN subnet advertisement (ip + mask).
                    PacketAction_NAT                                        = 0x29,   ///< Raw IP/NAT payload forwarding.
                    PacketAction_SYN                                        = 0x2A,   ///< TCP connect request.
                    PacketAction_SYNOK                                      = 0x2B,   ///< TCP connect acknowledgment.
                    PacketAction_PSH                                        = 0x2C,   ///< TCP stream payload data.
                    PacketAction_FIN                                        = 0x2D,   ///< TCP connection teardown notification.
                    PacketAction_SENDTO                                     = 0x2E,   ///< UDP datagram with endpoint descriptors.
                    PacketAction_ECHO                                       = 0x2F,   ///< Echo request (latency probe) payload.
                    PacketAction_ECHOACK                                    = 0x30,   ///< Echo acknowledgment by ID.
                    PacketAction_STATIC                                     = 0x31,   ///< Static port mapping query.
                    PacketAction_STATICACK                                  = 0x32,   ///< Static port mapping acknowledgment.
                    PacketAction_MUX                                        = 0x35,   ///< MUX channel setup request.
                    PacketAction_MUXON                                      = 0x36,   ///< MUX channel setup acknowledgment.
                }                                                           PacketAction;

            public:
                /** @brief Error codes returned by connect acknowledgment actions. */
                typedef enum {
                    ERRORS_SUCCESS,                 ///< Connection established successfully.
                    ERRORS_CONNECT_TO_DESTINATION,  ///< Failed to reach the remote destination host.
                    ERRORS_CONNECT_CANCEL,          ///< Connection was cancelled by local or remote policy.
                }                                                           ERROR_CODES;

            public:
                /**
                 * @brief Constructs a link-layer handler.
                 * @param configuration Application configuration object.
                 * @param context IO context used by asynchronous operations.
                 * @param id Session identifier associated with this handler.
                 */
                VirtualEthernetLinklayer(
                    const AppConfigurationPtr&                              configuration, 
                    const ContextPtr&                                       context,
                    const Int128&                                           id) noexcept;
                /** @brief Virtual destructor. */
                virtual ~VirtualEthernetLinklayer() noexcept = default;

            public:
                /** @brief Returns `shared_from_this()` for this object. */
                std::shared_ptr<VirtualEthernetLinklayer>                   GetReference() noexcept     { return shared_from_this(); }
                /** @brief Returns the associated IO context. */
                ContextPtr                                                  GetContext() noexcept       { return context_; }
                /** @brief Returns the configuration object. */
                AppConfigurationPtr&                                        GetConfiguration() noexcept { return configuration_; }
                /** @brief Returns the session identifier for this link layer. */
                Int128                                                      GetId() noexcept            { return id_; }

            public:
                /**
                 * @brief Processes incoming packets until read/parse failure.
                 * @param transmission Active transport channel.
                 * @param y Coroutine yield context.
                 * @return `true` when at least one packet is processed successfully.
                 */
                virtual bool                                                Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /**
                 * @brief Strictly decodes one complete INFO frame without dispatching it.
                 * @param packet Complete link-layer frame, including its action byte.
                 * @param packet_length Complete frame length.
                 * @param information Receives the base information and parsed extensions.
                 * @return `true` only for a complete INFO frame with valid extension JSON.
                 */
                static bool                                                 DecodeInformation(const Byte* packet, int packet_length, InformationEnvelope& information) noexcept {
                    InformationEnvelope decoded;
                    const int fixed_length = 1 + static_cast<int>(sizeof(VirtualEthernetInformation));
                    if (NULLPTR == packet || packet_length < fixed_length ||
                        packet[0] != static_cast<Byte>(PacketAction_INFO)) {
                        return false;
                    }

                    std::memcpy(&decoded.Base, packet + 1, sizeof(decoded.Base));
                    decoded.Base.BandwidthQoS = ppp::net::Ipep::NetworkToHostOrder(decoded.Base.BandwidthQoS);
                    decoded.Base.ExpiredTime = ntohl(decoded.Base.ExpiredTime);
                    decoded.Base.IncomingTraffic = ppp::net::Ipep::NetworkToHostOrder(decoded.Base.IncomingTraffic);
                    decoded.Base.OutgoingTraffic = ppp::net::Ipep::NetworkToHostOrder(decoded.Base.OutgoingTraffic);

                    const int extension_length = packet_length - fixed_length;
                    if (extension_length > 0) {
                        decoded.ExtendedJson.assign(
                            reinterpret_cast<const char*>(packet + fixed_length), extension_length);
                        try {
                            Json::CharReaderBuilder builder;
                            Json::CharReaderBuilder::strictMode(&builder.settings_);
                            builder["collectComments"] = false;
                            std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
                            Json::Value json;
                            Json::String errors;
                            if (!reader || !reader->parse(
                                    decoded.ExtendedJson.data(),
                                    decoded.ExtendedJson.data() + decoded.ExtendedJson.size(),
                                    &json, &errors) ||
                                !json.isObject() ||
                                !VirtualEthernetInformationExtensions::FromJson(decoded.Extensions, json)) {
                                return false;
                            }
                        }
                        catch (...) {
                            return false;
                        }
                    }

                    information = std::move(decoded);
                    return true;
                }
                /**
                 * @brief Reads and strictly decodes exactly one INFO frame without dispatch.
                 * @param transmission Pre-data transport channel.
                 * @param information Receives the decoded INFO envelope.
                 * @param y Coroutine yield context.
                 */
                static bool                                                 ReadInformation(const ITransmissionPtr& transmission, InformationEnvelope& information, YieldContext& y) noexcept;
                /** @brief Generates a protocol connection ID in 24-bit range. */
                static int                                                  NewId() noexcept;

            public:
                /** @brief Sends a LAN advertisement packet. */
                virtual bool                                                DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept;
                /** @brief Sends a NAT frame payload. */
                virtual bool                                                DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends base information payload. */
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept;
                /** @brief Sends information envelope with optional extension data. */
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept;
                /** @brief Sends TCP payload for an existing connection. */
                virtual bool                                                DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends TCP connect request using domain/host text. */
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept;
                /** @brief Sends TCP connect request using resolved endpoint. */
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept;
                /** @brief Sends TCP connect acknowledgment with status code. */
                virtual bool                                                DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept;
                /** @brief Sends TCP disconnect notification. */
                virtual bool                                                DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept;
                /** @brief Sends echo acknowledgment by ID. */
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept;
                /** @brief Sends echo payload packet. */
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends UDP payload with destination/source endpoint descriptors. */
                virtual bool                                                DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Requests static mapping information from peer. */
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Sends static mapping acknowledgment payload. */
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept;

            public:
                /** @brief Sends MUX setup request. */
                virtual bool                                                DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept;
                /** @brief Sends MUX setup acknowledgment. */
                virtual bool                                                DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept;

            protected:
                /** @brief Handles inbound MUX request. */
                virtual bool                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept { return false; }
                /** @brief Handles inbound MUX acknowledgment. */
                virtual bool                                                OnMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept { return false; }

            public:
                /** @brief Sends FRP mapping entry registration. */
                virtual bool                                                DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept;
                /** @brief Sends FRP UDP payload. */
                virtual bool                                                DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends FRP connect request. */
                virtual bool                                                DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                /** @brief Sends FRP connect acknowledgment. */
                virtual bool                                                DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept;
                /** @brief Sends FRP disconnect notification. */
                virtual bool                                                DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                /** @brief Sends FRP stream payload. */
                virtual bool                                                DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                /** @brief Handles inbound FRP entry registration. */
                virtual bool                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP UDP payload. */
                virtual bool                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP connect request. */
                virtual bool                                                OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP connect acknowledgment. */
                virtual bool                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP disconnect notification. */
                virtual bool                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept { return true; }
                /** @brief Handles inbound FRP stream payload. */
                virtual bool                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept { return true; }

            protected:
                /** @brief Handles inbound LAN advertisement. */
                virtual bool                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound NAT payload. */
                virtual bool                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound base information payload. */
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound information envelope payload. */
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept { return OnInformation(transmission, information.Base, y); }
                /** @brief Handles inbound TCP stream payload. */
                virtual bool                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound TCP connect request. */
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound connect acknowledgment. */
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound disconnect event. */
                virtual bool                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound echo acknowledgment. */
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound echo payload. */
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound UDP payload. */
                virtual bool                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound static request. */
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound static acknowledgment. */
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept { return true; }

            protected:
                /** @brief Hook called after connect endpoint parsing and validation. */
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                /** @brief Hook called after UDP endpoints parsing and validation. */
                virtual bool                                                OnPreparedSendTo(const ITransmissionPtr& transmission, const ppp::string& sourceHost, const boost::asio::ip::udp::endpoint& sourceEP, const ppp::string& destinationHost, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Sends keep-alive payload when scheduler triggers. */
                virtual bool                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept;
                
            protected:
                /** @brief Returns firewall used for endpoint filtering. */
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept;
                /** @brief Decodes and dispatches one inbound protocol packet. */
                virtual bool                                                PacketInput(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                /** @brief Associated IO context used for all async operations. */
                ContextPtr                                                  context_;
                /** @brief Session identifier shared with transmission peer. */
                Int128                                                      id_      = 0;
                /** @brief Monotonic timestamp of last successfully received packet, in ms. */
                UInt64                                                      last_    = 0;
                /** @brief Monotonic timestamp after which the next keep-alive must be sent, in ms. */
                UInt64                                                      next_ka_ = 0;
                /** @brief Runtime configuration source; determines timeouts and cipher settings. */
                AppConfigurationPtr                                         configuration_;
            };
        }
    }
}
