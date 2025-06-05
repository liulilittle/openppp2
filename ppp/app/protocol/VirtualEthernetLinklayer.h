#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/Int128.h>
#include <ppp/net/Firewall.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

namespace ppp {
    namespace app {
        namespace protocol {
            enum AddressType {
                None                                                        = 0,
                IPv4                                                        = 1,
                IPv6                                                        = 2,
                Domain                                                      = 3,
            };

            struct AddressEndPoint {
                AddressType                                                 Type = AddressType::None;
                ppp::string                                                 Host;
                int                                                         Port = 0;
            };

            /* 虚拟以太网链路层 */
            class VirtualEthernetLinklayer : public std::enable_shared_from_this<VirtualEthernetLinklayer> {
            public:
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                   ITransmission;
                typedef std::shared_ptr<ITransmission>                      ITransmissionPtr;
                typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
                typedef ppp::coroutines::YieldContext                       YieldContext;

            public:
                typedef enum {
                    // INFO
                    PacketAction_INFO                                       = 0x7E,
                    PacketAction_KEEPALIVED                                 = 0x7F,

                    // FRP
                    PacketAction_FRP_ENTRY                                  = 0x20,
                    PacketAction_FRP_CONNECT                                = 0x21,
                    PacketAction_FRP_CONNECTOK                              = 0x22,
                    PacketAction_FRP_PUSH                                   = 0x23,
                    PacketAction_FRP_DISCONNECT                             = 0x24,
                    PacketAction_FRP_SENDTO                                 = 0x25,

                    // VPN
                    PacketAction_LAN                                        = 0x28,
                    PacketAction_NAT                                        = 0x29,
                    PacketAction_SYN                                        = 0x2A,
                    PacketAction_SYNOK                                      = 0x2B,
                    PacketAction_PSH                                        = 0x2C,
                    PacketAction_FIN                                        = 0x2D,
                    PacketAction_SENDTO                                     = 0x2E,
                    PacketAction_ECHO                                       = 0x2F,
                    PacketAction_ECHOACK                                    = 0x30,
                    PacketAction_STATIC                                     = 0x31,
                    PacketAction_STATICACK                                  = 0x32,

                    // MUX
                    PacketAction_MUX                                        = 0x35,
                    PacketAction_MUXON                                      = 0x36,
                }                                                           PacketAction;

            public:
                typedef enum {
                    ERRORS_SUCCESS,
                    ERRORS_CONNECT_TO_DESTINATION,
                    ERRORS_CONNECT_CANCEL,
                }                                                           ERROR_CODES;

            public:
                VirtualEthernetLinklayer(
                    const AppConfigurationPtr&                              configuration, 
                    const ContextPtr&                                       context,
                    const Int128&                                           id) noexcept;
                virtual ~VirtualEthernetLinklayer() noexcept = default;

            public:
                std::shared_ptr<VirtualEthernetLinklayer>                   GetReference() noexcept     { return shared_from_this(); }
                ContextPtr                                                  GetContext() noexcept       { return context_; }
                AppConfigurationPtr&                                        GetConfiguration() noexcept { return configuration_; }
                Int128                                                      GetId() noexcept            { return id_; }

            public:
                virtual bool                                                Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                static int                                                  NewId() noexcept;

            public:
                virtual bool                                                DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept;
                virtual bool                                                DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept;
                virtual bool                                                DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept;
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept;
                virtual bool                                                DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept;
                virtual bool                                                DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept;
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept;
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept;

            public:
                virtual bool                                                DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept;
                virtual bool                                                DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept;

            protected:
                virtual bool                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept { return false; }
                virtual bool                                                OnMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept { return false; }

            public:
                virtual bool                                                DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept;
                virtual bool                                                DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                virtual bool                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept { return true; }
                virtual bool                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept { return true; }

            protected:
                virtual bool                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, int session_id, int remote_port, YieldContext& y) noexcept { return true; }

            protected:
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnPreparedSendTo(const ITransmissionPtr& transmission, const ppp::string& sourceHost, const boost::asio::ip::udp::endpoint& sourceEP, const ppp::string& destinationHost, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept;
                
            protected:
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept;
                virtual bool                                                PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                ContextPtr                                                  context_;
                Int128                                                      id_      = 0;
                UInt64                                                      last_    = 0;
                UInt64                                                      last_ka_ = 0;
                AppConfigurationPtr                                         configuration_;
            };
        }
    }
}