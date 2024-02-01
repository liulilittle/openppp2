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

                typedef enum {
                    // INFO
                    PacketAction_INFO                                       = 0x7E,

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
                }                                                           PacketAction;

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
                VirtualEthernetLinklayer(
                    const AppConfigurationPtr&                              configuration, 
                    const ContextPtr&                                       context,
                    const Int128&                                           id,
                    const std::shared_ptr<boost::asio::ip::tcp::resolver>&  tresolver,
                    const std::shared_ptr<boost::asio::ip::udp::resolver>&  uresolver) noexcept;
                virtual ~VirtualEthernetLinklayer() noexcept = default;

            public:
                std::shared_ptr<VirtualEthernetLinklayer>                   GetReference() noexcept;
                ContextPtr                                                  GetContext() noexcept;
                AppConfigurationPtr                                         GetConfiguration() noexcept;
                Int128                                                      GetId() noexcept;
                std::shared_ptr<boost::asio::ip::tcp::resolver>&            GetTResolver() noexcept { return tresolver_; }
                std::shared_ptr<boost::asio::ip::udp::resolver>&            GetUResolver() noexcept { return uresolver_; }

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

            public:
                virtual bool                                                DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept;
                virtual bool                                                DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                virtual bool                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                virtual bool                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept;
                virtual bool                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept;
                virtual bool                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept;

            protected:
                virtual bool                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept;
                virtual bool                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept;
                virtual bool                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept;
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept;
                virtual bool                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept;
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept;
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept;
                virtual bool                                                OnPreparedSendTo(const ITransmissionPtr& transmission, const ppp::string& sourceHost, const boost::asio::ip::udp::endpoint& sourceEP, const ppp::string& destinationHost, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept;
                virtual bool                                                PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                ContextPtr                                                  context_;
                bool                                                        disposed_;
                Int128                                                      id_;
                AppConfigurationPtr                                         configuration_;
                std::shared_ptr<boost::asio::ip::tcp::resolver>             tresolver_;
                std::shared_ptr<boost::asio::ip::udp::resolver>             uresolver_;
            };
        }
    }
}