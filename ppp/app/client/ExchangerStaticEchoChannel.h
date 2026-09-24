#pragma once

#include <boost/asio/ip/udp.hpp>
#include <memory>
#include <mutex>

#include <ppp/Int128.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace coroutines {
        class YieldContext;
    }

    namespace app {
        namespace protocol {
            class VirtualEthernetPacket;
        }

        namespace client {
            class VEthernetExchanger;
            struct ExchangerStaticEchoDetail;

            class ExchangerStaticEchoChannel {
                friend class VEthernetExchanger;
                friend struct ExchangerStaticEchoDetail;

            public:
                class StaticEchoDatagarmSocket final : public boost::asio::ip::udp::socket {
                public:
                    explicit StaticEchoDatagarmSocket(boost::asio::io_context& context) noexcept
                        : basic_datagram_socket(context) {
                    }

                    virtual ~StaticEchoDatagarmSocket() noexcept {
                        boost::asio::ip::udp::socket* socket = this;
                        destructor_invoked(socket);
                    }

                    bool is_open(bool only_native = false) noexcept {
                        return only_native
                            ? basic_datagram_socket::is_open()
                            : opened && basic_datagram_socket::is_open();
                    }

                    bool opened = false;

                    /**
                     * @brief Per-generation receive buffer and source endpoint.
                     *
                     * Socket rotation keeps the retired socket open for 500-1000 ms while
                     * its in-flight receive is still outstanding; giving every socket
                     * generation its own receive targets prevents the old and new sockets
                     * from writing the same owner-level buffer/endpoint concurrently.
                     */
                    std::shared_ptr<Byte> receive_buffer_;
                    boost::asio::ip::udp::endpoint receive_source_ep_;
                };

                static bool IsValidServerPort(int serverPort) noexcept {
                    return serverPort > ppp::net::IPEndPoint::MinPort && serverPort <= ppp::net::IPEndPoint::MaxPort;
                }

                static bool AcceptsBalancePoolEndpoint(const boost::asio::ip::address& destinationIP) noexcept {
                    return destinationIP.is_v6();
                }

                void Bind(VEthernetExchanger* owner) noexcept;
                void InitializeCiphers(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
                void ConfigureSession(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    const ppp::Int128& id,
                    const ppp::Int128& fsid,
                    int session_id,
                    int remote_port) noexcept;

                void StaticEchoClean() noexcept;
                bool StaticEchoAllocated() noexcept;
                bool StaticEchoSwapAsynchronousSocket() noexcept;
                bool StaticEchoGatewayServer(int ack_id) noexcept;
                bool StaticEchoAllocatedToRemoteExchanger(ppp::coroutines::YieldContext& y) noexcept;
                bool StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept;
                bool StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;
                bool StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                bool StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;

            private:
                VEthernetExchanger* owner_ = nullptr;
                bool static_echo_input_ = false;
                std::uint64_t static_echo_timeout_ = UINT64_MAX;
                int static_echo_session_id_ = 0;
                int static_echo_remote_port_ = ppp::net::IPEndPoint::MinPort;
                std::shared_ptr<ppp::cryptography::Ciphertext> static_echo_protocol_;
                std::shared_ptr<ppp::cryptography::Ciphertext> static_echo_transport_;
                std::shared_ptr<StaticEchoDatagarmSocket> static_echo_sockets_[2];
                boost::asio::ip::udp::endpoint static_echo_source_ep_;
                ppp::list<boost::asio::ip::udp::endpoint> static_echo_server_ep_balances_;
                ppp::unordered_set<boost::asio::ip::udp::endpoint> static_echo_server_ep_set_;
                std::mutex syncobj_;
            };
        }
    }
}
