#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>

namespace ppp {
    namespace app {
        namespace protocol {
            class VirtualEthernetMappingPort : public std::enable_shared_from_this<VirtualEthernetMappingPort> {
            public:
                typedef ppp::coroutines::YieldContext                                       YieldContext;
                typedef ppp::transmissions::ITransmission                                   ITransmission;
                typedef std::shared_ptr<ITransmission>                                      ITransmissionPtr;
                typedef ppp::configurations::AppConfiguration                               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                                   AppConfigurationPtr;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         Ptr;
                typedef std::shared_ptr<VirtualEthernetLogger>                              VirtualEthernetLoggerPtr;

            public:
                VirtualEthernetMappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept;
                virtual ~VirtualEthernetMappingPort() noexcept;

            public:
                std::shared_ptr<boost::asio::io_context>                                    GetContext() noexcept;
                std::shared_ptr<VirtualEthernetLinklayer>                                   GetLinklayer() noexcept;
                ITransmissionPtr                                                            GetTransmission() noexcept;
                bool                                                                        ProtocolIsTcpNetwork() noexcept;
                bool                                                                        ProtocolIsUdpNetwork() noexcept;
                bool                                                                        ProtocolIsNetworkV4() noexcept;
                bool                                                                        ProtocolIsNetworkV6() noexcept;
                int                                                                         GetRemotePort() noexcept;
                VirtualEthernetLoggerPtr                                                    GetLogger() noexcept { return logger_; }
                std::shared_ptr<ppp::threading::BufferswapAllocator>                        GetBufferAllocator() noexcept { return buffer_allocator_; }
                
            public:
                static constexpr uint32_t                                                   GetHashCode(bool in, bool tcp, int remote_port) noexcept {
                    uint32_t key = (in ? 1 : 0) << 24;
                    key |= (tcp ? 1 : 0) << 16;
                    key |= remote_port & 0xffff;
                    return key;
                }

            public:
                boost::asio::ip::tcp::endpoint                                              BoundEndPointOfFrpServer() noexcept;
                virtual bool                                                                OpenFrpServer(const VirtualEthernetLoggerPtr& logger) noexcept;
                virtual bool                                                                OpenFrpClient(const boost::asio::ip::address& local_ip, int local_port) noexcept;
                virtual void                                                                Dispose() noexcept;
                virtual bool                                                                Update(UInt64 now) noexcept;
                static int                                                                  NewId() noexcept;

            public:
                static std::shared_ptr<VirtualEthernetMappingPort>                          FindMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept;
                static bool                                                                 AddMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port, const Ptr& mapping_port) noexcept;
                static std::shared_ptr<VirtualEthernetMappingPort>                          DeleteMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept;

            public:
                bool                                                                        Server_OnFrpConnectOK(int connection_id, Byte error_code) noexcept;
                bool                                                                        Server_OnFrpDisconnect(int connection_id) noexcept;
                bool                                                                        Server_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept;
                bool                                                                        Server_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            public:
                bool                                                                        Client_OnFrpDisconnect(int connection_id) noexcept;
                bool                                                                        Client_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept;
                bool                                                                        Client_OnFrpConnect(int connection_id) noexcept;
                bool                                                                        Client_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                class Server final {
                public:
                    class Connection final : public ppp::net::asio::IAsynchronousWriteIoQueue {
                    public:
                        Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Server>& server, int connection_id, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                        ~Connection() noexcept;

                    public:
                        void                                                                Dispose() noexcept { Finalize(false); }
                        bool                                                                ConnectToFrpClient() noexcept;
                        bool                                                                SendToFrpUser(const void* packet, int packet_size) noexcept;
                        bool                                                                SendToFrpClient(const void* packet, int packet_size) noexcept;
                        void                                                                Update() noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            if (connection_stated_.load() < 3) {
                                timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                            }
                            else {
                                timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                            }
                        }
                        bool                                                                IsPortAging(UInt64 now) noexcept { return connection_stated_.load() > 3 || now >= timeout_; }

                    public:
                        bool                                                                OnConnectOK(Byte error_code) noexcept;
                        void                                                                OnDisconnect() noexcept { Finalize(true); }

                    private:
                        void                                                                Finalize(bool disconnect) noexcept;
                        bool                                                                ForwardFrpUserToFrpClient() noexcept;
                        virtual bool                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                    private:
                        std::atomic<int>                                                    connection_stated_;
                        std::shared_ptr<Server>                                             server_;
                        int                                                                 connection_id_;
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;
                        std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;
                        UInt64                                                              timeout_;
                        AppConfigurationPtr                                                 configuration_; 
                        std::shared_ptr<Byte>                                               buffer_chunked_;
                    };
                    typedef std::shared_ptr<Connection>                                     ConnectionPtr;

                public:
                    std::shared_ptr<Byte>                                                   socket_source_buf_;
                    boost::asio::ip::udp::endpoint                                          socket_source_ep_;
                    boost::asio::ip::udp::socket                                            socket_udp_;
                    boost::asio::ip::tcp::acceptor                                          socket_tcp_;
                    boost::asio::ip::tcp::endpoint                                          socket_endpoint_;
                    ppp::unordered_map<int, ConnectionPtr>                                  socket_connections_;

                public:
                    Server(VirtualEthernetMappingPort* owner) noexcept;
                };
                Server::ConnectionPtr                                                       Server_GetConnection(int connection_id) noexcept;

            private:
                class Client final {
                public:
                    class Connection final : public ppp::net::asio::IAsynchronousWriteIoQueue {
                    public:
                        Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, int connection_id) noexcept;
                        ~Connection() noexcept;

                    public:
                        bool                                                                ConnectToDestinationServer() noexcept;
                        void                                                                Update() noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            if (connection_stated_.load() < 3) {
                                timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                            }
                            else {
                                timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                            }
                        }
                        bool                                                                IsPortAging(UInt64 now) noexcept { return connection_stated_.load() > 3 || now >= timeout_; }
                        void                                                                Dispose() noexcept { Finalize(false); }
                        bool                                                                SendToDestinationServer(const void* packet, int packet_size) noexcept;

                    public:
                        bool                                                                OnConnectedOK(bool ok) noexcept;
                        void                                                                OnDisconnect() noexcept { Finalize(true); }

                    private:
                        void                                                                Finalize(bool disconnect) noexcept;
                        bool                                                                Loopback() noexcept;
                        virtual bool                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                    private:
                        std::atomic<int>                                                    connection_stated_ = FALSE;
                        std::shared_ptr<Client>                                             client_;
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;
                        int                                                                 connection_id_     = 0;
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;    
                        std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;    
                        UInt64                                                              timeout_           = 0;
                        AppConfigurationPtr                                                 configuration_;
                        ITransmissionPtr                                                    transmission_;
                        std::shared_ptr<Byte>                                               buffer_chunked_;
                    };
                    typedef std::shared_ptr<Connection>                                     ConnectionPtr;

                public:
                    class DatagramPort final : public std::enable_shared_from_this<DatagramPort> {
                    public:
                        DatagramPort(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, const boost::asio::ip::udp::endpoint& natEP) noexcept;
                        ~DatagramPort() noexcept;

                    public:
                        bool                                                                SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                        void                                                                Update() noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                        }
                        bool                                                                Open() noexcept;
                        bool                                                                IsPortAging(UInt64 now) noexcept { return disposed_.load() != FALSE || now >= timeout_; }
                        void                                                                Dispose() noexcept;

                    private:
                        bool                                                                Loopback() noexcept;
                        bool                                                                SendToDestinationServer(const void* packet, int packet_length) noexcept;

                    private:
                        std::atomic<int>                                                    disposed_ = FALSE;
                        boost::asio::ip::udp::socket                                        socket_;
                        uint64_t                                                            timeout_  = 0;
                        AppConfigurationPtr                                                 configuration_;
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;
                        std::shared_ptr<Byte>                                               buffer_chunked_;
                        boost::asio::ip::udp::endpoint                                      source_ep_;
                        boost::asio::ip::udp::endpoint                                      nat_ep_;
                        std::shared_ptr<Client>                                             client_;
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;
                        ITransmissionPtr                                                    transmission_;
                    };
                    typedef std::shared_ptr<DatagramPort>                                   DatagramPortPtr;

                public:
                    boost::asio::ip::udp::endpoint                                          local_ep_;
                    bool                                                                    local_in_;
                    ppp::unordered_map<int, ConnectionPtr>                                  socket_connections_;
                    ppp::unordered_map<boost::asio::ip::udp::endpoint, DatagramPortPtr>     socket_datagram_ports_;
                    
                public:
                    Client() noexcept;
                };
                Client::ConnectionPtr                                                       Client_GetConnection(int connection_id) noexcept;
                Client::DatagramPortPtr                                                     Client_GetDatagramPort(const boost::asio::ip::udp::endpoint& nat_key) noexcept;

            private:
                bool                                                                        Server_SendToFrpClient(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                bool                                                                        Server_AcceptFrpUserSocket(const std::shared_ptr<Server>& server, const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept;

            private:
                void                                                                        Finalize() noexcept;
                bool                                                                        LoopbackFrpServer() noexcept;
                bool                                                                        OpenNetworkSocketStream() noexcept;
                bool                                                                        OpenNetworkSocketDatagram() noexcept;

            private:
                std::atomic<int>                                                            disposed_     = FALSE;
                std::shared_ptr<VirtualEthernetLinklayer>                                   linklayer_; 
                ITransmissionPtr                                                            transmission_; 

                struct {
                    bool                                                                    tcp_          : 1; 
                    bool                                                                    in_           : 7; 
                };

                int                                                                         remote_port_  = 0;
                std::shared_ptr<boost::asio::io_context>                                    context_;
                std::shared_ptr<Server>                                                     server_;
                std::shared_ptr<Client>                                                     client_;
                AppConfigurationPtr                                                         configuration_;
                VirtualEthernetLoggerPtr                                                    logger_;
                std::shared_ptr<ppp::threading::BufferswapAllocator>                        buffer_allocator_;
            };
        }
    }
}