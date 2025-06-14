#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace rinetd {
            RinetdConnection::RinetdConnection(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket) noexcept
                : disposed_(false)
                , connected_(false)
                , timeout_(0)
                , context_(context)
                , strand_(strand)
                , local_socket_(local_socket)
                , configuration_(configuration) {
#if defined(_WIN32)
                if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                    qoss_[0] = ppp::net::QoSS::New(local_socket->native_handle());
                }
#endif

                Update();
            }

            RinetdConnection::~RinetdConnection() noexcept {
                Finalize();
            }

            void RinetdConnection::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        Finalize();
                    });
            }

            void RinetdConnection::Update() noexcept {
                uint64_t now = ppp::threading::Executors::GetTickCount();
                if (remote_buffer_) {
                    timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
                else {
                    timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                }
            }

            void RinetdConnection::Finalize() noexcept {
#if defined(_WIN32)
                for (std::shared_ptr<ppp::net::QoSS>& qoss : qoss_) {
                    qoss.reset();
                }
#endif

                disposed_ = true;
                ppp::net::Socket::Closesocket(local_socket_);
                ppp::net::Socket::Closesocket(remote_socket_);
            }
 
            bool RinetdConnection::Open(const boost::asio::ip::tcp::endpoint& remoteEP, ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                if (remote_socket_) {
                    return false;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (remoteIP.is_unspecified()) {
                    return false;
                }

                if (remoteIP.is_multicast()) {
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(remoteIP)) {
                    return false;
                }

                int remotePort = remoteEP.port();
                if (remotePort <= ppp::net::IPEndPoint::MinPort || remotePort > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand_ ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand_) : make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                remote_socket_= socket;
                
                if (NULL == socket) {
                    return false;
                }

                bool opened = ppp::coroutines::asio::async_open(y, *socket, remoteEP.protocol());
                if (!opened) {
                    return false;
                }

#if defined(_WIN32)
                if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                    qoss_[1] = ppp::net::QoSS::New(socket->native_handle(), remoteIP, remotePort);
                }
#elif defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                // IPV6 does not need to be linked, because VPN is IPV4, 
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (remoteIP.is_v4() && !remoteIP.is_loopback()) {
                    auto protector_network = ProtectorNetwork; 
                    if (NULL != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            return false;
                        }
                    }
                }
#endif

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                ppp::net::Socket::AdjustSocketOptional(*socket, remoteIP.is_v4(), configuration->tcp.fast_open, configuration->tcp.turbo);

                bool connect_ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                if (connect_ok) {
                    connected_ = true;
                    Update();
                }

                return connect_ok;
            }

            bool RinetdConnection::Run() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULL == configuration) {
                    return false;
                }

                local_buffer_ = ppp::threading::BufferswapAllocator::MakeByteArray(configuration->GetBufferAllocator(), PPP_BUFFER_SIZE);
                if (NULL == local_buffer_) {
                    return false;
                }

                remote_buffer_ = ppp::threading::BufferswapAllocator::MakeByteArray(configuration->GetBufferAllocator(), PPP_BUFFER_SIZE);
                if (NULL == remote_buffer_) {
                    return false;
                }

                bool ok = ForwardXToY(local_socket_.get(), remote_socket_.get(), local_buffer_.get()) && ForwardXToY(remote_socket_.get(), local_socket_.get(), remote_buffer_.get());
                if (ok) {
                    Update();
                }

                return ok;
            }

            bool RinetdConnection::ForwardXToY(boost::asio::ip::tcp::socket* socket, boost::asio::ip::tcp::socket* to, Byte* buffer) noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<RinetdConnection> self = shared_from_this();
                socket->async_receive(boost::asio::buffer(buffer, PPP_BUFFER_SIZE),
                    [self, this, socket, to, buffer](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        int bytes_transferred = std::max<int>(-1, ec ? -1 : static_cast<int>(sz));
                        if (bytes_transferred < 1) {
                            Dispose();
                            return false;
                        }

                        boost::asio::async_write(*to, boost::asio::buffer(buffer, bytes_transferred),
                            [self, this, socket, to, buffer](const boost::system::error_code& ec, uint32_t sz) noexcept {
                                bool ok = ec == boost::system::errc::success;
                                if (ok) {
                                    ok = ForwardXToY(socket, to, buffer);
                                }

                                if (ok) {
                                    Update();
                                }
                                else {
                                    Dispose();
                                }
                            });
                        return true;
                    });
                return true;
            }
        }
    }
}