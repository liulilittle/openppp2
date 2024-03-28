#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

using ppp::net::Socket;
using ppp::net::IPEndPoint;

namespace ppp {
    namespace transmissions {
        ITcpipTransmission::ITcpipTransmission(
            const ContextPtr&                                       context, 
            const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket, 
            const AppConfigurationPtr&                              configuration) noexcept 
            : ITransmission(context, configuration)
            , disposed_(false)
            , socket_(socket) {
            boost::system::error_code ec;
            remoteEP_ = ppp::net::Ipep::V6ToV4(socket->remote_endpoint(ec));
        }

        ITcpipTransmission::~ITcpipTransmission() noexcept {
            Finalize();
        }
 
        void ITcpipTransmission::Finalize() noexcept {
            exchangeof(disposed_, true); {
                Socket::Closesocket(socket_);
            }
        }

        void ITcpipTransmission::Dispose() noexcept {
            auto self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->post(
                [self, this]() noexcept {
                    Finalize();
                });
            ITransmission::Dispose();
        }

        boost::asio::ip::tcp::endpoint ITcpipTransmission::GetRemoteEndPoint() noexcept {
            return remoteEP_;
        }

        std::shared_ptr<Byte> ITcpipTransmission::DoReadBytes(YieldContext& y, int length) noexcept {
            if (disposed_) {
                return NULL;
            }

            auto self = shared_from_this();
            return ITransmissionQoS::DoReadBytes(y, length, self, *this, this->QoS);
        }

        std::shared_ptr<Byte> ITcpipTransmission::ReadBytes(YieldContext& y, int length) noexcept {
            if (disposed_) {
                return NULL;
            }

            if (length < 1) {
                return NULL;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket) {
                return NULL;
            }

            std::shared_ptr<BufferswapAllocator> allocator = this->BufferAllocator;
            std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, length);
            if (NULL == packet) {
                return NULL;
            }

            bool ok = ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(packet.get(), length), y);
            if (!ok) {
                return NULL;
            }

            std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
            if (statistics) {
                statistics->AddIncomingTraffic(length);
            }

            return packet;
        }

        bool ITcpipTransmission::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
            if (NULL == socket_ || !socket_->is_open()) {
                return false;
            }
            
            if (disposed_) {
                return false;
            }

            ContextPtr context = GetContext();
            if (NULL == context) {
                return false;
            }

            std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
            auto complete_do_write_bytes_async_callback = [self, this, packet, offset, packet_length, cb]() noexcept {
                boost::asio::async_write(*socket_, boost::asio::buffer((Byte*)packet.get() + offset, packet_length),
                    [self, this, packet, packet_length, cb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool ok = ec == boost::system::errc::success;
                        if (ok) {
                            std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
                            if (statistics) {
                                statistics->AddOutgoingTraffic(packet_length);
                            }
                        }

                        if (cb) {
                            cb(ok);
                        }
                    });
                };

            context->dispatch(complete_do_write_bytes_async_callback);
            return true;
        }
    }
}