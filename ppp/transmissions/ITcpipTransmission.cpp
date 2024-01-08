#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/net/Socket.h>
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
                Dispose();
                return NULL;
            }

            std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
            if (statistics) {
                statistics->AddIncomingTraffic(length);
            }
            return packet;
        }

        bool ITcpipTransmission::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const std::shared_ptr<AsynchronousWriteBytesCallback>& cb) noexcept {
            if (disposed_) { 
                return false;
            }

            if (!socket_) {
                return false;
            }

            if (!socket_->is_open()) {
                return false;
            }

            std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
            std::shared_ptr<AsynchronousWriteBytesCallback> fcb = cb;

            boost::asio::async_write(*socket_, boost::asio::buffer((Byte*)packet.get() + offset, packet_length), 
                [self, this, packet, packet_length, fcb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                    bool ok = ec == boost::system::errc::success;
                    if (ok) {
                        std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
                        if (statistics) {
                            statistics->AddOutgoingTraffic(packet_length);
                        }
                    }

                    if (fcb) {
                        (*fcb)(ok);
                    }
                });
            return true;
        }
    }
}