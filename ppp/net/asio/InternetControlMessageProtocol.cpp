#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>

typedef ppp::net::Socket                        Socket;
typedef ppp::net::native::ip_hdr                ip_hdr;
typedef ppp::net::native::ip_hdr                icmp_hdr;
typedef ppp::net::packet::IPFrame               IPFrame;
typedef ppp::net::packet::IcmpFrame             IcmpFrame;
typedef ppp::net::packet::IcmpType              IcmpType;
typedef ppp::net::packet::BufferSegment         BufferSegment;
typedef ppp::net::IPEndPoint                    IPEndPoint;
typedef ppp::net::AddressFamily                 AddressFamily;
typedef ppp::threading::Timer                   Timer;
typedef ppp::threading::Executors               Executors;
typedef ppp::collections::Dictionary            Dictionary;

namespace ppp {
    namespace net {
        namespace asio {
            static void Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket, uint32_t sockfd) noexcept {
                if (socket) {
                    if (socket->is_open()) {
                        Socket::Closesocket(socket);
                        return;
                    }
                }
                Socket::Closesocket(sockfd);
            }

            // RAII
            typedef class InternetControlMessageProtocol_EchoAsynchronousContext {
            public:
                std::shared_ptr<Timer>                                          timeout;
                std::shared_ptr<IcmpFrame>                                      frame;
                std::shared_ptr<IPFrame>                                        packet;
                std::shared_ptr<boost::asio::ip::udp::socket>                   socket;
                int                                                             sockfd;
                ppp::function<void(const boost::system::error_code&, size_t)>   callback;
                std::weak_ptr<InternetControlMessageProtocol>                   reference_weak;

            public:
                InternetControlMessageProtocol_EchoAsynchronousContext() noexcept
                    : sockfd(-1) {

                }
                ~InternetControlMessageProtocol_EchoAsynchronousContext() noexcept {
                    Release(this);
                }

            public:
                static void                                                     Release(InternetControlMessageProtocol_EchoAsynchronousContext* context) noexcept {
                    std::shared_ptr<Timer> timeout = std::move(context->timeout);
                    if (timeout) {
                        timeout->Dispose();
                    }

                    std::shared_ptr<boost::asio::ip::udp::socket> socket = std::move(context->socket);
                    if (socket) {
                        Closesocket(socket, context->sockfd);
                    }

                    std::weak_ptr<InternetControlMessageProtocol> reference_weak = std::move(context->reference_weak);
                    context->sockfd = -1;
                    context->frame.reset();
                    context->packet.reset();
                    context->socket.reset();
                    context->timeout.reset();
                    context->callback = NULL;
                    context->reference_weak.reset();

                    std::shared_ptr<InternetControlMessageProtocol> reference = reference_weak.lock();
                    if (reference) {
                        auto& timeouts = reference->timeouts_;
                        auto tail = timeouts.find(context);
                        auto endl = timeouts.end();
                        if (tail != endl) {
                            timeouts.erase(tail);
                        }
                    }
                }
            }                                                                   EchoAsynchronousContext;

            InternetControlMessageProtocol::InternetControlMessageProtocol(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<boost::asio::io_context>& context) noexcept
                : BufferAllocator(allocator)
                , disposed_(false)
                , executor_(context)
                , buffer_(Executors::GetCachedBuffer(context.get())) {

            }

            InternetControlMessageProtocol::~InternetControlMessageProtocol() noexcept {
                Finalize();
            }

            void InternetControlMessageProtocol::Finalize() noexcept {
                exchangeof(disposed_, true); {
                    Dictionary::ReleaseAllCallbacks(timeouts_);
                }
            }

            std::shared_ptr<InternetControlMessageProtocol> InternetControlMessageProtocol::GetReference() noexcept {
                return shared_from_this();
            }

            std::shared_ptr<boost::asio::io_context> InternetControlMessageProtocol::GetContext() noexcept {
                return executor_;
            }

            void InternetControlMessageProtocol::Dispose() noexcept {
                auto self = shared_from_this();
                executor_->post(std::bind(&InternetControlMessageProtocol::Finalize, self));
            }

            bool InternetControlMessageProtocol::Echo(
                const std::shared_ptr<IPFrame>& packet,
                const std::shared_ptr<IcmpFrame>& frame,
                const IPEndPoint& destinationEP) noexcept {

                if (disposed_) {
                    return false;
                }

                if (!packet || !frame) {
                    return false;
                }

                const std::shared_ptr<BufferSegment> messages = packet->Payload;
                if (!messages || !messages->Buffer || messages->Length < 1) {
                    return false;
                }

                const int sockfd = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
                if (sockfd == -1) {
                    return false;
                }
                else {
                    const int TTL = packet->Ttl;
                    if (::setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&TTL, sizeof(TTL))) { // SOL_SOCKET, SO_SNDTIMEO, SO_RCVTIMEO
                        Socket::Closesocket(sockfd);
                        return false;
                    }
                }

                boost::system::error_code ec;
                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*executor_);
                if (!socket) {
                    Socket::Closesocket(sockfd);
                    return false;
                }

                socket->assign(boost::asio::ip::udp::v4(), sockfd, ec);
                if (ec) {
                    Closesocket(socket, sockfd);
                    return false;
                }

                socket->send_to(boost::asio::buffer(messages->Buffer.get(), messages->Length), IPEndPoint::WrapAddressV4<boost::asio::ip::udp>(packet->Destination, IPEndPoint::MaxPort), 0, ec);
                if (ec) {
                    Closesocket(socket, sockfd);
                    return false;
                }

                const IPEndPoint dstEP = destinationEP;
                const std::shared_ptr<InternetControlMessageProtocol> self = shared_from_this();
                const std::shared_ptr<EchoAsynchronousContext> context = make_shared_object<EchoAsynchronousContext>();
                const std::weak_ptr<EchoAsynchronousContext> weak_context(context);
                context->frame = frame;
                context->packet = packet;
                context->sockfd = sockfd;
                context->socket = socket;
                context->reference_weak = self;

                const std::shared_ptr<TimeoutEventHandler> timeout_cb = make_shared_object<TimeoutEventHandler>(
                    [self, weak_context] {
                        const std::shared_ptr<EchoAsynchronousContext> context = weak_context.lock();
                        if (context) {
                            EchoAsynchronousContext::Release(context.get());
                        }
                    });
                context->timeout = Timer::Timeout(executor_, MAX_ICMP_TIMEOUT, timeout_cb);
                context->callback = [self, this, context, dstEP](const boost::system::error_code& ec, size_t sz) noexcept {
                    bool cleanup = true;
                    do {
                        if (ec) {
                            break;
                        }

                        const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                        const std::shared_ptr<IPFrame> response = IPFrame::Parse(allocator, buffer_.get(), (int)sz);
                        if (response) {
                            if (Replay(context->packet, context->frame, response, dstEP)) {
                                break;
                            }
                        }

                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = context->socket;
                        if (!socket) {
                            break;
                        }

                        cleanup = false;
                        socket->async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), ep_, context->callback);
                    } while (false);

                    if (cleanup) {
                        EchoAsynchronousContext::Release(context.get());
                    }
                };

                socket->async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), ep_, context->callback);
                return timeouts_.emplace(context.get(), timeout_cb).second;
            }

            bool InternetControlMessageProtocol::Replay(
                const std::shared_ptr<IPFrame>          ping, 
                const std::shared_ptr<IcmpFrame>&       request, 
                const std::shared_ptr<IPFrame>&         packet, 
                const IPEndPoint&                       destinationEP) noexcept {

                if (disposed_) {
                    return false;
                }

                if (!packet) {
                    return false;
                }

                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (!frame) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                if (frame->Type == IcmpType::ICMP_ER) { // Echo-replay 
                    if (frame->Source != request->Destination) {
                        return false;
                    }

                    std::shared_ptr<IPFrame> e = make_shared_object<IPFrame>();
                    if (!e) {
                        return false;
                    }

                    e->AddressesFamily = AddressFamily::InterNetwork;
                    e->ProtocolType = ip_hdr::IP_PROTO_ICMP;
                    e->Source = request->Destination;
                    e->Destination = request->Source;
                    e->Payload = packet->Payload;
                    e->Id = packet->Id;
                    e->Tos = packet->Tos;
                    e->Ttl = packet->Ttl;
                    e->Flags = packet->Flags;
                    e->Options = packet->Options;
                    e->SetFragmentOffset(packet->GetFragmentOffset());
                    return Output(e.get(), destinationEP);
                }
                elif(frame->Type == IcmpType::ICMP_TE) {
                    std::shared_ptr<BufferSegment> payload = frame->Payload;
                    if (!payload) {
                        return false;
                    }

                    std::shared_ptr<IPFrame> raw = IPFrame::Parse(allocator, payload->Buffer.get(), payload->Length, false);
                    if (!raw) {
                        return false;
                    }

                    if (raw->Destination != request->Destination) {
                        return false;
                    }

                    std::shared_ptr<IcmpFrame> out = make_shared_object<IcmpFrame>();
                    if (!out) {
                        return false;
                    }

                    out->AddressesFamily = AddressFamily::InterNetwork;
                    out->Source = frame->Source;
                    out->Destination = request->Source;
                    out->Payload = raw->ToArray(allocator);
                    out->Identification = frame->Identification;
                    out->Code = frame->Code;
                    out->Sequence = frame->Sequence;
                    out->Ttl = frame->Ttl;
                    out->Type = frame->Type;

                    std::shared_ptr<IPFrame> e = out->ToIp(allocator);
                    if (!e) {
                        return false;
                    }

                    e->AddressesFamily = AddressFamily::InterNetwork;
                    e->ProtocolType = ip_hdr::IP_PROTO_ICMP;
                    e->Id = packet->Id;
                    e->Tos = packet->Tos;
                    e->Ttl = packet->Ttl;
                    e->Flags = packet->Flags;
                    e->Options = packet->Options;
                    e->SetFragmentOffset(packet->GetFragmentOffset());
                    return Output(e.get(), destinationEP);
                }
                return false;
            }
        }
    }
}