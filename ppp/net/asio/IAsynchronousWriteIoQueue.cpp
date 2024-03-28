#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

namespace ppp {
    namespace net {
        namespace asio {
            std::shared_ptr<IAsynchronousWriteIoQueue> IAsynchronousWriteIoQueue::GetReference() noexcept {
                return shared_from_this();
            }

            IAsynchronousWriteIoQueue::AsynchronousWriteIoContext::AsynchronousWriteIoContext() noexcept
                : packet_length(0) {

            }

            IAsynchronousWriteIoQueue::AsynchronousWriteIoContext::~AsynchronousWriteIoContext() noexcept {
                AsynchronousWriteIoContext* context = this;
                (*context)(false);
            }

            void IAsynchronousWriteIoQueue::AsynchronousWriteIoContext::operator()(bool b) noexcept {
                AsynchronousWriteBytesCallback cb = this->Move();
                if (cb) {
                    cb(b);
                }
            }

            IAsynchronousWriteIoQueue::AsynchronousWriteBytesCallback IAsynchronousWriteIoQueue::AsynchronousWriteIoContext::Move() noexcept {
                AsynchronousWriteBytesCallback f = std::move(this->cb);
                this->cb.reset();

                return f;
            }

            IAsynchronousWriteIoQueue::IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept
                : BufferAllocator(allocator)
                , disposed_(false)
                , sending_(false) {

            }

            IAsynchronousWriteIoQueue::~IAsynchronousWriteIoQueue() noexcept {
                Finalize();
            }

            void IAsynchronousWriteIoQueue::Dispose() noexcept {
                Finalize();
            }

            void IAsynchronousWriteIoQueue::Finalize() noexcept {
                AsynchronousWriteIoContextQueue queues; {
                    SynchronizedObjectScope scope(syncobj_);
                    disposed_ = true;
                    sending_ = false;
    
                    queues = std::move(queues_);
                    queues_.clear();
                }

                for (AsynchronousWriteIoContextPtr& context : queues) {
                    AsynchronousWriteBytesCallback cb = context->Move();
                    if (cb) {
                        cb(false);
                    }
                }
            }

            std::shared_ptr<Byte> IAsynchronousWriteIoQueue::Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept {
                if (NULL == data || datalen < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> chunk = NULL != allocator ? allocator->MakeArray<Byte>(datalen) : make_shared_alloc<Byte>(datalen);
                if (NULL != chunk) {
                    memcpy(chunk.get(), data, datalen);
                }

                return chunk;
            }

            bool IAsynchronousWriteIoQueue::WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                return DoWriteYield<AsynchronousWriteBytesCallback>(y, packet, packet_length,
                    [this](const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                        return WriteBytes(packet, packet_length, cb);
                    });
            }

            bool IAsynchronousWriteIoQueue::WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                IAsynchronousWriteIoQueue* const q = this;
                if (q->disposed_) {
                    return false;
                }

                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (NULL == cb) {
                    return false;
                }

                std::shared_ptr<AsynchronousWriteIoContext> context = make_shared_object<AsynchronousWriteIoContext>();
                if (NULL == context) {
                    return false;
                }

                context->cb = cb;
                context->packet = packet;
                context->packet_length = packet_length;

                bool ok = false;
                if (NULL != q) {
                    SynchronizedObjectScope scope(q->syncobj_);
                    if (q->sending_) {
                        ok = true;
                        q->queues_.emplace_back(context);
                    }
                    else {
                        ok = q->DoWriteBytes(context);
                    }
                }

                return ok;
            }

            bool IAsynchronousWriteIoQueue::DoWriteBytes(AsynchronousWriteIoContextPtr message) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                auto evtf = [self, this, message](bool ok) noexcept {
                        if (message) {
                            (*message)(ok);
                        }

                        std::shared_ptr<AsynchronousWriteIoContext> context;
                        if (ok) {
                            SynchronizedObjectScope scope(syncobj_);
                            sending_ = false;

                            auto tail = queues_.begin();
                            auto endl = queues_.end();
                            if (tail != endl) {
                                context = std::move(*tail);
                                queues_.erase(tail);

                                ok = DoWriteBytes(context);
                            }
                        }

                        if (context) {
                            (*context)(ok);
                        }
                    };

                bool ok = DoWriteBytes(message->packet, 0, message->packet_length, evtf);
                if (ok) {
                    sending_ = true;
                }

                return ok;
            }

            bool IAsynchronousWriteIoQueue::DoWriteBytes(std::shared_ptr<IAsynchronousWriteIoQueue> queue, boost::asio::ip::tcp::socket& socket, std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                if (socket.is_open()) {
                    boost::asio::async_write(socket, boost::asio::buffer(packet.get() + offset, packet_length),
                        [queue, packet, cb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                            if (cb) {
                                cb(ec == boost::system::errc::success);
                            }
                        });
                    return true;
                }
                else {
                    return false;
                }
            }
        }
    }
}