#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/collections/Dictionary.h>

namespace ppp {
    namespace net {
        namespace asio {
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
                AsynchronousWriteIoContextQueue queues; 
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    disposed_ = true;
                    sending_ = false;
                    
                    queues = std::move(queues_);
                    queues_.clear();
                    break;
                }

                for (AsynchronousWriteIoContextPtr& context : queues) {
                    context->Forward(false);
                }
            }

            std::shared_ptr<Byte> IAsynchronousWriteIoQueue::Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept {
                if (NULL == data || datalen < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> chunk;
                if (NULL != allocator) {
                    chunk = allocator->MakeArray<Byte>(datalen);
                }
                else {
                    chunk = make_shared_alloc<Byte>(datalen);
                }

                if (NULL != chunk) {
                    void* memory = chunk.get();
                    memcpy(memory, data, datalen);
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
                while (NULL != q) {
                    SynchronizedObjectScope scope(q->syncobj_);
                    if (q->sending_) {
                        if (q->disposed_) {
                            break;
                        }

                        ok = true;
                        q->queues_.emplace_back(context);
                    }
                    else {
                        ok = q->DoTryWriteBytesUnsafe(context);
                    }

                    break;
                }

                if (ok) {
                    return true;
                }

                context->Clear();
                return false;
            }

            bool IAsynchronousWriteIoQueue::DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                auto evtf = 
                    [self, this, context](bool ok) noexcept {
                        int err = -1;
                        context->Forward(ok);

                        if (ok) {
                            err = DoTryWriteBytesNext();
                        }

                        if (err < 0) {
                            Dispose();
                        }
                    };

                bool ok = DoWriteBytes(context->packet, 0, context->packet_length, evtf);
                if (ok) {
                    sending_ = true;
                }

                return ok;
            }

            int IAsynchronousWriteIoQueue::DoTryWriteBytesNext() noexcept {
                bool ok = false;
                std::shared_ptr<AsynchronousWriteIoContext> context;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    sending_ = false;

                    if (disposed_) {
                        return -1;
                    }

                    do {
                        auto tail = queues_.begin();
                        auto endl = queues_.end();
                        if (tail == endl) {
                            return 0;
                        }

                        context = std::move(*tail);
                        queues_.erase(tail);
                    } while (NULL == context);

                    ok = DoTryWriteBytesUnsafe(context);
                    break;
                }

                if (ok) {
                    return 1;
                }
                
                context->Forward(false);
                return -1;
            }
        }
    }
}