#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace asio {
            class IAsynchronousWriteIoQueue : public std::enable_shared_from_this<IAsynchronousWriteIoQueue> {
            public:
                typedef ppp::function<void(bool)>                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;
                typedef ppp::coroutines::YieldContext                   YieldContext;
                typedef ppp::threading::BufferswapAllocator             BufferswapAllocator;
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef std::atomic<int>                                atomic_int;
                typedef atomic_int                                      atomic_boolean;

            public:
                const std::shared_ptr<BufferswapAllocator>              BufferAllocator;

            public:
                IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept;
                virtual ~IAsynchronousWriteIoQueue() noexcept;

            public:
                std::shared_ptr<IAsynchronousWriteIoQueue>              GetReference()          noexcept { return shared_from_this(); }
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }
                virtual void                                            Dispose() noexcept;
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;

            private:
                typedef ppp::unordered_set<YieldContext*>               YieldContextSet;
                class AsynchronousWriteIoContext final {
                public:
                    std::shared_ptr<Byte>                               packet;
                    int                                                 packet_length = 0;
                    AsynchronousWriteBytesCallback                      cb;
                    SynchronizedObject                                  lockobj;

                public:
                    AsynchronousWriteIoContext() noexcept
                        : packet_length(0) { 

                    }
                    ~AsynchronousWriteIoContext() noexcept {
                        Forward(false);
                    }

                public:
                    void                                                Clear() noexcept {
                        SynchronizedObjectScope scope(lockobj);
                        cb.reset();
                        packet.reset();
                        packet_length = 0;
                    }
                    void                                                Forward(bool ok) noexcept {
                        AsynchronousWriteBytesCallback fx;
                        for (SynchronizedObjectScope scope(lockobj);;) {
                            fx = std::move(cb);
                            cb.reset();
                            break;
                        }

                        if (NULL != fx) {
                            fx(ok);
                        }
                    }
                };
                typedef std::shared_ptr<AsynchronousWriteIoContext>     AsynchronousWriteIoContextPtr;
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;
                
            private:
                bool                                                    DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept;
                int                                                     DoTryWriteBytesNext() noexcept;
                void                                                    Finalize() noexcept;

            protected:
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                bool                                                    DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    using atomic_int = std::atomic<int>;

                    std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                    if (NULL == status) {
                        return false;
                    }

                    boost::asio::io_context* context = addressof(y.GetContext());
                    boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();

                    ppp::threading::Executors::Post(context, strand,
                        [&y, status, h, packet, packet_length]() noexcept {
                            bool waiting = 
                                h(packet, packet_length,
                                    [&y, status](bool b) noexcept {
                                        ppp::coroutines::asio::R(y, *status, b);
                                    });

                            if (!waiting) {
                                ppp::coroutines::asio::R(y, *status, false);
                            }
                        });

                    y.Suspend();
                    return status->load() > 0;
                }

            protected:
                virtual bool                                            WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;
                bool                                                    WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                virtual bool                                            DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept = 0;
                
            private:
                struct {
                    bool                                                disposed_  : 1;
                    bool                                                sending_   : 7;
                };
                SynchronizedObject                                      syncobj_;
                AsynchronousWriteIoContextQueue                         queues_;
            };
        }
    }
}