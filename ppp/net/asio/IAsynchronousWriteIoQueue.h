#pragma once

#include <ppp/stdafx.h>
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

            public:
                const std::shared_ptr<BufferswapAllocator>              BufferAllocator;

            public:
                IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept;
                virtual ~IAsynchronousWriteIoQueue() noexcept;

            public:
                std::shared_ptr<IAsynchronousWriteIoQueue>              GetReference() noexcept { return shared_from_this(); }
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }
                virtual void                                            Dispose() noexcept;
                bool                                                    Y(YieldContext& y) noexcept;
                bool                                                    R(YieldContext& y) noexcept;
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;

            private:
                class AsynchronousWriteIoContext final {
                public:
                    std::shared_ptr<Byte>                               packet;
                    int                                                 packet_length = 0;
                    AsynchronousWriteBytesCallback                      cb;

                public:
                    AsynchronousWriteIoContext() noexcept
                        : packet_length(0) { 

                    }
                    ~AsynchronousWriteIoContext() noexcept {
                        AsynchronousWriteIoContext* my = this;
                        (*my)(false);
                    }

                public:
                    void                                                operator()(bool b) noexcept {
                        AsynchronousWriteBytesCallback cb = this->Move();
                        if (cb) {
                            cb(b);
                        }
                    }

                public:
                    AsynchronousWriteBytesCallback                      Move() noexcept {
                        AsynchronousWriteBytesCallback f = std::move(this->cb);
                        this->cb.reset();
        
                        return f;
                    }
                };
                typedef std::shared_ptr<AsynchronousWriteIoContext>     AsynchronousWriteIoContextPtr;
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;

            private:
                bool                                                    DoWriteBytes(AsynchronousWriteIoContextPtr message) noexcept;
                void                                                    Finalize() noexcept;
                void                                                    AwaitInitiateAfterYieldCoroutine(YieldContext& y, std::atomic<int>& initiate) noexcept;

            protected:
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                bool                                                    DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    bool ok = false;
                    std::atomic<int> initiate = -1;

                    initiate = h(packet, packet_length,
                        [this, &y, &ok, &initiate](bool b) noexcept {
                            ok = b;
                            AwaitInitiateAfterYieldCoroutine(y, initiate);
                        }) ? 1 : 0;

                    if (initiate > 0) {
                        if (y.Suspend()) {
                            return ok;
                        }
                    }

                    return false;
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