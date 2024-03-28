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
                std::shared_ptr<IAsynchronousWriteIoQueue>              GetReference() noexcept;
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }

            public:
                virtual void                                            Dispose() noexcept;

            private:
                class AsynchronousWriteIoContext final {
                public:
                    std::shared_ptr<Byte>                               packet;
                    int                                                 packet_length;
                    AsynchronousWriteBytesCallback                      cb;

                public:
                    AsynchronousWriteIoContext() noexcept;
                    ~AsynchronousWriteIoContext() noexcept;

                public:
                    void                                                operator()(bool b) noexcept;

                public:
                    AsynchronousWriteBytesCallback                      Move() noexcept;
                };
                typedef std::shared_ptr<AsynchronousWriteIoContext>     AsynchronousWriteIoContextPtr;
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;

            public:
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;
                static bool                                             DoWriteBytes(std::shared_ptr<IAsynchronousWriteIoQueue> queue, boost::asio::ip::tcp::socket& socket, std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

            protected:
                virtual bool                                            WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;
                bool                                                    WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

            protected:
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                static bool                                             DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    bool ok = false;
                    bool complete = false;
                    bool initiate = false;

                    initiate = h(packet, packet_length, 
                        [&y, &ok, &initiate, &complete, h](bool b) noexcept {
                            ok = b;
                            complete = true;
                            if (initiate) {
                                auto& context = y.GetContext();
                                context.dispatch(std::bind(&YieldContext::Resume, y.GetPtr()));
                            }
                        });
                    if (!complete) {
                        if (initiate) {
                            y.Suspend();
                        }
                    }
                    return ok;
                }

                virtual bool                                            DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept = 0;

            private:
                bool                                                    DoWriteBytes(AsynchronousWriteIoContextPtr message) noexcept;
                void                                                    Finalize() noexcept;

            private:
                bool                                                    disposed_ = false;
                volatile bool                                           sending_  = false;
                AsynchronousWriteIoContextQueue                         queues_;
                SynchronizedObject                                      syncobj_;
            };
        }
    }
}