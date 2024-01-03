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
                typedef std::lock_guard<SynchronizedObject>		        SynchronizedObjectScope;

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
                class AsynchronousWriteIoContext {
                public:
                    std::shared_ptr<Byte>                               packet;
                    int                                                 packet_length;
                    std::shared_ptr<AsynchronousWriteBytesCallback>     cb;

                public:
                    AsynchronousWriteIoContext() noexcept;
                    ~AsynchronousWriteIoContext() noexcept;

                public:
                    void                                                operator()(bool b) noexcept;

                public:
                    std::shared_ptr<AsynchronousWriteBytesCallback>     Move() noexcept;
                };
                typedef std::shared_ptr<AsynchronousWriteIoContext>     AsynchronousWriteIoContextPtr;
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;

            public:
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;
                static bool                                             DoWriteBytes(std::shared_ptr<IAsynchronousWriteIoQueue> queue, boost::asio::ip::tcp::socket& socket, std::shared_ptr<Byte> packet, int offset, int packet_length, const std::shared_ptr<AsynchronousWriteBytesCallback>& cb) noexcept;

            protected:
                virtual bool                                            WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const std::shared_ptr<AsynchronousWriteBytesCallback>& cb) noexcept;
                bool                                                    WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

            protected:
                // Do not optimize this function, otherwise it will cause crash of the program, In linux-gcc 7.5.0 x86_64 cc test results.
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                static bool                                             DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    bool ok = false;
                    YieldContext* p = y.GetPtr();
                    bool initiate = h(packet, packet_length, make_shared_object<AsynchronousWriteCallback>(
                        [p, &ok, h](bool b) noexcept {
                            ok = b;
                            p->GetContext().dispatch(std::bind(&YieldContext::Resume, p));
                        }));

                    if (initiate) {
                        p->Suspend();
                    }
                    return ok;
                }
                virtual bool                                            DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const std::shared_ptr<AsynchronousWriteBytesCallback>& cb) noexcept = 0;

            private:
                bool                                                    DoWriteBytes(AsynchronousWriteIoContextPtr message) noexcept;
                void                                                    Finalize() noexcept;

            private:
                bool                                                    disposed_;
                volatile bool                                           sending_;
                AsynchronousWriteIoContextQueue                         queues_;
                SynchronizedObject                                      syncobj_;
            };
        }
    }
}