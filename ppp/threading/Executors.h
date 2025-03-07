#pragma once

#include <ppp/stdafx.h>
#include <ppp/DateTime.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace threading
    {
        class Executors
        {
        public:
            typedef ppp::function<int(int argc, const char* argv[])>                                ExecutorStart;
            typedef boost::asio::io_context                                                         Context;
            typedef std::shared_ptr<Context>                                                        ContextPtr;
            typedef boost::asio::strand<boost::asio::io_context::executor_type>                     Strand;
            typedef std::shared_ptr<Strand>                                                         StrandPtr;
            class Awaitable
            {
                typedef std::mutex                                                                  SynchronizedObject;
                typedef std::unique_lock<SynchronizedObject>                                        LK;

            public:
                Awaitable() noexcept;
                virtual ~Awaitable() noexcept = default;

            public:
                virtual void                                                                        Processed() noexcept;
                virtual bool                                                                        Await() noexcept;

            private:
                bool                                                                                completed = false;
                bool                                                                                processed = false;
                SynchronizedObject                                                                  mtx;
                std::condition_variable                                                             cv;
            };
            typedef ppp::function<void(int)>                                                        ApplicationExitEventHandler;

        public:
            static ApplicationExitEventHandler                                                      ApplicationExit;

        public:
            static std::shared_ptr<boost::asio::io_context>                                         GetExecutor() noexcept;
            static std::shared_ptr<boost::asio::io_context>                                         GetScheduler() noexcept;
            static std::shared_ptr<boost::asio::io_context>                                         GetCurrent(bool defaultContext = true) noexcept;
            static std::shared_ptr<boost::asio::io_context>                                         GetDefault() noexcept;
            static std::shared_ptr<Byte>                                                            GetCachedBuffer(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
            static void                                                                             GetAllContexts(ppp::vector<ContextPtr>& contexts) noexcept;

        public:
            static DateTime                                                                         Now() noexcept;
            static uint64_t                                                                         GetTickCount() noexcept;
            static bool                                                                             SetMaxSchedulers(int completionPortThreads) noexcept;

        public:
            static void                                                                             SetMaxThreads(const std::shared_ptr<BufferswapAllocator>& allocator, int completionPortThreads) noexcept;
            static bool                                                                             Exit() noexcept;
            static bool                                                                             Exit(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
            static int                                                                              Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start);
            static int                                                                              Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start, int argc, const char* argv[]);

        public:
            template <typename TSocket>
            static bool                                                                             ShiftToScheduler(
                TSocket&                                                                            socket,
                std::shared_ptr<TSocket>&                                                           socket_new,
                std::shared_ptr<boost::asio::io_context>&                                           scheduler,
                StrandPtr&                                                                          strand) noexcept
            {
                scheduler = ppp::threading::Executors::GetScheduler();
                if (NULL == scheduler)
                {
                    return false;
                }

                bool opened = socket.is_open();
                if (!opened)
                {
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::tcp::endpoint localEP = socket.local_endpoint(ec);
                if (ec)
                {
                    return false;
                }

                strand = make_shared_object<Strand>(boost::asio::make_strand(*scheduler));
                if (NULL == strand)
                {
                    return false;
                }

                socket_new = make_shared_object<TSocket>(*strand);
                if (NULL == socket_new)
                {
                    return false;
                }

#if defined(_WIN32)
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
                int socket_fd = socket.release(ec);
                if (ec)
                {
                    return false;
                }
#if defined(_WIN32)
#pragma warning(pop)
#endif

                socket_new->assign(localEP.protocol(), socket_fd, ec);
                if (ec)
                {
                    ppp::net::Socket::Closesocket(socket_fd);
                    return false;
                }

                return true;
            }

            static std::shared_ptr<boost::asio::io_context>                                         SelectScheduler(ppp::threading::Executors::StrandPtr& strand) noexcept;

            template <typename TContextPtr, typename TStrandPtr, typename LegacyCompletionHandler>
            static bool                                                                             Post(const TContextPtr& context, const TStrandPtr& strand, LegacyCompletionHandler&& handler) noexcept
            {
                using TCONTEXT_PTR = typename std::remove_reference<TContextPtr>::type;
                using TSTRAND_PTR  = typename std::remove_reference<TStrandPtr>::type;

                TCONTEXT_PTR context_copy = context;
                TSTRAND_PTR strand_copy   = strand;

                if (strand_copy)
                {
                    auto invoked = 
                        [context_copy, strand_copy, handler]() noexcept
                        {
                            handler();
                        };
                        
                    boost::asio::post(*strand_copy, invoked);
                    return true;
                }

                if (context_copy)
                {
                    auto invoked = 
                        [context_copy, handler]() noexcept
                        {
                            handler();
                        };
                        
                    boost::asio::post(*context_copy, invoked);
                    return true;
                }
                else
                {
                    return false;
                }
            }

        protected:
            static void                                                                             OnApplicationExit(const ContextPtr& context, int return_code) noexcept;
        };
    }
}