#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace threading
    {
        class Executors
        {
        public:
            typedef ppp::function<int(int argc, const char* argv[])>    ExecutorStart;
            typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
            class Awaitable
            {
                typedef std::mutex                                      SynchronizedObject;
                typedef std::unique_lock<SynchronizedObject>            LK;

            public:
                Awaitable() noexcept;

            public:
                virtual void                                            Processed() noexcept;
                virtual bool                                            Await() noexcept;
                virtual void                                            Dispose() noexcept;

            private:
                bool                                                    completed;
                bool                                                    processed;
                std::shared_ptr<SynchronizedObject>                     mtx;
                std::shared_ptr<std::condition_variable>                cv;
                std::shared_ptr<LK>                                     lk;
            };
            typedef ppp::function<void(int)>                            ApplicationExitEventHandler;

        public:
            static std::shared_ptr<ApplicationExitEventHandler>         ApplicationExit;

        public:
            static std::shared_ptr<boost::asio::io_context>             GetExecutor() noexcept;
            static std::shared_ptr<boost::asio::io_context>             GetCurrent() noexcept;
            static std::shared_ptr<boost::asio::io_context>             GetDefault() noexcept;
            static std::shared_ptr<Byte>                                GetCachedBuffer(const boost::asio::io_context* context) noexcept;
            static void                                                 GetAllContexts(ppp::vector<ContextPtr>& contexts) noexcept;

        public:
            static uint64_t                                             GetTickCount() noexcept;
            static int                                                  GetMaxConcurrency() noexcept;
            
        public:
            template <typename LegacyCompletionHandler>
            static void                                                 Post(const std::shared_ptr<boost::asio::io_context>& context, LegacyCompletionHandler&& handler) noexcept
            {
                class ForwardHandler final
                {
                public:
                    std::shared_ptr<boost::asio::io_context>            context_;
                    LegacyCompletionHandler                             h_;

                public:
                    ForwardHandler(std::shared_ptr<boost::asio::io_context>&& context, LegacyCompletionHandler&& h) noexcept
                        : context_(std::move(context))
                        , h_(std::move(h))
                    {

                    }

                public:
                    void                                                operator()(void) const noexcept
                    {
                        h_();
                    }
                };

                std::shared_ptr<boost::asio::io_context> ioc = context;
                if (ioc)
                {
                    context->post(ForwardHandler(std::move(ioc), std::move(handler)));
                }
            }

            template <typename Handler>
            class WrappedHandler final {
            public:
                std::shared_ptr<boost::asio::io_context>                context_;
                Handler                                                 h_;
                Byte                                                    d_;

            public:
                WrappedHandler(std::shared_ptr<boost::asio::io_context>&& context, Handler&& h) noexcept
                    : context_(std::move(context))
                    , h_(std::move(h))
                    , d_(0)
                {

                }

            public:
                template <typename... Args>
                void                                                    operator()(Args&&... args) const noexcept
                {
                    WrappedHandler w = std::move(*this);
                    if (w.d_)
                    {
                        w.d_ = 0;
                        w.h_(std::forward<Args>(args)...);
                    }
                    else
                    {
                        std::shared_ptr<boost::asio::io_context> ioc = context_;
                        if (ioc)
                        {
                            w.d_ = 1;
                            ioc->dispatch(std::bind(std::move(w), std::forward<Args>(args)...));
                        }
                    }
                }
            };

            template <typename Handler>
            static WrappedHandler<Handler>                              Wrap(const std::shared_ptr<boost::asio::io_context>& context, Handler&& handler) noexcept 
            {
                std::shared_ptr<boost::asio::io_context> ioc = context;
                return WrappedHandler<Handler>(std::move(ioc), std::move(handler));
            }

        public:
            static void                                                 SetMaxThreads(const std::shared_ptr<BufferswapAllocator>& allocator, int completionPortThreads) noexcept;
            static void                                                 Exit() noexcept;
            static void                                                 Exit(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
            static int                                                  Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start);
            static int                                                  Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start, int argc, const char* argv[]);

        protected:
            static void                                                 OnApplicationExit(const ContextPtr& context, int return_code) noexcept;
        };
    }
}