#pragma once

#include <ppp/stdafx.h>
#include <ppp/DateTime.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file Executors.h
 * @brief Declares process-wide executor and scheduler management utilities.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Provides global access to io_context executors and lifecycle controls.
         */
        class Executors final
        {
        public:
            /** @brief Entry-point callback signature executed on the default context. */
            typedef ppp::function<int(int argc, const char* argv[])>                                ExecutorStart;
            /** @brief Alias for Boost.Asio execution context. */
            typedef boost::asio::io_context                                                         Context;
            /** @brief Shared pointer alias for execution context instances. */
            typedef std::shared_ptr<Context>                                                        ContextPtr;
            /** @brief Alias for serialized execution on a context. */
            typedef boost::asio::strand<boost::asio::io_context::executor_type>                     Strand;
            /** @brief Shared pointer alias for strand instances. */
            typedef std::shared_ptr<Strand>                                                         StrandPtr;
            /**
             * @brief Synchronization helper used to wait for asynchronous completion.
             */
            class Awaitable
            {
                /** @brief Mutex type used by Awaitable state transitions. */
                typedef std::mutex                                                                  SynchronizedObject;
                /** @brief Lock type used to wait on condition-variable notifications. */
                typedef std::unique_lock<SynchronizedObject>                                        LK;

            public:
                /** @brief Initializes Awaitable in a non-completed state. */
                Awaitable() noexcept;
                /** @brief Virtual default destructor for polymorphic usage. */
                virtual ~Awaitable() noexcept = default;

            public:
                /** @brief Marks the awaitable as completed and notifies one waiter. */
                virtual void                                                                        Processed() noexcept;
                /** @brief Blocks until completion and returns processing status. */
                virtual bool                                                                        Await() noexcept;

            private:
                /** @brief Guards cv/completed/processed members from concurrent mutation. */
                bool                                                                                completed = false;
                /** @brief Set by Processed() to indicate that work has been completed. */
                bool                                                                                processed = false;
                SynchronizedObject                                                                  mtx;
                /** @brief Condition variable used to block/unblock Await() callers. */
                std::condition_variable                                                             cv;
            };
            /** @brief Callback signature for application shutdown notifications. */
            typedef ppp::function<void(int)>                                                        ApplicationExitEventHandler;

        public:
            /** @brief Global handler invoked when the application main run loop exits. */
            static ApplicationExitEventHandler                                                      ApplicationExit;

        public:
            /** @brief Returns an execution context selected for workload dispatch. */
            static std::shared_ptr<boost::asio::io_context>                                         GetExecutor() noexcept;
            /** @brief Returns the dedicated scheduler context, if configured. */
            static std::shared_ptr<boost::asio::io_context>                                         GetScheduler() noexcept;
            /** @brief Returns the current thread-bound context or a fallback default. */
            static std::shared_ptr<boost::asio::io_context>                                         GetCurrent(bool defaultContext = true) noexcept;
            /** @brief Returns the default context created by Run(). */
            static std::shared_ptr<boost::asio::io_context>                                         GetDefault() noexcept;
            /** @brief Returns the cached per-context buffer used by this executor system. */
            static std::shared_ptr<Byte>                                                            GetCachedBuffer(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
            /** @brief Collects all known worker contexts into the provided vector. */
            static void                                                                             GetAllContexts(ppp::vector<ContextPtr>& contexts) noexcept;

        public:
            /** @brief Returns cached current time maintained by the tick thread. */
            static DateTime                                                                         Now() noexcept;
            /** @brief Returns cached process tick count with fallback behavior. */
            static uint64_t                                                                         GetTickCount() noexcept;
            /** @brief Creates scheduler threads and their shared scheduler context. */
            static bool                                                                             SetMaxSchedulers(int completionPortThreads) noexcept;

        public:
            /** @brief Adjusts worker-thread executor count and per-thread context allocation. */
            static void                                                                             SetMaxThreads(const std::shared_ptr<BufferswapAllocator>& allocator, int completionPortThreads) noexcept;
            /** @brief Requests shutdown of all known contexts and worker threads. */
            static bool                                                                             Exit() noexcept;
            /** @brief Requests shutdown of a specific execution context. */
            static bool                                                                             Exit(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
            /** @brief Runs the default context and invokes the provided start callback. */
            static int                                                                              Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start);
            /** @brief Runs with explicit command-line arguments for the start callback. */
            static int                                                                              Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start, int argc, const char* argv[]);

        public:
            template <typename TSocket>
            /**
             * @brief Moves an opened socket onto a scheduler-bound strand context.
             * @param socket Existing socket to transfer from.
             * @param socket_new Output socket bound to target strand.
             * @param scheduler Output scheduler context selected for the socket.
             * @param strand Output strand used to serialize subsequent handlers.
             * @return true on successful transfer; otherwise false.
             */
            static bool                                                                             ShiftToScheduler(
                TSocket&                                                                            socket,
                std::shared_ptr<TSocket>&                                                           socket_new,
                std::shared_ptr<boost::asio::io_context>&                                           scheduler,
                StrandPtr&                                                                          strand) noexcept
            {
                /** @brief Resolve the scheduler context before transferring ownership. */
                scheduler = ppp::threading::Executors::GetScheduler();
                if (NULLPTR == scheduler)
                {
                    return false;
                }

                bool opened = socket.is_open();
                if (!opened)
                {
                    return false;
                }

                /** @brief Capture protocol information required for assign() on new socket. */
                boost::system::error_code ec;
                boost::asio::ip::tcp::endpoint localEP = socket.local_endpoint(ec);
                if (ec)
                {
                    return false;
                }

                strand = make_shared_object<Strand>(boost::asio::make_strand(*scheduler));
                if (NULLPTR == strand)
                {
                    return false;
                }

                socket_new = make_shared_object<TSocket>(*strand);
                if (NULLPTR == socket_new)
                {
                    return false;
                }

                /** @brief Release native handle from old socket then rebind to new socket. */
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

            /** @brief Selects scheduler when available and optionally returns a strand. */
            static std::shared_ptr<boost::asio::io_context>                                         SelectScheduler(ppp::threading::Executors::StrandPtr& strand) noexcept;
            /**
             * @brief Posts a completion handler to strand first, then context fallback.
             * @param context Target execution context when strand is absent.
             * @param strand Preferred serialized execution strand.
             * @param handler Callable to schedule.
             * @return true when scheduled; otherwise false.
             */
            template <typename TContextPtr, typename TStrandPtr, typename LegacyCompletionHandler>
            static bool                                                                             Post(const TContextPtr& context, const TStrandPtr& strand, LegacyCompletionHandler&& handler) noexcept
            {
                using TCONTEXT_PTR = typename std::remove_reference<TContextPtr>::type;
                using TSTRAND_PTR  = typename std::remove_reference<TStrandPtr>::type;

                TCONTEXT_PTR context_copy = context;
                TSTRAND_PTR strand_copy   = strand;

                /**
                 * @brief A stopped io_context never runs the handler, so reporting
                 *        success would let callers (e.g. coroutine Suspend paths)
                 *        wait forever for a wakeup that can never arrive.
                 */
                if (strand_copy)
                {
                    if (NULLPTR != context_copy && context_copy->stopped())
                    {
                        return false;
                    }

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
                    if (context_copy->stopped())
                    {
                        return false;
                    }

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
            /** @brief Invokes and clears the application exit callback. */
            static void                                                                             OnApplicationExit(const ContextPtr& context, int return_code) noexcept;
        };
    }
}
