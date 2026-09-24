#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/app/mux/vmux.h>
#include <ppp/app/mux/vmux_net.h>

#include <ppp/net/asio/vdns.h>

#include <common/libtcpip/netstack.h>

#if defined(_WIN32)
#include <windows/ppp/win32/Win32Native.h>
#endif

/**
 * @file Executors.cpp
 * @brief Implements global executor, scheduler, and thread lifecycle management.
 */

namespace ppp
{
    namespace net
    {
        namespace asio
        {
            void InternetControlMessageProtocol_DoEvents() noexcept;
        }
    }

    namespace threading
    {
        namespace detail
        {
            constexpr int kTickThreadSleepMilliseconds = 10;
            constexpr int kSecondsPerTickUnit = 1000;
            constexpr int kMinThreadCount = 1;
        }

        using detail::kTickThreadSleepMilliseconds;
        using detail::kSecondsPerTickUnit;
        using detail::kMinThreadCount;

        /** @brief Shared byte-buffer pointer alias for cached context buffers. */
        typedef std::shared_ptr<Byte>                                           BufferArray;
        /** @brief Mutex type used to guard executor global state. */
        typedef std::mutex                                                      SynchronizedObject;
        /** @brief RAII lock helper for executor synchronization. */
        typedef std::lock_guard<SynchronizedObject>                             SynchronizedObjectScope;
        /** @brief Shared pointer alias for io_context instances. */
        typedef std::shared_ptr<boost::asio::io_context>                        ExecutorContextPtr;
        /** @brief Maps worker thread IDs to their bound contexts. */
        typedef ppp::unordered_map<int64_t, ExecutorContextPtr>                 ExecutorTable;
        /** @brief Round-robin list of worker contexts. */
        typedef ppp::list<ExecutorContextPtr>                                   ExecutorLinkedList;
        /** @brief Shared pointer alias for managed worker threads. */
        typedef std::shared_ptr<Thread>                                         ExecutorThreadPtr;
        /** @brief Maps context pointers to owning worker threads. */
        typedef ppp::unordered_map<boost::asio::io_context*, ExecutorThreadPtr> ExecutorThreadTable;
        /** @brief Maps contexts to their reusable byte buffers. */
        typedef ppp::unordered_map<boost::asio::io_context*, BufferArray>       ExecutorBufferArrayTable;

        /**
         * @brief Stores global runtime state for executor management.
         */
        class ExecutorsInternal final
        {
        public:
            std::atomic<int64_t>                                                DefaultThreadId = 0;
            std::atomic<uint64_t>                                               TickCount = 0;
            std::atomic<bool>                                                   TickThreadStop = false;
            DateTime                                                           Now;
            ExecutorContextPtr                                                  Default;
            ExecutorContextPtr                                                  Scheduler;
            SynchronizedObject                                                  Lock;
            SynchronizedObject                                                  TickThreadLock;
            std::thread                                                         TickThread;
            ExecutorLinkedList                                                  ContextFifo;
            ExecutorTable                                                       ContextTable;
            ExecutorThreadTable                                                 Threads;
            ppp::vector<ExecutorThreadPtr>                                      SchedulerThreads;
            ExecutorBufferArrayTable                                            Buffers;

        public:
            /** @brief Initializes runtime callbacks and process priority behavior. */
            ExecutorsInternal() noexcept;
        };

        /** @brief Process-wide singleton containing executor runtime state. */
        static std::shared_ptr<ExecutorsInternal>                               Internal;
        /** @brief Public application-exit callback storage. */
        Executors::ApplicationExitEventHandler                                  Executors::ApplicationExit;

        /**
         * @brief Initializes global executor state and starts the tick maintenance thread.
         */
        void Executors_cctor() noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = ppp::make_shared_object<ExecutorsInternal>();
            Internal = i;

            if (NULLPTR != i) 
            {
                try
                {
                    i->TickThread = std::thread(
                        [i]() noexcept 
                        {
                            SetThreadName("tick");
                            while (!i->TickThreadStop.load(std::memory_order_acquire))
                            {
                                UInt64 now = ppp::GetTickCount();
                                bool past = false;
                                {
                                    SynchronizedObjectScope scope(i->Lock);
                                    UInt64 previous = i->TickCount.load(std::memory_order_relaxed);
                                    past = (now / kSecondsPerTickUnit) != (previous / kSecondsPerTickUnit);
                                    i->TickCount.store(now, std::memory_order_relaxed);
                                    i->Now = DateTime::Now();
                                }

                                if (past)
                                {
                                    ppp::net::asio::vdns::UpdateAsync();
                                    ppp::net::asio::InternetControlMessageProtocol_DoEvents();
                                }

                                Sleep(kTickThreadSleepMilliseconds);
                            }
                        });
                }
                catch (const std::exception&) {}
            }
        }

        /**
         * @brief Runs one io_context loop with platform-specific exception handling.
         * @param context Execution context to run.
         */
        static void Executors_Run(boost::asio::io_context& context) noexcept
        {
            auto run = 
                [&context]() noexcept
                {
                    auto work = boost::asio::make_work_guard(context);
                    context.restart();
                    try {
                        context.run();
                    }
                    catch (const std::exception&) {}
                };
#if defined(_WIN32)
            __try
            {
                run();
            }
            __except (ppp::win32::Win32Native::DumpApplicationAndExit(GetExceptionInformation())) {}
#else
            run();
#endif
        }

        /**
         * @brief Removes cached buffer associated with a context.
         * @param context Context key whose cached buffer should be erased.
         */
        static void Executors_DeleteCachedBuffer(const boost::asio::io_context* context) noexcept
        {
            ExecutorBufferArrayTable& buffers = Internal->Buffers;
            ExecutorBufferArrayTable::iterator tail = buffers.find(constantof(context));
            ExecutorBufferArrayTable::iterator endl = buffers.end();
            if (tail != endl)
            {
                buffers.erase(tail);
            }
        }

        /**
         * @brief Creates and attaches the process default context once.
         * @param allocator Optional allocator used for per-context buffer allocation.
         * @return Newly attached default context, or null if already attached/failure.
         */
        static std::shared_ptr<boost::asio::io_context> Executors_AttachDefaultContext(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept
        {
            SynchronizedObjectScope scope(Internal->Lock);
            if (NULLPTR != Internal->Default)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppAlreadyRunning);
                return NULLPTR;
            }

            std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
            if (NULLPTR == context)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            Internal->Default = context;
            Internal->DefaultThreadId = GetCurrentThreadId();
            Internal->Buffers[context.get()] = BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);

            return context;
        }

        /**
         * @brief Adds a worker-thread context and registers it in all tracking tables.
         * @param allocator Optional allocator for worker cached buffers.
         * @param threadId Current worker thread identifier.
         * @return Newly created context, or null on allocation failure.
         */
        static std::shared_ptr<boost::asio::io_context> Executors_AddNewThreadContext(const std::shared_ptr<BufferswapAllocator>& allocator, int64_t threadId) noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
            if (NULLPTR == context)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            boost::asio::io_context* key = context.get();
            SynchronizedObjectScope scope(Internal->Lock);

            Internal->ContextFifo.emplace_back(context);
            Internal->ContextTable[threadId] = context;
            Internal->Threads[key] = Thread::GetCurrentThread();
            Internal->Buffers[key] = BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
            return context;
        }

        /**
         * @brief Removes worker-thread context bookkeeping and cached resources.
         * @param threadId Worker thread identifier to detach.
         * @param context Context instance to unregister.
         */
        static void Executors_EndNewThreadContext(int64_t threadId, const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            ExecutorLinkedList& fifo = Internal->ContextFifo;
            ExecutorTable& contexts = Internal->ContextTable;
            ExecutorThreadTable& threads = Internal->Threads;
            SynchronizedObjectScope scope(Internal->Lock);

            auto CONTEXT_TABLE_TAIL = contexts.find(threadId);
            auto CONTEXT_TABLE_ENDL = contexts.end();
            if (CONTEXT_TABLE_TAIL != CONTEXT_TABLE_ENDL)
            {
                contexts.erase(CONTEXT_TABLE_TAIL);
            }

            auto CONTEXT_FIFO_ENDL = fifo.end();
            auto CONTEXT_FIFO_TAIL = std::find(fifo.begin(), CONTEXT_FIFO_ENDL, context);
            if (CONTEXT_FIFO_TAIL != CONTEXT_FIFO_ENDL)
            {
                fifo.erase(CONTEXT_FIFO_TAIL);
            }

            auto CONTEXT_THREAD_TAIL = threads.find(context.get());
            auto CONTEXT_THREAD_ENDL = threads.end();
            if (CONTEXT_THREAD_TAIL != CONTEXT_THREAD_ENDL)
            {
                threads.erase(CONTEXT_THREAD_TAIL);
            }

            Executors_DeleteCachedBuffer(context.get());
        }

        /**
         * @brief Clears default-context ownership and releases its cached buffer.
         * @param context Default context being detached.
         */
        static void Executors_UnattachDefaultContext(const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            SynchronizedObjectScope scope(Internal->Lock);
            Internal->DefaultThreadId = 0;
            Internal->Default.reset();

            Executors_DeleteCachedBuffer(context.get());
        }

        /**
         * @brief Attempts graceful netstack shutdown and waits for completion signal.
         * @return true when shutdown processing was observed; otherwise false.
         */
        bool Executors_NetstackTryExit() noexcept
        {
            std::shared_ptr<Executors::Awaitable> awaitable =
                make_shared_object<Executors::Awaitable>();
            if (NULLPTR == awaitable)
            {
                lwip::netstack::close();
                return false;
            }

            /*
             * Each shutdown owns its completion state. netstack::close() is
             * required to complete the callback even when its context has
             * already stopped, so Await() never runs under an external lock.
             */
            lwip::netstack::close(
                [awaitable]() noexcept
                {
                    awaitable->Processed();
                });

            bool processed = awaitable->Await();
            if (processed)
            {
                lwip::netstack::wait_closed();
            }
            return processed;
        }

        /**
         * @brief Collects all registered worker contexts or default fallback.
         * @param contexts Output container receiving discovered contexts.
         */
        void Executors::GetAllContexts(ppp::vector<ContextPtr>& contexts) noexcept
        {
            bool any = false;
            SynchronizedObjectScope scope(Internal->Lock);
            for (auto&& kv : Internal->ContextTable)
            {
                any = true;
                contexts.emplace_back(kv.second);
            }

            if (!any)
            {
                ExecutorContextPtr context = Internal->Default;
                if (NULLPTR != context)
                {
                    contexts.emplace_back(context);
                }
            }
        }

        /**
         * @brief Returns cached buffer for a given execution context.
         * @param context Context whose cached buffer is requested.
         * @return Shared byte buffer, or null when not present.
         */
        std::shared_ptr<Byte> Executors::GetCachedBuffer(const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            if (NULLPTR == context)
            {
                return NULLPTR;
            }

            ExecutorBufferArrayTable& buffers = Internal->Buffers;
            SynchronizedObjectScope scope(Internal->Lock);

            ExecutorBufferArrayTable::iterator tail = buffers.find(context.get());
            ExecutorBufferArrayTable::iterator endl = buffers.end();
            return tail != endl ? tail->second : NULLPTR;
        }

        /**
         * @brief Returns the context associated with the current thread.
         * @param defaultContext Whether to return default context as fallback.
         * @return Bound context, fallback default, or null.
         */
        std::shared_ptr<boost::asio::io_context> Executors::GetCurrent(bool defaultContext) noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = Internal;
            if (NULLPTR == i)
            {
                return NULLPTR;
            }

            int64_t threadId = GetCurrentThreadId();
            SynchronizedObjectScope scope(i->Lock);
            if (threadId == i->DefaultThreadId.load(std::memory_order_relaxed))
            {
                return i->Default;
            }

            ExecutorTable::iterator tail = i->ContextTable.find(threadId);
            if (tail != i->ContextTable.end())
            {
                return tail->second;
            }

            return defaultContext ? i->Default : NULLPTR;
        }

        /**
         * @brief Selects the next executor context using a FIFO round-robin policy.
         * @return Selected worker context or default context fallback.
         */
        std::shared_ptr<boost::asio::io_context> Executors::GetExecutor() noexcept
        {
            std::shared_ptr<boost::asio::io_context> context;

            ExecutorLinkedList& fifo = Internal->ContextFifo;
            ExecutorTable& contexts = Internal->ContextTable;

            for (SynchronizedObjectScope scope(Internal->Lock);;)
            {
                std::size_t context_size = contexts.size();
                if (context_size == 1)
                {
                    ExecutorTable::iterator tail = contexts.begin();
                    context = tail->second;
                }
                else
                {
                    ExecutorLinkedList::iterator tail = fifo.begin();
                    ExecutorLinkedList::iterator endl = fifo.end();
                    if (tail != endl)
                    {
                        context = std::move(*tail);
                        fifo.erase(tail);
                        fifo.emplace_back(context);
                    }
                }

                return context ? context : Internal->Default;
            }
        }

        /**
         * @brief Returns the dedicated scheduler context.
         * @return Scheduler context or null when not initialized.
         */
        std::shared_ptr<boost::asio::io_context> Executors::GetScheduler() noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = Internal;
            if (NULLPTR == i)
            {
                return NULLPTR;
            }

            SynchronizedObjectScope scope(i->Lock);
            return i->Scheduler;
        }

        /**
         * @brief Returns the default execution context.
         * @return Default context or null when not attached.
         */
        std::shared_ptr<boost::asio::io_context> Executors::GetDefault() noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = Internal;
            if (NULLPTR == i)
            {
                return NULLPTR;
            }

            SynchronizedObjectScope scope(i->Lock);
            return i->Default;
        }

        /**
         * @brief Runs using an empty argv/argc argument list.
         * @param allocator Optional allocator for context cached buffers.
         * @param start Entry callback to execute.
         * @return Callback return code.
         */
        int Executors::Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start)
        {
            const char* argv[1] = {};
            int argc = 0;

            return Run(allocator, start, argc, argv);
        }

        /**
         * @brief Attaches default context, schedules entry callback, and runs loop.
         * @param allocator Optional allocator for context cached buffers.
         * @param start Entry callback to execute on the default context.
         * @param argc Argument count passed to callback.
         * @param argv Argument vector passed to callback.
         * @return Callback return code after loop shutdown.
         */
        int Executors::Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start, int argc, const char* argv[])
        {
            if (NULLPTR == start)
            {
                throw std::invalid_argument(nameof(start));
            }

            if (argc < 0)
            {
                throw std::invalid_argument(nameof(argc));
            }

            int return_code = -1;
            if (argc > 0 && NULLPTR == argv)
            {
                throw std::invalid_argument(nameof(argv));
            }

            std::shared_ptr<boost::asio::io_context> context = Executors_AttachDefaultContext(allocator);
            if (NULLPTR == context)
            {
                throw std::runtime_error("This operation cannot be repeated.");
            }
            else
            {
                boost::asio::post(*context, 
                    [context, &return_code, &start, argc, argv]() noexcept
                    {
                        return_code = start(argc, argv);
                        if (return_code != 0)
                        {
                            Executors::Exit();
                        }
                    });
                Executors_Run(*context);
            }

            Executors_UnattachDefaultContext(context);
            OnApplicationExit(context, return_code);
            return return_code;
        }

        /**
         * @brief Invokes one-time application exit handler and clears it.
         * @param context Context associated with the completed run.
         * @param return_code Final application return code.
         */
        void Executors::OnApplicationExit(const ContextPtr& context, int return_code) noexcept
        {
            // I'm letting go, I am finally willing to let go of your hands, because love you love to my heart.
            ApplicationExitEventHandler h = std::move(Executors::ApplicationExit);
            if (NULLPTR != h)
            {
                h(return_code);
                Executors::ApplicationExit = NULLPTR;
            }
        }

        /**
         * @brief Constructs Awaitable with reset completion flags.
         */
        Executors::Awaitable::Awaitable() noexcept 
            : completed(false)
            , processed(false)
        {
        
        }

        /**
         * @brief Signals that asynchronous processing has completed.
         */
        void Executors::Awaitable::Processed() noexcept
        {
            LK lk(mtx);
            completed = true;
            processed = true;

            cv.notify_one();
        }

        /**
         * @brief Waits for a completion signal and returns processed state.
         * @return true if Processed() was observed; otherwise false.
         */
        bool Executors::Awaitable::Await() noexcept
        {
            LK lk(mtx);
            cv.wait(lk, [this]() noexcept {  return completed; });

            bool ok = false;
            ok = processed;
            processed = false;
            completed = false;

            return ok;
        }

        /**
         * @brief Creates and starts one worker thread with its own io_context.
         * @param allocator Optional allocator used for per-thread cached buffers.
         * @return true when thread startup handshake completes; otherwise false.
         */
        static bool Executors_CreateNewThread(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept
        {
            std::shared_ptr<Executors::Awaitable> awaitable = make_shared_object<Executors::Awaitable>();
            if (NULLPTR == awaitable)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            std::weak_ptr<Executors::Awaitable> awaitable_weak = awaitable;
            std::shared_ptr<Thread> t = make_shared_object<Thread>(
                [allocator, awaitable_weak](Thread* my) noexcept
                {
                    int64_t threadId = GetCurrentThreadId();
                    if (std::shared_ptr<Executors::Awaitable> awaitable = awaitable_weak.lock(); NULLPTR != awaitable)
                    {
                        awaitable->Processed();
                    }

                    std::shared_ptr<boost::asio::io_context> context = Executors_AddNewThreadContext(allocator, threadId);
                    if (NULLPTR != context)
                    {
                        Executors_Run(*context);
                    }

                    Executors_EndNewThreadContext(threadId, context);
                });
            if (NULLPTR == t)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            t->SetPriority(ThreadPriority::Highest);
            if (!t->Start())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
                return false;
            }

            bool ok = awaitable->Await();
            if (!ok)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartupHandshakeFailed);
            }

            return ok;
        }

        /**
         * @brief Adjusts number of worker executor threads to requested count.
         * @param allocator Optional allocator for thread context buffers.
         * @param completionPortThreads Target worker thread count.
         */
        void Executors::SetMaxThreads(const std::shared_ptr<BufferswapAllocator>& allocator, int completionPortThreads) noexcept
        {
            if (1 > completionPortThreads)
            {
                completionPortThreads = kMinThreadCount;
            }

            ppp::vector<ExecutorContextPtr> releases;
            if (completionPortThreads)
            {
                ExecutorLinkedList& fifo = Internal->ContextFifo;
                ExecutorThreadTable& threads = Internal->Threads;
                ExecutorTable& contexts = Internal->ContextTable;
                SynchronizedObjectScope scope(Internal->Lock);

                for (int i = contexts.size(); i < completionPortThreads; i++)
                {
                    bool bok = Executors_CreateNewThread(allocator);
                    if (!bok)
                    {
                        break;
                    }
                }

                for (int i = completionPortThreads, max = contexts.size(); i < max; i++)
                {
                    auto CONTEXT_FIFO_TAIL = fifo.begin();
                    auto CONTEXT_FIFO_ENDL = fifo.end();
                    if (CONTEXT_FIFO_TAIL == CONTEXT_FIFO_ENDL)
                    {
                        break;
                    }

                    ExecutorContextPtr context = std::move(*CONTEXT_FIFO_TAIL);
                    fifo.erase(CONTEXT_FIFO_TAIL);

                    auto CONTEXT_THREAD_TAIL = threads.find(context.get()); 
                    auto CONTEXT_THREAD_ENDL = threads.end();
                    if (CONTEXT_THREAD_TAIL != CONTEXT_THREAD_ENDL)
                    {
                        auto& thread = CONTEXT_THREAD_TAIL->second; 
                        if (NULLPTR != thread)
                        {
                            auto CONTEXT_TABLE_TAIL = contexts.find(thread->Id); 
                            auto CONTEXT_TABLE_ENDL = contexts.end();
                            if (CONTEXT_TABLE_TAIL != CONTEXT_TABLE_ENDL)
                            {
                                contexts.erase(CONTEXT_TABLE_TAIL);
                            }
                        }

                        threads.erase(CONTEXT_THREAD_TAIL);
                    }

                    releases.emplace_back(context);
                }
            }

            for (auto&& context : releases)
            {
                Exit(context);
            }
        }

        /**
         * @brief Requests asynchronous stop on a specific context.
         * @param context Context to stop.
         * @return true when stop request is posted; otherwise false.
         */
        bool Executors::Exit(const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            if (NULLPTR == context || context->stopped())
            {
                return false;
            }

            /* io_context::stop() is thread-safe and cannot be stranded behind
             * a stopped event loop like a posted stop handler can. */
            context->stop();
            return true;
        }

        /**
         * @brief Stops all known contexts, joins worker threads, and closes netstack.
         * @return true when any stop action is performed; otherwise false.
         */
        bool Executors::Exit() noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = Internal;
            if (NULLPTR == i)
            {
                return false;
            }

            ExecutorContextPtr Default;
            ExecutorContextPtr Scheduler;
            ExecutorLinkedList ContextFifo;
            ExecutorTable ContextTable;
            ExecutorThreadTable Threads;
            ppp::vector<ExecutorThreadPtr> SchedulerThreads;
            {
                SynchronizedObjectScope scope(i->Lock);
                ContextFifo = i->ContextFifo;
                ContextTable = i->ContextTable;
                Threads = i->Threads;
                Default = i->Default;
                Scheduler = i->Scheduler;
                SchedulerThreads = i->SchedulerThreads;
            }

            /* Signal the tick thread to leave its loop so it stops taking the
             * executor lock and calling into vdns/ICMP before teardown proceeds. */
            i->TickThreadStop.store(true, std::memory_order_release);

            bool any = false;
            for (auto&& context : ContextFifo)
            {
                any |= Exit(context);
            }

            for (auto&& [_, context] : ContextTable)
            {
                any |= Exit(context);
            }

            for (auto&& [_, thread] : Threads)
            {
                if (NULLPTR != thread)
                {
                    thread->Join();
                }
            }

            Executors_NetstackTryExit();
            if (Exit(Scheduler))
            {
                any |= true;
            }

            /* Scheduler threads are registered in SchedulerThreads instead of
             * Threads; join them once their context has been stopped. */
            for (auto&& thread : SchedulerThreads)
            {
                if (NULLPTR != thread)
                {
                    thread->Join();
                }
            }

            if (Exit(Default))
            {
                any |= true;
            }

            /* Join the tick thread last: after this returns it can no longer
             * hold the executor lock or call into vdns during process exit. */
            {
                SynchronizedObjectScope scope(i->TickThreadLock);
                if (i->TickThread.joinable() && i->TickThread.get_id() != std::this_thread::get_id())
                {
                    try
                    {
                        i->TickThread.join();
                    }
                    catch (const std::exception&) {}
                }
            }

            return any;
        }

        /**
         * @brief Returns cached current time maintained by executor runtime.
         * @return Cached DateTime value or immediate system time fallback.
         */
        DateTime Executors::Now() noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = Internal;
            if (NULLPTR == i)
            {
                return DateTime::Now();
            }

            SynchronizedObjectScope scope(i->Lock);
            return i->Now;
        }

        /**
         * @brief Returns cached tick count while default context is alive.
         * @return Cached tick count or immediate system tick fallback.
         */
        uint64_t Executors::GetTickCount() noexcept
        {
            std::shared_ptr<ExecutorsInternal> i = Internal;
            if (NULLPTR != i)
            {
                SynchronizedObjectScope scope(i->Lock);
                if (NULLPTR != i->Default)
                {
                    return i->TickCount.load(std::memory_order_relaxed);
                }
            }

            return ppp::GetTickCount();
        }

        /**
         * @brief Initializes scheduler context and spawns scheduler threads.
         * @param completionPortThreads Number of scheduler threads to create.
         * @return true when scheduler is ready or already initialized.
         */
        bool Executors::SetMaxSchedulers(int completionPortThreads) noexcept
        {
            if (1 > completionPortThreads)
            {
                completionPortThreads = kMinThreadCount;
            }

            SynchronizedObjectScope scope(Internal->Lock);
            if (NULLPTR != Internal->Scheduler)
            {
                return true;
            }

            ExecutorContextPtr scheduler = make_shared_object<boost::asio::io_context>();
            if (NULLPTR == scheduler)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeSchedulerUnavailable);
                return false;
            }

#if defined(_WIN32)
            if (!ppp::win32::Win32Native::IsWindows81OrLaterVersion())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ExecutorsSetMaxSchedulersPlatformUnsupported);
                return false;
            }
#endif

            Internal->Scheduler = scheduler;
            for (int i = 0; i < completionPortThreads; i++)
            {
                std::shared_ptr<Thread> t = make_shared_object<Thread>(
                    [](Thread* my) noexcept
                    {
                        ExecutorContextPtr scheduler = Executors::GetScheduler();
                        if (NULLPTR != scheduler)
                        {
                            if (ppp::RT) 
                            {
                                SetThreadPriorityToMaxLevel();
                            }

                            SetThreadName("scheduler");
                            Executors_Run(*scheduler);
                        }
                    });

                if (NULLPTR == t)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
                    return false;
                }

                if (ppp::RT)
                {
                    t->SetPriority(ThreadPriority::Highest);
                }

                if (!t->Start())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
                    return false;
                }

                Internal->SchedulerThreads.emplace_back(t);
            }
            return true;
        }

        /**
         * @brief Initializes runtime hooks and optional real-time priorities.
         */
        ExecutorsInternal::ExecutorsInternal() noexcept
            : TickCount(ppp::GetTickCount())
        {
            if (ppp::RT)
            {
                SetThreadPriorityToMaxLevel();
                SetProcessPriorityToMaxLevel();
            }
        }

        /**
         * @brief Selects scheduler context when available and creates a strand.
         * @param strand Output strand when scheduler context is used.
         * @return Selected context, with executor fallback on failure.
         */
        std::shared_ptr<boost::asio::io_context> Executors::SelectScheduler(ppp::threading::Executors::StrandPtr& strand) noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = GetScheduler();
            if (NULLPTR == context)
            {
                context = ppp::threading::Executors::GetExecutor();
            }
            else
            {
                strand = make_shared_object<Strand>(boost::asio::make_strand(*context));
                if (NULLPTR == strand)
                {
                    context = ppp::threading::Executors::GetExecutor();
                }
            }

            return context;
        }
    }
}
