#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <common/libtcpip/netstack.h>

#ifdef _WIN32
#include <windows/ppp/win32/Win32Native.h>
#endif

namespace ppp
{
    namespace threading
    {
        typedef std::shared_ptr<Byte>                                           BufferArray;
        typedef std::mutex									                    SynchronizedObject;
        typedef std::lock_guard<SynchronizedObject>			                    SynchronizedObjectScope;
        typedef std::shared_ptr<boost::asio::io_context>	                    ExecutorContextPtr;
        typedef ppp::unordered_map<int, ExecutorContextPtr>                     ExecutorTable;
        typedef ppp::list<ExecutorContextPtr>				                    ExecutorLinkedList;
        typedef std::shared_ptr<Thread>                                         ExecutorThreadPtr;
        typedef ppp::unordered_map<boost::asio::io_context*, ExecutorThreadPtr> ExecutorThreadTable;
        typedef ppp::unordered_map<boost::asio::io_context*, BufferArray>       ExecutorBufferArrayTable;

        static struct ExecutorsInternal
        {
        public:
            std::atomic<int>                                    DefaultThreadId = 0;
            std::atomic<uint64_t>                               TickCount = 0;
            std::shared_ptr<boost::asio::deadline_timer>        Tick;
            ExecutorContextPtr								    Default;
            SynchronizedObject								    Lock;
            ExecutorLinkedList								    ContextFifo;
            ExecutorTable									    ContextTable;
            ExecutorThreadTable                                 Threads;
            ExecutorBufferArrayTable                            Buffers;
            std::shared_ptr<Executors::Awaitable>               NetstackExitAwaitable;

        public:
            ExecutorsInternal() noexcept
            {
                lwip::netstack::close_event =
                    [this]() noexcept
                    {
                        std::shared_ptr<Executors::Awaitable> awaitable = NetstackExitAwaitable;
                        if (NULL != awaitable)
                        {
                            awaitable->Processed();
                        }
                    };
                SetThreadPriorityToMaxLevel();
                SetProcessPriorityToMaxLevel();
            }
        }                                                       Internal;

        std::shared_ptr<Executors::ApplicationExitEventHandler> Executors::ApplicationExit;

        static bool Executors_AwaitTickInternalLoops() noexcept
        {
            ExecutorContextPtr context = Internal.Default;
            if (NULL == context)
            {
                return false;
            }

            std::shared_ptr<boost::asio::deadline_timer> t = Internal.Tick;
            if (NULL == t)
            {
                return false;
            }

            boost::asio::deadline_timer::duration_type durationTime = ppp::threading::Timer::DurationTime(10);
            t->expires_from_now(durationTime);
            t->async_wait(
                [context, t](const boost::system::error_code& ec) noexcept {
                    if (ec) {
                        if (ec != boost::system::errc::operation_canceled) {
                            return;
                        }
                    }
                    else {
                        Internal.TickCount = ppp::GetTickCount();
                    }
                    Executors_AwaitTickInternalLoops();
                });
            return true;
        }

        static void Executors_DeleteTickByDefaultContext() noexcept
        {
            std::shared_ptr<boost::asio::deadline_timer> t = std::move(Internal.Tick);
            if (NULL != t)
            {
                Internal.Tick = NULL;
                try {
                    boost::system::error_code ec;
                    t->cancel(ec);
                }
                catch (const std::exception&) {}
            }
        }

        static bool Executors_AddTickByDefaultContext() noexcept
        {
            ExecutorContextPtr context = Internal.Default;
            if (NULL == context)
            {
                return false;
            }
            else
            {
                Executors_DeleteTickByDefaultContext();
            }

            std::shared_ptr<boost::asio::deadline_timer> t = make_shared_object<boost::asio::deadline_timer>(*context);
            if (NULL == t)
            {
                return false;
            }
            else
            {
                Internal.TickCount = ppp::GetTickCount();
                Internal.Tick = std::move(t);
            }
            return Executors_AwaitTickInternalLoops();
        }

        static void Executors_DeleteCachedBuffer(const boost::asio::io_context* context) noexcept
        {
            ExecutorBufferArrayTable::iterator tail = Internal.Buffers.find(constantof(context));
            ExecutorBufferArrayTable::iterator endl = Internal.Buffers.end();
            if (tail != endl)
            {
                Internal.Buffers.erase(tail);
            }
        }

        static std::shared_ptr<boost::asio::io_context> Executors_AttachDefaultContext(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            if (NULL != Internal.Default)
            {
                return NULL;
            }

            std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
            Internal.Default = context;
            Internal.DefaultThreadId = Thread::GetCurrentThreadId();
            Internal.Buffers[context.get()] = BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
            Executors_AddTickByDefaultContext();
            return context;
        }

        static std::shared_ptr<boost::asio::io_context> Executors_AddNewThreadContext(const std::shared_ptr<BufferswapAllocator>& allocator, int threadId) noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
            Internal.ContextFifo.emplace_back(context);
            Internal.ContextTable[threadId] = context;
            Internal.Threads[context.get()] = Thread::GetCurrentThread();
            Internal.Buffers[context.get()] = BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
            return context;
        }

        static void Executors_EndNewThreadContext(int threadId, const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            auto CONTEXT_TABLE_TAIL = Internal.ContextTable.find(threadId);
            auto CONTEXT_TABLE_ENDL = Internal.ContextTable.end();
            if (CONTEXT_TABLE_TAIL != CONTEXT_TABLE_ENDL)
            {
                Internal.ContextTable.erase(CONTEXT_TABLE_TAIL);
            }

            auto CONTEXT_LIST_ENDL = Internal.ContextFifo.end();
            auto CONTEXT_LIST_TAIL = std::find(Internal.ContextFifo.begin(), CONTEXT_LIST_ENDL, context);
            if (CONTEXT_LIST_TAIL != CONTEXT_LIST_ENDL)
            {
                Internal.ContextFifo.erase(CONTEXT_LIST_TAIL);
            }

            auto THREAD_TAIL = Internal.Threads.find(context.get());
            auto THREAD_ENDL = Internal.Threads.end();
            if (THREAD_TAIL != THREAD_ENDL)
            {
                Internal.Threads.erase(THREAD_TAIL);
            }

            Executors_DeleteCachedBuffer(context.get());
        }

        static void Executors_UnattachDefaultContext(const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            Internal.DefaultThreadId = 0;
            Internal.Default.reset();
            Executors_DeleteTickByDefaultContext();
            Executors_DeleteCachedBuffer(context.get());
        }
        
        static void Executors_NetstackTryExit() noexcept
        {
            lwip::netstack::close();
            do
            {
                std::shared_ptr<Executors::Awaitable> awaitable = Internal.NetstackExitAwaitable;
                if (NULL != awaitable)
                {
                    awaitable->Await();
                }

                Internal.NetstackExitAwaitable.reset();
            } while (false);
        }

        void Executors_NetstackAllocExitAwaitable() noexcept
        {
            Internal.NetstackExitAwaitable = make_shared_object<Executors::Awaitable>();
        }

        static void Executors_Run(boost::asio::io_context& context) noexcept
        {
            auto run = [&context]() noexcept
                {
                    boost::asio::io_context::work work(context);
                    boost::system::error_code ec;
                    context.run(ec);
                };
#ifdef _WIN32
            __try
            {
                run();
            }
            __except (ppp::win32::Win32Native::DumpApplicationAndExit(GetExceptionInformation())) {}
#else
            run();
#endif
        }

        void Executors::GetAllContexts(ppp::vector<ContextPtr>& contexts) noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            for (auto&& kv : Internal.ContextTable)
            {
                contexts.emplace_back(kv.second);
            }
        }

        std::shared_ptr<Byte> Executors::GetCachedBuffer(const boost::asio::io_context* context) noexcept
        {
            if (NULL == context)
            {
                return NULL;
            }

            SynchronizedObjectScope scope(Internal.Lock);
            ExecutorBufferArrayTable::iterator tail = Internal.Buffers.find(constantof(context));
            ExecutorBufferArrayTable::iterator endl = Internal.Buffers.end();
            if (tail == endl)
            {
                return NULL;
            }
            return tail->second;
        }

        std::shared_ptr<boost::asio::io_context> Executors::GetCurrent() noexcept
        {
            int threadId = Thread::GetCurrentThreadId();
            if (threadId == Internal.DefaultThreadId)
            {
                return Internal.Default;
            }

            SynchronizedObjectScope scope(Internal.Lock);
            ExecutorTable& t = Internal.ContextTable;
            ExecutorTable::iterator tail = t.find(threadId);
            ExecutorTable::iterator endl = t.end();
            if (tail == endl)
            {
                return NULL;
            }
            else
            {
                return tail->second;
            }
        }

        std::shared_ptr<boost::asio::io_context> Executors::GetExecutor() noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            ExecutorLinkedList& fifo = Internal.ContextFifo;
            ExecutorLinkedList::iterator tail = fifo.begin();
            ExecutorLinkedList::iterator endl = fifo.end();
            if (tail == endl)
            {
                return NULL;
            }
            else
            {
                std::shared_ptr<boost::asio::io_context> context = std::move(*tail);
                fifo.erase(tail);
                fifo.emplace_back(context);
                return context;
            }
        }

        std::shared_ptr<boost::asio::io_context> Executors::GetDefault() noexcept
        {
            return Internal.Default;
        }

        int Executors::Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start)
        {
            const char* argv[1] = {};
            int argc = 0;

            return Run(allocator, start, argc, argv);
        }

        int Executors::Run(const std::shared_ptr<BufferswapAllocator>& allocator, const ExecutorStart& start, int argc, const char* argv[])
        {
            if (NULL == start)
            {
                throw std::invalid_argument(nameof(start));
            }

            if (argc < 0)
            {
                throw std::invalid_argument(nameof(argc));
            }

            int return_code = -1;
            if (argc > 0 && NULL == argv)
            {
                throw std::invalid_argument(nameof(argv));
            }

            std::shared_ptr<boost::asio::io_context> context = Executors_AttachDefaultContext(allocator);
            if (NULL == context)
            {
                throw std::runtime_error("This operation cannot be repeated.");
            }
            else
            {
#ifdef _WIN32
                ppp::win32::SYSTEM_WINDOWS_COM_INITIALIZED __SYSTEM_WINDOWS_COM_INITIALIZED__;
#endif
                context->post([&return_code, &start, argc, argv]() noexcept
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

        void Executors::OnApplicationExit(const ContextPtr& context, int return_code) noexcept
        {
            std::shared_ptr<ApplicationExitEventHandler> eh = std::move(Executors::ApplicationExit);
            if (eh)
            {
                Executors::ApplicationExit = NULL;

                // I'm letting go, I am finally willing to let go of your hands, because love you love to my heart.
                (*eh)(return_code);
            }
        }

        Executors::Awaitable::Awaitable() noexcept
            : completed(false)
            , processed(false)
        {
            mtx = make_shared_object<SynchronizedObjectt>();
            cv = make_shared_object<std::condition_variable>();
            lk = make_shared_object<LK>(*mtx);
        }

        void Executors::Awaitable::Processed() noexcept
        {
            completed = true;
            processed = true;

            std::shared_ptr<SynchronizedObjectt> pmtx = mtx;
            std::shared_ptr<std::condition_variable> pcv = cv;
            std::shared_ptr<LK> plk = lk;
            if (NULL != pcv) 
            {
                pcv->notify_all();
            }
        }

        bool Executors::Awaitable::Await() noexcept
        {
            std::shared_ptr<SynchronizedObjectt> pmtx = mtx;
            std::shared_ptr<std::condition_variable> pcv = cv;
            std::shared_ptr<LK> plk = lk;
            if (NULL == pcv)
            {
                return false;
            }

            pcv->wait(*lk, [&]() noexcept { return completed; });
            return processed;
        }

        void Executors::Awaitable::Dispose() noexcept
        {
            lk = NULL;
            cv = NULL;
            mtx = NULL;
        }

        static bool Executors_CreateNewThread(std::shared_ptr<BufferswapAllocator> allocator) noexcept
        {
            std::shared_ptr<Executors::Awaitable> awaitalbe_managed = make_shared_object<Executors::Awaitable>();
            if (NULL == awaitalbe_managed)
            {
                return false;
            }

            Executors::Awaitable* awaitalbe = awaitalbe_managed.get();
            std::shared_ptr<Thread> t = make_shared_object<Thread>(
                [awaitalbe, allocator]() noexcept
                {
                    if (NULL != awaitalbe)
                    {
                        int threadId = Thread::GetCurrentThreadId();
                        awaitalbe->Processed();

                        std::shared_ptr<boost::asio::io_context> context = Executors_AddNewThreadContext(allocator, threadId);
                        if (context)
                        {
                            Executors_Run(*context);
                        }

                        Executors_EndNewThreadContext(threadId, context);
                    }
                });

            bool ok = false;
            t->SetPriority(ThreadPriority::Highest);
            if (t->Start())
            {
                ok = awaitalbe->Await();
            }

            return ok;
        }

        void Executors::SetMaxThreads(const std::shared_ptr<BufferswapAllocator>& allocator, int completionPortThreads) noexcept
        {
            if (completionPortThreads < 1)
            {
                completionPortThreads = 1;
            }

            ppp::vector<ExecutorContextPtr> releases;
            if (completionPortThreads)
            {
                SynchronizedObjectScope scope(Internal.Lock);
                for (int i = Internal.ContextTable.size(); i < completionPortThreads; i++)
                {
                    bool bok = Executors_CreateNewThread(allocator);
                    if (!bok)
                    {
                        break;
                    }
                }

                for (int i = completionPortThreads, max = Internal.ContextTable.size(); i < max; i++)
                {
                    auto CONTEXT_LIST_TAIL = Internal.ContextFifo.begin();
                    auto CONTEXT_LIST_ENDL = Internal.ContextFifo.end();
                    if (CONTEXT_LIST_TAIL == CONTEXT_LIST_ENDL)
                    {
                        break;
                    }

                    ExecutorContextPtr context = std::move(*CONTEXT_LIST_TAIL);
                    Internal.ContextFifo.erase(CONTEXT_LIST_TAIL);

                    auto THREAD_TAIL = Internal.Threads.find(context.get());
                    auto THREAD_ENDL = Internal.Threads.end();
                    if (THREAD_TAIL != THREAD_ENDL)
                    {
                        auto& thread = THREAD_TAIL->second;
                        if (NULL != thread)
                        {
                            auto CONTEXT_TABLE_TAIL = Internal.ContextTable.find(thread->Id);
                            auto CONTEXT_TABLE_ENDL = Internal.ContextTable.end();
                            if (CONTEXT_TABLE_TAIL != CONTEXT_TABLE_ENDL)
                            {
                                Internal.ContextTable.erase(CONTEXT_TABLE_TAIL);
                            }
                        }

                        Internal.Threads.erase(THREAD_TAIL);
                    }

                    releases.emplace_back(context);
                }
            }

            for (auto&& context : releases)
            {
                Exit(context);
            }
        }

        void Executors::Exit(const std::shared_ptr<boost::asio::io_context>& context) noexcept
        {
            if (NULL != context)
            {
                bool stopped = context->stopped();
                if (!stopped)
                {
                    context->post(std::bind(&boost::asio::io_context::stop, context));
                }
            }
        }

        void Executors::Exit() noexcept
        {
            ExecutorContextPtr Default;
            ExecutorLinkedList ContextFifo;
            ExecutorTable ContextTable;
            ExecutorThreadTable Threads;
            {
                SynchronizedObjectScope scope(Internal.Lock);
                ContextFifo = Internal.ContextFifo;
                ContextTable = Internal.ContextTable;
                Threads = Internal.Threads;
                Default = Internal.Default;
            }

            for (auto&& context : ContextFifo)
            {
                Exit(context);
            }

            for (auto&& /*[id, context]*/ kv : ContextTable)
            {
                Exit(kv.second);
            }

            for (auto&& /*[context, thread]*/ kv : Threads)
            {
                auto& thread = kv.second;
                if (NULL != thread)
                {
                    thread->Join();
                }
            }

            Executors_NetstackTryExit();
            Exit(Default);
        }

        uint64_t Executors::GetTickCount() noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = Internal.Default;
            if (NULL != context)
            {
                return Internal.TickCount;
            }
            else
            {
                return ppp::GetTickCount();
            }
        }

        int Executors::GetMaxConcurrency() noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            return Internal.Threads.size();
        }
    }
}