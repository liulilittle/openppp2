#include <ppp/stdafx.h>
#include <ppp/threading/Thread.h>

namespace ppp
{
    namespace threading
    {
        typedef std::mutex                          SynchronizedObject;
        typedef std::lock_guard<SynchronizedObject> SynchronizedObjectScope;
        typedef std::shared_ptr<Thread>             ThreadPtr;
        typedef ppp::unordered_map<int, ThreadPtr>  ThreadTable;

        struct ThreadInternal final
        {
            ThreadTable                             Threads;
            SynchronizedObject                      Lock;
        };

        static std::shared_ptr<ThreadInternal>      Internal;

        void Thread_cctor() noexcept 
        {
            Internal = ppp::make_shared_object<ThreadInternal>();
        }

        Thread::Thread() noexcept
            : Id(0)
            , State(ThreadState::Stopped)
            , Priority(ThreadPriority::Normal)
        {

        }

        Thread::Thread(const ThreadStart& start) noexcept
            : Thread()
        {
            _start = start;
        }

        Thread::SynchronizedObject& Thread::GetSynchronizedObject() noexcept
        {
            return _syncobj;
        }

        std::shared_ptr<Thread> Thread::GetCurrentThread() noexcept
        {
            SynchronizedObjectScope scope(Internal->Lock);
            auto tail = Internal->Threads.find(GetCurrentThreadId());
            auto endl = Internal->Threads.end();
            if (tail == endl)
            {
                return NULL;
            }
            else
            {
                return tail->second;
            }
        }

        int Thread::GetProcessorCount() noexcept
        {
            return ppp::GetProcesserCount();
        }

        bool Thread::Join() noexcept
        {
            auto& t = _thread;
            if (!t.joinable())
            {
                return false;
            }

            try
            {
                t.join();
                return true;
            }
            catch (const std::exception&)
            {
                return false;
            }
        }

        bool Thread::Start() noexcept
        {
            SynchronizedObjectScope scope(_syncobj);
            if (State != ThreadState::Stopped)
            {
                return false;
            }

            if (Id != 0)
            {
                return false;
            }

            ThreadStart start = std::move(_start);
            if (NULL == start)
            {
                return false;
            }

            auto self = shared_from_this();
            auto thread_start = [this, self, start]() noexcept
                {
                    const_cast<int64_t&>(Id) = GetCurrentThreadId();
                    if (Priority != ThreadPriority::Normal)
                    {
                        SetThreadPriorityToMaxLevel();
                    }

                    const_cast<ThreadState&>(State) = ThreadState::Running;
                    {
                        SynchronizedObjectScope scope(Internal->Lock);
                        Internal->Threads[Id] = self;
                    }

                    SetThreadName("fork");
                    start(this);

                    const_cast<ThreadState&>(State) = ThreadState::Stopped;
                    {
                        SynchronizedObjectScope scope(Internal->Lock);
                        auto tail = Internal->Threads.find(Id);
                        auto endl = Internal->Threads.end();
                        if (tail != endl)
                        {
                            Internal->Threads.erase(tail);
                        }
                    }
                };

            _thread = std::thread(thread_start);
            return true;
        }

        void* Thread::GetData(int index) noexcept
        {
            SynchronizedObjectScope scope(_syncobj);
            auto tail = _tls.find(index);
            auto endl = _tls.end();
            if (tail == endl)
            {
                return NULL;
            }
            else
            {
                return tail->second;
            }
        }

        void* Thread::SetData(int index, const void* value) noexcept
        {
            SynchronizedObjectScope scope(_syncobj);
            if (NULL == value)
            {
                auto tail = _tls.find(index);
                auto endl = _tls.end();
                if (tail == endl)
                {
                    return NULL;
                }

                void* result = tail->second;
                _tls.erase(tail);
                return result;
            }
            else
            {
                void*& storage = _tls[index];
                void* result = storage;
                storage = (void*)value;
                return result;
            }
        }

        void Thread::SetPriority(ThreadPriority priority) noexcept
        {
            const_cast<ThreadPriority&>(Priority) = priority;
        }
    }
}