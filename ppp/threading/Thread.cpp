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

        static struct ThreadInternal
        {
            ThreadTable                             Threads;
            SynchronizedObject                      Lock;
        }                                           Internal;

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

        int Thread::GetCurrentThreadId() noexcept
        {
            return ppp::GetCurrentThreadId();
        }

        Thread::SynchronizedObject& Thread::GetSynchronizedObject() noexcept
        {
            return _syncobj;
        }

        std::shared_ptr<Thread> Thread::GetCurrentThread() noexcept
        {
            SynchronizedObjectScope scope(Internal.Lock);
            auto tail = Internal.Threads.find(GetCurrentThreadId());
            auto endl = Internal.Threads.end();
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
                    const_cast<int&>(Id) = Thread::GetCurrentThreadId();
                    const_cast<ThreadState&>(State) = ThreadState::Running;
                    if (Priority != ThreadPriority::Normal)
                    {
                        SetThreadPriorityToMaxLevel();
                    }

                    do
                    {
                        do
                        {
                            SynchronizedObjectScope scope(Internal.Lock);
                            Internal.Threads[Id] = self;
                        } while (false);

                        start();
                    } while (false);

                    const_cast<ThreadState&>(State) = ThreadState::Stopped;
                    do
                    {
                        SynchronizedObjectScope scope(Internal.Lock);
                        auto tail = Internal.Threads.find(Id);
                        auto endl = Internal.Threads.end();
                        if (tail != endl)
                        {
                            Internal.Threads.erase(tail);
                        }
                    } while (false);
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
            return tail->second;
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
                else
                {
                    void* result = tail->second;
                    _tls.erase(tail);
                    return result;
                }
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