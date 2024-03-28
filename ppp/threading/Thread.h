#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace threading
    {
        enum ThreadState
        {
            Stopped = 0,
            Running = 1,
        };

        enum ThreadPriority
        {
            Normal = 0,
            Highest = 1,
        };

        class Thread final : public std::enable_shared_from_this<Thread>
        {
        private:
            typedef ppp::unordered_map<int, void*>                          ThreadLocalStorageData;
            
        public:                 
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;
            typedef ppp::function<void(Thread*)>                            ThreadStart;
            
        public:         
            Thread() noexcept;          
            Thread(const ThreadStart& start) noexcept;          
            
        public:         
            const int64_t                                                   Id;
            const ThreadState                                               State;
            const ThreadPriority                                            Priority;
            
        public:                     
            bool                                                            Start() noexcept;
            bool                                                            Join() noexcept;
            SynchronizedObject&                                             GetSynchronizedObject() noexcept;
            void*                                                           GetData(int index) noexcept;
            void*                                                           SetData(int index, const void* value) noexcept;
            void                                                            SetPriority(ThreadPriority priority) noexcept;

        public:                 
            static void                                                     MemoryBarrier() noexcept
            {
                std::atomic_thread_fence(std::memory_order_seq_cst);
            }

            template <typename T>
            static T                                                        VolatileRead(std::atomic<T>& v) noexcept
            {           
                return v.load(std::memory_order_acquire);           
            }           

            template <typename T>            
            static T                                                        VolatileWrite(std::atomic<T>& v) noexcept
            {
                return v.load(std::memory_order_release);
            }

            template <typename T>
            static                                      std::atomic<T>*     From(const T* v) noexcept
            {
                std::atomic<T>* p = static_cast<std::atomic<T>*>(static_cast<void*>((T*)v));
                std::atomic_init(p, *v);
                return p;
            }

        public:
            static std::shared_ptr<Thread>                                  GetCurrentThread() noexcept;
            static int                                                      GetProcessorCount() noexcept;
                    
        private:                    
            std::thread                                                     _thread;
            SynchronizedObject                                              _syncobj;
            ThreadStart                                                     _start;
            ThreadLocalStorageData                                          _tls;
        };
    }
}