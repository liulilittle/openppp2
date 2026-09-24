#pragma once

#include <ppp/stdafx.h>

/**
 * @file Thread.h
 * @brief Declares a managed thread wrapper with TLS utilities.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Represents runtime state of a managed thread.
         */
        enum ThreadState
        {
            Stopped = 0,
            Running = 1,
        };

        /**
         * @brief Represents supported thread priority presets.
         */
        enum ThreadPriority
        {
            Normal  = 0,
            Highest = 1,
        };

        /**
         * @brief Managed thread abstraction with lifecycle and thread-local data access.
         */
        class Thread final : public std::enable_shared_from_this<Thread>
        {
        private:
            typedef ppp::unordered_map<int, void*>                          ThreadLocalStorageData;

        public:
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;
            typedef ppp::function<void(Thread*)>                            ThreadStart;

        public:
            /**
             * @brief Constructs an empty thread instance.
             */
            Thread() noexcept;
            /**
             * @brief Constructs a thread instance bound to an entry callback.
             * @param start Callback invoked on thread start.
             */
            Thread(const ThreadStart& start) noexcept;
            /**
             * @brief Detaches the underlying thread on destruction when joinable.
             */
            ~Thread() noexcept;

        public:
            /** @brief Atomically published numeric worker identifier; zero until the worker enters. */
            std::atomic<int64_t>                                            Id{0};
            /** @brief Atomically published runtime state of the managed thread. */
            std::atomic<ThreadState>                                        State{ThreadState::Stopped};
            /** @brief Atomically published scheduling priority applied during startup. */
            std::atomic<ThreadPriority>                                     Priority{ThreadPriority::Normal};

        public:
            /**
             * @brief Starts execution of the configured callback.
             * @return true when thread creation succeeds; otherwise false.
             */
            bool                                                            Start() noexcept;
            /**
             * @brief Joins the underlying thread if joinable.
             * @return true on successful join; otherwise false.
             */
            bool                                                            Join() noexcept;
            /**
             * @brief Detaches the underlying thread if joinable.
             * @return true on successful detach; otherwise false.
             */
            bool                                                            Detach() noexcept;
            /**
             * @brief Gets the synchronization object used by the TLS helpers.
             * @return Reference to the internal TLS mutex.
             */
            SynchronizedObject&                                             GetSynchronizedObject() noexcept;
            /**
             * @brief Retrieves a thread-local storage value by integer key.
             * @param index Storage slot index.
             * @return Stored pointer or null when absent.
             */
            void*                                                           GetData(int index) noexcept;
            /**
             * @brief Sets or removes a thread-local storage value by key.
             * @param index Storage slot index.
             * @param value New pointer value; null removes the key.
             * @return Previous stored pointer, or null when none existed.
             */
            void*                                                           SetData(int index, const void* value) noexcept;
            /**
             * @brief Sets desired thread priority for startup.
             * @param priority Target priority preset.
             */
            void                                                            SetPriority(ThreadPriority priority) noexcept;

        public:
            /**
             * @brief Issues a full sequentially-consistent memory fence.
             */
            static void                                                     MemoryBarrier() noexcept
            {
                std::atomic_thread_fence(std::memory_order_seq_cst);
            }

            /**
             * @brief Performs an acquire-load from an atomic value.
             * @tparam T Atomic value type.
             * @param v Atomic variable.
             * @return Loaded value.
             */
            template <typename T>
            static T                                                        VolatileRead(std::atomic<T>& v) noexcept
            {
                return v.load(std::memory_order_acquire);
            }

            /**
             * @brief Performs an operation intended as a volatile write helper.
             * @tparam T Atomic value type.
             * @param v Atomic variable.
             * @return Value returned by the current implementation.
             */
            template <typename T>
            static T                                                        VolatileWrite(std::atomic<T>& v) noexcept
            {
                return v.load(std::memory_order_release);
            }

            /**
             * @brief Reinterprets a plain pointer as atomic storage and initializes it.
             * @tparam T Value type.
             * @param v Pointer to source value.
             * @return Atomic pointer overlaying the same storage.
             */
            template <typename T>
            static std::atomic<T>*                                          From(const T* v) noexcept
            {
                std::atomic<T>* p = static_cast<std::atomic<T>*>(static_cast<void*>((T*)v));
                std::atomic_init(p, *v);
                return p;
            }

        public:
            /**
             * @brief Gets the current managed thread wrapper if registered.
             * @return Shared pointer to current thread object, or null.
             */
            static std::shared_ptr<Thread>                                  GetCurrentThread() noexcept;
            /**
             * @brief Gets logical processor count available to the process.
             * @return Processor count.
             */
            static int                                                      GetProcessorCount() noexcept;

        private:
            /** @brief Underlying OS thread object, accessed only under `_lifecycle`. */
            std::thread                                                     _thread;
            /** @brief Serializes thread-handle and one-shot startup transitions. */
            SynchronizedObject                                              _lifecycle;
            /** @brief True after a worker thread has been created for this one-shot wrapper. */
            bool                                                            _started = false;
            /**
             * @brief Set while a `Join()` is in progress so `Detach()` cannot run
             *        concurrently on the same `std::thread` object.
             * @note  Concurrent `join()`/`detach()` on one `std::thread` is undefined
             *        behaviour (crash during shutdown). `Join()` may not hold
             *        `_lifecycle` while blocking, or the worker thread's own `Detach()`
             *        would deadlock, so the flag serializes the two paths instead.
             */
            bool                                                            _joining = false;
            /** @brief User-supplied entry-point callback, accessed only under `_lifecycle`. */
            ThreadStart                                                     _start;
            /** @brief Mutex guarding thread-local storage and exposed to existing callers. */
            SynchronizedObject                                              _syncobj;
            /** @brief Per-thread key-value storage map. */
            ThreadLocalStorageData                                          _tls;
        };
    }
}
