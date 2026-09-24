#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file ITransmissionQoS.h
 * @brief Declares a lightweight bandwidth throttling helper for transmission reads.
 */

namespace ppp {
    namespace transmissions {
        /**
         * @brief Provides per-second traffic gating for asynchronous read operations.
         */
        class ITransmissionQoS : public std::enable_shared_from_this<ITransmissionQoS> {
        public:
            /** @brief Mutex type used for internal synchronization. */
            typedef std::mutex                                          SynchronizedObject;
            /** @brief RAII lock scope for SynchronizedObject. */
            typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;
            /** @brief Coroutine yield context type used for suspending bandwidth-limited reads. */
            typedef ppp::coroutines::YieldContext                       YieldContext;
            /** @brief Shared byte array returned by read callbacks. */
            typedef std::shared_ptr<Byte>                               ByteArrayPtr;
            /** @brief Signature for the underlying raw-read callback used by DoReadBytes. */
            typedef ppp::function<ByteArrayPtr(YieldContext&, int*)>    ReadBytesAsynchronousCallback;
            /** @brief Signature for a deferred begin-read callback queued when over budget. */
            typedef ppp::function<void()>                               BeginReadAsynchronousCallback;

        public:
            /**
             * @brief Creates a QoS controller bound to an io_context.
             * @param context Event loop used to serialize update/dispose callbacks.
             * @param bandwidth Bandwidth limit in Kbps; non-positive means unlimited.
             */
            ITransmissionQoS(const std::shared_ptr<boost::asio::io_context>& context, Int64 bandwidth) noexcept;
            /**
             * @brief Finalizes pending waiters and callbacks.
             */
            virtual ~ITransmissionQoS() noexcept;

        public:
            /** @brief Returns the io_context bound at construction. */
            std::shared_ptr<boost::asio::io_context>                    GetContext()                  noexcept { return context_; }
            /** @brief Returns a shared reference to this QoS instance. */
            std::shared_ptr<ITransmissionQoS>                           GetReference()                noexcept { return shared_from_this(); }
            /** @brief Returns the configured bandwidth limit in Kbps (0 = unlimited). */
            Int64                                                       GetBandwidth()                noexcept { return bandwidth_.load(std::memory_order_relaxed); }
            /**
             * @brief Updates the bandwidth limit.
             * @param bandwidth New limit in Kbps; values less than 1 disable throttling.
             * @note  Stored atomically with relaxed ordering; values below 1 are clamped to 0 (ReLU).
             */
            void                                                        SetBandwidth(Int64 bandwidth) noexcept { bandwidth_.store(bandwidth < 1 ? 0 : bandwidth, std::memory_order_relaxed); /* ReLU */ }
            /**
             * @brief Checks whether the current second already consumed the configured limit.
             * @return true if reads should be throttled; otherwise false.
             */
            bool                                                        IsPeek()                      noexcept {
                // The unit "bps" stands for bits per second, where "b" represents bits.
                // Therefore, 1 Kbps can be correctly expressed in English as "one kilobit per second," 
                // Where "K" stands for kilo - (representing a factor of 1, 000).
                Int64 bandwidth = bandwidth_.load(std::memory_order_relaxed);
                if (bandwidth < 1) {
                    return false;
                }

                UInt64 traffic = traffic_ >> 7;
                return traffic >= (UInt64)bandwidth;
            }

        public:
            /**
             * @brief Advances the QoS window using the provided clock tick.
             * @param tick Clock value in milliseconds.
             */
            virtual void                                                Update(UInt64 tick) noexcept;
            /**
             * @brief Schedules asynchronous disposal on the bound io_context.
             */
            virtual void                                                Dispose() noexcept;
            /**
             * @brief Reads bytes with QoS throttling support.
             * @param y Coroutine context.
             * @param length Requested payload size.
             * @param cb Read callback invoked when reading is permitted.
             * @return Packet pointer on success; otherwise nullptr.
             */
            virtual std::shared_ptr<Byte>                               ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallback& cb) noexcept;

        public:
            /**
             * @brief Starts a deferred read callback when throttling is active.
             * @param cb Callback to execute immediately or queue for later.
             * @return true if callback is accepted.
             */
            virtual bool                                                BeginRead(const BeginReadAsynchronousCallback& cb) noexcept;
            /**
             * @brief Records completed read traffic in bytes.
             * @param bytes_transferred Number of bytes read by transport.
             * @return true if traffic is accounted; otherwise false.
             */
            virtual bool                                                EndRead(int bytes_transferred) noexcept;

        public: 
            /**
             * @brief Reads through QoS when available and disposes transport on failure.
             * @tparam Reference Owner/self capture type.
             * @tparam Transmission Transmission implementation type.
             * @param y Coroutine context.
             * @param length Requested byte count.
             * @param self Owner/self reference kept by callback capture.
             * @param transmission Concrete transmission object.
             * @param qos Optional QoS instance.
             * @return Packet pointer on success; otherwise nullptr.
             */
            template <class Reference, class Transmission>  
            static std::shared_ptr<Byte>                                DoReadBytes(
                YieldContext&                                           y,
                const int                                               length,
                const Reference                                         self,
                Transmission&                                           transmission,
                const std::shared_ptr<ITransmissionQoS>                 qos) noexcept {

                if (length < 1) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> packet;
                if (NULLPTR != qos) {
                    packet = qos->ReadBytes(y, length, 
                        [self, &transmission, qos](YieldContext& y, int* length) noexcept {
                            return transmission.ReadBytes(y, *length);
                        });
                }
                else {
                    packet = transmission.ReadBytes(y, length);
                }

                if (NULLPTR != packet) {
                    return packet;
                }

                transmission.Dispose();
                return NULLPTR;
            }

        protected:
            /**
             * @brief Shared completion latch for one throttled coroutine read.
             * @details The QoS queue owns this state instead of a bare YieldContext pointer.
             *          A completion that wins before Await() is consumed without suspending.
             */
            class ReadWaiter final {
            public:
                bool                                                    Complete() noexcept;
                bool                                                    Await(YieldContext& y) noexcept;

            private:
                std::mutex                                              syncobj_;
                bool                                                    completed_ = false;
                ppp::function<bool()>                                   resume_;
            };
            typedef std::shared_ptr<ReadWaiter>                          ReadWaiterPtr;

            /** @brief Wait seam used by deterministic admission/completion tests. */
            virtual bool                                                AwaitRead(YieldContext& y, const ReadWaiterPtr& waiter) noexcept;

        private:
            /**
             * @brief Marks disposed and resumes all pending callbacks/coroutines.
             */
            void                                                        Finalize() noexcept;
            static int                                                  CompleteAllWaiters(ppp::list<ReadWaiterPtr>& waiters) noexcept;

        private:
            /** @brief Set when Dispose() has been called; prevents re-entry. */
            bool                                                        disposed_  = false;
            /** @brief Mutex protecting reads_ and waiters_ from concurrent modification. */
            SynchronizedObject                                          syncobj_;
            /** @brief Bound io_context used to post deferred callbacks and disposal. */
            std::shared_ptr<boost::asio::io_context>                    context_;
            /** @brief Configured bandwidth limit in Kbps; 0 means unlimited. Atomic for lock-free cross-thread reads. */
            std::atomic<Int64>                                          bandwidth_ = 0;
            /** @brief Millisecond timestamp of the start of the current QoS window. */
            UInt64                                                      last_      = 0;
            /** @brief Byte counter for the current one-second window (scaled; divide by 128 for Kbps). */
            std::atomic<UInt64>                                         traffic_   = 0;

            /** @brief Queue of deferred read callbacks waiting for QoS budget to open. */
            ppp::list<BeginReadAsynchronousCallback>                    reads_;
            /** @brief Shared waiter latches for throttled coroutine reads. */
            ppp::list<ReadWaiterPtr>                                    waiters_;
        };
    }
}
