#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file ITransmissionQoS.cpp
 * @brief Implements bandwidth-aware flow control for transmission reads.
 */

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        using BeginReadAsynchronousCallback = ITransmissionQoS::BeginReadAsynchronousCallback;

        /**
         * @brief Initializes QoS state and applies initial bandwidth.
         */
        ITransmissionQoS::ITransmissionQoS(const std::shared_ptr<boost::asio::io_context>& context, Int64 bandwidth) noexcept
            : disposed_(false)
            , context_(context)
            , bandwidth_(0)
            , last_(0)
            , traffic_(0) {
            SetBandwidth(bandwidth);
        }

        /**
         * @brief Ensures pending operations are released during destruction.
         */
        ITransmissionQoS::~ITransmissionQoS() noexcept {
            Finalize();
        }

        /** @brief Completes this waiter once and wakes an active coroutine wait. */
        bool ITransmissionQoS::ReadWaiter::Complete() noexcept {
            std::lock_guard<std::mutex> scope(syncobj_);
            if (completed_) {
                return false;
            }

            completed_ = true;
            if (resume_) {
                resume_();
            }
            return true;
        }

        /** @brief Suspends until completion, or consumes an already-latched completion. */
        bool ITransmissionQoS::ReadWaiter::Await(YieldContext& y) noexcept {
            std::unique_lock<std::mutex> scope(syncobj_);
            if (completed_) {
                return true;
            }

            resume_ = [&y]() noexcept { return y.R(); };
            scope.unlock();
            bool suspended = y.Suspend();
            scope.lock();
            resume_ = NULLPTR;
            return suspended;
        }

        /** @brief Production wait path, virtual only to expose deterministic admission tests. */
        bool ITransmissionQoS::AwaitRead(YieldContext& y, const ReadWaiterPtr& waiter) noexcept {
            return NULLPTR != waiter && waiter->Await(y);
        }

        /** @brief Completes all shared coroutine waiters exactly once. */
        int ITransmissionQoS::CompleteAllWaiters(ppp::list<ReadWaiterPtr>& waiters) noexcept {
            int events = 0;
            for (const ReadWaiterPtr& waiter : waiters) {
                if (NULLPTR != waiter && waiter->Complete()) {
                    events++;
                }
            }
            return events;
        }

        /**
         * @brief Executes all queued begin-read callbacks.
         * @param s Collection of begin-read callbacks.
         * @return Number of callbacks executed.
         */
        static int ITransmissionQoS_ResumeAllReads(ppp::list<BeginReadAsynchronousCallback>& s) noexcept {
            int events = 0;
            for (const BeginReadAsynchronousCallback& f : s) {
                f();
                events++;
            }

            return events;
        }

        /**
         * @brief Performs a throttled read under the current bandwidth policy.
         */
        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallback& cb) noexcept {
            if (length < 1) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionQosReadBytesLengthInvalid, NULLPTR);
            }

            if (NULLPTR == cb) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TransmissionQosReadBytesNullCallback, NULLPTR);
            }

            ReadWaiterPtr waiter;
            {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionClosing, NULLPTR);
                }

                if (IsPeek()) {
                    waiter = make_shared_object<ReadWaiter>();
                    if (NULLPTR == waiter) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, NULLPTR);
                    }
                    waiters_.emplace_back(waiter);
                }
            }

            if (NULLPTR != waiter && !AwaitRead(y, waiter)) {
                SynchronizedObjectScope scope(syncobj_);
                waiters_.remove(waiter);
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid, NULLPTR);
            }

            {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionClosing, NULLPTR);
                }
            }

            std::shared_ptr<Byte> packet = cb(y, &length);
            if (length > 0 && packet) {
                traffic_ += length;
            }

            return packet;
        }

        /**
         * @brief Accounts bytes after a completed read operation.
         */
        bool ITransmissionQoS::EndRead(int bytes_transferred) noexcept {
            if (bytes_transferred < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionQosEndReadInvalidBytes);
                return false;
            }
            else {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    return false;
                }
            }

            traffic_ += bytes_transferred;
            return true;
        }

        /**
         * @brief Schedules or executes a read-start callback based on throttle state.
         */
        bool ITransmissionQoS::BeginRead(const BeginReadAsynchronousCallback& cb) noexcept {
            if (cb) {
                bool bawait = false; 
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                        return false;
                    }

                    bawait = IsPeek();
                    if (bawait) {
                        reads_.emplace_back(cb);
                    }

                    break;
                }

                if (!bawait) {
                    cb();
                }

                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TransmissionQosBeginReadNullCallback);
            return false;
        }

        /**
         * @brief Marks the object disposed and releases all pending waits.
         */
        void ITransmissionQoS::Finalize() noexcept {
            ppp::list<BeginReadAsynchronousCallback> reads;
            ppp::list<ReadWaiterPtr> waiters;

            /**
             * @brief Atomically switches to disposed state and drains wait queues.
             */
            for (;;) {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
                last_     = 0;
                traffic_  = 0;

                reads     = std::move(reads_);
                reads_.clear();

                waiters   = std::move(waiters_);
                waiters_.clear();
                break;
            }

            ITransmissionQoS_ResumeAllReads(reads);
            CompleteAllWaiters(waiters);
        }

        /**
         * @brief Posts deferred disposal work to the associated io_context.
         */
        void ITransmissionQoS::Dispose() noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();

            boost::asio::post(*context, 
                [self, this, context]() noexcept {
                    Finalize();
                });
        }

        /**
         * @brief Posts periodic QoS window refresh and waiter release logic.
         */
        void ITransmissionQoS::Update(UInt64 tick) noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();

            boost::asio::post(*context, 
                [self, this, context, tick]() noexcept {

                    ppp::list<BeginReadAsynchronousCallback> reads;
                    ppp::list<ReadWaiterPtr> waiters;

                    /**
                     * @brief Releases deferred operations when a new second begins.
                     */
                    for (SynchronizedObjectScope scope(syncobj_);;) {
                        UInt64 now   = tick / 1000; 
                        if (now != last_) {
                            last_    = now;
                            traffic_ = 0;

                            reads    = std::move(reads_);
                            reads_.clear();

                            waiters  = std::move(waiters_);
                            waiters_.clear();
                        }

                        break;
                    }

                    ITransmissionQoS_ResumeAllReads(reads);
                    CompleteAllWaiters(waiters);
                });
        }
    }
}
