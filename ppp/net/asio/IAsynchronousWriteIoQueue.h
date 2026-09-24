#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file IAsynchronousWriteIoQueue.h
 * @brief Declares a serialized asynchronous write queue abstraction.
 *
 * Problem statement
 * -----------------
 * Boost.Asio TCP and UDP sockets are NOT safe for concurrent async_write
 * calls.  Issuing a second async_write before the first completes results
 * in interleaved, corrupted output.  @ref IAsynchronousWriteIoQueue solves
 * this by serialising all outbound packets through an internal FIFO queue:
 * only one async write is in flight at any time; subsequent callers are
 * enqueued and dispatched in order.
 *
 * Design
 * ------
 * - The abstract @ref DoWriteBytes method is implemented by subclasses to
 *   perform the actual platform I/O (TCP send, UDP sendto, WebSocket write, …).
 * - The public @ref WriteBytes(packet, length, cb) entry point and its
 *   coroutine twin @ref WriteBytes(y, packet, length) both delegate to the
 *   queue logic, which calls @ref DoWriteBytes only when no prior write is
 *   pending.
 * - @ref Dispose / @ref Finalize fail all queued callbacks with `false` and
 *   prevent further enqueuing.  Both funnel through a one-shot `exchange` guard
 *   so that concurrent or repeated calls drain the queue exactly once.
 *
 * Thread safety
 * -------------
 * - Dispatch ownership and accounting transitions (@ref in_flight_, @ref sending_,
 *   @ref queues_, and pending counters) are protected by @ref syncobj_.
 * - @ref disposed_ is `std::atomic_bool` to allow lock-free early-exit reads
 *   in @ref WriteBytes / @ref DoTryWriteBytesUnsafe without acquiring @ref syncobj_.
 *   One-shot finalization uses `exchange(acq_rel)`; reads use `load(acquire)` to establish
 *   happens-before ordering with the full critical-section path.
 *
 * Coroutine support
 * -----------------
 * @ref DoWriteYield bridges the callback-based queue with Boost.Asio coroutines:
 * it posts the enqueue call onto the strand, suspends the coroutine, and resumes
 * it when the completion callback fires.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Serialized asynchronous write queue for packet-oriented output.
             *
             * This base class guarantees in-order write dispatch and provides both callback
             * and coroutine-friendly APIs for enqueueing outbound buffers.
             *
             * Subclasses must implement @ref DoWriteBytes to perform the actual I/O and
             * invoke the supplied callback upon completion (success or failure).
             */
            class IAsynchronousWriteIoQueue : public std::enable_shared_from_this<IAsynchronousWriteIoQueue> {
            public:
                /** @brief Completion callback invoked with `true` on success, `false` on failure. */
                typedef ppp::function<void(bool)>                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;
                /** @brief Coroutine yield context alias used by @ref DoWriteYield. */
                typedef ppp::coroutines::YieldContext                   YieldContext;
                /** @brief Buffer allocator used for copying packet memory during enqueue. */
                typedef ppp::threading::BufferswapAllocator             BufferswapAllocator;
                /** @brief Mutex type protecting queue flags and the pending-write list. */
                typedef std::mutex                                      SynchronizedObject;
                /** @brief RAII lock guard for synchronised sections. */
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                /** @brief Atomic integer alias used in coroutine suspension bookkeeping. */
                typedef std::atomic<int>                                atomic_int;
                /** @brief Atomic boolean represented as int (-1 = pending, 0 = false, 1 = true). */
                typedef atomic_int                                      atomic_boolean;

            public:
                /**
                 * @brief Shared allocator used when cloning packet memory into the queue.
                 *
                 * Callers may read this value to allocate compatible buffers before calling
                 * @ref WriteBytes.  Assigned once during construction and never changed.
                 */
                const std::shared_ptr<BufferswapAllocator>              BufferAllocator;

            public:
                /**
                 * @brief Initializes the queue with a packet allocator.
                 * @param allocator  Shared allocator forwarded to @ref BufferAllocator;
                 *                   may be NULLPTR when the subclass manages its own buffers.
                 */
                IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Finalizes the queue and clears pending write contexts.
                 *
                 * Calls @ref Finalize internally; all queued @ref AsynchronousWriteBytesCallback
                 * instances are invoked with `false` before destruction completes.
                 */
                virtual ~IAsynchronousWriteIoQueue() noexcept;

            public:
                /**
                 * @brief Returns a shared reference to this queue instance.
                 * @return  shared_ptr keeping this object alive for at least one more scope.
                 */
                std::shared_ptr<IAsynchronousWriteIoQueue>              GetReference()          noexcept { return shared_from_this(); }

                /**
                 * @brief Returns the mutex guarding mutable queue state.
                 * @return  Reference to @ref syncobj_; callers may lock it for compound operations.
                 * @warning Holding this lock while calling any public method causes deadlock.
                 */
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }

                /**
                 * @brief Stops the queue and fails all pending operations.
                 *
                 * Delegates to @ref Finalize, which uses a one-shot `exchange` guard
                 * to ensure the queue is drained exactly once even when called
                 * concurrently from multiple threads or after the destructor.
                 * Subclasses should call this (or the base) from their own Dispose overrides.
                 */
                virtual void                                            Dispose() noexcept;

                /**
                 * @brief Copies raw bytes into a newly allocated shared buffer.
                 *
                 * Uses @p allocator when non-null; falls back to global `new[]` otherwise.
                 *
                 * @param allocator  Allocator to use; may be NULLPTR.
                 * @param data       Source data pointer.
                 * @param datalen    Number of bytes to copy; negative returns NULLPTR.
                 * @return           Shared byte buffer containing a copy of @p data, or NULLPTR
                 *                   on allocation failure.
                 */
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;

                /**
                 * @brief Returns a shared_ptr view of @p data backed by @p owner (zero-copy).
                 *
                 * When @p owner is non-null the function returns a wrap_shared_pointer slice
                 * into the owner buffer without copying.  When @p owner is null it falls back
                 * to the copy-based Copy(allocator, data, datalen) overload.
                 */
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<Byte>& owner, const void* data, int datalen) noexcept;

                /**
                 * @brief Returns the number of write contexts currently accepted but not yet completed.
                 * @return  Pending item count (queued + in-flight).
                 */
                int                                                     GetPendingItems() const noexcept { return pending_items_.load(std::memory_order_relaxed); }

                /**
                 * @brief Returns the total bytes of write contexts currently accepted but not yet completed.
                 * @return  Pending byte count.
                 */
                int                                                     GetPendingBytes() const noexcept { return pending_bytes_.load(std::memory_order_relaxed); }

                /**
                 * @brief Returns the configured maximum pending item count (0 = unlimited).
                 * @return  Max items threshold.
                 */
                int                                                     GetMaxPendingItems() const noexcept { return max_pending_items_.load(std::memory_order_relaxed); }

                /**
                 * @brief Configures the maximum pending item count.
                 *
                 * Negative values are clamped to 0 (unlimited).
                 *
                 * @param value  Max items; 0 disables the limit.
                 */
                void                                                    SetMaxPendingItems(int value) noexcept { max_pending_items_.store(value < 0 ? 0 : value, std::memory_order_relaxed); }

                /**
                 * @brief Returns the configured maximum pending byte count (0 = unlimited).
                 * @return  Max bytes threshold.
                 */
                int                                                     GetMaxPendingBytes() const noexcept { return max_pending_bytes_.load(std::memory_order_relaxed); }

                /**
                 * @brief Configures the maximum pending byte count.
                 *
                 * Negative values are clamped to 0 (unlimited).
                 *
                 * @param value  Max bytes; 0 disables the limit.
                 */
                void                                                    SetMaxPendingBytes(int value) noexcept { max_pending_bytes_.store(value < 0 ? 0 : value, std::memory_order_relaxed); }

            private:
                /**
                 * @brief Set of coroutine yield contexts waiting for their write to complete.
                 *
                 * Used internally by @ref DoWriteYield; entries are erased when the
                 * corresponding write callback fires.
                 */
                typedef ppp::unordered_set<YieldContext*>               YieldContextSet;

                /**
                 * @brief Context for a single queued write request.
                 *
                 * Holds all state necessary to dispatch one async write and invoke
                 * its completion callback exactly once, even if destruction races
                 * with an in-flight callback.
                 *
                 * Structure layout:
                 *   packet        = std::shared_ptr<Byte>,                 ///< Packet buffer
                 *   packet_length = int,                                   ///< Bytes to send
                 *   cb            = AsynchronousWriteBytesCallback,        ///< Completion handler
                 *   lockobj       = SynchronizedObject                     ///< Per-context lock
                 */
                class AsynchronousWriteIoContext final {
                public:
                    /** @brief Packet buffer to be transmitted. */
                    std::shared_ptr<Byte>                               packet;
                    /** @brief Number of bytes to write from @ref packet offset 0. */
                    int                                                 packet_length = 0;
                    /** @brief Completion callback and one-shot ownership token. */
                    AsynchronousWriteBytesCallback                      cb;

                public:
                    /**
                     * @brief Claims all terminal ownership for this context exactly once.
                     *
                     * The queue calls this while holding its synchronization object for an
                     * active context, or after exclusively detaching a waiting context. The
                     * winner receives callback and accounting length, then clears packet state
                     * so late completions cannot callback or account again.
                     */
                    bool                                                Claim(AsynchronousWriteBytesCallback& callback, int& length) noexcept {
                        if (NULLPTR == cb) {
                            return false;
                        }

                        callback = std::move(cb);
                        length = packet_length;
                        cb = NULLPTR;
                        packet.reset();
                        packet_length = 0;
                        return true;
                    }
                };

                /** @brief Shared pointer alias for write context objects. */
                typedef std::shared_ptr<AsynchronousWriteIoContext>     AsynchronousWriteIoContextPtr;
                /**
                 * @brief FIFO queue of contexts waiting behind @ref in_flight_.
                 *
                 * The front element is the next context selected after the current write
                 * reaches a terminal state; no dispatched context remains in this list.
                 */
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;

            private:
                /**
                 * @brief Starts one preselected in-flight context outside the queue lock.
                 *
                 * A synchronous completion may claim the context before DoWriteBytes returns.
                 * In that case a false start result is treated as already accepted. A genuine
                 * first-item start failure is silent; a queued-item start failure reports false
                 * and disposes the remaining queue.
                 *
                 * @param context Context already installed in @ref in_flight_.
                 * @param callback_on_start_failure Whether a start failure must callback false.
                 * @return true if accepted or synchronously completed; false on start failure.
                 */
                bool                                                    DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context, bool callback_on_start_failure) noexcept;

                /**
                 * @brief One-shot finalization that fails all pending operations.
                 *
                 * Uses `disposed_.exchange(true, acq_rel)` to guarantee exactly-once
                 * semantics: the first caller drains the pending queue and decrements
                 * backpressure counters; subsequent callers (Dispose, destructor,
                 * or concurrent threads) return immediately without touching state.
                 *
                 * After the exchange succeeds, acquires @ref syncobj_ to detach the
                 * explicit in-flight context and pending queue. Every detached context
                 * is claimed and counters are reset before callbacks run outside the lock.
                 */
                void                                                    Finalize() noexcept;

            protected:
                /**
                 * @brief Coroutine adapter that bridges callback-based writes to yield semantics.
                 *
                 * Posts the enqueue call onto the executor associated with @p y, suspends
                 * the coroutine, and resumes it when the callback fires.  Suitable for use
                 * inside Boost.Asio coroutine bodies (boost::asio::spawn).
                 *
                 * @tparam AsynchronousWriteCallback  Callback signature accepted by @p h.
                 * @tparam WriteHandler               Callable with signature
                 *   `bool(const PacketBuffer&, int, AsynchronousWriteCallback)`.
                 * @tparam PacketBuffer               Packet representation (e.g. shared_ptr<Byte>).
                 * @param y              Coroutine context used to suspend until completion.
                 * @param packet         Packet buffer passed to @p h.
                 * @param packet_length  Number of bytes to transmit.
                 * @param h              Write-starter callable that returns true when the async
                 *                       operation is accepted.
                 * @return               true if the I/O completed successfully; false on failure
                 *                       or if @p h rejected the operation.
                 */
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                bool                                                    DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    using atomic_int = std::atomic<int>;

                    std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                    if (NULLPTR == status) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueYieldStatusAllocFailed);
                        return false;
                    }

                    boost::asio::io_context* context = addressof(y.GetContext());
                    boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();

                    // Guard Suspend() behind the post result: if the executor is unavailable
                    // the lambda (and every ppp::coroutines::asio::R() inside it) will never
                    // run, so calling Suspend() would park the coroutine with no future
                    // Resume() – a permanent coroutine leak.
                    bool posted = ppp::threading::Executors::Post(context, strand,
                        [&y, status, h, packet, packet_length]() noexcept {
                            bool waiting = 
                                h(packet, packet_length,
                                    [&y, status](bool b) noexcept {
                                        ppp::coroutines::asio::R(y, *status, b);
                                    });

                            if (!waiting) {
                                ppp::coroutines::asio::R(y, *status, false);
                            }
                        });

                    if (false == posted) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                        return false;
                    }

                    y.Suspend();
                    return status->load() > 0;
                }

            protected:
                /**
                 * @brief Enqueues packet bytes for asynchronous transmission.
                 *
                 * If no write is currently in flight (@ref sending_ == false), the packet
                 * is dispatched immediately via @ref DoWriteBytes.  Otherwise it is
                 * appended to @ref queues_ and dispatched when the current write completes.
                 *
                 * @param packet        Shared buffer containing packet data.
                 * @param packet_length Number of valid bytes in @p packet.
                 * @param cb            Completion callback; invoked once when the write finishes.
                 * @return              true if the packet was accepted (queued or in flight);
                 *                      false when @ref disposed_ is true or @p packet is NULLPTR.
                 */
                virtual bool                                            WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                /**
                 * @brief Coroutine wrapper that waits for write completion.
                 *
                 * Internally calls @ref WriteBytes(packet, packet_length, cb) and suspends
                 * the coroutine until @p cb fires, then resumes returning the result.
                 *
                 * @param y              Coroutine context.
                 * @param packet         Shared buffer to transmit.
                 * @param packet_length  Number of bytes in @p packet.
                 * @return               true on write success; false on failure or disposal.
                 */
                bool                                                    WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

                /**
                 * @brief Subclass-implemented primitive that performs the actual I/O write.
                 *
                 * This pure-virtual method is called by the queue whenever the front packet
                 * is ready for transmission.  The implementation must call @p cb exactly once
                 * when the operation completes or fails.
                 *
                 * @param packet         Packet buffer; ownership is shared with the queue.
                 * @param offset         Byte offset into @p packet where data begins.
                 * @param packet_length  Number of bytes to send starting at @p offset.
                 * @param cb             Callback invoked with true on success, false on error.
                 * @return               true when the async operation was successfully initiated;
                 *                       false if the operation could not be started (in which case
                 *                       @p cb must NOT be called by the subclass).
                 */
                virtual bool                                            DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept = 0;

            private:
                /**
                 * @brief True once Dispose()/Finalize() has been called; read without the lock
                 *        only as an early-exit fast-path (the lock re-checks it to be definitive).
                 *
                 * @note  Stored as `std::atomic_bool` so that concurrent lock-free reads
                 *        (e.g. in WriteBytes/DoTryWriteBytesUnsafe) do not race with
                 *        lock-protected writes in Finalize().  One-shot finalization
                 *        uses `exchange(true, acq_rel)` to ensure exactly-once drain;
                 *        readers use `load(acquire)` to guarantee visibility of all
                 *        side-effects performed before the disposal flag was set.
                 */
                std::atomic_bool                                            disposed_{false};

                /**
                 * @brief True while an async write is in flight; always accessed under syncobj_.
                 *
                 * @note  Plain bool — safe because every read/write of sending_ is performed
                 *        while holding syncobj_, so no concurrent access exists.
                 */
                bool                                                    sending_  = false;

                /** @brief Mutex guarding in-flight, queued, sending, disposal, and accounting transitions. */
                SynchronizedObject                                      syncobj_;

                /** @brief The single context currently dispatched to @ref DoWriteBytes. */
                AsynchronousWriteIoContextPtr                           in_flight_;

                /** @brief FIFO list of contexts waiting behind @ref in_flight_. */
                AsynchronousWriteIoContextQueue                         queues_;

                /** @brief Number of write contexts accepted but not yet completed (queued + in-flight). */
                std::atomic<int>                                        pending_items_{0};

                /** @brief Total bytes of write contexts accepted but not yet completed. */
                std::atomic<int>                                        pending_bytes_{0};

                /**
                 * @brief Maximum number of pending write items before backpressure rejection.
                 *
                 * A value of 0 disables the item-count limit.  Default: 4096.
                 * Stored as std::atomic<int> to avoid data races between setter
                 * calls from configuration threads and lock-free reads in WriteBytes().
                 */
                std::atomic<int>                                        max_pending_items_{4096};

                /**
                 * @brief Maximum total bytes of pending writes before backpressure rejection.
                 *
                 * A value of 0 disables the byte-count limit.  Default: 16 MiB.
                 * Stored as std::atomic<int> to avoid data races between setter
                 * calls from configuration threads and lock-free reads in WriteBytes().
                 */
                std::atomic<int>                                        max_pending_bytes_{16 * 1024 * 1024};
            };
        }
    }
}
