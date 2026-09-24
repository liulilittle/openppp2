#pragma once

#include <mutex>

#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file InternetControlMessageProtocol.h
 * @brief Declares asynchronous ICMP echo and translation helpers.
 *
 * @ref ppp::net::asio::InternetControlMessageProtocol provides the virtual-NIC
 * stack with the ability to forward ICMP echo requests from the TAP interface to
 * a real network interface and relay the responses back.
 *
 * Architecture
 * ------------
 * - @ref Echo() accepts a parsed @ref IPFrame / @ref IcmpFrame pair, sends a raw
 *   ICMP probe to the actual destination, and arms a timeout timer.
 * - When a reply arrives (or the timeout fires), the abstract @ref Output() method
 *   is called with a synthesised echo-reply or error @ref IPFrame.
 * - @ref ER() builds an ICMP Echo Reply from request metadata (used on successful reply).
 * - @ref TE() builds an ICMP Time Exceeded message (used when TTL expires in transit).
 *
 * Lifecycle
 * ---------
 * 1. Construct with a @ref BufferswapAllocator and an @p io_context.
 * 2. Override @ref Output() in a derived class to route generated packets back to
 *    the originating virtual NIC session.
 * 3. Call @ref Echo() from the IO thread for each inbound ICMP echo request.
 * 4. Call @ref Dispose() to cancel all in-flight probes and release resources.
 *
 * @note  All data-path methods must be invoked from the executor thread associated
 *        with the @p io_context supplied to the constructor.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /** @brief Forward declaration for per-request ICMP echo async context. */
            class InternetControlMessageProtocol_EchoAsynchronousContext;

            /**
             * @brief ICMP processing helper for asynchronous echo and error generation.
             *
             * Sends raw ICMP echo probes, tracks in-flight requests via a timeout table,
             * and reports translated ICMP responses through the abstract @ref Output interface.
             *
             * @note  This class is not thread-safe; all entry points must be called from
             *        the same IO executor thread (single-threaded Asio model).
             */
            class InternetControlMessageProtocol : public std::enable_shared_from_this<InternetControlMessageProtocol> {
                friend class                                                    InternetControlMessageProtocol_EchoAsynchronousContext;

            public:
                /** @brief Timer utility used for per-request timeout handling. */
                typedef ppp::threading::Timer                                   Timer;
                /** @brief Timeout callback functor type stored per in-flight request. */
                typedef Timer::TimeoutEventHandler                              TimeoutEventHandler;
                /** @brief Shared pointer to a timeout callback for lifetime management. */
                typedef Timer::TimeoutEventHandlerPtr                           TimeoutEventHandlerPtr;
                /**
                 * @brief Active timeout callback table indexed by asynchronous context pointer.
                 *
                 * Key:   raw pointer to the per-request async context (used as a unique ID).
                 * Value: shared timeout callback that cancels the request on expiry.
                 */
                typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>       TimeoutEventHandlerTable;
                /** @brief IPv4 packet frame type alias. */
                typedef ppp::net::packet::IPFrame                               IPFrame;
                /** @brief ICMP frame type alias. */
                typedef ppp::net::packet::IcmpFrame                             IcmpFrame;
                /** @brief Endpoint type used for output forwarding decisions. */
                typedef ppp::net::IPEndPoint                                    IPEndPoint;

            public:
                /**
                 * @brief Maximum wait time for an ICMP echo reply in milliseconds.
                 *
                 * Probes that do not receive a reply within this window are cancelled and
                 * the corresponding in-flight context is removed from @ref timeouts_.
                 */
                static constexpr int MAX_ICMP_TIMEOUT                           = 3000;

            public:
                /**
                 * @brief Shared allocator used for packet and frame buffer allocation.
                 *
                 * Passed to @ref IPFrame::Parse, @ref ER, and @ref TE for all dynamic
                 * buffer operations.  Assigned once at construction and never replaced.
                 */
                const std::shared_ptr<ppp::threading::BufferswapAllocator>      BufferAllocator;

            public:
                /**
                 * @brief Initializes ICMP protocol helper with allocator and executor context.
                 * @param allocator  Shared allocator for frame buffers.
                 * @param context    IO context used to drive the async receive loop and timers.
                 */
                InternetControlMessageProtocol(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<boost::asio::io_context>& context) noexcept;

                /**
                 * @brief Finalizes state and releases all pending timeout handlers.
                 *
                 * Calls @ref Finalize; all registered timeout callbacks are cancelled and
                 * their shared pointers are released.
                 */
                virtual ~InternetControlMessageProtocol() noexcept;

            public:
                /**
                 * @brief Returns the associated IO execution context.
                 * @return  Shared pointer to the io_context supplied at construction.
                 */
                std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept;

                /**
                 * @brief Returns a shared reference to this protocol instance.
                 * @return  shared_ptr keeping this object alive for callback scopes.
                 */
                std::shared_ptr<InternetControlMessageProtocol>                 GetReference() noexcept;

            public:
                /**
                 * @brief Sends an ICMP echo probe asynchronously and forwards the translated response.
                 *
                 * Creates an @ref InternetControlMessageProtocol_EchoAsynchronousContext, opens a
                 * raw ICMP socket, sends the probe to @p destinationEP, and arms a
                 * @ref MAX_ICMP_TIMEOUT millisecond timer.  On reply or timeout the helper
                 * synthesises an appropriate frame and calls @ref Output.
                 *
                 * @param packet       Original IPv4 frame received from the virtual NIC.
                 * @param frame        Parsed ICMP echo-request extracted from @p packet.
                 * @param destinationEP Destination endpoint for the raw ICMP probe.
                 * @return             true if the probe was successfully sent; false on error
                 *                     (e.g. socket open failure or @ref disposed_ is true).
                 */
                virtual bool                                                    Echo(
                    const std::shared_ptr<IPFrame>&                             packet,
                    const std::shared_ptr<IcmpFrame>&                           frame,
                    const IPEndPoint&                                           destinationEP) noexcept;

                /**
                 * @brief Asynchronously disposes protocol state on the executor thread.
                 *
                 * Posts a task to the IO context that calls @ref Finalize, ensuring all
                 * cleanup happens on the correct executor thread even if @ref Dispose is
                 * called from a different thread.
                 */
                virtual void                                                    Dispose() noexcept;

            public:
                /**
                 * @brief Builds an ICMP echo-reply packet from original request metadata.
                 *
                 * Swaps source/destination, sets type to ICMP_ECHOREPLY, preserves
                 * identification and sequence, and recalculates the checksum.
                 *
                 * @param packet     Original IP frame (provides source/destination addresses).
                 * @param frame      Original ICMP echo-request frame (provides id/seq/payload).
                 * @param ttl        TTL to place in the synthesised reply.
                 * @param allocator  Allocator for the reply frame's buffer.
                 * @return           Synthesised echo-reply IP frame; NULLPTR on allocation failure.
                 */
                static std::shared_ptr<IPFrame>                                 ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Builds an ICMP time-exceeded packet that embeds the original IP header.
                 *
                 * Constructs an ICMP Type 11 (Time Exceeded) message whose payload contains
                 * the first 8 bytes of the original datagram header as required by RFC 792.
                 *
                 * @param packet     Original IP frame triggering the TTL expiry.
                 * @param frame      Original ICMP frame (used for payload extraction).
                 * @param source     IPv4 source address (in network byte order) of the router
                 *                   generating the time-exceeded message.
                 * @param allocator  Allocator for the error frame's buffer.
                 * @return           Synthesised time-exceeded IP frame; NULLPTR on failure.
                 */
                static std::shared_ptr<IPFrame>                                 TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            protected:
                /**
                 * @brief Emits a generated packet to target endpoint via the implementation backend.
                 *
                 * Pure-virtual; overridden by derived classes to route the synthesised
                 * ICMP response back to the originating virtual NIC session.
                 *
                 * @param packet       Synthesised IP frame to deliver (echo-reply or time-exceeded).
                 * @param destinationEP Endpoint identifying the original requester.
                 * @return             true if the packet was accepted for delivery; false otherwise.
                 */
                virtual bool                                                    Output(
                    const IPFrame*                                              packet,
                    const IPEndPoint&                                           destinationEP) noexcept = 0;

            private:
                /**
                 * @brief Marks disposed and clears all registered timeout callbacks.
                 *
                 * Sets @ref disposed_ = true, then iterates @ref timeouts_ and calls
                 * cancel on each @ref Timer.  Called from both the destructor and the
                 * async @ref Dispose path.
                 */
                void                                                            Finalize() noexcept;

            private:
                /** @brief Set to true after @ref Dispose / @ref Finalize; guards re-entry. */
                bool                                                            disposed_ = false;
                /** @brief IO executor used for posting state transitions and timer callbacks. */
                std::shared_ptr<boost::asio::io_context>                        executor_;
                /**
                 * @brief Serializes access to @ref timeouts_.
                 *
                 * Echo() registers entries from the caller thread while receive
                 * completions and @ref Finalize remove/clear them from executor threads,
                 * so the table is guarded by this mutex.  @ref Finalize moves the table
                 * out under the lock and invokes the handlers lock-free to avoid
                 * re-entrant deadlock through @ref InternetControlMessageProtocol_EchoAsynchronousContext::Release.
                 */
                std::mutex                                                      timeouts_syncobj_;
                /** @brief Map of in-flight echo context pointers to their timeout handlers. */
                TimeoutEventHandlerTable                                        timeouts_;
            };
        }
    }
}
