#pragma once

/**
 * @file VEthernetDatagramPort.h
 * @brief Datagram relay port for client-side virtual Ethernet exchange.
 *
 * @details
 * VEthernetDatagramPort represents a single UDP relay session on the client side.
 * Each port is keyed by a local source endpoint (the IP:port tuple from the TAP
 * device) and is owned by VEthernetExchanger's datagram port table.
 *
 * ### Responsibilities
 *  - Receives outbound UDP datagrams from the local virtual network and forwards
 *    them to the remote server through the active ITransmission channel.
 *  - Routes inbound UDP datagrams received from the server back to the local
 *    virtual network via the owning VEthernetNetworkSwitcher.
 *  - Tracks an inactivity timeout, using a shorter DNS-only timeout when the
 *    port handles only DNS traffic.
 *  - On Android, manages a real UDP socket to bypass VPN protection for direct
 *    OS-level communication.
 *
 * ### Threading model
 * All public methods must be called from the IO thread associated with the
 * owning io_context. The `syncobj_` mutex protects only the Android message
 * queue and the disposal flag path.
 *
 * ### Lifecycle
 * 1. Constructed by VEthernetExchanger::NewDatagramPort() on first UDP packet.
 * 2. On Android, Open() must be called in a coroutine before SendTo().
 * 3. IsPortAging() is checked periodically; expired ports are removed.
 * 4. Dispose() releases the socket and unregisters from the exchanger.
 *
 * This file is part of the project and is distributed under the terms of
 * the GNU General Public License v3.0 (GPL-3.0).
 */

#include <atomic>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/client/udp/UdpRelayHost.h>
#include <ppp/app/client/routing/UdpRoutingSelector.h>

#if defined(_ANDROID)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp::configurations { class AppConfiguration; }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            /**
             * @brief UDP datagram relay port bound to a single local source endpoint.
             *
             * @details
             * Instances are created by VEthernetExchanger on demand when a new UDP
             * source endpoint is seen from the virtual TAP interface. The port forwards
             * outbound datagrams over the VPN transmission channel and injects received
             * responses back into the local virtual network through the switcher.
             *
             * Inactivity timeouts enforce session cleanup:
             *  - DNS-only sessions: short timeout from `configuration->udp.dns.timeout`.
             *  - Regular sessions:  standard timeout from `configuration->udp.inactive.timeout`.
             *
             * @note
             * On Android, a real protected UDP socket is opened so that DNS and other
             * UDP traffic can bypass the VPN route protection without infinite recursion.
             */
            class VEthernetDatagramPort : public std::enable_shared_from_this<VEthernetDatagramPort> {
            public:
                /** @brief Application configuration type alias. */
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                /** @brief Shared pointer alias for application configuration. */
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                /** @brief Executors utility alias. */
                typedef ppp::threading::Executors                       Executors;
                /** @brief Shared pointer alias for Boost.Asio io_context. */
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                /** @brief Transmission interface alias. */
                typedef ppp::transmissions::ITransmission               ITransmission;
                /** @brief Shared pointer alias for transmission interface. */
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                /** @brief Internal mutex type. */
                typedef std::mutex                                      SynchronizedObject;
                /** @brief RAII lock guard for the internal mutex. */
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                /** @brief Shared pointer alias for owning exchanger. */
                typedef std::shared_ptr<VEthernetExchanger>             VEthernetExchangerPtr;

#if defined(_ANDROID)
            public:
                /** @brief Shared pointer alias for Android socket protector. */
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>     ProtectorNetworkPtr;

                /**
                 * @brief Buffered UDP datagram pending local delivery on Android.
                 *
                 * @details
                 * Android requires socket protection before send. Datagrams received
                 * before the socket is ready are queued here and flushed after Open().
                 */
                typedef struct {
                    std::shared_ptr<Byte>                               packet;        ///< Datagram payload buffer.
                    int                                                 packet_length = 0; ///< Payload length in bytes.
                    boost::asio::ip::udp::endpoint                      destinationEP; ///< Target UDP endpoint.
                    routing::RoutingAction                              action = routing::RoutingAction::Auto; ///< Per-datagram routing policy.
                }                                                       Message;

                /** @brief Queue of pending outbound messages on Android. */
                typedef ppp::list<Message>                              Messages;

            public:
                /**
                 * @brief Optional Android socket protector.
                 *
                 * @details
                 * Must be set before Open() is called on Android. The protector marks
                 * the real UDP socket so that its traffic bypasses the VPN tunnel.
                 */
                ProtectorNetworkPtr                                     ProtectorNetwork;
#endif

            public:
                /**
                 * @brief Initializes a datagram relay port bound to the given source endpoint.
                 *
                 * @param exchanger    Owning exchanger that manages this port's lifetime.
                 * @param transmission Active transport channel used for outbound forwarding.
                 * @param sourceEP     Local TAP-side UDP source endpoint this port represents.
                 */
                VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger, udp::UdpRelayHostPorts ports, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Releases all resources owned by the port.
                 *
                 * @note Calls Finalize() to unregister from the exchanger and close the socket.
                 */
                virtual ~VEthernetDatagramPort() noexcept;

            public:
                /**
                 * @brief Returns a shared self-reference.
                 * @return shared_ptr to this instance.
                 */
                std::shared_ptr<VEthernetDatagramPort>                  GetReference()     noexcept { return shared_from_this(); }

                /**
                 * @brief Returns the io_context used for async operations.
                 * @return Shared io_context pointer.
                 */
                ContextPtr                                              GetContext()       noexcept { return context_; }

                /**
                 * @brief Returns the immutable runtime configuration.
                 * @return Shared AppConfiguration snapshot.
                 */
                AppConfigurationPtr                                     GetConfiguration() noexcept { return configuration_; }

                /**
                 * @brief Returns the local UDP source endpoint this port represents.
                 * @return Reference to the source endpoint.
                 */
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept { return sourceEP_; }

            public:
                /**
                 * @brief Checks whether the port is disposed or has exceeded its inactivity timeout.
                 *
                 * @param now  Current tick count in milliseconds (from Executors::GetTickCount()).
                 * @return true if the port should be removed; false if still active.
                 */
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }

                /**
                 * @brief Disposes the relay port and releases owned resources.
                 *
                 * @note Safe to call multiple times; subsequent calls are no-ops.
                 *       Schedules Finalize() on the io_context thread.
                 */
                virtual void                                            Dispose() noexcept;

                /**
                 * @brief Sends a UDP payload using the legacy automatic routing policy.
                 *
                 * @param packet        Payload buffer pointer.
                 * @param packet_length Payload length in bytes.
                 * @param destinationEP Target UDP endpoint on the remote network.
                 * @return true if the datagram was forwarded; false on error.
                 * @note Refreshes the inactivity timeout on success.
                 */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

                /**
                 * @brief Sends a UDP payload using the supplied per-datagram routing action.
                 *
                 * @param packet        Payload buffer pointer.
                 * @param packet_length Payload length in bytes.
                 * @param destinationEP Target UDP endpoint on the remote network.
                 * @param action        Routing action evaluated independently for this datagram.
                 * @return true if the selected path accepted the datagram; false on error or
                 *         when direct routing is unsupported and therefore rejected fail-closed.
                 */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP, routing::RoutingAction action) noexcept;

                /**
                 * @brief Replaces the tunnel carrier while retaining this logical UDP flow.
                 * @param transmission New carrier, or null while the L3 session is suspended.
                 * @return true when the replacement uses this port's io_context and was installed.
                 */
                bool                                                    RebindTransmission(const ITransmissionPtr& transmission) noexcept;

#if defined(_ANDROID)
            public:
                /**
                 * @brief Opens the Android protected UDP socket and starts the loopback receive loop.
                 *
                 * @param y  Coroutine yield context; blocks until the socket is ready.
                 * @return true if the socket was protected and the receive loop started; false otherwise.
                 * @note ProtectorNetwork is mandatory: a missing protector or failed Protect() call
                 *       fails closed before readiness, queued-message flush, or receive-loop startup.
                 */
                bool                                                    Open(ppp::coroutines::YieldContext& y) noexcept;

            private:
                /**
                 * @brief Drains the pending message queue and starts the async receive loop.
                 *
                 * @return true if the loopback was set up; false on socket error.
                 * @note Android-only. Called internally after Open() completes.
                 */
                bool                                                    Loopback() noexcept;
#endif

            public: // P2-c: manager routes inbound datagrams without exchanger friendship
                /**
                 * @brief Handles a datagram received from the remote server for this source endpoint.
                 *
                 * @param packet         Pointer to the received payload buffer.
                 * @param packet_length  Payload length in bytes.
                 * @param destinationEP  Original source endpoint on the remote side (becomes local dest).
                 * @note Default implementation routes the datagram through the switcher's DatagramOutput.
                 */
                virtual void                                            OnMessage(const std::shared_ptr<Byte>& owner, void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

            private:
                /**
                 * @brief Finalizes the port: unregisters from exchanger and closes the socket.
                 * @note Called from Dispose() and the destructor.
                 */
                void                                                    Finalize() noexcept;

                /**
                 * @brief Refreshes the inactivity timeout based on the current traffic mode.
                 *
                 * @details
                 * DNS-only mode uses the shorter `udp.dns.timeout`; regular mode uses
                 * `udp.inactive.timeout`. Both values are multiplied by 1000 (ms).
                 */
                void                                                    Update() noexcept {
                    UInt64 now = Executors::GetTickCount();
                    if (onlydns_) {
                        timeout_ = now + (UInt64)configuration_->udp.dns.timeout * 1000;
                    }
                    else {
                        timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                    }
                }

                /**
                 * @brief Marks this port as finalized by an external caller (e.g. exchanger GC sweep).
                 * @note After this call the port will not re-enter the exchanger tables.
                 */
            public: // P2-c: manager needs the finalize signal without exchanger friendship
                void                                                    MarkFinalize() noexcept { finalize_ = true; }

            private:

            private:
                // Lifecycle state is shared with the manager GC thread (IsPortAging) and the
                // Dispose/Finalize path, so every field below is individually atomic.
                std::atomic<bool>                                       disposed_{false}; ///< True when Dispose() has been called.
                std::atomic<bool>                                       onlydns_{false};  ///< True when only DNS traffic has been seen.
                std::atomic<bool>                                       sendto_{false};   ///< True once the first SendTo() call succeeds.
                std::atomic<bool>                                       finalize_{false}; ///< Non-zero after MarkFinalize() is called.
                std::atomic<UInt64>                                     timeout_{0};      ///< Absolute tick-count expiry timestamp.
                /** @brief Guards disposal flag and Android message queue. */
                SynchronizedObject                                      syncobj_;
                /** @brief IO context for all async operations. */
                ContextPtr                                              context_;
                /** @brief Injected exchanger/switcher capabilities (no back-pointer coupling). */
                udp::UdpRelayHostPorts                                  ports_;
                /** @brief Lifecycle anchor only: keeps the owning exchanger alive across async
                 *         finalize; never dereferenced, all capabilities go through ports_. */
                VEthernetExchangerPtr                                   exchanger_;
                /** @brief Active transport channel for outbound forwarding. */
                ITransmissionPtr                                        transmission_;
                /** @brief Immutable configuration snapshot. */
                AppConfigurationPtr                                     configuration_;
                /** @brief Local TAP-side source endpoint represented by this port. */
                boost::asio::ip::udp::endpoint                          sourceEP_;
#if defined(_ANDROID)
                /** @brief Queue of pending outbound messages awaiting socket readiness. */
                Messages                                                messages_;
                /** @brief State machine flag for socket open progress (0=init, 1=opening, 2=open). */
                int                                                     opened_   = 0;
                /** @brief Real protected UDP socket used on Android to bypass VPN. */
                boost::asio::ip::udp::socket                            socket_;
                /** @brief Receive buffer for the Android UDP socket receive loop. */
                std::shared_ptr<Byte>                                   buffer_;
                /** @brief Last remote endpoint received from the Android UDP socket. */
                boost::asio::ip::udp::endpoint                          remoteEP_;
#endif
            };
        }
    }
}
