#pragma once

/**
 * @file VirtualEthernetDatagramPort.h
 * @brief Datagram port abstraction used by the server-side virtual ethernet exchanger.
 *
 * @details `VirtualEthernetDatagramPort` manages a single async UDP socket that
 *          relays packets between the internet and one virtual ethernet client session.
 *          Each unique client source endpoint (`sourceEP`) that sends a UDP datagram
 *          gets its own `VirtualEthernetDatagramPort` instance.
 *
 *          Key responsibilities:
 *          - Opens a UDP socket bound to a kernel-assigned local port.
 *          - Forwards datagrams received from the internet back to the client via
 *            the session transmission channel.
 *          - Tracks whether all traffic for this port is DNS-only and applies a
 *            shorter DNS timeout (`configuration_->udp.dns.timeout`) in that case.
 *          - Inserts inbound DNS responses into the server's namespace cache.
 *          - Provides two static helpers (`NamespaceQuery`) for cache lookup and update.
 *
 *          Lifecycle:
 *          - Created by `VirtualEthernetExchanger::NewDatagramPort()`.
 *          - `Open()` binds the socket and starts the asynchronous receive loop.
 *          - `SendTo()` sends a datagram and refreshes the activity timeout.
 *          - `IsPortAging(now)` returns true when the port has timed out or is disposed.
 *          - `Dispose()` schedules asynchronous teardown on the owning io_context.
 *
 *          Finalization coordination:
 *          - The `finalize_` bitfield flag (set by `MarkFinalize()`) allows the owner
 *            GC sweep to signal that the port is being externally released, preventing
 *            a double-free race between the owner's GC and self-disposal.
 *
 *          Thread safety:
 *          - All methods are called from the single io_context thread that owns the
 *            parent `VirtualEthernetExchanger`.  No explicit locking is required.
 */

namespace ppp::configurations { class AppConfiguration; }
#include <atomic>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/server/udp/ServerUdpRelayHost.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetExchanger;

            /**
             * @brief Represents one UDP relay port bound to a single virtual ethernet source endpoint.
             *
             * @details This object owns an async UDP socket, forwards packets between the
             *          local network and a transmission channel, and tracks DNS-only timeout
             *          behavior.  It also participates in DNS response caching via the
             *          `NamespaceQuery` static helpers.
             */
            class VirtualEthernetDatagramPort : public std::enable_shared_from_this<VirtualEthernetDatagramPort> {
            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                /**
                 * @brief Creates a UDP datagram relay port for a specific client source endpoint.
                 *
                 * @param exchanger   Owner exchanger that manages the lifetime of this port.
                 * @param transmission Transmission channel used to forward received packets back to the client.
                 * @param sourceEP    Client-side UDP source endpoint represented by this port.
                 */
                VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, ppp::app::server::udp::ServerUdpRelayHostPorts ports, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Finalizes resources and unregisters the port from the owner exchanger.
                 *
                 * @details Calls `Finalize()` to ensure the socket is closed and the transmission
                 *          reference is released even if `Dispose()` was never called.
                 */
                virtual ~VirtualEthernetDatagramPort() noexcept;

            public:
                /** @brief Returns a shared self-reference via `shared_from_this()`. */
                std::shared_ptr<VirtualEthernetDatagramPort>            GetReference() noexcept      { return shared_from_this(); }
                /** @brief Returns the io_context associated with this port. */
                ContextPtr                                              GetContext() noexcept        { return context_; }
                /** @brief Returns the application configuration snapshot. */
                AppConfigurationPtr                                     GetConfiguration() noexcept  { return configuration_; }
                /** @brief Returns the local UDP endpoint bound by the OS for outbound traffic. */
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept  { return localEP_; }
                /** @brief Returns the client-side source endpoint this port represents. */
                boost::asio::ip::udp::endpoint&                         GetSourceEndPoint() noexcept { return sourceEP_; }

            public:
                /**
                 * @brief Schedules asynchronous disposal of this port on the owning io_context.
                 *
                 * @details Posts a coroutine that closes the socket and releases the transmission.
                 *          Safe to call multiple times.
                 */
                virtual void                                            Dispose() noexcept;

                /**
                 * @brief Opens and configures the UDP socket, then starts the receive loop.
                 *
                 * @return True if the socket binds and the receive loop starts successfully.
                 */
                virtual bool                                            Open() noexcept;

                /**
                 * @brief Sends one UDP datagram to the destination endpoint and refreshes the timeout.
                 *
                 * @param packet        Pointer to the payload buffer.
                 * @param packet_length Payload size in bytes.
                 * @param destinationEP Target UDP endpoint.
                 * @return True on successful send and timeout refresh; false on socket error.
                 */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

                /** @brief Rebinds replies to a replacement carrier, or null while suspended. */
                virtual bool                                            RebindTransmission(const ITransmissionPtr& transmission) noexcept;

                /**
                 * @brief Checks whether the port is disposed or has exceeded its activity timeout.
                 *
                 * @param now Current monotonic tick count in milliseconds.
                 * @return True if the port should be considered aging and eligible for GC.
                 */
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }

                /**
                 * @brief Marks this port as externally finalized before the owner releases it.
                 *
                 * @details Set by the owner (exchanger GC sweep / session manager) before it drops
                 *          the shared_ptr.  Prevents a race between external release and a
                 *          self-triggered `Dispose()`.  Public since P2-e so the session manager can
                 *          signal it without friendship.
                 */
                void                                                    MarkFinalize() noexcept { finalize_ = true; }

            private:
                /** @brief Schedules one SENDTO frame on the transmission coroutine strand. */
                bool                                                    SendToClient(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& destinationEP, const Byte* packet, int packet_length) noexcept;

                /** @brief Closes the UDP socket and releases the transmission reference. */
                void                                                    Finalize() noexcept;

                /**
                 * @brief Initiates one asynchronous UDP receive cycle.
                 *
                 * @return True if the async_receive_from call is successfully posted.
                 */
                bool                                                    Loopback() noexcept;

                /**
                 * @brief Refreshes the activity timeout based on the current traffic type.
                 *
                 * @details Uses `configuration_->udp.dns.timeout` when `onlydns_` is true,
                 *          otherwise uses `configuration_->udp.inactive.timeout`.  Both values
                 *          are in seconds and are converted to milliseconds relative to the
                 *          current tick count.
                 */
                void                                                    Update() noexcept;

            private:
                /**
                 * @brief Lifecycle flags and timeout for this port.
                 *
                 * Fields:
                 *   - disposed_ — True after Dispose() is called.
                 *   - onlydns_  — True when all traffic through this port is DNS traffic.
                 *   - sendto_   — True while a SendTo operation is in progress.
                 *   - in_       — True when the port is in the inbound receive path.
                 *   - finalize_ — Set by MarkFinalize() to signal external GC completion.
                 *   - timeout_  — Absolute tick (ms) after which the port is considered aging.
                 *
                 * @details Every field is individually atomic because IsPortAging() is read by the
                 *          manager GC thread while SendTo()/Finalize()/receive completions run on
                 *          the owning io_context thread.
                 */
                std::atomic<bool>                                       disposed_{false};  ///< True after Dispose() is called.
                std::atomic<bool>                                       onlydns_{false};   ///< True when all datagrams are DNS traffic.
                std::atomic<bool>                                       sendto_{false};    ///< True while a SendTo is in flight.
                std::atomic<bool>                                       in_{false};        ///< True when port is in the inbound receive path.
                std::atomic<bool>                                       finalize_{false};  ///< Set by MarkFinalize() from the GC sweep.
                std::atomic<UInt64>                                     timeout_{0};       ///< Absolute expiry tick in milliseconds.
                std::shared_ptr<boost::asio::io_context>                context_;           ///< io_context for async operations.
                boost::asio::ip::udp::socket                            socket_;            ///< UDP socket for outbound/inbound traffic.
                ppp::app::server::udp::ServerUdpRelayHostPorts          ports_;             ///< Injected exchanger/switcher capabilities (P2-e-2).
                VirtualEthernetExchangerPtr                             exchanger_;         ///< Lifecycle anchor only; never dereferenced (P2-e-2).
                ITransmissionPtr                                        transmission_;      ///< Session transmission channel.
                AppConfigurationPtr                                     configuration_;     ///< Application configuration snapshot.
                std::shared_ptr<Byte>                                   buffer_;            ///< Thread-local 64KB receive buffer.
                boost::asio::ip::udp::endpoint                          localEP_;           ///< OS-assigned local UDP endpoint.
                boost::asio::ip::udp::endpoint                          remoteEP_;          ///< Most-recently-received remote endpoint.
                boost::asio::ip::udp::endpoint                          sourceEP_;          ///< Client-side source endpoint this port represents.
            };
        }
    }
}
