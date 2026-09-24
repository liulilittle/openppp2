#pragma once

/**
 * @file VirtualEthernetNetworkTcpipConnection.h
 * @brief Declares server-side TCP/IP link handling for a virtual ethernet session.
 */

namespace ppp::configurations { class AppConfiguration; }
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;

            /**
             * @brief Owns one TCP/IP transport connection bound to a switch session.
             */
            class VirtualEthernetNetworkTcpipConnection : public std::enable_shared_from_this<VirtualEthernetNetworkTcpipConnection> {
            public:
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                   ITransmission;
                typedef std::shared_ptr<ITransmission>                      ITransmissionPtr;

            public:
                /**
                 * @brief Initializes the network connection wrapper.
                 * @param switcher Parent switcher that tracks connection lifecycle.
                 * @param id Session identifier.
                 * @param transmission Accepted transport channel.
                 */
                VirtualEthernetNetworkTcpipConnection(
                    const std::shared_ptr<VirtualEthernetSwitcher>&         switcher,
                    const Int128&                                           id,
                    const ITransmissionPtr&                                 transmission) noexcept;
                /** @brief Disposes transport resources when the object is destroyed. */
                virtual ~VirtualEthernetNetworkTcpipConnection() noexcept;

            public:
                std::shared_ptr<boost::asio::io_context>                    GetContext()       noexcept { return context_; }
                ppp::threading::Executors::StrandPtr                        GetStrand()        noexcept { return strand_; }
                Int128                                                      GetId()            noexcept { return id_; }
                ITransmissionPtr                                            GetTransmission()  noexcept { return transmission_; }
                AppConfigurationPtr                                         GetConfiguration() noexcept { return configuration_; }
                std::shared_ptr<VirtualEthernetSwitcher>                    GetSwitcher()      noexcept { return switcher_; }
                bool                                                        IsMux()            noexcept { return mux_; }

            public:
                /**
                 * @brief Accepts and runs a virtual ethernet TCP/IP connection.
                 * @param y Coroutine context used by async handshake/run logic.
                 * @return true if connection run completes in expected path; otherwise false.
                 */
                virtual bool                                                Run(ppp::coroutines::YieldContext& y) noexcept;
                /** @brief Refreshes inactivity timeout based on current connection state. */
                virtual void                                                Update() noexcept;
                /** @brief Asynchronously releases connection and transmission resources. */
                virtual void                                                Dispose() noexcept;
                void                                                        Dispose(ppp::function<void()> completion) noexcept;
                /**
                 * @brief Checks whether this port has timed out or been disposed.
                 * @param now Current tick count in milliseconds.
                 * @return true when disposed or timeout reached for non-mux links.
                 */
                bool                                                        IsPortAging(uint64_t now) noexcept { return disposed_ || (!mux_ && now >= timeout_); }

            private:
                /** @brief Performs final synchronous cleanup and deregistration from switcher. */
                void                                                        Finalize() noexcept;
                /**
                 * @brief Creates and accepts the protocol-level TCP/IP connection object.
                 * @param y Coroutine context for accept handshake.
                 * @return Accepted protocol connection or null on failure.
                 */
                std::shared_ptr<VirtualEthernetTcpipConnection>             AcceptConnection(ppp::coroutines::YieldContext& y) noexcept;
                /**
                 * @brief Attaches this connection into an existing multiplexed linklayer.
                 * @param connection Accepted protocol connection instance.
                 * @param vlan Expected mux vlan.
                 * @param seq Mux sequence value.
                 * @param ack Mux acknowledgement value.
                 * @param y Coroutine context for mux yielding.
                 * @return true if mux linklayer registration succeeds; otherwise false.
                 */
                bool                                                        AcceptMuxLinklayer(const std::shared_ptr<VirtualEthernetTcpipConnection>& connection, uint32_t vlan, uint32_t seq, uint32_t ack, ppp::coroutines::YieldContext& y) noexcept;

            private:
                // Cross-strand lifecycle/aging state: written on this connection's strand/coroutine,
                // read by the switcher aging scan (TickAllConnections) under syncobj_.
                std::atomic<bool>                                               disposed_ = { false };
                std::atomic<bool>                                               mux_      = { false };
                Int128                                                          id_       = 0;
                std::atomic<UInt64>                                             timeout_  = 0;
                ppp::threading::Executors::ContextPtr                       context_;
                ppp::threading::Executors::StrandPtr                        strand_;
                std::shared_ptr<VirtualEthernetSwitcher>                    switcher_;
                ITransmissionPtr                                            transmission_;
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
                AppConfigurationPtr                                         configuration_;
            };
        }
    }
}
