#pragma once 

/**
 * @file VEthernetNetworkTcpipStack.h
 * @brief Declares the client TCP/IP virtual Ethernet stack facade.
 * @details This header exposes `VEthernetNetworkTcpipStack`, the concrete
 *          `VNetstack` subclass used by the client-side network switcher.
 *          It bridges accepted lwIP TCP flows to `VEthernetNetworkTcpipConnection`
 *          objects that forward traffic through the VPN transmission channel.
 * @license GPL-3.0
 */

#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>

namespace ppp::configurations { class AppConfiguration; }
namespace ppp::app::client::xtcp { class XtcpFirstLegHooks; }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            /**
             * @brief TCP/IP stack implementation used by the client network switcher.
             *
             * @details `VEthernetNetworkTcpipStack` subclasses `ppp::ethernet::VNetstack` and acts
             *          as the factory and timeout-policy provider for TCP client connections
             *          originating from the local virtual TAP device.
             *
             *          Lifecycle:
             *          - Constructed and owned by `VEthernetNetworkSwitcher`.
             *          - `BeginAcceptClient()` is called by the base class event loop for each
             *            new TCP flow accepted from the lwIP stack.
             *          - Timeout values are read from the associated `AppConfiguration` snapshot
             *            captured at construction time.
             *
             *          Thread safety:
             *          - All virtual overrides are called from the single IO thread that owns
             *            the `VEthernetNetworkSwitcher`.  No additional synchronization is needed.
             */
            class VEthernetNetworkTcpipStack : public ppp::ethernet::VNetstack {
            public:
                /**
                 * @brief Owning switcher used for exchanger and configuration access.
                 *
                 * @details Held as a `shared_ptr` so that `BeginAcceptClient()` can safely
                 *          capture the switcher reference into spawned connection objects
                 *          without risk of dangling pointers.
                 */
                const std::shared_ptr<VEthernetNetworkSwitcher>         Ethernet;

            public:
                /**
                 * @brief Constructs the stack bound to a specific client switcher.
                 *
                 * @param ethernet Shared pointer to the owning `VEthernetNetworkSwitcher`.
                 *                 Must not be null; the constructor extracts the configuration
                 *                 snapshot and stores it in `configuration_`.
                 */
                VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept;

                /**
                 * @brief Destroys the stack.
                 *
                 * @details The base class `VNetstack` destructor handles IO context teardown.
                 *          No additional cleanup is required at this level.
                 */
                virtual ~VEthernetNetworkTcpipStack() noexcept = default;

                bool BeginExternalAccept(
                    const boost::asio::ip::tcp::endpoint& localEP,
                    const boost::asio::ip::tcp::endpoint& remoteEP,
                    uint16_t source_port,
                    uint64_t runtime_generation,
                    uint64_t flow_generation,
                    const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks) noexcept;

                /** @brief XTCP-VNET-BRIDGE-BYPASS-001: takes ownership of the XTCP-side socketpair fd (fd >= 0), registers it for direct adoption, and falls back to listener pairing when fd < 0. */
                bool BeginExternalAcceptWithFd(
                    const boost::asio::ip::tcp::endpoint& localEP,
                    const boost::asio::ip::tcp::endpoint& remoteEP,
                    uint16_t source_port,
                    uint64_t runtime_generation,
                    uint64_t flow_generation,
                    const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks, int fd) noexcept;

            protected:
                /**
                 * @brief Returns the connect timeout in milliseconds for outbound sockets.
                 *
                 * @details Reads `configuration_->tcp.connect.timeout` (seconds) and converts
                 *          to milliseconds.  Called by the base class before each dial attempt.
                 *
                 * @return Connect timeout in milliseconds.
                 */
                virtual uint64_t                                        GetMaxConnectTimeout() noexcept override;

                /**
                 * @brief Returns the inactive established-connection timeout in milliseconds.
                 *
                 * @details Reads `configuration_->tcp.inactive.timeout` (seconds) and converts
                 *          to milliseconds.  The base class tears down connections that exceed
                 *          this value without any data transfer.
                 *
                 * @return Inactive connection timeout in milliseconds.
                 */
                virtual uint64_t                                        GetMaxEstablishedTimeout() noexcept override;

                /**
                 * @brief Creates and opens a TCP client handler for an accepted lwIP flow.
                 *
                 * @details Resolves fake destinations and selects the strict routing mode before
                 *          allocating `VEthernetNetworkTcpipConnection`. Unresolved fake addresses
                 *          and unsupported routing modes are rejected. Returns null on any failure.
                 *
                 * @param localEP  Local (TAP-side) TCP endpoint of the accepted connection.
                 * @param remoteEP Remote (Internet-side) TCP endpoint of the accepted connection.
                 * @return Shared pointer to the opened `TapTcpClient`, or null on failure.
                 */
                virtual std::shared_ptr<TapTcpClient>                   BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept override;
            
            private:
                /**
                 * @brief Cached configuration snapshot extracted from the owning switcher.
                 *
                 * @details Stored separately so that timeout queries do not require an
                 *          additional indirection through the `Ethernet` shared_ptr on the
                 *          hot path.
                 */
                std::shared_ptr<ppp::configurations::AppConfiguration>  configuration_;
            };
        }
    }
}
