#pragma once

/**
 * @file VEthernetNetworkTcpipConnection.h
 * @brief Declares TCP/IP connection bridging for the virtual Ethernet client.
 *
 * @details
 * VEthernetNetworkTcpipConnection is a per-session TCP client handler created by
 * VEthernetNetworkTcpipStack for each TCP flow accepted from the local TAP device.
 *
 * ### Connection strategy
 * The stack supplies one strict routing mode per flow. Direct forces the Rinetd
 * path and fails without tunnel fallback; Proxy skips Rinetd entirely; Auto keeps
 * the legacy bypass-first selection followed by VMUX or VPN transmission.
 *
 * ### Threading model
 * All virtual callbacks (BeginAccept, EndAccept, Establish) are invoked from the
 * IO strand associated with the connection. Dispose() is safe to call from any
 * thread.
 *
 * ### Lifecycle
 * 1. Constructed by VEthernetNetworkTcpipStack::BeginAcceptClient().
 * 2. Non-candidates connect before AckAccept; sniff candidates AckAccept immediately.
 * 3. After EndAccept stores the socket, candidates sniff, connect, then forward;
 *    non-candidates enter their already-connected forwarding loop unchanged.
 * 4. Dispose() tears down all forwarding channels.
 *
 * @license GPL-3.0
 */

#include <ppp/transmissions/ITransmission.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/xtcp/XtcpFirstLegHooks.h>
#include <ppp/app/client/routing/TcpRoutingSelector.h>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>

namespace ppp::configurations { class AppConfiguration; }
namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            /**
             * @brief Per-session TCP/IP forwarding handler for the client virtual Ethernet stack.
             *
             * @details
             * Derives from VNetstack::TapTcpClient and selects one of three forwarding
             * strategies for each accepted TCP flow:
             *
             *  - **Rinetd**: Direct OS-level TCP relay for bypass (non-VPN) destinations.
             *  - **VMUX**: Multiplexed sub-channel over an existing vmux session.
             *  - **VPN Transmission**: Full VirtualEthernetTcpipConnection tunnel path.
             *
             * The static helper templates Rinetd<TReference>() and Mux<TReference>() are
             * designed to be called from derived classes or companion handlers that share
             * the exchanger reference but manage their own lifecycle.
             *
             * @note
             * One instance is created per accepted TCP flow. Instances are short-lived and
             * self-dispose when the forwarding path closes.
             */
            class VEthernetNetworkTcpipConnection :
                public ppp::ethernet::VNetstack::TapTcpClient,
                public xtcp::XtcpSecondLegHooks {
            public:
                /** @brief VPN TCP/IP connection type alias. */
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;
                /** @brief Rinetd direct relay connection type alias. */
                typedef ppp::net::rinetd::RinetdConnection                  RinetdConnection;
                /** @brief Application configuration type alias. */
                typedef ppp::configurations::AppConfiguration               AppConfiguration;

            public:
                /**
                 * @brief Constructs a TCP/IP session handler bound to the given exchanger.
                 *
                 * @param exchanger  Shared exchanger providing configuration, switcher, and mux.
                 * @param context    Boost.Asio io_context for all async operations.
                 * @param strand     Serialized execution strand for this connection.
                 * @param routing_mode Per-flow IP/default fallback selection.
                 * @param routing_rules Immutable rules used for optional domain refinement.
                 * @param domain_sniff_candidate Whether accept must defer peer connection for sniffing.
                 */
                VEthernetNetworkTcpipConnection(
                    const std::shared_ptr<VEthernetExchanger>& exchanger,
                    const std::shared_ptr<boost::asio::io_context>& context,
                    const ppp::threading::Executors::StrandPtr& strand,
                    routing::TcpRoutingMode routing_mode,
                    const std::shared_ptr<const routing::HumanRoutingRules>& routing_rules,
                    bool domain_sniff_candidate) noexcept;

                /**
                 * @brief Releases all owned forwarding channel resources.
                 *
                 * @note Calls Finalize() to ensure all three connection paths are cleaned up.
                 */
                virtual ~VEthernetNetworkTcpipConnection() noexcept;

            public:
                /**
                 * @brief Returns the owning exchanger instance.
                 * @return Shared VEthernetExchanger pointer.
                 */
                std::shared_ptr<VEthernetExchanger>                         GetExchanger() noexcept { return exchanger_; }

                /**
                 * @brief Disposes this connection and all queued asynchronous resources.
                 *
                 * @note Safe to call multiple times; subsequent calls are no-ops.
                 *       Delegates to all active forwarding channels' Dispose() methods.
                 */
                virtual void                                                Dispose() noexcept override;
                virtual xtcp::XtcpDirectResult                              SendToPeer(const std::uint8_t* data, std::uint32_t length,
                    xtcp::XtcpUploadBudget::Reservation&& credit) noexcept override;
                virtual void                                                OnDownloadComplete(
                    const xtcp::XtcpDirectReadReservation& reservation,
                    xtcp::XtcpDirectCompletion completion) noexcept override;
                virtual void                                                SetDirectQueueTelemetry(
                    const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry) noexcept override;
                virtual void                                                ClosePeerSend() noexcept override;
                void                                                        SetExternalFirstLeg(
                    uint64_t runtime_generation,
                    uint64_t flow_generation,
                    const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks) noexcept;

            public:
                /**
                 * @brief Attempts to establish an rinetd bypass forwarding connection.
                 *
                 * @details
                 * Checks whether the destination IP is in the bypass list. If so, creates
                 * a VEthernetRinetdConnection adapter and opens it to the remote endpoint.
                 * The adapter relays lifecycle events (Update, Dispose) back to the owner.
                 *
                 * @tparam TReference  Owner type that provides GetContext(), GetStrand(),
                 *                     Update(), and Dispose() methods.
                 * @param reference    Shared owner reference for lifecycle event dispatch.
                 * @param exchanger    Active exchanger for configuration and switcher access.
                 * @param context      IO context.
                 * @param strand       Serialized execution strand.
                 * @param configuration  Application configuration snapshot.
                 * @param socket       Accepted local TCP socket from the TAP stack.
                 * @param remoteEP     Destination TCP endpoint to connect to directly.
                 * @param force        Bypass the legacy bypass-list gate when true.
                 * @param out          Receives the created RinetdConnection on success.
                 * @param y            Coroutine yield context; blocks until connected.
                 * @return  0 on success (out is valid),
                 *          1 if bypass is not applicable (destination not in bypass list),
                 *         -1 on failure (out is null, SetLastError called).
                 */
                template <class TReference>
                static int                                                  Rinetd(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const std::shared_ptr<boost::asio::io_context>&         context,
                    const ppp::threading::Executors::StrandPtr&             strand,
                    const std::shared_ptr<AppConfiguration>&                configuration,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP,
                    bool                                                    force,
                    std::shared_ptr<RinetdConnection>&                      out,
                    ppp::coroutines::YieldContext&                          y) noexcept;

                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const ppp::string&                                      host,
                    const int                                               port,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept;

                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept;

            protected:
                /**
                 * @brief Starts candidate sniff/connect/forward or the legacy forwarding loop.
                 *
                 * @return true if the forwarding coroutine was launched; false on error.
                 * @note Called by the base TapTcpClient after EndAccept() succeeds.
                 */
                virtual bool                                                Establish() noexcept override;

                /**
                 * @brief Acknowledges candidates immediately; otherwise connects before acknowledgment.
                 *
                 * @return true if acknowledgment or legacy peer setup was started; false on error.
                 * @note The non-candidate coroutine preserves the original ConnectToPeer/AckAccept order.
                 */
                virtual bool                                                BeginAccept() noexcept override;
                virtual bool                                                AckAccept() noexcept override;

                /**
                 * @brief Applies accepted-socket options before final accept handling.
                 *
                 * @param socket   Accepted TCP socket from the local TAP stack.
                 * @param natEP    NAT endpoint used for source address rewriting.
                 * @return true to proceed with accept; false to reject.
                 */
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept override;

#if defined(_IPHONE) || defined(IPHONE)
                virtual bool                                                StartNativeRelay() noexcept override;
                virtual bool                                                DeliverNativePayload(ppp::ethernet::VNetstack::tcp_hdr* tcp, int tcp_len) noexcept override;
#endif

            private:
                /**
                 * @brief Releases all active forwarding channels (VPN, rinetd, vmux).
                 * @note Called from Dispose() and the destructor.
                 */
                void                                                        Finalize() noexcept;
#if defined(_IPHONE) || defined(IPHONE)
                /** @brief Releases the held iOS child transmission slot, if any. */
                void                                                        ReleaseIosChildTransmissionSlot() noexcept;
#endif

                /**
                 * @brief Runs the currently selected forwarding path data loop.
                 *
                 * @param y  Coroutine yield context.
                 * @return true if the loop completed normally; false on error.
                 */
                bool                                                        Loopback(ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Selects and builds the forwarding path to the peer.
                 *
                 * @details
                 * ForceDirect uses only Rinetd, ForceProxy skips Rinetd, and LegacyAuto
                 * tries the bypass-gated Rinetd path before Mux or the full VPN path.
                 * Sets connection_, connection_rinetd_, or connection_mux_ on success.
                 *
                 * @param y  Coroutine yield context.
                 * @return true if the selected forwarding path was established; false otherwise.
                 */
                bool                                                        ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept;

                /** @brief Peeks the accepted payload and refines this flow's route on a domain match. */
                bool                                                        SniffDomainRouting(ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Schedules a coroutine on the configured executor or strand.
                 *
                 * @param coroutine  Coroutine function to execute.
                 * @return true if the coroutine was spawned; false on error.
                 */
                bool                                                        Spawn(const ppp::function<bool(ppp::coroutines::YieldContext&)>& coroutine) noexcept;

            private:
                /** @brief Owning exchanger providing mux, switcher, and configuration. */
                std::shared_ptr<VEthernetExchanger>                         exchanger_;
                /** @brief IP/default fallback, optionally refined after accepted-payload sniffing. */
                routing::TcpRoutingMode                                     routing_mode_;
                /** @brief Immutable human rules snapshot used only by sniff candidates. */
                std::shared_ptr<const routing::HumanRoutingRules>            routing_rules_;
                /** @brief True when peer connection must wait for bounded domain sniffing. */
                bool                                                        domain_sniff_candidate_ = false;
                /** @brief Active VPN tunnel TCP connection; null if not using VPN path. */
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
                /** @brief Active rinetd bypass connection; null if not using bypass path. */
                std::shared_ptr<RinetdConnection>                           connection_rinetd_;
                /** @brief Active VMUX sub-channel socket; null if not using mux path. */
                std::shared_ptr<vmux::vmux_skt>                             connection_mux_;
                std::weak_ptr<xtcp::XtcpFirstLegHooks>                     external_first_leg_hooks_;
                uint64_t                                                    external_runtime_generation_ = 0;
                uint64_t                                                    external_flow_generation_ = 0;
                std::atomic<bool>                                           external_ready_signaled_{false};
                std::atomic<bool>                                           external_closed_signaled_{false};
                std::mutex                                                  external_direct_sync_;
                std::weak_ptr<VirtualEthernetTcpipConnection>               external_direct_connection_;
#if defined(_IPHONE) || defined(IPHONE)
                /** @brief Tracks iOS per-flow server TCP slot held for mux=0 VPN path. */
                bool                                                        ios_child_transmission_slot_held_ = false;
                /** @brief Generation token for the held iOS child slot. */
                uint64_t                                                    ios_child_transmission_slot_generation_ = 0;
#endif
            };
        }
    }
}
