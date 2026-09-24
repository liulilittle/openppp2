#pragma once

#include <atomic>
#include <memory>
#include <mutex>

#include <ppp/app/client/dns/DnsSessionContext.h>
#include <ppp/app/client/dns/IDnsPolicy.h>
#include <ppp/dns/DnsUdpFlowRegistry.h>
#include <ppp/app/client/dns/IDnsTimerScheduler.h>

namespace ppp::configurations { class AppConfiguration; }
namespace ppp::app::protocol { struct VirtualEthernetInformationExtensions; }
#if defined(_LINUX)
namespace ppp::net { class ProtectorNetwork; }
#endif

namespace ppp::app::client::dns {

// Used through std::shared_ptr so async resolver callbacks can hold a weak reference
// to the controller and bail out once it has been destroyed (see HandleQuery).
class DnsController final : public std::enable_shared_from_this<DnsController> {
public:
    DnsController(
        std::unique_ptr<IDnsPolicy> policy,
        std::shared_ptr<IDnsTimerScheduler> timers) noexcept;
    ~DnsController() noexcept;

    bool Open(
        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
        const std::shared_ptr<boost::asio::io_context>& context,
        bool proxy_only
#if defined(_LINUX)
        , const std::shared_ptr<ppp::net::ProtectorNetwork>& protect_network
#endif
    ) noexcept;
    void OnSessionInfo(
        const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions,
        bool allow_ipv6_response) noexcept;
    int LoadRules(const ppp::string& rules, bool from_file = false) noexcept;
    void CollectReachabilityIps(
        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
        bool intercept_unmatched,
        const ppp::function<void(uint32_t)>& add_tunnel_ip,
        const ppp::function<void(uint32_t)>& add_nic_ip) noexcept;
    boost::asio::ip::address RewriteFakeIpAddress(
        const boost::asio::ip::address& address) const noexcept;
    std::shared_ptr<const routing::HumanRoutingRules> GetHumanRoutingRules() const noexcept;
    bool ResolveDestination(
        const ppp::net::IPEndPoint& endpoint,
        routing::ResolvedDestination& destination) const noexcept;
    bool GetFakeIpRoute(uint32_t& network, int& prefix) const noexcept;
    bool ConsumeUdpFlow(
        uint16_t local_port,
        const boost::asio::ip::udp::endpoint& remote) noexcept;

    std::shared_ptr<const DnsSessionContext> OpenSession(
        const std::shared_ptr<IDnsTunnelTransport>& transport) noexcept;
    bool Configure(DnsQueryContext context) noexcept;
    bool HandleQuery(
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
    void HandleResolverResponse(
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        ppp::vector<Byte> response) noexcept;
    void Close() noexcept;
    bool IsClosed() const noexcept;
    bool IsConfigured() const noexcept;
    bool HasActiveSession() const noexcept;

private:
    std::unique_ptr<IDnsPolicy> policy_;
    std::shared_ptr<IDnsTimerScheduler> timers_;
    std::shared_ptr<DnsSessionContext> active_session_;
    std::shared_ptr<ppp::dns::DnsUdpFlowRegistry> udp_flow_registry_ =
        std::make_shared<ppp::dns::DnsUdpFlowRegistry>();
    DnsQueryContext context_;
    std::atomic_uint64_t generation_{0};
    std::atomic_bool closed_{false};
    std::atomic_bool configured_{false};
    mutable std::recursive_mutex lifecycle_gate_;
    mutable std::mutex syncobj_;
};

}
