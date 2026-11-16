#pragma once

#include <memory>
#include <boost/asio/ip/tcp.hpp>

#include <ppp/app/client/dns/DnsQueryContext.h>
#include <ppp/app/client/dns/PolicyTelemetry.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>
#include <ppp/app/client/routing/ResolvedDestination.h>

namespace ppp::net::packet { class IPFrame; class UdpFrame; class BufferSegment; }
namespace ppp::configurations { class AppConfiguration; }
namespace ppp::dns { class DnsUdpFlowRegistry; }
namespace ppp::coroutines { class YieldContext; }
namespace ppp::app::client::policy { class PolicySnapshot; class PolicyRuntime; }
namespace ppp::app::protocol { struct VirtualEthernetInformationExtensions; }
#if defined(_LINUX)
namespace ppp::net { class ProtectorNetwork; }
#endif

namespace ppp::app::client::dns {

class DnsSessionContext;
class DurableFakeIpStore;

class IDnsPolicy {
public:
    virtual ~IDnsPolicy() noexcept = default;
    virtual bool Open(
        const std::shared_ptr<ppp::configurations::AppConfiguration>&,
        const std::shared_ptr<boost::asio::io_context>&,
        bool
#if defined(_LINUX)
        , const std::shared_ptr<ppp::net::ProtectorNetwork>&
#endif
    ) noexcept { return false; }
    virtual void OnSessionInfo(
        const ppp::app::protocol::VirtualEthernetInformationExtensions&,
        bool) noexcept {}
    virtual int LoadRules(const ppp::string&, bool = false) noexcept { return 0; }
    virtual void CollectReachabilityIps(
        const std::shared_ptr<ppp::configurations::AppConfiguration>&,
        bool,
        const ppp::function<void(uint32_t)>&,
        const ppp::function<void(uint32_t)>&) noexcept {}
    virtual void SetUdpFlowRegistry(const std::shared_ptr<ppp::dns::DnsUdpFlowRegistry>&) noexcept {}
    virtual void SetPolicyRuntime(const std::shared_ptr<policy::PolicyRuntime>&) noexcept {}
    virtual void SetPolicyFakeIpStore(const std::shared_ptr<DurableFakeIpStore>&) noexcept {}
    virtual void SetDirectSocketProtector(const ppp::function<bool(boost::asio::ip::tcp::socket::native_handle_type)>&) noexcept {}
    virtual bool ResolvePolicyDestination(const std::string&,
        const std::shared_ptr<const policy::PolicySnapshot>&,
        const std::shared_ptr<const DnsSessionContext>&,
        ppp::coroutines::YieldContext&, boost::asio::ip::address&) noexcept { return false; }
    virtual boost::asio::ip::address RewriteFakeIpAddress(
        const boost::asio::ip::address& address) const noexcept { return address; }
    virtual std::shared_ptr<const routing::HumanRoutingRules> GetHumanRoutingRules() const noexcept {
        return nullptr;
    }
    virtual bool ResolveDestination(
        const ppp::net::IPEndPoint& endpoint,
        routing::ResolvedDestination& destination) const noexcept {
        destination.original_endpoint = endpoint;
        destination.connect_endpoint = endpoint;
        return true;
    }
    virtual bool GetFakeIpRoute(uint32_t&, int&) const noexcept { return false; }
    virtual PolicyTelemetrySnapshot SnapshotPolicyTelemetry() const noexcept { return {}; }
    virtual void RecordPolicyDecision(policy::PolicyAction) noexcept {}
    virtual bool HandleQuery(
        const DnsQueryContext& context,
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept = 0;
    virtual void Close() noexcept = 0;
};

}
