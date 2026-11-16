#pragma once

/**
 * @file DnsInterceptor.h
 * @brief Owns DNS rules, resolver lifecycle, and intercepted query handling.
 */

#include <ppp/app/client/dns/IDnsPolicy.h>
#include <ppp/app/client/dns/FakeIpPool.h>
#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/stdafx.h>

namespace ppp { namespace configurations { class AppConfiguration; } }
namespace ppp { namespace dns { class DnsResolver; class DnsUdpFlowRegistry; } }
namespace ppp::app::client::dns { class PolicyResolverService; }

#if defined(_LINUX)
namespace ppp { namespace net { class ProtectorNetwork; } }
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                class DnsInterceptor final : public IDnsPolicy {
                public:
                    using RuleMap = ppp::unordered_map<ppp::string, Rule::Ptr>;

                    DnsInterceptor() noexcept;

                    bool Open(
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        const std::shared_ptr<boost::asio::io_context>& context,
                        bool proxy_only
#if defined(_LINUX)
                        , const std::shared_ptr<ppp::net::ProtectorNetwork>& protect_network
#endif
                    ) noexcept;

                    void Close() noexcept override;

                    void OnSessionInfo(
                        const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions,
                        bool allow_ipv6_response) noexcept;

                    int LoadRules(const ppp::string& rules, bool from_file = false) noexcept;

                    void CollectReachabilityIps(
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        bool intercept_unmatched,
                        const ppp::function<void(uint32_t)>& add_tunnel_ip,
                        const ppp::function<void(uint32_t)>& add_nic_ip) noexcept;
                    void SetUdpFlowRegistry(
                        const std::shared_ptr<ppp::dns::DnsUdpFlowRegistry>& registry) noexcept override;
                    void SetPolicyRuntime(const std::shared_ptr<policy::PolicyRuntime>& runtime) noexcept override;
                    void SetPolicyFakeIpStore(const std::shared_ptr<DurableFakeIpStore>& store) noexcept override;
                    void SetDirectSocketProtector(const ppp::function<bool(boost::asio::ip::tcp::socket::native_handle_type)>& protect) noexcept override;
                    bool ResolvePolicyDestination(const std::string& domain,
                        const std::shared_ptr<const policy::PolicySnapshot>& snapshot,
                        const std::shared_ptr<const DnsSessionContext>& session,
                        ppp::coroutines::YieldContext& yield, boost::asio::ip::address& address) noexcept override;

                    boost::asio::ip::address RewriteFakeIpAddress(
                        const boost::asio::ip::address& address) const noexcept override;
                    std::shared_ptr<const routing::HumanRoutingRules> GetHumanRoutingRules() const noexcept override;
                    bool ResolveDestination(
                        const ppp::net::IPEndPoint& endpoint,
                        routing::ResolvedDestination& destination) const noexcept override;
                    bool GetFakeIpRoute(uint32_t& network, int& prefix) const noexcept override;
                    PolicyTelemetrySnapshot SnapshotPolicyTelemetry() const noexcept override;
                    void RecordPolicyDecision(policy::PolicyAction action) noexcept override;

                    bool HandleQuery(
                        const DnsQueryContext& context,
                        const std::shared_ptr<const DnsSessionContext>& session,
                        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept override;

                    std::shared_ptr<ppp::dns::DnsResolver> GetResolver() const noexcept {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        return dns_resolver_;
                    }

                    const RuleMap* RuleTables() const noexcept { return dns_ruless_; }

                    std::shared_ptr<const FakeIpPool> GetFakeIpPool() const noexcept { return std::atomic_load(&fake_ip_pool_); }

                private:
                    struct FakeIpRequestState final {
                        std::atomic_bool active{true};
                        std::atomic_uint64_t generation{0};
                    };

                    void SpawnFakeIpBackgroundResolve(
                        const std::shared_ptr<FakeIpPool>& pool,
                        const std::shared_ptr<ppp::dns::DnsResolver>& resolver,
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        const DnsRedirectPlanResult& plan,
                        const Rule::Ptr& rule,
                        const ppp::string& hostname,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const std::shared_ptr<const routing::HumanRoutingRules>& human_rules) noexcept;

                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration_;
                    std::shared_ptr<ppp::dns::DnsResolver> dns_resolver_;
                    std::shared_ptr<PolicyResolverService> policy_resolver_;
                    std::shared_ptr<policy::PolicyRuntime> policy_runtime_;
                    std::shared_ptr<DurableFakeIpStore> policy_fake_ip_store_;
                    std::shared_ptr<PolicyTelemetry> policy_telemetry_ = std::make_shared<PolicyTelemetry>();
                    std::shared_ptr<FakeIpRequestState> fake_ip_request_state_ = std::make_shared<FakeIpRequestState>();
                    ppp::function<bool(boost::asio::ip::tcp::socket::native_handle_type)> direct_socket_protector_;
                    std::shared_ptr<ppp::dns::DnsUdpFlowRegistry> udp_flow_registry_;
                    std::shared_ptr<FakeIpPool> fake_ip_pool_ = make_shared_object<FakeIpPool>();
                    std::shared_ptr<const routing::HumanRoutingRules> human_routing_rules_;
                    RuleMap dns_ruless_[3];
                    /** @brief Serializes runtime-generation publication and DNS rule-table access. */
                    mutable std::mutex syncobj_;
                };

            }
        }
    }
}
