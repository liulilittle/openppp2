#include <ppp/app/client/dns/DnsController.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/configurations/AppConfiguration.h>

#include <utility>

namespace ppp::app::client::dns {

DnsController::DnsController(
    std::unique_ptr<IDnsPolicy> policy,
    std::shared_ptr<IDnsTimerScheduler> timers) noexcept
    : policy_(std::move(policy)),
      timers_(std::move(timers)) {
}

DnsController::~DnsController() noexcept = default;

bool DnsController::Open(
    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
    const std::shared_ptr<boost::asio::io_context>& context,
    bool proxy_only
#if defined(_LINUX)
    , const std::shared_ptr<ppp::net::ProtectorNetwork>& protect_network
#endif
) noexcept {
    if (!policy_) {
        return false;
    }
    policy_->SetUdpFlowRegistry(udp_flow_registry_);
    return policy_->Open(
        configuration,
        context,
        proxy_only
#if defined(_LINUX)
        , protect_network
#endif
    );
}

void DnsController::OnSessionInfo(
    const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions,
    bool allow_ipv6_response) noexcept {
    if (policy_) {
        policy_->OnSessionInfo(extensions, allow_ipv6_response);
    }
}

int DnsController::LoadRules(const ppp::string& rules, bool from_file) noexcept {
    return policy_ ? policy_->LoadRules(rules, from_file) : 0;
}

void DnsController::CollectReachabilityIps(
    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
    bool intercept_unmatched,
    const ppp::function<void(uint32_t)>& add_tunnel_ip,
    const ppp::function<void(uint32_t)>& add_nic_ip) noexcept {
    if (policy_) {
        policy_->CollectReachabilityIps(
            configuration, intercept_unmatched, add_tunnel_ip, add_nic_ip);
    }
}

boost::asio::ip::address DnsController::RewriteFakeIpAddress(
    const boost::asio::ip::address& address) const noexcept {
    return policy_ ? policy_->RewriteFakeIpAddress(address) : address;
}

std::shared_ptr<const routing::HumanRoutingRules> DnsController::GetHumanRoutingRules() const noexcept {
    return policy_ ? policy_->GetHumanRoutingRules() : nullptr;
}

bool DnsController::ResolveDestination(
    const ppp::net::IPEndPoint& endpoint,
    routing::ResolvedDestination& destination) const noexcept {
    if (policy_) {
        return policy_->ResolveDestination(endpoint, destination);
    }
    destination = routing::ResolvedDestination{};
    destination.original_endpoint = endpoint;
    destination.connect_endpoint = endpoint;
    return true;
}

bool DnsController::GetFakeIpRoute(uint32_t& network, int& prefix) const noexcept {
    return policy_ && policy_->GetFakeIpRoute(network, prefix);
}

bool DnsController::ConsumeUdpFlow(
    uint16_t local_port,
    const boost::asio::ip::udp::endpoint& remote) noexcept {

    return udp_flow_registry_ && udp_flow_registry_->Consume(local_port, remote);
}

std::shared_ptr<const DnsSessionContext> DnsController::OpenSession(
    const std::shared_ptr<IDnsTunnelTransport>& transport) noexcept {
    if (nullptr == transport || closed_.load(std::memory_order_acquire)) {
        return nullptr;
    }

    std::lock_guard<std::mutex> scope(syncobj_);
    if (closed_.load(std::memory_order_relaxed)) {
        return nullptr;
    }
    if (active_session_) {
        active_session_->Close();
    }
    active_session_ = std::make_shared<DnsSessionContext>(
        transport,
        generation_.fetch_add(1, std::memory_order_acq_rel) + 1);
    return active_session_;
}

bool DnsController::Configure(DnsQueryContext context) noexcept {
    if (!context.IsValid()) {
        return false;
    }

    std::lock_guard<std::recursive_mutex> lifecycle_scope(lifecycle_gate_);
    if (closed_.load(std::memory_order_acquire)) {
        return false;
    }

    std::lock_guard<std::mutex> scope(syncobj_);
    context.udp_flow_registry = udp_flow_registry_;
    context_ = std::move(context);
    configured_.store(true, std::memory_order_release);
    return true;
}

bool DnsController::HandleQuery(
    const std::shared_ptr<const DnsSessionContext>& session,
    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept {
    if (!policy_ || !session || !session->IsActive()) {
        return false;
    }

    std::lock_guard<std::recursive_mutex> lifecycle_scope(lifecycle_gate_);
    if (closed_.load(std::memory_order_acquire) || !session->IsActive()) {
        return false;
    }

    DnsQueryContext context;
    {
        std::lock_guard<std::mutex> scope(syncobj_);
        context = context_;
    }
    // Capture a weak self reference: the resolver callback may complete after this
    // controller has been closed or destroyed; bail out instead of touching freed memory.
    std::weak_ptr<DnsController> weak_self = weak_from_this();
    context.handle_resolver_response =
        [weak_self, session](const auto& pending, const auto& source, const auto& destination, auto response) noexcept {
            std::shared_ptr<DnsController> self = weak_self.lock();
            if (nullptr == self) {
                return;
            }
            self->HandleResolverResponse(session, pending, source, destination, std::move(response));
        };
    return context.IsValid() && policy_->HandleQuery(context, session, packet, frame, messages);
}

void DnsController::HandleResolverResponse(
    const std::shared_ptr<const DnsSessionContext>& session,
    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
    const boost::asio::ip::udp::endpoint& source,
    const boost::asio::ip::udp::endpoint& destination,
    ppp::vector<Byte> response) noexcept {
    if (!session) {
        return;
    }

    std::lock_guard<std::recursive_mutex> lifecycle_scope(lifecycle_gate_);
    if (closed_.load(std::memory_order_acquire) || !session->IsActive()) {
        return;
    }

    DnsQueryContext context;
    {
        std::lock_guard<std::mutex> scope(syncobj_);
        context = context_;
    }
    DnsResponseHandlerPorts ports;
    if (context.configuration && context.configuration->udp.dns.cache) {
        ports.enable_dns_cache = true;
        ports.write_cache = context.write_cache;
    }
    ports.datagram_output = context.datagram_output;
    if (session) {
        ports.tunnel_send = [session](const auto& source_ep, const auto& destination_ep, const void* packet, int size) noexcept {
            return session->Send(source_ep, destination_ep, packet, size);
        };
    }
    DnsResponseHandler::HandleWithPorts(
        ports, messages, source, destination, std::move(response));
}

void DnsController::Close() noexcept {
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    std::shared_ptr<DnsSessionContext> session;
    {
        // Drain any response already producing output, then publish the closed state
        // without holding this gate across policy/timer shutdown callbacks.
        std::lock_guard<std::recursive_mutex> lifecycle_scope(lifecycle_gate_);
        {
            std::lock_guard<std::mutex> scope(syncobj_);
            session = std::move(active_session_);
            context_ = DnsQueryContext();
            configured_.store(false, std::memory_order_release);
        }
        if (session) {
            session->Close();
        }
    }
    if (timers_) {
        timers_->CancelAll();
    }
    if (policy_) {
        policy_->Close();
    }
}

bool DnsController::IsClosed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

bool DnsController::IsConfigured() const noexcept {
    return configured_.load(std::memory_order_acquire);
}

bool DnsController::HasActiveSession() const noexcept {
    std::lock_guard<std::mutex> scope(syncobj_);
    return active_session_ && active_session_->IsActive();
}

}
