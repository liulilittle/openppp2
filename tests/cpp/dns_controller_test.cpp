#define BOOST_TEST_MODULE dns_controller_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsController.h>

namespace dns = ppp::app::client::dns;

namespace {

class FakeTimers final : public dns::IDnsTimerScheduler {
public:
    int cancel_all = 0;
    uint64_t Schedule(int64_t, std::function<void()>) noexcept override { return 1; }
    bool Cancel(uint64_t) noexcept override { return true; }
    void CancelAll() noexcept override { ++cancel_all; }
};

class FakeTransport final : public dns::IDnsTunnelTransport {
public:
    int sends = 0;

    bool SendDnsDatagram(
        const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&,
        const void*, int) noexcept override {
        ++sends;
        return true;
    }
};

struct ResolverCallbackState final {
    decltype(dns::DnsQueryContext::handle_resolver_response) callback;

    void Trigger() const {
        BOOST_REQUIRE(callback);
        callback(
            nullptr,
            boost::asio::ip::udp::endpoint(),
            boost::asio::ip::udp::endpoint(),
            ppp::vector<ppp::Byte>{0x12, 0x34});
    }
};

class FakePolicy final : public dns::IDnsPolicy {
public:
    explicit FakePolicy(std::shared_ptr<ResolverCallbackState> state = nullptr) noexcept
        : state_(std::move(state)) {
    }

    bool HandleQuery(
        const dns::DnsQueryContext& context,
        const std::shared_ptr<const dns::DnsSessionContext>&,
        const std::shared_ptr<ppp::net::packet::IPFrame>&,
        const std::shared_ptr<ppp::net::packet::UdpFrame>&,
        const std::shared_ptr<ppp::net::packet::BufferSegment>&) noexcept override {
        if (state_) {
            state_->callback = context.handle_resolver_response;
        }
        return true;
    }
    void Close() noexcept override {}

    std::shared_ptr<const ppp::app::client::routing::HumanRoutingRules>
    GetHumanRoutingRules() const noexcept override {
        return human_rules;
    }

    bool ResolveDestination(
        const ppp::net::IPEndPoint& endpoint,
        ppp::app::client::routing::ResolvedDestination& destination) const noexcept override {
        if (!human_rules) {
            return dns::IDnsPolicy::ResolveDestination(endpoint, destination);
        }
        destination.original_endpoint = endpoint;
        destination.connect_endpoint = ppp::net::IPEndPoint(htonl(0xCB007107u), endpoint.Port);
        destination.hostname = "resolved.example";
        destination.action = ppp::app::client::routing::RoutingAction::Proxy;
        destination.is_fake_ip = true;
        destination.is_resolved = true;
        return true;
    }

    std::shared_ptr<const ppp::app::client::routing::HumanRoutingRules> human_rules;

private:
    std::shared_ptr<ResolverCallbackState> state_;
};

dns::DnsQueryContext MakeQueryContext(int& datagram_outputs) {
    dns::DnsQueryContext context;
    context.datagram_output = [&datagram_outputs](const auto&, const auto&, const std::shared_ptr<ppp::Byte>&, void*, int, bool) {
        ++datagram_outputs;
        return true;
    };
    context.tap = std::shared_ptr<ppp::tap::ITap>(reinterpret_cast<ppp::tap::ITap*>(1), [](auto*) {});
    context.configuration = std::shared_ptr<ppp::configurations::AppConfiguration>(
        reinterpret_cast<ppp::configurations::AppConfiguration*>(1), [](auto*) {});
    context.io_context = std::make_shared<boost::asio::io_context>();
    context.emplace_timeout = [](void*, const auto&) { return true; };
    context.delete_timeout = [](void*) { return true; };
    context.handle_resolver_response = [](const auto&, const auto&, const auto&, auto) {};
    return context;
}

}

BOOST_AUTO_TEST_CASE(new_session_replaces_previous_generation) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(std::make_unique<FakePolicy>(), timers);
    auto first = controller.OpenSession(std::make_shared<FakeTransport>());
    auto second = controller.OpenSession(std::make_shared<FakeTransport>());
    BOOST_REQUIRE(first != nullptr);
    BOOST_REQUIRE(second != nullptr);
    BOOST_TEST(first->Generation() == 1u);
    BOOST_TEST(second->Generation() == 2u);
    BOOST_TEST(!first->IsActive());
    BOOST_TEST(second->IsActive());
    BOOST_TEST(controller.HasActiveSession());
    BOOST_TEST(!controller.IsConfigured());
}

BOOST_AUTO_TEST_CASE(close_stops_session_and_timers_and_rejects_new_sessions) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(std::make_unique<FakePolicy>(), timers);
    auto session = controller.OpenSession(std::make_shared<FakeTransport>());
    controller.Close();
    controller.Close();
    BOOST_TEST(!session->IsActive());
    BOOST_TEST(timers->cancel_all == 1);
    BOOST_TEST(!controller.HasActiveSession());
    BOOST_TEST(!controller.IsConfigured());
    BOOST_TEST(controller.OpenSession(std::make_shared<FakeTransport>()) == nullptr);
}

BOOST_AUTO_TEST_CASE(fake_ip_rewrite_is_owned_by_controller) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(std::make_unique<FakePolicy>(), timers);
    const auto ipv4 = boost::asio::ip::make_address("10.0.0.7");
    const auto ipv6 = boost::asio::ip::make_address("2001:db8::7");
    BOOST_TEST(controller.RewriteFakeIpAddress(ipv4) == ipv4);
    BOOST_TEST(controller.RewriteFakeIpAddress(ipv6) == ipv6);
}

BOOST_AUTO_TEST_CASE(query_context_accepts_standard_allocator_fallback) {
    int datagram_outputs = 0;
    dns::DnsQueryContext context = MakeQueryContext(datagram_outputs);

    BOOST_TEST(context.allocator == nullptr);
    BOOST_TEST(context.IsValid());
}

BOOST_AUTO_TEST_CASE(late_resolver_callback_after_close_has_no_output) {
    int datagram_outputs = 0;
    auto callback_state = std::make_shared<ResolverCallbackState>();
    auto transport = std::make_shared<FakeTransport>();
    auto controller = std::make_shared<dns::DnsController>(
        std::make_unique<FakePolicy>(callback_state),
        std::make_shared<FakeTimers>());

    BOOST_REQUIRE(controller->Configure(MakeQueryContext(datagram_outputs)));
    auto session = controller->OpenSession(transport);
    BOOST_REQUIRE(session != nullptr);
    BOOST_REQUIRE(controller->HandleQuery(session, nullptr, nullptr, nullptr));

    controller->Close();
    callback_state->Trigger();

    BOOST_TEST(datagram_outputs == 0);
    BOOST_TEST(transport->sends == 0);
}

BOOST_AUTO_TEST_CASE(late_resolver_callback_after_controller_destruction_is_safe) {
    int datagram_outputs = 0;
    auto callback_state = std::make_shared<ResolverCallbackState>();
    auto transport = std::make_shared<FakeTransport>();
    auto controller = std::make_shared<dns::DnsController>(
        std::make_unique<FakePolicy>(callback_state),
        std::make_shared<FakeTimers>());

    BOOST_REQUIRE(controller->Configure(MakeQueryContext(datagram_outputs)));
    auto session = controller->OpenSession(transport);
    BOOST_REQUIRE(session != nullptr);
    BOOST_REQUIRE(controller->HandleQuery(session, nullptr, nullptr, nullptr));

    controller.reset();
    callback_state->Trigger();

    BOOST_TEST(datagram_outputs == 0);
    BOOST_TEST(transport->sends == 0);
}

BOOST_AUTO_TEST_CASE(human_policy_snapshot_and_destination_resolution_are_forwarded) {
    auto policy = std::make_unique<FakePolicy>();
    auto expected_rules = std::make_shared<ppp::app::client::routing::HumanRoutingRules>();
    policy->human_rules = expected_rules;
    dns::DnsController controller(std::move(policy), std::make_shared<FakeTimers>());

    BOOST_TEST(controller.GetHumanRoutingRules() == expected_rules);
    const ppp::net::IPEndPoint original(htonl(0xC6120005u), 443);
    ppp::app::client::routing::ResolvedDestination destination;
    BOOST_REQUIRE(controller.ResolveDestination(original, destination));
    BOOST_TEST(destination.original_endpoint.Equals(original));
    BOOST_TEST(ntohl(destination.connect_endpoint.GetAddress()) == 0xCB007107u);
    BOOST_TEST(destination.connect_endpoint.Port == 443);
    BOOST_TEST(destination.hostname == "resolved.example");
    BOOST_TEST(static_cast<int>(destination.action) ==
        static_cast<int>(ppp::app::client::routing::RoutingAction::Proxy));
    BOOST_TEST(destination.is_fake_ip);
    BOOST_TEST(destination.is_resolved);
}

BOOST_AUTO_TEST_CASE(absent_human_policy_preserves_original_destination) {
    dns::DnsController controller(
        std::make_unique<FakePolicy>(),
        std::make_shared<FakeTimers>());
    BOOST_TEST(controller.GetHumanRoutingRules() == nullptr);

    const ppp::net::IPEndPoint original(htonl(0x08080808u), 53);
    ppp::app::client::routing::ResolvedDestination destination;
    BOOST_REQUIRE(controller.ResolveDestination(original, destination));
    BOOST_TEST(destination.original_endpoint.Equals(original));
    BOOST_TEST(destination.connect_endpoint.Equals(original));
    BOOST_TEST(static_cast<int>(destination.action) ==
        static_cast<int>(ppp::app::client::routing::RoutingAction::Auto));
    BOOST_TEST(!destination.is_fake_ip);
    BOOST_TEST(destination.is_resolved);
}
