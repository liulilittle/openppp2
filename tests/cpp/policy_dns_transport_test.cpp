#include <ppp/app/client/dns/PolicyResolverService.h>
#include <ppp/app/client/policy/PolicyRuntime.h>
#include <common/dnslib/message.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace client_dns = ppp::app::client::dns;
namespace policy = ppp::app::client::policy;
using Packet = ppp::vector<ppp::Byte>;
using Service = client_dns::PolicyResolverService;
using DnsMessage = ::dns::Message;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

Packet EncodeMessage(DnsMessage& message) {
    Packet packet(65535);
    std::size_t length = 0;
    Require(message.encode(packet.data(), packet.size(), length) == ::dns::BufferResult::NoError,
        "DNS test message must encode");
    packet.resize(length);
    return packet;
}

DnsMessage DecodeMessage(const Packet& packet) {
    DnsMessage message;
    Require(message.decode(packet.data(), packet.size()) == ::dns::BufferResult::NoError,
        "DNS test message must decode");
    return message;
}

Packet AResponse(const Packet& query, std::uint32_t ttl) {
    auto message = DecodeMessage(query);
    message.mQr = 1;
    message.mRA = 1;
    message.answers.emplace_back();
    auto& answer = message.answers.back();
    answer.mName = message.questions.front().mName;
    answer.mType = ::dns::RecordType::kA;
    answer.mClass = ::dns::RecordClass::kIN;
    answer.mTtl = ttl;
    auto address = std::make_shared<::dns::RDataA>();
    address->setAddress("203.0.113.9");
    answer.setRData(address);
    return EncodeMessage(message);
}

Packet NegativeResponse(const Packet& query, const std::string& zone, std::uint32_t rr_ttl,
    std::uint32_t minimum) {
    auto message = DecodeMessage(query);
    message.mQr = 1;
    message.mRA = 1;
    message.mRCode = 3;
    message.authorities.emplace_back();
    auto& soa_record = message.authorities.back();
    soa_record.mName = zone;
    soa_record.mType = ::dns::RecordType::SOA;
    soa_record.mClass = ::dns::RecordClass::kIN;
    soa_record.mTtl = rr_ttl;
    auto soa = std::make_shared<::dns::RDataSOA>();
    soa->mMName = "ns.example";
    soa->mRName = "hostmaster.example";
    soa->mMinimum = minimum;
    soa_record.setRData(soa);
    return EncodeMessage(message);
}

Packet EdnsQuery(const Packet& query, bool dnssec_ok, const std::string& ecs_address = {}) {
    auto message = DecodeMessage(query);
    message.additions.emplace_back();
    auto& opt_record = message.additions.back();
    opt_record.mType = ::dns::RecordType::kOPT;
    opt_record.mClass = static_cast<::dns::RecordClass>(1232);
    opt_record.mTtl = dnssec_ok ? 0x8000 : 0;
    auto options = std::make_shared<::dns::RDataOPT>();
    if (!ecs_address.empty()) {
        options->mData = {0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113};
        if (ecs_address == "198.51.100.0") options->mData[8] = 198, options->mData[9] = 51, options->mData[10] = 100;
    }
    opt_record.setRData(options);
    return EncodeMessage(message);
}

struct Transport final : client_dns::IDnsTunnelTransport {
    std::atomic_int sends{0};
    bool SendDnsDatagram(const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&, const void*, int) noexcept override {
        ++sends;
        return true;
    }
};

struct Fixture {
    boost::asio::io_context context;
    policy::PolicyRuntime runtime;
    std::shared_ptr<Transport> transport = std::make_shared<Transport>();
    std::shared_ptr<client_dns::DnsSessionContext> session =
        std::make_shared<client_dns::DnsSessionContext>(transport, 71);
    std::shared_ptr<const policy::PolicySnapshot> snapshot;
    Fixture(const std::vector<std::string>& servers = {"udp://192.0.2.53:5353"},
        const std::vector<policy::PolicyResolver::Server>& structured = {},
        const std::vector<policy::PolicyResolver::ServerRef>& order = {}) {
        policy::PolicySource source;
        source.rules_path = "dns-transport-test.rules";
        source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n[direct]\n=direct.example\n[proxy]\n=proxy.example\n[reject]\n=blocked.example\n";
        source.resolvers["local"] = {policy::PolicyAction::Direct, servers};
        policy::PolicyResolver remote;
        remote.via = policy::PolicyAction::Proxy;
        remote.servers = servers;
        remote.server_specs = structured;
        remote.server_order = order;
        if (remote.server_order.empty()) {
            for (std::size_t i = 0; i < servers.size(); ++i) remote.server_order.push_back({false, i});
            for (std::size_t i = 0; i < structured.size(); ++i) remote.server_order.push_back({true, i});
        }
        source.resolvers["remote"] = std::move(remote);
        const auto prepared = runtime.Prepare(source);
        Require(prepared.Ok() && runtime.Commit(prepared), "DNS fixture must install an actual runtime snapshot");
        snapshot = runtime.GetSnapshot();
        Require(snapshot && snapshot->Version() != 0, "Runtime snapshot version must exist");
    }
    void Drain() { context.restart(); context.poll(); }
};

void ProtocolsAndSameExitFallback() {
    Fixture fixture({"udp://192.0.2.53:5353", "tcp://198.51.100.53:5354",
        "tls://dns.example:853", "https://dns.example:443/dns-query"});
    struct Attempt {
        ppp::dns::Protocol protocol;
        std::string address, hostname, url;
        policy::PolicyAction via;
    };
    std::vector<Attempt> attempts;
    int completed = 0;
    Packet response;
    auto query = Service::BuildQuery("direct.example");
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const ppp::dns::ServerEntry& entry, policy::PolicyAction via, const Packet& packet,
            const std::shared_ptr<const client_dns::DnsSessionContext>& session, const Service::Callback& callback) {
            Require(packet == query, "Exchange must receive the original DNS query");
            Require(session == fixture.session && session->Generation() == 71, "Exchange must receive captured session");
            attempts.push_back({entry.protocol, {entry.address.data(), entry.address.size()},
                {entry.hostname.data(), entry.hostname.size()}, {entry.url.data(), entry.url.size()}, via});
            auto reply = Service::ErrorResponse(packet, attempts.size() % 4 == 3 ? 2 : 0);
            if (attempts.size() % 4 == 1) reply[0] ^= 1;
            if (attempts.size() % 4 == 2) reply[2] |= 0x02;
            callback(std::move(reply));
        });
    auto finish = [&](Packet packet) { ++completed; response = std::move(packet); };
    service->Resolve(fixture.snapshot, fixture.session, query, finish);
    fixture.context.run();
    Require(completed == 1 && !response.empty() && attempts.size() == 4, "Failures must progress through same-exit fallback exactly once");
    const std::vector<ppp::dns::Protocol> protocols = {ppp::dns::Protocol::UDP, ppp::dns::Protocol::TCP,
        ppp::dns::Protocol::DoT, ppp::dns::Protocol::DoH};
    const std::vector<std::string> addresses = {"192.0.2.53:5353", "198.51.100.53:5354", "dns.example:853", "dns.example:443"};
    for (std::size_t i = 0; i < attempts.size(); ++i) {
        Require(attempts[i].protocol == protocols[i] && attempts[i].address == addresses[i], "Protocol and authority must survive entry parsing");
        Require(attempts[i].via == policy::PolicyAction::Direct, "Direct fallback must never switch to proxy");
    }
    Require(attempts[2].hostname == "dns.example" && attempts[3].hostname == "dns.example" &&
        attempts[3].url == "https://dns.example:443/dns-query", "TLS peer hostname and DoH URL must survive entry parsing");
    attempts.clear(); completed = 0; response.clear();
    query = Service::BuildQuery("proxy.example");
    service->Resolve(fixture.snapshot, fixture.session, query, finish);
    fixture.context.restart(); fixture.context.run();
    Require(completed == 1 && attempts.size() == 4 && !response.empty(), "Proxy fallback must finish once");
    for (const auto& attempt : attempts) Require(attempt.via == policy::PolicyAction::Proxy, "Proxy fallback must never switch to direct");
    Require(fixture.transport->sends == 0, "Mock Exchange must not use network transport");
    service->Close(); fixture.Drain();
}

void RejectedQueriesNeverExchange() {
    Fixture fixture;
    int exchanges = 0, completed = 0;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const auto&, const auto&, const auto&) { ++exchanges; });
    Packet response;
    auto finish = [&](Packet packet) { ++completed; response = std::move(packet); };
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("blocked.example"), finish);
    fixture.Drain();
    Require(completed == 1 && response.size() >= 12 && (response[3] & 15) == 5, "Explicit reject must answer REFUSED without Exchange");
    auto aaaa = Service::BuildQuery("proxy.example");
    Require(aaaa.size() >= 4, "AAAA fixture needs a valid question");
    aaaa[aaaa.size() - 3] = 28;
    service->Resolve(fixture.snapshot, fixture.session, aaaa, finish);
    fixture.Drain();
    Require(completed == 2 && response.size() >= 12 && (response[3] & 15) == 0 && response[6] == 0 && response[7] == 0,
        "AAAA must answer empty NOERROR without Exchange");
    Require(Service::BuildQuery("bad..example").empty(), "BuildQuery must reject interior empty labels instead of changing question identity");
    for (const auto& domain : {std::string("bad..example"), std::string("-bad.example"), std::string("bad_name.example")}) {
        service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery(domain), finish);
        fixture.Drain();
    }
    service->Resolve(fixture.snapshot, fixture.session, Packet{1, 2, 3}, finish);
    fixture.Drain();
    Require(completed == 6 && exchanges == 0, "Malformed DNS/domain inputs must complete without Exchange");
    fixture.session->Close();
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"), finish);
    Require(completed == 7 && response.empty() && exchanges == 0, "Closed session must return empty without Exchange");
    service->Close(); fixture.Drain();
}

void LateResponseAfterSessionClose() {
    Fixture fixture({"udp://192.0.2.53:5353", "tcp://198.51.100.53:5354"});
    int exchanges = 0, completed = 0;
    Service::Callback late;
    Packet sent, response;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchanges; sent = query; late = callback;
        });
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [&](Packet packet) { ++completed; response = std::move(packet); });
    fixture.Drain();
    Require(exchanges == 1 && late && completed == 0, "Query must be pending before closing session");
    fixture.session->Close();
    late(Service::ErrorResponse(sent, 0));
    fixture.Drain();
    Require(completed == 1 && response.empty() && exchanges == 1 && fixture.transport->sends == 0,
        "Late success after close must neither emit DNS packet nor try fallback");
    late(Service::ErrorResponse(sent, 0)); fixture.Drain();
    Require(completed == 1, "Duplicate late response must not invoke completion twice");
    auto fresh = std::make_shared<client_dns::DnsSessionContext>(fixture.transport, 72);
    service->Resolve(fixture.snapshot, fresh, sent, [&](Packet packet) { ++completed; response = std::move(packet); });
    fixture.Drain();
    Require(exchanges == 2 && completed == 1, "A new session must perform fresh Exchange instead of reusing late closed-session response");
    late(Service::ErrorResponse(sent, 0)); fixture.Drain();
    Require(completed == 2 && !response.empty(), "Fresh session response must complete normally");
    service->Close(); fixture.Drain();
}

void TimeoutAndReentrantConcurrentClose() {
    Fixture fixture;
    std::vector<Service::Callback> late;
    int completed = 0;
    Packet response;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const auto&, const auto&, const Service::Callback& callback) { late.push_back(callback); });
    auto query = Service::BuildQuery("proxy.example");
    service->Resolve(fixture.snapshot, fixture.session, query, [&](Packet packet) { ++completed; response = std::move(packet); });
    fixture.context.run_for(std::chrono::milliseconds(1400));
    Require(completed == 1 && response.size() >= 12 && (response[3] & 15) == 2, "Timed out final upstream must complete with SERVFAIL once");
    for (const auto& callback : late) callback(Service::ErrorResponse(query, 0));
    fixture.Drain();
    Require(completed == 1, "Post-timeout upstream callback must not complete again");
    service->Close(); fixture.Drain();

    Fixture pending_fixture;
    std::atomic_int callbacks{0}, exchanges{0};
    auto pending = std::make_shared<Service>(pending_fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const auto&, const auto&, const auto&) { ++exchanges; });
    pending->Resolve(pending_fixture.snapshot, pending_fixture.session, query, [&](Packet packet) {
        Require(packet.empty(), "Service close must wake awaiter with no response");
        ++callbacks;
        pending->Close();
        pending->Resolve(pending_fixture.snapshot, pending_fixture.session, query, [&](Packet closed_packet) {
            Require(closed_packet.empty(), "Reentrant Resolve after close must refuse");
            ++callbacks;
        });
    });
    pending_fixture.Drain();
    Require(exchanges == 1, "Close test must have a pending operation");
    std::vector<std::thread> closers;
    for (unsigned i = 0; i < 4; ++i) closers.emplace_back([pending] { for (unsigned j = 0; j < 100; ++j) pending->Close(); });
    for (auto& closer : closers) closer.join();
    pending_fixture.context.restart(); pending_fixture.context.run();
    Require(callbacks == 2 && exchanges == 1, "Concurrent/reentrant close must not deadlock or duplicate completion");
}

void OverallDeadlineCompletesOnce() {
    Fixture fixture(std::vector<std::string>(8, "udp://192.0.2.53:5353"));
    std::vector<Service::Callback> late;
    int completed = 0;
    Packet response;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const auto&, const auto&, const Service::Callback& callback) { late.push_back(callback); });
    const auto query = Service::BuildQuery("proxy.example");
    service->Resolve(fixture.snapshot, fixture.session, query, [&](Packet packet) { ++completed; response = std::move(packet); });
    fixture.context.run_for(std::chrono::milliseconds(5400));
    Require(completed == 1 && response.size() >= 12 && (response[3] & 15) == 2,
        "Overall deadline must complete SERVFAIL even before exhausting all upstreams");
    Require(!late.empty() && late.size() < 8, "Overall deadline must stop trying remaining upstreams");
    const auto attempts = late.size();
    for (const auto& callback : late) callback(Service::ErrorResponse(query, 0));
    fixture.Drain();
    Require(completed == 1 && late.size() == attempts, "Late callbacks after deadline must neither complete nor retry");
    service->Close(); fixture.Drain();
}

void SuccessCallbackCanCloseReentrantly() {
    Fixture fixture;
    int completed = 0;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            callback(Service::ErrorResponse(query, 0));
        });
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"), [&](Packet response) {
        Require(!response.empty(), "Successful callback must retain response before reentrant close");
        ++completed;
        service->Close();
        service->Close();
    });
    fixture.context.run();
    Require(completed == 1, "Reentrant close from success callback must not deadlock or repeat completion");
}

void CoalescingAndIndependentCancellation() {
    Fixture fixture;
    auto telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    std::vector<Service::Callback> upstream;
    std::vector<Packet> sent;
    int exchanges = 0;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchanges; sent.push_back(query); upstream.push_back(callback);
        }, Service::NowFunction{}, telemetry);
    Packet first_result, second_result;
    int first_calls = 0, second_calls = 0;
    const auto first_query = Service::BuildQuery("proxy.example");
    auto second_query = first_query;
    second_query[0] ^= 0x21;
    auto first = service->Resolve(fixture.snapshot, fixture.session, first_query,
        [&](Packet packet) { ++first_calls; first_result = std::move(packet); });
    auto second = service->Resolve(fixture.snapshot, fixture.session, second_query,
        [&](Packet packet) { ++second_calls; second_result = std::move(packet); });
    fixture.Drain();
    Require(exchanges == 1 && upstream.size() == 1, "Equivalent DNS questions must share one upstream exchange");
    first.Cancel();
    fixture.Drain();
    Require(first_calls == 1 && first_result.empty() && second_calls == 0,
        "Canceling one waiter must complete only that waiter");
    upstream.front()(AResponse(sent.front(), 12));
    fixture.Drain();
    Require(second_calls == 1 && !second_result.empty(), "Remaining waiter must receive shared response");
    const auto first_message = DecodeMessage(first_result.empty() ? first_query : first_result);
    const auto second_message = DecodeMessage(second_result);
    Require(second_message.mId == DecodeMessage(second_query).mId && second_message.mId != first_message.mId,
        "Each waiter must receive its own transaction ID");
    Packet cached;
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [&](Packet packet) { cached = std::move(packet); });
    const auto counters = telemetry->Snapshot();
    Require(!cached.empty() && counters.dns_cache_misses == 2 && counters.dns_cache_coalesced == 1 &&
        counters.dns_cancelled == 1 && counters.dns_cache_hits == 1,
        "Resolver telemetry must count cache misses, coalescing, explicit cancellation, and cache hits");
    service->Close(); fixture.Drain();
}

void UpstreamFailuresAreCounted() {
    Fixture fixture({"udp://192.0.2.53:5353", "udp://192.0.2.54:5353"});
    auto telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    int exchanges = 0;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchanges;
            callback(exchanges == 1 ? Service::ErrorResponse(query, 2) : AResponse(query, 20));
        }, Service::NowFunction{}, telemetry);
    int completed = 0;
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [&](Packet response) { Require(!response.empty(), "Fallback after upstream failure must resolve"); ++completed; });
    fixture.context.run();
    const auto counters = telemetry->Snapshot();
    Require(completed == 1 && exchanges == 2 && counters.dns_upstream_failures == 1,
        "Resolver telemetry must count failed upstream responses before fallback");
    service->Close(); fixture.Drain();
}

void TelemetryIsPerServiceAndReadableAfterClose() {
    Fixture fixture;
    auto first_telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    auto second_telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    auto make_service = [&](const std::shared_ptr<client_dns::PolicyTelemetry>& telemetry) {
        return std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
            [](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
                callback(AResponse(query, 30));
            }, Service::NowFunction{}, telemetry);
    };
    auto first = make_service(first_telemetry);
    auto second = make_service(second_telemetry);
    auto query = Service::BuildQuery("proxy.example");
    first->Resolve(fixture.snapshot, fixture.session, query,
        [](Packet response) { Require(!response.empty(), "First service query must resolve"); });
    fixture.Drain();
    first->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [](Packet response) { Require(!response.empty(), "First service cache hit must resolve"); });
    second->Resolve(fixture.snapshot, fixture.session, query,
        [](Packet response) { Require(!response.empty(), "Second service query must resolve"); });
    fixture.Drain();
    first->Close();
    second->Close();
    fixture.Drain();
    const auto first_stats = first_telemetry->Snapshot();
    const auto second_stats = second_telemetry->Snapshot();
    Require(first_stats.dns_cache_misses == 1 && first_stats.dns_cache_hits == 1 &&
        second_stats.dns_cache_misses == 1 && second_stats.dns_cache_hits == 0 &&
        first_stats.policy_proxy == 2 && second_stats.policy_proxy == 1,
        "Resolver telemetry must remain isolated by service and readable after close");
}

void ExhaustedTimeoutAttemptsCountOneRequest() {
    Fixture fixture({"udp://192.0.2.53:5353", "udp://192.0.2.54:5354"});
    auto telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [](const auto&, auto, const Packet&, const auto&, const Service::Callback&) {},
        Service::NowFunction{}, telemetry);
    int completed = 0;
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [&](Packet response) {
            ++completed;
            Require(!response.empty() && (response[3] & 15) == 2,
                "Exhausted timeout attempts must complete with SERVFAIL");
        });
    fixture.context.run_for(std::chrono::milliseconds(2300));
    const auto counters = telemetry->Snapshot();
    Require(completed == 1 && counters.dns_timeout_attempts == 2 && counters.dns_timeouts == 1,
        "Two timed-out upstream attempts must count as one timed-out DNS request");
    service->Close(); fixture.Drain();
}

void CacheTtlZeroAndNegativeTtl() {
    Fixture fixture;
    auto now = std::make_shared<Service::Clock::time_point>(Service::Clock::time_point{});
    int exchanges = 0;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchanges; callback(AResponse(query, 10));
        }, [now] { return *now; });
    auto query = Service::BuildQuery("proxy.example");
    service->Resolve(fixture.snapshot, fixture.session, query, [](Packet response) {
        Require(!response.empty(), "Initial successful answer must complete");
    });
    fixture.Drain();
    *now += std::chrono::seconds(3);
    Packet cached;
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [&](Packet response) { cached = std::move(response); });
    auto cached_message = DecodeMessage(cached);
    Require(exchanges == 1 && cached_message.answers.front().mTtl == 7,
        "Cache hits must decrement TTL using the injected monotonic clock");
    service->Close(); fixture.Drain();

    Fixture zero_fixture;
    int zero_exchanges = 0;
    auto zero_service = std::make_shared<Service>(zero_fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& packet, const auto&, const Service::Callback& callback) {
            ++zero_exchanges; callback(AResponse(packet, 0));
        });
    for (int i = 0; i < 2; ++i) {
        zero_service->Resolve(zero_fixture.snapshot, zero_fixture.session, Service::BuildQuery("proxy.example"),
            [](Packet response) { Require(!response.empty(), "TTL zero answer still serves its current request"); });
        zero_fixture.Drain();
    }
    Require(zero_exchanges == 2, "TTL zero answers must not be cached");
    zero_service->Close(); zero_fixture.Drain();

    Fixture negative_fixture;
    auto negative_now = std::make_shared<Service::Clock::time_point>(Service::Clock::time_point{});
    int negative_exchanges = 0;
    auto negative_service = std::make_shared<Service>(negative_fixture.context,
        ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& packet, const auto&, const Service::Callback& callback) {
            ++negative_exchanges; callback(NegativeResponse(packet, "example", 80, 30));
        }, [negative_now] { return *negative_now; });
    auto negative_query = Service::BuildQuery("proxy.example");
    negative_service->Resolve(negative_fixture.snapshot, negative_fixture.session, negative_query,
        [](Packet response) { Require(!response.empty(), "NXDOMAIN with a zone SOA must complete"); });
    negative_fixture.Drain();
    *negative_now += std::chrono::seconds(4);
    Packet negative_cached;
    negative_service->Resolve(negative_fixture.snapshot, negative_fixture.session,
        Service::BuildQuery("proxy.example"), [&](Packet response) { negative_cached = std::move(response); });
    const auto negative_message = DecodeMessage(negative_cached);
    Require(negative_exchanges == 1 && negative_message.mRCode == 3 &&
        negative_message.authorities.front().mTtl == 26,
        "Negative cache must use min(SOA TTL, SOA minimum) and decrement it");
    negative_service->Close(); negative_fixture.Drain();
}

void LastCancellationCanReenterResolve() {
    Fixture fixture;
    std::vector<Service::Callback> upstream;
    std::vector<Packet> sent;
    int exchanges = 0, canceled = 0, completed = 0;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchanges; sent.push_back(query); upstream.push_back(callback);
        });
    Service::RequestHandle reentrant;
    const auto query = Service::BuildQuery("proxy.example");
    auto first = service->Resolve(fixture.snapshot, fixture.session, query, [&](Packet response) {
        Require(response.empty(), "Canceled waiter must complete empty");
        ++canceled;
        reentrant = service->Resolve(fixture.snapshot, fixture.session, query,
            [&](Packet result) { Require(!result.empty(), "Reentrant fresh flight must complete normally"); ++completed; });
    });
    fixture.Drain();
    Require(exchanges == 1, "Initial cancellable flight must begin once");
    first.Cancel();
    fixture.Drain();
    Require(canceled == 1 && exchanges == 2,
        "A callback that reenters Resolve must create a fresh flight after final waiter cancellation");
    upstream[0](AResponse(sent[0], 20));
    upstream[1](AResponse(sent[1], 20));
    fixture.Drain();
    Require(completed == 1, "Late completion from canceled flight must not affect its replacement");
    service->Close(); fixture.Drain();
}

void StructuredBootstrapResolution() {
    policy::PolicyResolver::Server structured;
    structured.uri = "tls://dns.example:853";
    structured.bootstrap = {"udp://192.0.2.10:53", "udp://192.0.2.11:53"};
    Fixture fixture({}, {structured});
    struct Attempt { std::string address, hostname, qname; policy::PolicyAction via; };
    std::vector<Attempt> attempts;
    int completed = 0;
    auto query = Service::BuildQuery("proxy.example");
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto& entry, auto via, const Packet& packet, const auto&, const Service::Callback& callback) {
            const auto question = DecodeMessage(packet).questions.front().mName;
            attempts.push_back({std::string(entry.address.data(), entry.address.size()),
                std::string(entry.hostname.data(), entry.hostname.size()), question, via});
            if (question == "dns.example" && entry.address == "192.0.2.10:53") {
                callback(Service::ErrorResponse(packet, 2));
            } else if (question == "dns.example") {
                callback(AResponse(packet, 60));
            } else {
                callback(AResponse(packet, 30));
            }
        });
    service->Resolve(fixture.snapshot, fixture.session, query, [&](Packet response) {
        Require(!response.empty(), "Resolved upstream target must return the requested DNS answer");
        ++completed;
    });
    fixture.context.run();
    Require(completed == 1 && attempts.size() == 3,
        "Bootstrap must try its declared resolver order before issuing the requested query");
    Require(attempts[0].address == "192.0.2.10:53" && attempts[1].address == "192.0.2.11:53" &&
        attempts[0].via == policy::PolicyAction::Direct && attempts[1].via == policy::PolicyAction::Direct,
        "Bootstrap lookups must use configured numeric endpoints through direct egress");
    Require(attempts[2].qname == "proxy.example" && attempts[2].address == "203.0.113.9:853" &&
        attempts[2].hostname == "dns.example" && attempts[2].via == policy::PolicyAction::Proxy,
        "Resolved IP must replace the socket endpoint while original TLS hostname and selected exit remain");
    service->Close(); fixture.Drain();

    auto prioritized = structured;
    prioritized.addresses = {"198.51.100.53"};
    Fixture address_fixture({}, {prioritized});
    int address_calls = 0;
    std::string address_endpoint, address_hostname;
    auto address_service = std::make_shared<Service>(address_fixture.context,
        ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto& entry, auto, const Packet& packet, const auto&, const Service::Callback& callback) {
            ++address_calls;
            address_endpoint.assign(entry.address.data(), entry.address.size());
            address_hostname.assign(entry.hostname.data(), entry.hostname.size());
            callback(AResponse(packet, 30));
        });
    address_service->Resolve(address_fixture.snapshot, address_fixture.session, query,
        [](Packet response) { Require(!response.empty(), "Literal endpoint address must resolve"); });
    address_fixture.context.run();
    Require(address_calls == 1 && address_endpoint == "198.51.100.53:853" && address_hostname == "dns.example",
        "Explicit addresses must take priority over bootstrap resolvers");
    address_service->Close(); address_fixture.Drain();
}

void BootstrapCancellationAndNamespace() {
    policy::PolicyResolver::Server first_spec;
    first_spec.uri = "tls://dns.example:853";
    first_spec.bootstrap = {"udp://192.0.2.20:53"};
    policy::PolicyResolver::Server second_spec = first_spec;
    second_spec.bootstrap = {"udp://192.0.2.21:53"};
    Fixture fixture({}, {first_spec});
    int exchanges = 0, callbacks = 0;
    std::vector<Service::Callback> pending;
    auto service = std::make_shared<Service>(fixture.context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet&, const auto&, const Service::Callback& callback) {
            ++exchanges; pending.push_back(callback);
        });
    const auto query = Service::BuildQuery("proxy.example");
    auto cancelled = service->Resolve(fixture.snapshot, fixture.session, query, [&](Packet response) {
        Require(response.empty(), "Cancel during bootstrap must complete the waiter empty");
        ++callbacks;
    });
    fixture.Drain();
    Require(exchanges == 1, "Hostname endpoint must begin with its explicit bootstrap resolver");
    cancelled.Cancel();
    fixture.Drain();
    pending.front()(AResponse(Service::BuildQuery("dns.example"), 30));
    fixture.Drain();
    Require(callbacks == 1 && exchanges == 1,
        "A late bootstrap answer after cancellation must not issue the target query");
    service->Close(); fixture.Drain();

    Fixture cache_fixture({}, {first_spec});
    Fixture other_bootstrap({}, {second_spec});
    int cache_exchanges = 0;
    auto cache_service = std::make_shared<Service>(cache_fixture.context,
        ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto& entry, auto, const Packet& packet, const auto&, const Service::Callback& callback) {
            ++cache_exchanges;
            if (entry.address == "192.0.2.20:53") callback(AResponse(packet, 60));
            else if (entry.address == "192.0.2.21:53") callback(AResponse(packet, 60));
            else callback(AResponse(packet, 30));
        });
    cache_service->Resolve(cache_fixture.snapshot, cache_fixture.session, query,
        [](Packet response) { Require(!response.empty(), "First bootstrap configuration must resolve"); });
    cache_fixture.context.run();
    cache_service->Resolve(other_bootstrap.snapshot, cache_fixture.session, query,
        [](Packet response) { Require(!response.empty(), "Changed bootstrap configuration must resolve independently"); });
    cache_fixture.context.restart(); cache_fixture.context.run();
    Require(cache_exchanges == 4,
        "Changing explicit bootstrap configuration must change the resolver cache namespace");
    cache_service->Close(); cache_fixture.Drain();
}

void BootstrapTimeoutAndMixedOrder() {
    policy::PolicyResolver::Server structured;
    structured.uri = "tls://dns.example:853";
    structured.addresses = {"198.51.100.53"};
    const std::vector<policy::PolicyResolver::ServerRef> order = {{true, 0}, {false, 0}};
    Fixture fixture({"udp://192.0.2.53:5353"}, {structured}, order);
    std::vector<std::string> attempts;
    int completed = 0;
    auto service = std::make_shared<Service>(fixture.context,
        ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto& entry, auto, const Packet& packet, const auto&, const Service::Callback& callback) {
            attempts.emplace_back(entry.address.data(), entry.address.size());
            if (entry.address == "198.51.100.53:853") callback(Service::ErrorResponse(packet, 2));
            else callback(AResponse(packet, 20));
        });
    service->Resolve(fixture.snapshot, fixture.session, Service::BuildQuery("proxy.example"),
        [&](Packet response) { Require(!response.empty(), "Mixed resolver list fallback must succeed"); ++completed; });
    fixture.context.run();
    Require(attempts.size() == 2 && attempts[0] == "198.51.100.53:853" &&
        attempts[1] == "192.0.2.53:5353" && completed == 1,
        "Structured and legacy resolver entries must retain their declared fallback order");
    service->Close(); fixture.Drain();

    policy::PolicyResolver::Server timed;
    timed.uri = "tls://dns.example:853";
    timed.bootstrap = {"udp://192.0.2.31:53", "udp://192.0.2.32:53"};
    Fixture timeout_fixture({}, {timed});
    int bootstrap_attempts = 0, timeout_completed = 0;
    auto telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    auto timeout_service = std::make_shared<Service>(timeout_fixture.context,
        ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto& entry, auto, const Packet& packet, const auto&, const Service::Callback& callback) {
            if (entry.address == "192.0.2.31:53") { ++bootstrap_attempts; return; }
            if (entry.address == "192.0.2.32:53") { ++bootstrap_attempts; callback(AResponse(packet, 60)); return; }
            callback(AResponse(packet, 20));
        }, Service::NowFunction{}, telemetry);
    timeout_service->Resolve(timeout_fixture.snapshot, timeout_fixture.session,
        Service::BuildQuery("proxy.example"), [&](Packet response) {
            Require(!response.empty(), "Bootstrap timeout fallback must eventually resolve"); ++timeout_completed;
        });
    timeout_fixture.context.run_for(std::chrono::milliseconds(1400));
    Require(bootstrap_attempts == 2 && timeout_completed == 1,
        "A bootstrap attempt timeout must advance to the next declared numeric resolver");
    const auto timeout_stats = telemetry->Snapshot();
    Require(timeout_stats.dns_timeout_attempts == 1 && timeout_stats.dns_timeouts == 0,
        "A recovered bootstrap timeout counts one attempt and no failed resolver request");
    timeout_service->Close(); timeout_fixture.Drain();
}

void CacheKeyIncludesDnsFlagsAndEcs() {
    Fixture fixture;
    std::vector<Service::Callback> upstream;
    std::vector<Packet> sent;
    int exchanges = 0;
    auto service = std::make_shared<Service>(fixture.context,
        ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchanges; sent.push_back(query); upstream.push_back(callback);
        });
    const auto base = Service::BuildQuery("proxy.example");
    auto no_recursion = base;
    no_recursion[2] &= static_cast<ppp::Byte>(~1);
    const auto dnssec = EdnsQuery(base, true);
    const auto ecs_a = EdnsQuery(base, false, "203.0.113.0");
    const auto ecs_b = EdnsQuery(base, false, "198.51.100.0");
    for (const auto& query : {base, no_recursion, dnssec, ecs_a, ecs_b})
        service->Resolve(fixture.snapshot, fixture.session, query, [](Packet) {});
    fixture.Drain();
    Require(exchanges == 5,
        "RD, DO and ECS differences must produce separate pending DNS operations");
    for (std::size_t i = 0; i < upstream.size(); ++i)
        upstream[i](AResponse(sent[i], 20));
    fixture.Drain();
    service->Close(); fixture.Drain();
}
}

int main() {
    try {
        ProtocolsAndSameExitFallback();
        RejectedQueriesNeverExchange();
        LateResponseAfterSessionClose();
        TimeoutAndReentrantConcurrentClose();
        OverallDeadlineCompletesOnce();
        SuccessCallbackCanCloseReentrantly();
        CoalescingAndIndependentCancellation();
        UpstreamFailuresAreCounted();
        TelemetryIsPerServiceAndReadableAfterClose();
        ExhaustedTimeoutAttemptsCountOneRequest();
        CacheTtlZeroAndNegativeTtl();
        LastCancellationCanReenterResolve();
        StructuredBootstrapResolution();
        BootstrapCancellationAndNamespace();
        BootstrapTimeoutAndMixedOrder();
        CacheKeyIncludesDnsFlagsAndEcs();
        std::cout << "policy DNS transport tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
