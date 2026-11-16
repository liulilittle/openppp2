#include <ppp/app/client/dns/PolicyResolverService.h>
#include <ppp/app/client/dns/IDnsTunnelTransport.h>
#include <ppp/app/client/policy/PolicyRuntime.h>
#include <common/dnslib/message.h>
#include <json/json.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace client_dns = ppp::app::client::dns;
namespace policy = ppp::app::client::policy;
using Packet = ppp::vector<ppp::Byte>;
using Service = client_dns::PolicyResolverService;
using Clock = std::chrono::steady_clock;

struct Options {
    std::size_t samples = 5000;
    std::string output;
};

struct FakeTransport final : client_dns::IDnsTunnelTransport {
    bool SendDnsDatagram(const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&, const void*, int) noexcept override {
        return true;
    }
};

std::uint64_t ParseUnsigned(const std::string& text, const char* name, std::uint64_t max) {
    if (text.empty()) throw std::runtime_error(std::string("missing value for ") + name);
    std::size_t consumed = 0;
    const auto value = std::stoull(text, &consumed, 10);
    if (consumed != text.size() || value > max) throw std::runtime_error(std::string("invalid value for ") + name);
    return value;
}

Options ParseOptions(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--help") {
            std::cout << "usage: policy_dns_cache_benchmark [--samples N] [--output FILE]\n";
            std::exit(0);
        }
        if (i + 1 >= argc) throw std::runtime_error("option requires a value: " + arg);
        const std::string value(argv[++i]);
        if (arg == "--samples") options.samples = static_cast<std::size_t>(ParseUnsigned(value, "--samples", 1000000));
        else if (arg == "--output") options.output = value;
        else throw std::runtime_error("unknown option: " + arg);
    }
    if (!options.samples) throw std::runtime_error("samples must be positive");
    return options;
}

Packet AResponse(const Packet& query, std::uint32_t ttl) {
    ::dns::Message message;
    if (query.size() < 12 || message.decode(query.data(), query.size()) != ::dns::BufferResult::NoError ||
        message.questions.size() != 1) return {};
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
    Packet response(65535);
    std::size_t size = 0;
    if (message.encode(response.data(), response.size(), size) != ::dns::BufferResult::NoError) return {};
    response.resize(size);
    return response;
}

Packet Query(const std::string& domain) {
    return Service::BuildQuery(domain);
}

policy::PolicySource Source() {
    policy::PolicySource source;
    source.rules_path = "dns-cache-benchmark.rules";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n[direct]\n";
    source.resolvers["local"] = {policy::PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {policy::PolicyAction::Proxy, {"udp://192.0.2.54:53"}};
    return source;
}

Json::Value Quantiles(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const auto quantile = [&values](double fraction) {
        const auto index = static_cast<std::size_t>(fraction * static_cast<double>(values.size() - 1));
        return values[index];
    };
    Json::Value result(Json::objectValue);
    result["unit"] = "ns";
    result["p50"] = quantile(0.50);
    result["p95"] = quantile(0.95);
    result["p99"] = quantile(0.99);
    return result;
}

Json::Value Run(const Options& options) {
    boost::asio::io_context context;
    policy::PolicyRuntime runtime;
    const auto prepared = runtime.Prepare(Source());
    if (!prepared.Ok() || !runtime.Commit(prepared)) throw std::runtime_error("cache benchmark policy failed to compile");
    const auto snapshot = runtime.GetSnapshot();
    auto transport = std::make_shared<FakeTransport>();
    auto session = std::make_shared<client_dns::DnsSessionContext>(transport, 1);
    auto telemetry = std::make_shared<client_dns::PolicyTelemetry>();
    std::uint64_t exchange_calls = 0;
    const Service::Clock::time_point fixed_now{};
    auto service = std::make_shared<Service>(context, ppp::dns::DnsResolver::ProtectSocketCallback{},
        [&](const auto&, auto, const Packet& query, const auto&, const Service::Callback& callback) {
            ++exchange_calls;
            callback(AResponse(query, 60));
        }, [fixed_now] { return fixed_now; }, telemetry);

    std::vector<double> miss_times, hit_times;
    miss_times.reserve(options.samples);
    hit_times.reserve(options.samples);
    const auto run_miss = [&](const std::string& name) {
        const auto query = Query(name);
        if (query.empty()) throw std::runtime_error("cache benchmark query did not encode");
        bool completed = false;
        context.restart();
        const auto start = Clock::now();
        service->Resolve(snapshot, session, query, [&](Packet response) {
            completed = !response.empty();
        });
        context.run();
        const auto elapsed = std::chrono::duration<double, std::nano>(Clock::now() - start).count();
        if (!completed) throw std::runtime_error("fake resolver did not complete a cache miss");
        return elapsed;
    };
    for (std::size_t i = 0; i < options.samples; ++i) {
        const auto domain = "cache-miss-" + std::to_string(i) + ".example.test";
        miss_times.push_back(run_miss(domain));
        const auto warm_query = Query(domain);
        bool completed = false;
        const auto start = Clock::now();
        service->Resolve(snapshot, session, warm_query, [&](Packet response) {
            completed = !response.empty();
        });
        hit_times.push_back(std::chrono::duration<double, std::nano>(Clock::now() - start).count());
        if (!completed) throw std::runtime_error("cache hit did not complete synchronously");
    }

    const auto counters = telemetry->Snapshot();
    if (exchange_calls != options.samples || counters.dns_cache_misses != options.samples ||
        counters.dns_cache_hits != options.samples)
        throw std::runtime_error("fake transport calls and cache telemetry did not match the sample count");

    Json::Value report(Json::objectValue);
    report["schema_version"] = 1;
    report["benchmark"] = "policy_dns_cache";
    report["transport"] = "fake_callback";
    report["clock"] = "fixed_steady_clock";
    report["sample_count"] = static_cast<Json::UInt64>(options.samples);
    report["cache_capacity_entries"] = static_cast<Json::UInt64>(Service::kCacheCapacityEntries);
    report["working_set_entries"] = 1;
    report["upstream_exchange_calls"] = static_cast<Json::UInt64>(exchange_calls);
    report["cache_hit_calls"] = static_cast<Json::UInt64>(counters.dns_cache_hits);
    report["cache_miss_calls"] = static_cast<Json::UInt64>(counters.dns_cache_misses);
    report["cache_hit_latency"] = Quantiles(std::move(hit_times));
    report["cache_miss_latency"] = Quantiles(std::move(miss_times));
    service->Close();
    return report;
}

}

int main(int argc, char** argv) {
    try {
        const auto options = ParseOptions(argc, argv);
        const auto report = Run(options);
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "  ";
        const auto text = Json::writeString(writer, report);
        if (options.output.empty()) std::cout << text << '\n';
        else {
            std::ofstream output(options.output, std::ios::binary | std::ios::trunc);
            if (!output) throw std::runtime_error("cannot write output report");
            output << text << '\n';
            if (!output) throw std::runtime_error("failed to finish output report");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
