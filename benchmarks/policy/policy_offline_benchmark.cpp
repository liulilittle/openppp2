#include <ppp/app/client/policy/PolicyRuntime.h>
#include <ppp/app/client/policy/PolicySourceLoader.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <json/json.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#include <sys/utsname.h>
#endif

namespace {
using namespace ppp::app::client::policy;
using Clock = std::chrono::steady_clock;

struct Options {
    std::string scale = "small";
    std::string output;
    std::size_t rules = 2000;
    std::size_t samples = 5000;
    std::uint32_t seed = 7121407;
};

struct Distribution {
    double p50 = 0;
    double p95 = 0;
    double p99 = 0;
};

struct TemporaryDirectory {
    std::filesystem::path path;
    TemporaryDirectory() = default;
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
    TemporaryDirectory(TemporaryDirectory&& other) noexcept : path(std::move(other.path)) { other.path.clear(); }
    TemporaryDirectory& operator=(TemporaryDirectory&& other) noexcept {
        if (this != &other) {
            std::error_code error;
            std::filesystem::remove_all(path, error);
            path = std::move(other.path);
            other.path.clear();
        }
        return *this;
    }
    ~TemporaryDirectory() { std::error_code error; std::filesystem::remove_all(path, error); }
};

std::uint64_t ParseUnsigned(const std::string& text, const char* name, std::uint64_t maximum) {
    if (text.empty()) throw std::runtime_error(std::string("missing value for ") + name);
    std::size_t consumed = 0;
    const auto value = std::stoull(text, &consumed, 10);
    if (consumed != text.size() || value > maximum) throw std::runtime_error(std::string("invalid value for ") + name);
    return value;
}

Options ParseOptions(int argc, char** argv) {
    Options options;
    bool custom_rules = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--help") {
            std::cout << "usage: policy_offline_benchmark [--scale small|100k|1m] [--rules N] "
                         "[--samples N] [--seed N] [--output FILE]\n";
            std::exit(0);
        }
        if (i + 1 >= argc) throw std::runtime_error("option requires a value: " + arg);
        const std::string value(argv[++i]);
        if (arg == "--scale") {
            options.scale = value;
            if (value == "small") options.rules = 2000;
            else if (value == "100k") options.rules = 100000;
            else if (value == "1m") options.rules = 1000000;
            else throw std::runtime_error("scale must be small, 100k, or 1m");
        } else if (arg == "--rules") {
            options.rules = static_cast<std::size_t>(ParseUnsigned(value, "--rules", 1000000));
            custom_rules = true;
        } else if (arg == "--samples") {
            options.samples = static_cast<std::size_t>(ParseUnsigned(value, "--samples", 1000000));
        } else if (arg == "--seed") {
            options.seed = static_cast<std::uint32_t>(ParseUnsigned(value, "--seed", UINT32_MAX));
        } else if (arg == "--output") {
            options.output = value;
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    if (!custom_rules) {
        if (options.scale == "small") options.rules = 2000;
        else if (options.scale == "100k") options.rules = 100000;
        else options.rules = 1000000;
    } else {
        options.scale = "custom";
    }
    if (options.rules < 2 || !options.samples) throw std::runtime_error("rules must be at least 2 and samples must be positive");
    return options;
}

std::string Ipv4(std::uint32_t value) {
    return std::to_string((value >> 24) & 255) + "." +
        std::to_string((value >> 16) & 255) + "." +
        std::to_string((value >> 8) & 255) + "." + std::to_string(value & 255);
}

Distribution Summarize(std::vector<double> values) {
    if (values.empty()) return {};
    std::sort(values.begin(), values.end());
    const auto quantile = [&values](double fraction) {
        const auto index = static_cast<std::size_t>(fraction * static_cast<double>(values.size() - 1));
        return values[index];
    };
    return {quantile(0.50), quantile(0.95), quantile(0.99)};
}

template<class QueryFactory>
Distribution Measure(std::size_t samples, QueryFactory make_query, const PolicyRuntime& runtime) {
    std::vector<std::string> queries;
    queries.reserve(samples);
    for (std::size_t i = 0; i < samples; ++i) queries.push_back(make_query(i));
    std::vector<double> nanoseconds;
    nanoseconds.reserve(samples);
    for (const auto& query : queries) {
        const auto start = Clock::now();
        (void)runtime.Evaluate(query);
        const auto end = Clock::now();
        nanoseconds.push_back(std::chrono::duration<double, std::nano>(end - start).count());
    }
    return Summarize(std::move(nanoseconds));
}

template<class QueryFactory>
Distribution MeasureIp(std::size_t samples, QueryFactory make_query, const PolicyRuntime& runtime) {
    std::vector<std::string> queries;
    queries.reserve(samples);
    for (std::size_t i = 0; i < samples; ++i) queries.push_back(make_query(i));
    std::vector<double> nanoseconds;
    nanoseconds.reserve(samples);
    for (const auto& query : queries) {
        const auto start = Clock::now();
        (void)runtime.Evaluate("", query);
        const auto end = Clock::now();
        nanoseconds.push_back(std::chrono::duration<double, std::nano>(end - start).count());
    }
    return Summarize(std::move(nanoseconds));
}

Json::Value Quantiles(const Distribution& value) {
    Json::Value output(Json::objectValue);
    output["unit"] = "ns";
    output["p50"] = value.p50;
    output["p95"] = value.p95;
    output["p99"] = value.p99;
    return output;
}

std::uint64_t PeakRssBytes() {
#if defined(__linux__) || defined(__APPLE__)
    struct rusage usage {};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        return static_cast<std::uint64_t>(usage.ru_maxrss);
#else
        return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024;
#endif
    }
#endif
    return 0;
}

Json::Value Environment() {
    Json::Value environment(Json::objectValue);
#if defined(__linux__)
    environment["os"] = "linux";
#elif defined(__APPLE__)
    environment["os"] = "macos";
#elif defined(_WIN32)
    environment["os"] = "windows";
#else
    environment["os"] = "unknown";
#endif
#if defined(NDEBUG)
    environment["build_mode"] = "release";
#else
    environment["build_mode"] = "debug";
#endif
#if defined(__VERSION__)
    environment["compiler"] = __VERSION__;
#else
    environment["compiler"] = "unknown";
#endif
    environment["hardware_threads"] = std::thread::hardware_concurrency();
#if defined(__linux__) || defined(__APPLE__)
    struct utsname system {};
    if (uname(&system) == 0) environment["kernel"] = system.release;
#endif
    return environment;
}

Json::Value Config() {
    Json::Value config(Json::objectValue);
    auto& policy = config["client"]["policy"];
    policy["version"] = 2;
    policy["rules"]["path"] = "rules.txt";
    policy["dns"]["mode"] = "real";
    policy["dns"]["resolvers"]["local"]["via"] = "direct";
    policy["dns"]["resolvers"]["local"]["servers"].append("udp://192.0.2.53:53");
    policy["dns"]["resolvers"]["remote"]["via"] = "proxy";
    policy["dns"]["resolvers"]["remote"]["servers"].append("udp://198.51.100.53:53");
    return config;
}

TemporaryDirectory MakeRules(const Options& options, std::vector<std::string>& domains,
    std::vector<std::string>& addresses) {
    TemporaryDirectory temporary;
    temporary.path = std::filesystem::temp_directory_path() /
        ("openppp-policy-benchmark-" + std::to_string(options.seed) + "-" +
            std::to_string(Clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temporary.path);
    const auto rules_path = temporary.path / "rules.txt";
    std::ofstream rules(rules_path, std::ios::binary);
    if (!rules) throw std::runtime_error("cannot create temporary rules file");
    rules << "default proxy\ndns direct local\ndns proxy remote\n[direct]\n";

    const std::size_t domain_count = options.rules / 2;
    const std::size_t cidr_count = options.rules - domain_count;
    std::vector<std::uint32_t> domain_ids(domain_count), ip_ids(cidr_count);
    for (std::size_t i = 0; i < domain_count; ++i) domain_ids[i] = static_cast<std::uint32_t>(i);
    for (std::size_t i = 0; i < cidr_count; ++i) ip_ids[i] = static_cast<std::uint32_t>(i);
    std::mt19937 random(options.seed);
    std::shuffle(domain_ids.begin(), domain_ids.end(), random);
    std::shuffle(ip_ids.begin(), ip_ids.end(), random);
    domains.reserve(domain_count);
    for (const auto id : domain_ids) {
        const auto domain = "bench-" + std::to_string(id) + ".bucket.example.test";
        rules << '=' << domain << '\n';
        domains.push_back(domain);
    }
    rules << "[proxy]\n";
    addresses.reserve(cidr_count);
    for (const auto id : ip_ids) {
        const auto address = Ipv4(0x0a000000u + id);
        rules << address << "/32\n";
        addresses.push_back(address);
    }
    rules.close();
    if (!rules) throw std::runtime_error("cannot finish temporary rules file");

    return temporary;
}

Json::Value RegexGrowth(std::uint32_t seed, std::size_t samples) {
    Json::Value growth(Json::arrayValue);
    const std::vector<std::size_t> counts = {0, 5, 20, 50};
    for (const auto count : counts) {
        PolicySource source;
        source.rules_path = "regex-growth.rules";
        source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n[direct]\n";
        source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
        source.resolvers["remote"] = {PolicyAction::Proxy, {"udp://198.51.100.53:53"}};
        for (std::size_t i = 0; i < count; ++i)
            source.rules_text += "regexp:^regex-" + std::to_string(i) + "-" + std::to_string(seed) + "\\.example\\.test$\n";
        const auto compile_start = Clock::now();
        const auto compiled = PolicyCompiler::Compile(source, 1);
        const auto compile_end = Clock::now();
        if (!compiled.Ok()) throw std::runtime_error("regex growth policy did not compile");
        const std::string target = count ? "regex-" + std::to_string(count - 1) + "-" +
            std::to_string(seed) + ".example.test" : "not-a-regex.example.test";
        std::vector<double> values;
        values.reserve(samples);
        for (std::size_t i = 0; i < samples; ++i) {
            const auto start = Clock::now();
            (void)PolicyEvaluator::Evaluate(*compiled.snapshot, target);
            values.push_back(std::chrono::duration<double, std::nano>(Clock::now() - start).count());
        }
        Json::Value item(Json::objectValue);
        item["regex_rules"] = static_cast<Json::UInt64>(count);
        item["compile_ms"] = std::chrono::duration<double, std::milli>(compile_end - compile_start).count();
        item["sample_count"] = static_cast<Json::UInt64>(samples);
        item["evaluation"] = Quantiles(Summarize(std::move(values)));
        growth.append(std::move(item));
    }
    return growth;
}

Json::Value Run(const Options& options) {
    std::vector<std::string> domains, addresses;
    auto temporary = MakeRules(options, domains, addresses);
    (void)temporary;

    Json::Value report(Json::objectValue);
    report["schema_version"] = 1;
    report["benchmark"] = "policy_offline";
    report["scale"] = Json::Value(options.scale.c_str());
    report["seed"] = options.seed;
    report["environment"] = Environment();
    report["rule_distribution"]["total"] = static_cast<Json::UInt64>(options.rules);
    report["rule_distribution"]["exact_domain"] = static_cast<Json::UInt64>(domains.size());
    report["rule_distribution"]["ipv4_cidr_32"] = static_cast<Json::UInt64>(addresses.size());
    report["rule_distribution"]["regex"] = 0;
    report["sample_count"] = static_cast<Json::UInt64>(options.samples);

    const auto load_start = Clock::now();
    const auto loaded = PolicySourceLoader::Load(Config(), (temporary.path / "config.json").string());
    const auto load_end = Clock::now();
    if (!loaded.Ok()) throw std::runtime_error("generated source failed second loader validation");

    PolicyRuntime runtime;
    const auto compile_start = Clock::now();
    const auto candidate = runtime.Prepare(loaded.source);
    const auto compile_end = Clock::now();
    if (!candidate.Ok() || !runtime.Commit(candidate)) throw std::runtime_error("generated policy failed runtime prepare/commit");
    report["load_ms"] = std::chrono::duration<double, std::milli>(load_end - load_start).count();
    report["compile_ms"] = std::chrono::duration<double, std::milli>(compile_end - compile_start).count();
    report["active_version"] = static_cast<Json::UInt64>(runtime.GetSnapshot()->Version());

    std::mt19937 random(options.seed ^ 0x9e3779b9u);
    auto domain_hit = [&] { return domains[random() % domains.size()]; };
    auto domain_miss = [&] { return "missing-" + std::to_string(random()) + ".outside.example.test"; };
    auto ip_hit = [&] { return addresses[random() % addresses.size()]; };
    auto ip_miss = [&] { return Ipv4(0xc0000201u + (random() % 250)); };
    report["domain_hit"] = Quantiles(Measure(options.samples, [&](std::size_t) { return domain_hit(); }, runtime));
    report["domain_miss"] = Quantiles(Measure(options.samples, [&](std::size_t) { return domain_miss(); }, runtime));
    report["ip_hit"] = Quantiles(MeasureIp(options.samples, [&](std::size_t) { return ip_hit(); }, runtime));
    report["ip_miss"] = Quantiles(MeasureIp(options.samples, [&](std::size_t) { return ip_miss(); }, runtime));

    report["regex_growth"] = RegexGrowth(options.seed, std::min<std::size_t>(options.samples, 2000));

    PolicySource update_source = loaded.source;
    update_source.rules_text += "\n[reject]\n=update-" + std::to_string(options.seed) + ".example.test\n";
    std::atomic_bool stop{false};
    std::atomic<std::uint64_t> ready{0};
    constexpr std::size_t reader_count = 2;
    std::vector<std::vector<double>> reader_latency(reader_count);
    std::vector<std::uint64_t> reader_reads(reader_count, 0);
    std::vector<std::thread> readers;
    for (std::size_t thread_id = 0; thread_id < reader_count; ++thread_id) {
        reader_latency[thread_id].reserve(20000);
        readers.emplace_back([&, thread_id] {
            ++ready;
            while (!stop.load(std::memory_order_acquire)) {
                const auto start = Clock::now();
                (void)runtime.Evaluate(domains[thread_id % domains.size()]);
                const auto elapsed = std::chrono::duration<double, std::nano>(Clock::now() - start).count();
                ++reader_reads[thread_id];
                if (reader_latency[thread_id].size() < 20000) reader_latency[thread_id].push_back(elapsed);
            }
        });
    }
    while (ready.load(std::memory_order_acquire) != reader_count) std::this_thread::yield();
    const auto update_compile_start = Clock::now();
    const auto update = runtime.Prepare(update_source);
    const auto update_compile_end = Clock::now();
    if (!update.Ok()) { stop = true; for (auto& reader : readers) reader.join(); throw std::runtime_error("concurrent update candidate failed"); }
    const auto commit_start = Clock::now();
    const bool committed = runtime.Commit(update);
    const auto commit_end = Clock::now();
    stop.store(true, std::memory_order_release);
    for (auto& reader : readers) reader.join();
    if (!committed) throw std::runtime_error("concurrent update commit failed");
    std::vector<double> all_reader_latency;
    std::uint64_t total_reader_reads = 0;
    for (std::size_t i = 0; i < reader_count; ++i) {
        total_reader_reads += reader_reads[i];
        all_reader_latency.insert(all_reader_latency.end(), reader_latency[i].begin(), reader_latency[i].end());
    }
    Json::Value concurrent(Json::objectValue);
    concurrent["reader_threads"] = static_cast<Json::UInt64>(reader_count);
    concurrent["reader_count"] = static_cast<Json::UInt64>(total_reader_reads);
    concurrent["sample_count"] = static_cast<Json::UInt64>(all_reader_latency.size());
    concurrent["candidate_compile_ms"] = std::chrono::duration<double, std::milli>(update_compile_end - update_compile_start).count();
    concurrent["commit_ms"] = std::chrono::duration<double, std::milli>(commit_end - commit_start).count();
    concurrent["reader_latency"] = Quantiles(Summarize(std::move(all_reader_latency)));
    concurrent["active_version"] = static_cast<Json::UInt64>(runtime.GetSnapshot()->Version());
    report["concurrent_update"] = std::move(concurrent);
    report["peak_rss_bytes"] = static_cast<Json::UInt64>(PeakRssBytes());
    report["rss_method"] = "getrusage.ru_maxrss";
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
        if (options.output.empty()) {
            std::cout << text << '\n';
        } else {
            const std::filesystem::path path(options.output);
            if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
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
