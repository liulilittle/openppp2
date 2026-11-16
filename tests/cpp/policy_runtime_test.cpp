#include <ppp/app/client/policy/PolicyRuntime.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ppp::app::client::policy;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
PolicySource Source(const std::string& action = "direct") {
    PolicySource source;
    source.rules_path = "runtime.rules";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n[" + action +
        "]\n=domain.example\n[direct]\n192.0.2.0/24\n";
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}
void Lifecycle() {
    PolicyRuntime runtime;
    Require(!runtime.GetSnapshot(), "Runtime starts without a policy");
    Require(runtime.Evaluate("domain.example").action == PolicyAction::Reject, "Unconfigured runtime must fail closed");
    Require(runtime.PlanDns("domain.example").rejected, "Unconfigured DNS must fail closed");
    auto first = runtime.Prepare(Source());
    Require(first.Ok() && !runtime.GetSnapshot(), "Preparation must not publish");
    Require(runtime.Commit(first), "Valid candidate commits");
    auto original = runtime.GetSnapshot();
    Require(!runtime.Commit(first), "Same candidate cannot republish");
    auto source = Source(); source.rules_text += "[reject]\n=domain.example\n";
    auto failed = runtime.Prepare(source);
    Require(!failed.Ok() && !runtime.Commit(failed) && runtime.GetSnapshot() == original, "Failed candidate preserves active snapshot");
    auto earlier = runtime.Prepare(Source());
    auto later = runtime.Prepare(Source("proxy"));
    Require(runtime.Commit(later) && !runtime.Commit(earlier), "Stale candidate cannot roll back a newer commit");
    Require(runtime.GetSnapshot()->Version() > original->Version(), "Published versions increase");
    Require(PolicyEvaluator::Evaluate(*original, "domain.example").action == PolicyAction::Direct, "Held snapshot survives newer publication");
    Require(runtime.Evaluate("domain.example", "192.0.2.1").action == PolicyAction::Proxy, "Original domain evidence overrides resolved IP");
    Require(runtime.Evaluate("unmatched.example", "192.0.2.1").action == PolicyAction::Direct, "Unmatched domain uses IP");
    Require(runtime.Evaluate("unmatched.example").needs_ip_resolution, "Unresolved domain remains provisional");
    Require(runtime.PlanDns("domain.example").resolver == "remote", "Runtime DNS follows matching domain action");
    Require(runtime.Evaluate("domain.example", "2001:db8::1").reason == "unsupported_ipv6", "IPv6 block overrides domain match");
    Require(runtime.Evaluate("domain.example", "bad-ip").action == PolicyAction::Reject, "Malformed target IP must fail closed");
    PolicyRuntime foreign;
    Require(!foreign.Commit(later), "Candidates belong to the preparing runtime");
    auto tampered = earlier; tampered.snapshot = original;
    Require(!runtime.Commit(tampered), "Replacing a candidate snapshot cannot commit");
}
void JsonAndPath() {
    const auto directory = std::filesystem::temp_directory_path() / ("openppp-runtime-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path directory;
        ~Cleanup() { std::error_code error; std::filesystem::remove_all(directory, error); }
    } cleanup{directory};
    std::filesystem::create_directory(directory);
    std::ofstream rules(directory / "routing.rules"); rules << Source().rules_text; rules.close();
    Require(bool(rules), "Rules fixture creation");
    Json::Value config;
    auto& policy = config["client"]["policy"];
    policy["version"] = 2;
    policy["rules"]["path"] = "routing.rules";
    policy["dns"]["resolvers"]["local"]["via"] = "direct";
    policy["dns"]["resolvers"]["local"]["servers"].append("udp://192.0.2.53:53");
    policy["dns"]["resolvers"]["remote"]["via"] = "proxy";
    policy["dns"]["resolvers"]["remote"]["servers"].append("tcp://198.51.100.53:53");
    const auto filename = (directory / "client.json").string();
    PolicyRuntime runtime;
    auto loaded = runtime.Prepare(config, filename);
    Require(loaded.Ok() && runtime.Commit(loaded), "In-memory config resolves resources relative to config filename");
    std::ofstream file(filename); file << config; file.close();
    auto disk = runtime.PrepareFile(filename);
    Require(disk.Ok() && runtime.Commit(disk), "File config prepares and publishes");
    auto active = runtime.GetSnapshot();
    policy["version"] = 1;
    auto invalid = runtime.Prepare(config, filename);
    Require(!invalid.Ok() && !runtime.Commit(invalid) && runtime.GetSnapshot() == active, "JSON load failure preserves active policy");
}
void ConcurrentReaders() {
    PolicyRuntime runtime;
    Require(runtime.Commit(runtime.Prepare(Source())), "Initial concurrent policy");
    std::atomic<bool> done{false}, failed{false};
    std::atomic<std::size_t> reads{0};
    std::vector<std::thread> readers;
    for (unsigned i = 0; i < 4; ++i) readers.emplace_back([&] {
        std::uint64_t last = 0;
        while (!done.load(std::memory_order_acquire)) {
            auto snapshot = runtime.GetSnapshot();
            auto route = PolicyEvaluator::Evaluate(*snapshot, "domain.example", "192.0.2.1");
            auto dns = PolicyEvaluator::PlanDns(*snapshot, "domain.example");
            if (snapshot->Version() < last || route.version != dns.version ||
                (route.action == PolicyAction::Direct ? dns.resolver != "local" : dns.resolver != "remote")) failed = true;
            last = snapshot->Version();
            ++reads;
        }
    });
    for (unsigned i = 0; i < 64; ++i) {
        // Yield between publications so reader threads are guaranteed to observe
        // at least one snapshot on Windows, where the main thread may otherwise
        // finish all 64 commits before a reader is first scheduled.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!runtime.Commit(runtime.Prepare(Source(i % 2 ? "direct" : "proxy")))) failed = true;
    }
    done.store(true, std::memory_order_release);
    for (auto& reader : readers) reader.join();
    Require(!failed, "Readers must observe complete immutable policies with monotonic versions");
    Require(reads > 0, "Concurrent readers must exercise snapshot evaluation");
}
}

int main() {
    try {
        Lifecycle(); JsonAndPath(); ConcurrentReaders();
        std::cout << "policy runtime tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
