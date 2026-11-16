#define BOOST_TEST_MODULE policy_command_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/app/ApplicationPolicyCommand.h>
#include <json/json.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace {
struct Invocation {
    std::optional<int> code;
    std::string output;
    std::string error;
    Json::Value Json() const {
        Json::CharReaderBuilder reader;
        Json::Value value;
        Json::String errors;
        std::istringstream input(output);
        BOOST_REQUIRE_MESSAGE(Json::parseFromStream(reader, input, &value, &errors), errors);
        return value;
    }
};

Invocation Run(std::vector<std::string> args) {
    std::vector<const char*> pointers;
    for (const auto& arg : args) pointers.push_back(arg.c_str());
    std::ostringstream output, error;
    auto code = ppp::app::ApplicationPolicyCommand::Dispatch(static_cast<int>(pointers.size()), pointers.data(), output, error);
    return {code, output.str(), error.str()};
}

struct Fixture {
    std::filesystem::path directory;
    Fixture() {
        directory = std::filesystem::temp_directory_path() / ("openppp-policy-command-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(directory);
        Write("routing.rules", "default proxy\ndns direct local\ndns proxy remote\n[direct]\n=local.example\n192.0.2.0/24\n[reject]\n=blocked.example\n[dns:local]\n=override.example\n");
        Write("client.json", R"({"client":{"policy":{"version":2,"rules":{"path":"routing.rules"},"dns":{"resolvers":{"local":{"via":"direct","servers":["udp://192.0.2.53:53"]},"remote":{"via":"proxy","servers":["udp://198.51.100.53:53"]}}}}}})");
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
    void Write(const char* name, const std::string& text) { std::ofstream(directory / name) << text; }
    std::vector<std::string> Args(const std::string& command = "explain") const {
        return {"ppp", "policy", command, "--config", (directory / "client.json").string(), "--runtime", "tun", "--platform", "android", "--json"};
    }
};
}

BOOST_AUTO_TEST_CASE(legacy_dispatch_is_unhandled_and_policy_errors_are_handled) {
    BOOST_TEST(!Run({"ppp", "--config", "legacy.json"}).code.has_value());
    auto result = Run({"ppp", "policy", "update", "--json"});
    BOOST_REQUIRE(result.code.has_value());
    BOOST_TEST(*result.code == 2);
    BOOST_TEST(result.Json()["diagnostics"][0]["code"].asString() == "E_POLICY_ARGUMENT");
}

BOOST_FIXTURE_TEST_CASE(arguments_are_strict_before_resource_loading, Fixture) {
    const std::vector<std::vector<std::string>> bad = {
        {"--domain", "a.example", "--network", "icmp"},
        {"--domain", "a.example", "--port", "0"},
        {"--domain", "a.example", "--port", "65536"},
        {"--domain", "a.example", "--port", "12x"},
        {"--domain", "a.example", "--runtime", "tun"},
        {"--domain", "a.example", "--unknown", "value"},
        {"--domain"},
        {"--domain", "192.0.2.10"},
        {"--domain", "bad..example"},
        {"--ip", "192.0.2.999"},
        {}
    };
    for (const auto& tail : bad) {
        auto args = Args();
        args.insert(args.end(), tail.begin(), tail.end());
        auto result = Run(args);
        BOOST_REQUIRE(result.code.has_value());
        BOOST_TEST(*result.code == 2);
        BOOST_TEST(result.Json()["diagnostics"][0]["code"].asString() == "E_POLICY_ARGUMENT");
    }
    auto args = Args("check");
    args.insert(args.end(), {"--domain", "a.example"});
    BOOST_TEST(*Run(args).code == 2);
}

BOOST_FIXTURE_TEST_CASE(explain_provenance_dns_and_pending_ip, Fixture) {
    auto args = Args();
    args.insert(args.end(), {"--domain", "LOCAL.EXAMPLE.", "--ip", "198.51.100.10", "--port", "443"});
    auto result = Run(args);
    BOOST_TEST(*result.code == 0);
    auto report = result.Json();
    BOOST_TEST(report["plan_only"].asBool());
    BOOST_TEST(!report["runtime_installed"].asBool());
    BOOST_TEST(report["route"]["action"].asString() == "direct");
    BOOST_TEST(report["route"]["matched"].asBool());
    BOOST_TEST(!report["route"]["needs_ip"].asBool());
    BOOST_TEST(!report["route"]["rule_id"].asString().empty());
    BOOST_TEST(!report["route"]["source"].asString().empty());
    BOOST_TEST(report["dns"]["resolver"].asString() == "local");
    BOOST_TEST(report["dns"]["via"].asString() == "direct");
    BOOST_TEST(report["port"].asUInt() == 443u);
    args = Args();
    args.insert(args.end(), {"--domain", "unmatched.example"});
    report = Run(args).Json();
    BOOST_TEST(report["route"]["needs_ip"].asBool());
    BOOST_TEST(report["dns"]["resolver"].asString() == "remote");
    args = Args();
    args.insert(args.end(), {"--domain", "override.example"});
    report = Run(args).Json();
    BOOST_TEST(report["route"]["action"].asString() == "proxy");
    BOOST_TEST(report["dns"]["resolver"].asString() == "local");
}

BOOST_FIXTURE_TEST_CASE(ip_phase_and_reject_are_plans, Fixture) {
    auto args = Args();
    args.insert(args.end(), {"--domain", "unknown.example", "--ip", "192.0.2.5"});
    auto report = Run(args).Json();
    BOOST_TEST(report["route"]["action"].asString() == "direct");
    BOOST_TEST(!report["route"]["needs_ip"].asBool());
    BOOST_TEST(report["dns"]["resolver"].asString() == "remote");
    args = Args();
    args.insert(args.end(), {"--domain", "blocked.example"});
    report = Run(args).Json();
    BOOST_TEST(report["route"]["action"].asString() == "reject");
    BOOST_TEST(report["dns"]["rejected"].asBool());
    args = Args();
    args.insert(args.end(), {"--ip", "192.0.2.5"});
    BOOST_TEST(!Run(args).Json()["dns"]["applicable"].asBool());
}

BOOST_FIXTURE_TEST_CASE(capability_failure_preserves_explanation, Fixture) {
    auto args = Args();
    for (auto& arg : args) if (arg == "android") arg = "ios";
    args.insert(args.end(), {"--domain", "local.example", "--network", "udp"});
    auto result = Run(args);
    BOOST_TEST(*result.code == 4);
    auto report = result.Json();
    BOOST_TEST(report["route"]["action"].asString() == "direct");
    BOOST_TEST(report["diagnostics"][0]["code"].asString() == "E_POLICY_CAPABILITY_UNSUPPORTED");
    args = Args("check");
    BOOST_TEST(*Run(args).code == 0);
    for (auto& arg : args) if (arg == "android") arg = "linux";
    BOOST_TEST(*Run(args).code == 0);
    for (auto& arg : args) if (arg == "linux") arg = "ios";
    BOOST_TEST(*Run(args).code == 4);
    args = Args();
    args.insert(args.end(), {"--ip", "2001:db8::1"});
    BOOST_TEST(*Run(args).code == 4);
}

BOOST_FIXTURE_TEST_CASE(source_and_legacy_errors_have_distinct_exit_codes, Fixture) {
    std::filesystem::remove(directory / "routing.rules");
    BOOST_TEST(*Run(Args("check")).code == 3);
    Write("client.json", "{\"client\":{\"routing\":{}}}");
    BOOST_TEST(*Run(Args("check")).code == 2);
    Write("client.json", "invalid JSON");
    BOOST_TEST(*Run(Args("check")).code == 2);
}

BOOST_FIXTURE_TEST_CASE(shared_udp_capability_and_http_transport_scope, Fixture) {
    for (const auto* runtime : {"tun", "socks"}) {
        for (const auto* platform : {"linux", "windows", "macos", "android"}) {
            auto args = Args();
            for (auto& arg : args) {
                if (arg == "tun") arg = runtime;
                else if (arg == "android") arg = platform;
            }
            args.insert(args.end(), {"--domain", "local.example", "--network", "udp"});
            BOOST_TEST(*Run(args).code == 0);
        }
    }
    auto args = Args("check");
    for (auto& arg : args) if (arg == "tun") arg = "http";
    BOOST_TEST(*Run(args).code == 0);
    args = Args();
    for (auto& arg : args) if (arg == "tun") arg = "http";
    args.insert(args.end(), {"--domain", "blocked.example", "--network", "udp"});
    BOOST_TEST(*Run(args).code == 4);
}

BOOST_FIXTURE_TEST_CASE(ios_dns_checks_only_potentially_referenced_resolvers, Fixture) {
    Write("routing.rules", "default proxy\ndns direct local\ndns proxy remote\n[proxy]\n=remote.example\n");
    auto args = Args("check");
    for (auto& arg : args) if (arg == "android") arg = "ios";
    BOOST_TEST(*Run(args).code == 0);
    Write("routing.rules", "default proxy\ndns direct local\ndns proxy remote\n[dns:local]\n=exception.example\n");
    BOOST_TEST(*Run(args).code == 4);
    args = Args();
    for (auto& arg : args) if (arg == "android") arg = "ios";
    args.insert(args.end(), {"--domain", "unmatched.example"});
    BOOST_TEST(*Run(args).code == 0);
    args = Args();
    for (auto& arg : args) if (arg == "android") arg = "ios";
    args.insert(args.end(), {"--domain", "exception.example"});
    BOOST_TEST(*Run(args).code == 4);
}

BOOST_FIXTURE_TEST_CASE(ios_tcp_sniff_is_an_explicit_capability_error, Fixture) {
    Write("routing.rules", "default proxy\ndns direct local\ndns proxy remote\n");
    std::ifstream stream(directory / "client.json");
    Json::Value config;
    stream >> config;
    BOOST_REQUIRE(bool(stream));
    stream.close();
    config["client"]["policy"]["tcp-domain-sniff"] = true;
    Json::StreamWriterBuilder writer;
    auto json = Json::writeString(writer, config);
    Write("client.json", std::string(json.data(), json.size()));
    for (const auto* command : {"check", "explain"}) {
        auto args = Args(command);
        for (auto& arg : args) if (arg == "android") arg = "ios";
        if (std::string(command) == "explain") args.insert(args.end(), {"--domain", "unknown.example"});
        auto result = Run(args);
        BOOST_TEST(*result.code == 4);
        BOOST_TEST(result.Json()["diagnostics"][0]["code"].asString() == "E_POLICY_CAPABILITY_UNSUPPORTED");
    }
    for (const auto* runtime : {"http", "socks"}) {
        auto args = Args("check");
        for (auto& arg : args) {
            if (arg == "android") arg = "ios";
            else if (arg == "tun") arg = runtime;
        }
        auto result = Run(args);
        BOOST_TEST(*result.code == 0);
        BOOST_TEST(!result.Json()["tcp_domain_sniff_applicable"].asBool());
        BOOST_TEST(result.Json()["diagnostics"][0]["severity"].asString() == "warning");
    }
    config["client"]["policy"]["tcp-domain-sniff"] = false;
    json = Json::writeString(writer, config);
    Write("client.json", std::string(json.data(), json.size()));
    auto args = Args("check");
    for (auto& arg : args) if (arg == "android") arg = "ios";
    BOOST_TEST(*Run(args).code == 0);
}

BOOST_FIXTURE_TEST_CASE(human_output_uses_same_decision_and_discloses_plan_limit, Fixture) {
    auto args = Args();
    args.erase(std::find(args.begin(), args.end(), "--json"));
    args.insert(args.end(), {"--domain", "local.example"});
    auto result = Run(args);
    BOOST_TEST(*result.code == 0);
    BOOST_TEST(result.error.empty());
    BOOST_TEST(result.output.find("Route plan: direct") != std::string::npos);
    BOOST_TEST(result.output.find("DNS plan: local; via: direct") != std::string::npos);
    BOOST_TEST(result.output.find("Offline policy command; no runtime was started.") != std::string::npos);
    args = Args();
    args.erase(std::find(args.begin(), args.end(), "--json"));
    args.insert(args.end(), {"--ip", "192.0.2.5"});
    result = Run(args);
    BOOST_TEST(result.output.find("DNS plan: not applicable") != std::string::npos);
}
