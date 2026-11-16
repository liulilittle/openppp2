#include <ppp/configurations/AppConfiguration.h>
#include <json/json.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
using ppp::configurations::AppConfiguration;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Json::Value Definition() {
    Json::Value value;
    value["client"]["policy"]["version"] = 2;
    value["client"]["policy"]["rules"]["path"] = "routing.rules";
    value["client"]["policy"]["dns"]["mode"] = "auto";
    value["client"]["policy"]["dns"]["resolvers"]["local"]["via"] = "direct";
    value["client"]["policy"]["dns"]["resolvers"]["local"]["servers"].append("udp://192.0.2.53:53");
    value["client"]["policy"]["dns"]["resolvers"]["remote"]["via"] = "proxy";
    value["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"].append("tcp://198.51.100.53:53");
    value["client"]["proxy-only"] = true;
    return value;
}

void RoundTripAndLegacy() {
    AppConfiguration config;
    auto json = Definition();
    Require(config.Load(json, "/tmp/policy-test/config.json"), "Explicit v2 configuration must load");
    Require(config.client.policy != nullptr, "Explicit policy ownership must survive loading");
    Require(*config.client.policy == json["client"]["policy"], "Policy definition must be preserved exactly");
    Require(config.client.policy_config_path == "/tmp/policy-test/config.json", "Resource anchor must be retained");
    Require(!config.client.policy_config_file_backed, "JSON configuration with a path anchor must stay in-memory backed");
    Require(config.client.proxy_only, "Policy must preserve independent proxy runtime mode");
    auto serialized = config.ToJson();
    Require(serialized["client"]["policy"] == json["client"]["policy"], "Policy must serialize without loss");
    for (const char* key : {"dns", "routing", "geo-rules"})
        Require(!serialized.isMember(key), "V2 serialization must omit legacy policy defaults");
    Require(!serialized["udp"].isMember("dns"), "V2 serialization must omit legacy DNS defaults");
    AppConfiguration reloaded;
    Require(reloaded.Load(serialized), "Serialized v2 configuration must load again");
    Require(!reloaded.client.policy_config_path.empty(), "In-memory configuration must have a resource anchor");
    Require(!reloaded.client.policy_config_file_backed, "JSON round-trip must stay in-memory backed");
    json["client"]["policy"]["rules"]["path"] = "changed.rules";
    Require((*config.client.policy)["rules"]["path"].asString() == "routing.rules", "Configuration must own its policy definition");
    AppConfiguration legacy;
    auto old = legacy.ToJson();
    Require(config.Load(old), "Legacy configuration must remain loadable");
    Require(!config.client.policy && config.client.policy_config_path.empty(), "Legacy reload must clear v2 state");
    old["client"]["policy"] = Json::Value();
    Require(config.Load(old) && !config.client.policy, "Null policy retains legacy semantics");
}

void InvalidDefinitionsAndConflicts() {
    AppConfiguration config;
    for (const auto& value : {Json::Value("invalid"), Json::Value(Json::arrayValue), Json::Value(2)}) {
        auto json = Definition(); json["client"]["policy"] = value;
        Require(!config.Load(json), "Non-object policy must be rejected");
    }
    for (const auto& value : {Json::Value(1), Json::Value(3), Json::Value("2"), Json::Value(2.0), Json::Value()}) {
        auto json = Definition(); json["client"]["policy"]["version"] = value;
        Require(!config.Load(json), "Policy version must be integer 2");
    }
    for (const char* field : {"routing", "bypass", "dns-rules"}) {
        auto json = Definition(); json["client"][field] = Json::Value(Json::objectValue);
        Require(!config.Load(json), "Legacy client policy cannot coexist with v2");
    }
    for (const char* field : {"routing", "geo-rules", "dns", "bypass", "dns-rules"}) {
        auto json = Definition(); json[field] = Json::Value(Json::objectValue);
        Require(!config.Load(json), "Legacy root policy cannot coexist with v2");
    }
    auto json = Definition(); json["udp"]["dns"] = Json::Value(Json::objectValue);
    Require(!config.Load(json), "Legacy UDP DNS configuration cannot coexist with v2");
}

void FileAnchor() {
    const auto path = std::filesystem::temp_directory_path() / ("openppp-policy-config-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove(path, error); }
    } cleanup{path};
    std::ofstream file(path, std::ios::binary);
    file << Definition(); file.close();
    Require(bool(file), "Configuration fixture write failed");
    AppConfiguration config;
    const auto filename = path.string();
    Require(config.Load(ppp::string(filename.data(), filename.size())), "File configuration must load");
    Require(config.client.policy_config_file_backed, "Loading a file must mark its policy file-backed");
    const auto anchor = std::string(config.client.policy_config_path.data(), config.client.policy_config_path.size());
    Require(std::filesystem::path(anchor) == std::filesystem::absolute(path), "File loading must retain absolute resource anchor");
    std::ofstream duplicate(path, std::ios::binary | std::ios::trunc);
    duplicate << "{\"client\":{\"policy\":{\"version\":2,\"version\":2}}}";
    duplicate.close();
    Require(!config.Load(ppp::string(filename.data(), filename.size())), "V2 file loading must reject duplicate keys");
    Require(!config.client.policy_config_file_backed, "Failed file loading must not retain stale origin metadata");
}
}

int main() {
    try {
        RoundTripAndLegacy(); InvalidDefinitionsAndConflicts(); FileAnchor();
        std::cout << "policy configuration tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
    return 0;
}
