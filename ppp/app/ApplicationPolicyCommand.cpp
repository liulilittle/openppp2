#include <ppp/app/ApplicationPolicyCommand.h>
#include <ppp/app/client/policy/PolicySourceLoader.h>
#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/app/client/policy/LegacyPolicyAdapter.h>
#include <ppp/app/client/policy/LegacyPolicyMigration.h>
#include <ppp/app/client/policy/PolicyStatusFile.h>
#include <ppp/app/client/policy/PolicyUpdateService.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/Filesystem.h>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <openssl/sha.h>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <vector>

namespace ppp::app {
namespace {
namespace policy = client::policy;
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;

std::string Sha256(const std::string& bytes) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest);
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}

const char* ActionName(policy::PolicyAction action) {
    switch (action) {
    case policy::PolicyAction::Direct: return "direct";
    case policy::PolicyAction::Reject: return "reject";
    default: return "proxy";
    }
}

const char* HostPlatform() {
#if defined(__ANDROID__)
    return "android";
#elif defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

void AddDiagnostic(Json::Value& report, const std::string& code, const std::string& message,
    const std::string& severity = "error", const std::string& source = "", std::size_t line = 0) {
    Json::Value item(Json::objectValue);
    item["code"] = code.c_str();
    item["severity"] = severity.c_str();
    item["message"] = message.c_str();
    item["source"] = source.c_str();
    item["line"] = Json::UInt64(line);
    report["diagnostics"].append(item);
}

void AddDiagnostics(Json::Value& report, const std::vector<policy::PolicyDiagnostic>& diagnostics) {
    for (const auto& item : diagnostics) {
        AddDiagnostic(report, item.code, item.message, item.severity, item.file, item.line);
        report["diagnostics"][report["diagnostics"].size() - 1]["path"] = item.path.c_str();
    }
}

int DiagnosticExit(const std::vector<policy::PolicyDiagnostic>& diagnostics) {
    for (const auto& item : diagnostics) {
        if (item.severity == "error" && (item.code == "E_POLICY_SOURCE_UNAVAILABLE" || item.code == "rule_set_unavailable")) return 3;
    }
    for (const auto& item : diagnostics) {
        if (item.severity == "error" && item.code == "E_POLICY_CAPABILITY_UNSUPPORTED") return 4;
    }
    return 2;
}

bool ValidDomain(std::string domain) {
    if (!domain.empty() && domain.back() == '.') domain.pop_back();
    if (domain.empty() || domain.size() > 253) return false;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= domain.size(); ++i) {
        if (i == domain.size() || domain[i] == '.') {
            if (i == start || i - start > 63 || domain[start] == '-' || domain[i - 1] == '-') return false;
            start = i + 1;
        } else {
            unsigned char c = static_cast<unsigned char>(domain[i]);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-')) return false;
        }
    }
    boost::system::error_code ec;
    boost::asio::ip::make_address(domain, ec);
    return !!ec;
}

bool UnsupportedDirect(const std::string& platform) {
    return platform == "ios";
}

bool Capability(Json::Value& report, const std::string& runtime, const std::string& platform,
    const std::string& network, policy::PolicyAction action) {
    if (runtime == "http" && network == "udp") {
        AddDiagnostic(report, "E_POLICY_CAPABILITY_UNSUPPORTED", "HTTP local proxy has no UDP transport.");
        return false;
    }
    if (action == policy::PolicyAction::Direct && UnsupportedDirect(platform)) {
        AddDiagnostic(report, "E_POLICY_CAPABILITY_UNSUPPORTED",
            network == "udp"
                ? "iOS direct UDP requires an installed Packet Tunnel datagram transport factory; offline validation cannot establish its availability."
                : "Current iOS TCP paths cannot enforce protected forced-direct routing.");
        return false;
    }
    return true;
}

bool DnsCapability(Json::Value& report, const std::string& runtime,
    const std::string& platform, policy::PolicyAction via) {
    if (via == policy::PolicyAction::Direct && runtime == "tun" && platform == "ios") {
        AddDiagnostic(report, "E_POLICY_CAPABILITY_UNSUPPORTED",
            "Current iOS TUN DNS cannot protect direct resolver sockets; the UDP business-flow provider does not supply direct DNS transport.");
        return false;
    }
    return true;
}

int Emit(Json::Value& report, int code, bool json, std::ostream& output, std::ostream& error) {
    report["exit_code"] = code;
    if (!report.isMember("status") || !report.isMember("preserve_status"))
        report["status"] = code == 0 ? "ok" : "error";
    report.removeMember("preserve_status");
    if (json) {
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "  ";
        output << Json::writeString(writer, report) << '\n';
    } else {
        std::ostream& stream = code == 0 ? output : error;
        stream << "policy " << report["command"].asString() << ": " << report["status"].asString() << '\n';
        if (report["command"].asString() == "update")
            stream << "Update does not install an active policy; a successful result is prepared for the next start.\n";
        else if (report["command"].asString() == "status")
            stream << "Runtime state is read from the durable status record; this command does not contact the process.\n";
        else stream << "Offline policy command; no runtime was started.\n";
        if (report.isMember("policy_version")) {
            stream << "Policy version: " << report["policy_version"].asUInt64()
                << "; config schema: " << report["config_version"].asInt() << '\n';
        }
        if (report.isMember("route")) {
            const auto& route = report["route"];
            stream << "Route plan: " << route["action"].asString() << "; needs IP: "
                << (route["needs_ip"].asBool() ? "yes" : "no") << "; rule: "
                << route["rule_id"].asString() << "; source: " << route["source"].asString()
                << "; file: " << route["file"].asString() << ':' << route["line"].asUInt64()
                << (route["provisional"].asBool() ? "; provisional default" : "") << '\n';
            const auto& dns = report["dns"];
            if (!dns["applicable"].asBool()) stream << "DNS plan: not applicable\n";
            else stream << "DNS plan: " << (dns["rejected"].asBool() ? "refused" : dns["resolver"].asCString())
                    << "; via: " << dns["via"].asString() << "; rule: " << dns["rule_id"].asString()
                    << "; source: " << dns["source"].asString() << "; file: " << dns["file"].asString()
                    << ':' << dns["line"].asUInt64() << '\n';
        }
        for (const auto& item : report["diagnostics"]) {
            stream << item["severity"].asString() << ' ' << item["code"].asString() << ": "
                << item["message"].asString();
            if (!item["source"].asString().empty()) stream << " (" << item["source"].asString() << ':' << item["line"].asUInt64() << ')';
            stream << '\n';
        }
    }
    return code;
}

struct ParsedOptions final {
    std::map<std::string, std::string> values;
    std::set<std::string> flags;
    std::string error;
};

ParsedOptions ParseStrictOptions(int argc, const char* const* argv,
    const std::set<std::string>& value_options, const std::set<std::string>& flag_options) {
    ParsedOptions parsed;
    for (int i = 3; i < argc; ++i) {
        if (!argv[i]) { parsed.error = "Null command argument."; return parsed; }
        const std::string name = argv[i];
        if (flag_options.count(name)) {
            if (parsed.flags.count(name) || parsed.values.count(name)) {
                parsed.error = "Duplicate policy option: " + name;
                return parsed;
            }
            parsed.flags.insert(name);
            continue;
        }
        if (!value_options.count(name)) { parsed.error = "Unknown policy option: " + name; return parsed; }
        if (parsed.values.count(name) || parsed.flags.count(name)) {
            parsed.error = "Duplicate policy option: " + name;
            return parsed;
        }
        if (i + 1 >= argc || !argv[i + 1] || std::string(argv[i + 1]).rfind("--", 0) == 0) {
            parsed.error = "Missing value for " + name;
            return parsed;
        }
        parsed.values.emplace(name, argv[++i]);
        if (parsed.values[name].empty()) { parsed.error = "Empty value for " + name; return parsed; }
    }
    return parsed;
}

std::string JsonText(const Json::Value& value) {
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "  ";
    const auto encoded = Json::writeString(writer, value);
    return std::string(encoded.data(), encoded.size()) + "\n";
}

Json::String JsonString(const std::string& value) {
    return Json::String(value.data(), value.size());
}

bool ReadJsonFile(const std::string& path, Json::Value& value) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    std::string bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    if (stream.bad()) return false;
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    builder["failIfExtra"] = true;
    builder["allowComments"] = false;
    builder["allowTrailingCommas"] = false;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::String errors;
    return reader->parse(bytes.data(), bytes.data() + bytes.size(), &value, &errors) && value.isObject();
}

bool WriteFilesNoReplace(const std::vector<std::pair<fs::path, std::string>>& files, std::string& error) {
    for (const auto& item : files) {
        error_code ec;
        if (fs::exists(item.first, ec) || ec) { error = "An output file already exists or cannot be inspected."; return false; }
    }
    std::vector<fs::path> temps;
    std::vector<fs::path> installed;
    const auto nonce = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto cleanup = [&]() {
        error_code ec;
        for (const auto& path : temps) fs::remove(path, ec);
        for (const auto& path : installed) fs::remove(path, ec);
    };
    for (std::size_t i = 0; i < files.size(); ++i) {
        auto temp = files[i].first;
        temp += ".tmp-" + nonce + "-" + std::to_string(i);
        temps.push_back(temp);
        std::ofstream stream(ppp::filesystem::StreamPath(temp), std::ios::binary | std::ios::out | std::ios::trunc);
        if (!stream) { error = "Could not create a temporary output file."; cleanup(); return false; }
        stream.write(files[i].second.data(), static_cast<std::streamsize>(files[i].second.size()));
        stream.close();
        if (!stream) { error = "Could not complete a temporary output file."; cleanup(); return false; }
    }
    for (std::size_t i = 0; i < files.size(); ++i) {
        error_code ec;
        if (fs::exists(files[i].first, ec) || ec) {
            error = "An output file appeared while writing; no existing file was replaced.";
            cleanup(); return false;
        }
        fs::create_hard_link(temps[i], files[i].first, ec);
        if (ec) { error = "Could not atomically install every output file."; cleanup(); return false; }
        installed.push_back(files[i].first);
        fs::remove(temps[i], ec);
    }
    return true;
}

void RemoveEmptyDirectoriesReverse(const std::vector<fs::path>& directories) noexcept {
    error_code ec;
    for (auto it = directories.rbegin(); it != directories.rend(); ++it) {
        fs::remove(*it, ec);
        ec.clear();
    }
}

bool CreateParentDirectories(const fs::path& directory,
    std::vector<fs::path>& created, std::string& error) {
    created.clear();
    fs::path current = directory.root_path();
    error_code ec;
    for (const auto& component : directory.relative_path()) {
        current /= component;
        if (fs::exists(current, ec)) {
            if (ec || !fs::is_directory(current, ec) || ec) {
                error = "An export parent path is not a directory.";
                RemoveEmptyDirectoriesReverse(created);
                created.clear();
                return false;
            }
            continue;
        }
        if (ec) {
            error = "Could not inspect an export parent path.";
            RemoveEmptyDirectoriesReverse(created);
            created.clear();
            return false;
        }
        if (fs::create_directory(current, ec)) {
            created.push_back(current);
        } else if (ec || !fs::is_directory(current, ec) || ec) {
            error = "Could not create an export parent directory.";
            RemoveEmptyDirectoriesReverse(created);
            created.clear();
            return false;
        }
    }
    return true;
}

int HandleInit(const ParsedOptions& parsed, Json::Value& report, bool json,
    std::ostream& output, std::ostream& error) {
    auto fail = [&](const std::string& code, const std::string& message, int exit) {
        AddDiagnostic(report, code, message);
        return Emit(report, exit, json, output, error);
    };
    if (!parsed.error.empty()) return fail("E_POLICY_ARGUMENT", parsed.error, 2);
    if (!parsed.values.count("--out") || !parsed.values.count("--template") || !parsed.values.count("--runtime"))
        return fail("E_POLICY_ARGUMENT", "--out, --template and --runtime are required.", 2);
    const auto& out_value = parsed.values.at("--out");
    const auto& name = parsed.values.at("--template");
    const auto& runtime = parsed.values.at("--runtime");
    if (name != "proxy-all" && name != "direct-all" && name != "split-cn")
        return fail("E_POLICY_ARGUMENT", "--template must be proxy-all, direct-all or split-cn.", 2);
    if (runtime != "tun" && runtime != "http" && runtime != "socks")
        return fail("E_POLICY_ARGUMENT", "--runtime must be tun, http or socks.", 2);
    if (name == "split-cn" && (!parsed.values.count("--geoip") || !parsed.values.count("--geosite")))
        return fail("E_POLICY_ARGUMENT", "split-cn requires --geoip and --geosite local paths or URLs.", 2);
    auto source = [&](const std::string& value, Json::Value& rule_set) -> bool {
        if (value.rfind("https://", 0) == 0 || value.rfind("http://", 0) == 0) {
            rule_set["source"]["url"] = JsonString(value);
            return true;
        }
        error_code ec;
        if (!fs::is_regular_file(value, ec) || ec) return false;
        const auto size = fs::file_size(value, ec);
        if (ec || size > 64u * 1024u * 1024u) return false;
        std::ifstream input(value, std::ios::binary);
        if (!input) return false;
        std::string bytes(static_cast<std::size_t>(size), '\0');
        if (size && !input.read(bytes.data(), static_cast<std::streamsize>(size))) return false;
        if (input.bad()) return false;
        rule_set["source"]["path"] = JsonString(fs::absolute(value, ec).lexically_normal().string());
        if (ec) return false;
        rule_set["sha256"] = JsonString(Sha256(bytes));
        return true;
    };
    Json::Value policy_value(Json::objectValue);
    policy_value["version"] = 2;
    policy_value["rules"]["path"] = "routing.rules";
    policy_value["ipv6"] = "block";
    policy_value["dns"]["resolvers"]["local"]["via"] = "direct";
    policy_value["dns"]["resolvers"]["local"]["servers"].append("doh.pub");
    policy_value["dns"]["resolvers"]["remote"]["via"] = "proxy";
    policy_value["dns"]["resolvers"]["remote"]["servers"].append("cloudflare");
    policy_value["dns"]["mode"] = runtime == "tun" ? "fake-ip" : "real";
    if (runtime == "tun") {
        policy_value["dns"]["fake-ip"]["range"] = "198.18.0.0/16";
        policy_value["dns"]["fake-ip"]["storage"] = "./dns-fake-ip";
        policy_value["dns"]["fake-ip"]["identity"] = "client-default";
    }
    std::string rules = "default proxy\ndns direct local\ndns proxy remote\n";
    if (name == "direct-all") {
        rules = "default direct\ndns direct local\ndns proxy remote\n";
    } else if (name == "split-cn") {
        rules += "[direct]\nset:geoip-cn\nset:geosite-cn\n";
        if (!source(parsed.values.at("--geoip"), policy_value["rule-sets"]["geoip-cn"]) ||
            !source(parsed.values.at("--geosite"), policy_value["rule-sets"]["geosite-cn"]))
            return fail("E_POLICY_SOURCE_UNAVAILABLE", "split-cn sources must be existing files or explicit http(s) URLs.", 3);
        auto& geoip = policy_value["rule-sets"]["geoip-cn"];
        geoip["format"] = "geoip-text";
        geoip["tag"] = "cn";
        auto& geosite = policy_value["rule-sets"]["geosite-cn"];
        geosite["format"] = "geosite-text";
        geosite["tag"] = "cn";
    }
    Json::Value config(Json::objectValue);
    config["client"]["policy"] = policy_value;
    config["template"] = name.c_str();
    config["runtime"] = runtime.c_str();
    fs::path directory = fs::absolute(out_value).lexically_normal();
    error_code ec;
    const bool existed = fs::exists(directory, ec);
    if (ec || (existed && !fs::is_directory(directory, ec)))
        return fail("E_POLICY_STORAGE", "--out must name a directory that can be created.", 3);
    if (!existed && !fs::create_directories(directory, ec) && ec)
        return fail("E_POLICY_STORAGE", "Could not create the output directory.", 3);
    std::vector<std::pair<fs::path, std::string>> files = {
        {directory / "policy.json", JsonText(config)},
        {directory / "routing.rules", rules}
    };
    std::string write_error;
    if (!WriteFilesNoReplace(files, write_error)) {
        if (!existed) fs::remove(directory, ec);
        return fail("E_POLICY_STORAGE", write_error, 3);
    }
    report["files"].append(JsonString((directory / "policy.json").string()));
    report["files"].append(JsonString((directory / "routing.rules").string()));
    report["runtime"] = runtime.c_str();
    report["template"] = name.c_str();
    report["incomplete"] = true;
    return Emit(report, 0, json, output, error);
}

int HandleMigrate(const ParsedOptions& parsed, Json::Value& report, bool json,
    std::ostream& output, std::ostream& error) {
    auto fail = [&](const std::string& code, const std::string& message, int exit) {
        AddDiagnostic(report, code, message);
        return Emit(report, exit, json, output, error);
    };
    if (!parsed.error.empty()) return fail("E_POLICY_ARGUMENT", parsed.error, 2);
    if (!parsed.values.count("--config") || !parsed.values.count("--out"))
        return fail("E_POLICY_ARGUMENT", "--config and --out are required.", 2);
    std::ifstream input_config(parsed.values.at("--config"), std::ios::binary);
    if (!input_config) return fail("E_POLICY_SOURCE_UNAVAILABLE", "Legacy configuration file could not be read.", 3);
    const std::string original_bytes((std::istreambuf_iterator<char>(input_config)), std::istreambuf_iterator<char>());
    if (input_config.bad()) return fail("E_POLICY_SOURCE_UNAVAILABLE", "Legacy configuration file could not be read completely.", 3);
    const auto original_hash = Sha256(original_bytes);
    if (parsed.values.count("--runtime") && parsed.values.at("--runtime") != "tun" &&
        parsed.values.at("--runtime") != "http" && parsed.values.at("--runtime") != "socks")
        return fail("E_POLICY_ARGUMENT", "--runtime must be tun, http or socks.", 2);
    ppp::configurations::AppConfiguration configuration;
    if (!configuration.Load(ppp::string(parsed.values.at("--config"))))
        return fail("E_POLICY_CONFIG", "Legacy configuration could not be loaded.", 2);
    policy::LegacyPolicyAdapterInput input;
    if (parsed.values.count("--bypass")) input.cli_bypass.push_back(parsed.values.at("--bypass"));
    if (parsed.values.count("--dns-rules")) input.cli_dns_rules.push_back(parsed.values.at("--dns-rules"));
    if (parsed.values.count("--platform")) {
        const auto platform = parsed.values.at("--platform");
        if (platform != "linux" && platform != "windows" && platform != "macos" &&
            platform != "android" && platform != "ios")
            return fail("E_POLICY_ARGUMENT", "Unknown --platform.", 2);
    }
    auto legacy = policy::LegacyPolicyAdapter::Adapt(configuration, input);
    std::ifstream input_after(parsed.values.at("--config"), std::ios::binary);
    const std::string after_bytes((std::istreambuf_iterator<char>(input_after)), std::istreambuf_iterator<char>());
    if (input_after.bad() || Sha256(after_bytes) != original_hash)
        return fail("E_POLICY_SOURCE_UNAVAILABLE", "Legacy configuration changed during migration analysis; no output was written.", 3);
    report["source_sha256"] = original_hash.c_str();
    fs::path directory = fs::absolute(parsed.values.at("--out")).lexically_normal();
    error_code ec;
    const bool existed = fs::exists(directory, ec);
    if (ec || (existed && !fs::is_directory(directory, ec)))
        return fail("E_POLICY_STORAGE", "--out must name a directory that can be created.", 3);
    if (!existed && !fs::create_directories(directory, ec) && ec)
        return fail("E_POLICY_STORAGE", "Could not create the migration output directory.", 3);
    auto migrated = policy::LegacyPolicyMigration::CreateDraft(legacy, (directory / "policy.json").string(),
        parsed.values.count("--runtime") ? parsed.values.at("--runtime") : std::string(),
        parsed.values.count("--platform") ? parsed.values.at("--platform") : std::string());
    migrated.policy_config["incomplete"] = true;
    std::vector<std::pair<fs::path, std::string>> files = {
        {directory / "policy.json", JsonText(migrated.policy_config)},
        {directory / "routing.rules", migrated.rules_text},
        {directory / "migration-report.json", JsonText(migrated.report)}
    };
    std::string write_error;
    if (!WriteFilesNoReplace(files, write_error)) {
        if (!existed) fs::remove(directory, ec);
        return fail("E_POLICY_STORAGE", write_error, 3);
    }
    report["migration"] = migrated.report;
    report["files"].append(JsonString((directory / "policy.json").string()));
    report["files"].append(JsonString((directory / "routing.rules").string()));
    report["files"].append(JsonString((directory / "migration-report.json").string()));
    const int exit = migrated.routing_equivalent && migrated.complete ? 0 : 5;
    report["status"] = exit == 0 ? "equivalent" : "draft";
    report["preserve_status"] = true;
    return Emit(report, exit, json, output, error);
}

std::string StoreRoot(const ParsedOptions& parsed, const std::string& config_path);

int HandleExport(const ParsedOptions& parsed, Json::Value& report, bool json,
    std::ostream& output, std::ostream& error) {
    auto fail = [&](const std::string& code, const std::string& message, int exit) {
        AddDiagnostic(report, code, message);
        return Emit(report, exit, json, output, error);
    };
    if (!parsed.error.empty()) return fail("E_POLICY_ARGUMENT", parsed.error, 2);
    if (!parsed.values.count("--config") || !parsed.values.count("--out"))
        return fail("E_POLICY_ARGUMENT", "--config and --out are required.", 2);
    Json::Value config;
    if (!ReadJsonFile(parsed.values.at("--config"), config))
        return fail("E_POLICY_CONFIG", "Configuration JSON could not be read without duplicate keys.", 2);
    auto declarations = policy::PolicySourceLoader::LoadDeclarations(config, parsed.values.at("--config"));
    AddDiagnostics(report, declarations.diagnostics);
    if (!declarations.Ok()) return Emit(report, DiagnosticExit(declarations.diagnostics), json, output, error);
    auto loaded = policy::PolicySourceLoader::LoadFile(parsed.values.at("--config"));
    bool load_ok = true;
    bool has_remote = false;
    for (const auto& entry : declarations.source.rule_sets) has_remote = has_remote || !entry.second.url.empty();
    for (const auto& diagnostic : loaded.diagnostics) {
        bool declared_remote_source = false;
        if (diagnostic.code == "E_POLICY_SOURCE_UNAVAILABLE") {
            for (const auto& entry : declarations.source.rule_sets) {
                const auto expected_path = "client.policy.rule-sets." + entry.first + ".source.url";
                if (!entry.second.url.empty() && diagnostic.path == expected_path) {
                    declared_remote_source = true;
                    break;
                }
            }
        }
        if (declared_remote_source) continue;
        AddDiagnostic(report, diagnostic.code, diagnostic.message, diagnostic.severity,
            diagnostic.file, diagnostic.line);
        report["diagnostics"][report["diagnostics"].size() - 1]["path"] = diagnostic.path.c_str();
        if (diagnostic.severity == "error") load_ok = false;
    }
    if (!load_ok) return Emit(report, DiagnosticExit(loaded.diagnostics), json, output, error);
    std::shared_ptr<policy::FileDurablePolicyBundleStore> store;
    std::string identity;
    if (has_remote) {
        identity = policy::PolicyUpdateService::ImmutableFingerprint(loaded.source);
        store = std::make_shared<policy::FileDurablePolicyBundleStore>(StoreRoot(parsed, parsed.values.at("--config")));
        const auto bundle = store->LoadCurrent(identity);
        if (!bundle.Ok())
            return fail("E_POLICY_SOURCE_UNAVAILABLE", "Remote export requires a verified durable CURRENT bundle for this policy identity.", 3);
        for (auto& pair : loaded.source.rule_sets) {
            if (pair.second.url.empty()) continue;
            const auto source = bundle.bundle.rule_sets.find(pair.first);
            if (source == bundle.bundle.rule_sets.end() || source->second.format != pair.second.format ||
                source->second.tag != pair.second.tag)
                return fail("E_POLICY_SOURCE_UNAVAILABLE", "The verified bundle does not contain the declared remote rule-set.", 3);
            pair.second.text = source->second.bytes;
            pair.second.materialized = true;
        }
        loaded.source.rules_text = bundle.bundle.rules;
        loaded.source.rules_path.clear();
    }
    auto compiled = policy::PolicyCompiler::Compile(loaded.source);
    AddDiagnostics(report, compiled.diagnostics);
    if (!compiled.Ok()) return Emit(report, DiagnosticExit(compiled.diagnostics), json, output, error);
    for (const auto& pair : loaded.source.rule_sets) {
        if (!pair.second.materialized)
            return fail("E_POLICY_SOURCE_UNAVAILABLE", "Export requires each rule-set to have a checked local materialization.", 3);
    }
    Json::Value exported(Json::objectValue);
    exported["client"]["policy"] = config["client"]["policy"];
    auto& policy_config = exported["client"]["policy"];
    Json::Value exported_resolvers(Json::objectValue);
    for (const auto& resolver : loaded.source.resolvers) {
        Json::Value item(Json::objectValue);
        item["via"] = resolver.second.via == policy::PolicyAction::Direct ? "direct" : "proxy";
        item["servers"] = Json::Value(Json::arrayValue);
        for (const auto& ref : resolver.second.server_order) {
            if (ref.structured) {
                if (ref.index >= resolver.second.server_specs.size())
                    return fail("E_POLICY_CONFIG", "Resolver server order refers to a missing structured server.", 2);
                const auto& server = resolver.second.server_specs[ref.index];
                if (server.uri.find_first_of("@?#") != std::string::npos)
                    return fail("E_POLICY_CONFIG", "Resolver URI contains user-specific or query data and cannot be exported safely.", 2);
                Json::Value spec(Json::objectValue);
                spec["uri"] = JsonString(server.uri);
                spec["addresses"] = Json::Value(Json::arrayValue);
                for (const auto& address : server.addresses) {
                    if (address.find_first_of("@?#") != std::string::npos)
                        return fail("E_POLICY_CONFIG", "Resolver address contains user-specific or query data and cannot be exported safely.", 2);
                    spec["addresses"].append(address.c_str());
                }
                spec["bootstrap"] = Json::Value(Json::arrayValue);
                for (const auto& endpoint : server.bootstrap) {
                    if (endpoint.find_first_of("@?#") != std::string::npos)
                        return fail("E_POLICY_CONFIG", "Resolver bootstrap contains user-specific or query data and cannot be exported safely.", 2);
                    spec["bootstrap"].append(endpoint.c_str());
                }
                item["servers"].append(std::move(spec));
            } else {
                if (ref.index >= resolver.second.servers.size())
                    return fail("E_POLICY_CONFIG", "Resolver server order refers to a missing server.", 2);
                const auto& server = resolver.second.servers[ref.index];
                if (server.find_first_of("@?#") != std::string::npos)
                    return fail("E_POLICY_CONFIG", "Resolver URI contains user-specific or query data and cannot be exported safely.", 2);
                item["servers"].append(server.c_str());
            }
        }
        if (item["servers"].empty())
            return fail("E_POLICY_CONFIG", "Resolver has no exportable upstream servers.", 2);
        exported_resolvers[JsonString(resolver.first)] = std::move(item);
    }
    policy_config["dns"]["resolvers"] = exported_resolvers;
    if (!policy_config.isMember("ipv6")) policy_config["ipv6"] = "block";
    if (!policy_config["dns"].isMember("mode")) policy_config["dns"]["mode"] = loaded.source.dns_mode.c_str();
    if (!policy_config["tcp-domain-sniff"].isBool())
        policy_config["tcp-domain-sniff"] = loaded.source.tcp_domain_sniff;
    if (!policy_config["dns"].isMember("fake-ip")) {
        policy_config["dns"]["fake-ip"]["range"] = loaded.source.fake_ip_range.c_str();
        policy_config["dns"]["fake-ip"]["storage"] = JsonString(loaded.source.fake_ip_storage);
        policy_config["dns"]["fake-ip"]["identity"] = loaded.source.fake_ip_identity.c_str();
    } else {
        auto& fake_ip = policy_config["dns"]["fake-ip"];
        if (!fake_ip.isMember("range")) fake_ip["range"] = loaded.source.fake_ip_range.c_str();
        if (!fake_ip.isMember("storage")) fake_ip["storage"] = JsonString(loaded.source.fake_ip_storage);
        if (!fake_ip.isMember("identity")) fake_ip["identity"] = loaded.source.fake_ip_identity.c_str();
    }
    auto& updates = policy_config["updates"];
    if (!updates.isMember("enabled")) updates["enabled"] = loaded.source.updates_enabled;
    if (!updates.isMember("interval")) updates["interval"] = loaded.source.updates_interval.c_str();
    if (!updates.isMember("via")) updates["via"] = loaded.source.updates_via == policy::PolicyAction::Direct ? "direct" : "proxy";
    if (!updates.isMember("bootstrap")) {
        updates["bootstrap"] = Json::Value(Json::arrayValue);
        for (const auto& endpoint : loaded.source.updates_bootstrap) updates["bootstrap"].append(endpoint.c_str());
    }
    const fs::path target = fs::absolute(parsed.values.at("--out")).lexically_normal();
    const auto rules_name = target.filename().string() + ".routing.rules";
    policy_config["rules"]["path"] = JsonString(rules_name);
    std::vector<std::pair<fs::path, std::string>> output_files;
    output_files.emplace_back(target.parent_path() / rules_name, loaded.source.rules_text);
    Json::Value metadata(Json::objectValue);
    metadata["schema"] = 1;
    metadata["policy_version"] = Json::UInt64(compiled.snapshot->Version());
    metadata["rules_sha256"] = JsonString(Sha256(loaded.source.rules_text));
    metadata["rules_bytes"] = Json::UInt64(loaded.source.rules_text.size());
    metadata["base_path"] = ".";
    metadata["dns_mode"] = loaded.source.dns_mode.c_str();
    metadata["ipv6"] = loaded.source.ipv6.c_str();
    metadata["tcp_domain_sniff"] = loaded.source.tcp_domain_sniff;
    metadata["fake_ip_range"] = loaded.source.fake_ip_range.c_str();
    const auto fake_ip_storage = target.filename().string() + ".dns-fake-ip";
    const auto fake_ip_identity = "export-" + policy::PolicyUpdateService::ImmutableFingerprint(loaded.source).substr(0, 16);
    policy_config["dns"]["fake-ip"]["storage"] = JsonString(fake_ip_storage);
    policy_config["dns"]["fake-ip"]["identity"] = JsonString(fake_ip_identity);
    metadata["fake_ip_storage"] = JsonString(fake_ip_storage);
    metadata["fake_ip_identity"] = JsonString(fake_ip_identity);
    metadata["resolvers"] = exported_resolvers;
    metadata["rule_sets"] = Json::Value(Json::objectValue);
    for (auto& pair : loaded.source.rule_sets) {
        const auto asset_sha256 = Sha256(pair.second.text);
        const auto asset_name = target.filename().string() + ".asset." + pair.first + "." + asset_sha256;
        auto& set = policy_config["rule-sets"][JsonString(pair.first)];
        const std::string source_url = pair.second.url;
        set["source"].removeMember("url");
        set["source"]["path"] = JsonString(asset_name);
        set["sha256"] = JsonString(asset_sha256);
        output_files.emplace_back(target.parent_path() / asset_name, pair.second.text);
        Json::Value item(Json::objectValue);
        item["format"] = pair.second.format.c_str();
        item["tag"] = pair.second.tag.c_str();
        item["sha256"] = JsonString(asset_sha256);
        item["bytes"] = Json::UInt64(pair.second.text.size());
        if (!source_url.empty()) item["source_url_redacted"] = JsonString(policy::RedactPolicySourceUrl(source_url));
        metadata["rule_sets"][JsonString(pair.first)] = std::move(item);
    }
    exported["policy_export"] = metadata;
    output_files.emplace_back(target, JsonText(exported));
    std::string write_error;
    std::vector<fs::path> created_directories;
    if (!CreateParentDirectories(target.parent_path(), created_directories, write_error))
        return fail("E_POLICY_STORAGE", write_error, 3);
    if (!WriteFilesNoReplace(output_files, write_error)) {
        RemoveEmptyDirectoriesReverse(created_directories);
        return fail("E_POLICY_STORAGE", write_error, 3);
    }
    report["policy_version"] = Json::UInt64(compiled.snapshot->Version());
    report["out"] = JsonString(target.string());
    return Emit(report, 0, json, output, error);
}

std::int64_t EpochMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool LoadPolicyDeclarations(const std::string& path, policy::PolicyLoadResult& loaded,
    Json::Value& report) {
    Json::Value config;
    if (!ReadJsonFile(path, config)) {
        AddDiagnostic(report, "E_POLICY_CONFIG", "Configuration JSON could not be read without duplicate keys.");
        return false;
    }
    loaded = policy::PolicySourceLoader::LoadDeclarations(config, path);
    AddDiagnostics(report, loaded.diagnostics);
    return loaded.Ok();
}

bool ParseBootstrapEndpoints(const std::string& value,
    std::vector<boost::asio::ip::udp::endpoint>& endpoints) {
    std::size_t start = 0;
    while (start < value.size()) {
        const auto comma = value.find(',', start);
        const auto end = comma == std::string::npos ? value.size() : comma;
        const auto entry = value.substr(start, end - start);
        if (entry.rfind("udp://", 0) != 0) return false;
        const auto port_sep = entry.rfind(':');
        if (port_sep == std::string::npos || port_sep <= 6 || port_sep + 1 == entry.size()) return false;
        const auto port = entry.substr(port_sep + 1);
        if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) return false;
        unsigned port_value = 0;
        for (char c : port) port_value = port_value * 10 + static_cast<unsigned>(c - '0');
        if (!port_value || port_value > 65535) return false;
        boost::system::error_code ec;
        const auto address = boost::asio::ip::make_address(entry.substr(6, port_sep - 6), ec);
        if (ec || !address.is_v4()) return false;
        const boost::asio::ip::udp::endpoint endpoint(address, static_cast<unsigned short>(port_value));
        if (std::find(endpoints.begin(), endpoints.end(), endpoint) == endpoints.end()) endpoints.push_back(endpoint);
        if (comma == std::string::npos) break;
        start = comma + 1;
        if (start == value.size()) return false;
    }
    return !endpoints.empty();
}

std::string StoreRoot(const ParsedOptions& parsed, const std::string& config_path) {
    if (parsed.values.count("--store")) return fs::absolute(parsed.values.at("--store")).lexically_normal().string();
    return policy::PolicyStoreRootForConfig(config_path);
}

Json::Value StatusJson(const policy::PolicyUpdateStatus& status) {
    Json::Value value(Json::objectValue);
    value["active_version"] = Json::UInt64(status.active_version);
    value["identity"] = JsonString(status.identity_fingerprint);
    value["durable_current"] = status.durable_current;
    value["durable_previous"] = status.durable_previous;
    value["prepared_pending_commit"] = status.prepared_pending_commit;
    value["prepared_version"] = Json::UInt64(status.prepared_version);
    value["prepared_digest"] = JsonString(status.prepared_digest);
    value["offline"] = status.offline;
    value["last_attempt_ms"] = Json::Int64(status.last_attempt_ms);
    value["last_success_ms"] = Json::Int64(status.last_success_ms);
    value["next_attempt_ms"] = Json::Int64(status.next_attempt_ms);
    value["last_result"] = JsonString(status.last_result);
    value["last_diagnostic"] = JsonString(status.last_diagnostic);
    value["sources"] = Json::Value(Json::arrayValue);
    for (const auto& source : status.sources) {
        Json::Value item(Json::objectValue);
        item["name"] = JsonString(source.name);
        item["url_redacted"] = JsonString(source.url_redacted);
        item["etag"] = JsonString(source.etag);
        item["last_modified"] = JsonString(source.last_modified);
        item["sha256"] = JsonString(source.sha256);
        item["bytes"] = Json::UInt64(source.bytes);
        item["validated_at_ms"] = Json::Int64(source.validated_at_ms);
        value["sources"].append(std::move(item));
    }
    return value;
}

Json::Value CountersJson(const policy::PolicyStatusCounters& counters) {
    Json::Value value(Json::objectValue);
    value["dns_cache_hits"] = Json::UInt64(counters.dns_cache_hits);
    value["dns_cache_misses"] = Json::UInt64(counters.dns_cache_misses);
    value["dns_cache_coalesced"] = Json::UInt64(counters.dns_cache_coalesced);
    value["dns_timeout_attempts"] = Json::UInt64(counters.dns_timeout_attempts);
    value["dns_timeouts"] = Json::UInt64(counters.dns_timeouts);
    value["dns_upstream_failures"] = Json::UInt64(counters.dns_upstream_failures);
    value["dns_cancelled"] = Json::UInt64(counters.dns_cancelled);
    value["fake_ip_mappings"] = Json::UInt64(counters.fake_ip_mappings);
    value["fake_ip_exhaustions"] = Json::UInt64(counters.fake_ip_exhaustions);
    value["fake_ip_persistence_errors"] = Json::UInt64(counters.fake_ip_persistence_errors);
    value["fake_ip_pending"] = Json::UInt64(counters.fake_ip_pending);
    value["policy_direct"] = Json::UInt64(counters.policy_direct);
    value["policy_proxy"] = Json::UInt64(counters.policy_proxy);
    value["policy_reject"] = Json::UInt64(counters.policy_reject);
    return value;
}

int HandleStatus(const ParsedOptions& parsed, Json::Value& report, bool json,
    std::ostream& output, std::ostream& error) {
    if (!parsed.error.empty()) {
        AddDiagnostic(report, "E_POLICY_ARGUMENT", parsed.error);
        return Emit(report, 2, json, output, error);
    }
    policy::PolicyLoadResult loaded;
    if (!parsed.values.count("--config") ||
        !LoadPolicyDeclarations(parsed.values.at("--config"), loaded, report))
        return Emit(report, 2, json, output, error);
    const auto identity = policy::PolicyUpdateService::ImmutableFingerprint(loaded.source);
    const auto root = StoreRoot(parsed, parsed.values.at("--config"));
    const auto status_path = (fs::path(root) / identity / "STATUS.json").string();
    auto result = policy::ReadStatus(status_path, identity, EpochMillis());
    report["identity"] = JsonString(identity);
    report["status_file"] = JsonString(status_path);
    report["runtime_state"] = policy::PolicyStatusStateName(result.state);
    report["reason"] = JsonString(result.reason);
    if (!result.record.identity.empty()) {
        report["pid"] = Json::UInt64(result.record.pid);
        report["process_start"] = JsonString(result.record.process_start);
        report["updated_at_ms"] = Json::Int64(result.record.updated_at_ms);
        report["session_generation"] = Json::UInt64(result.record.session_generation);
        report["active_version"] = Json::UInt64(result.record.active_version);
        report["prepared_version"] = Json::UInt64(result.record.prepared_version);
        report["prepared_digest"] = JsonString(result.record.prepared_digest);
        report["prepared_pending_commit"] = result.record.prepared_version != 0 &&
            result.record.prepared_version != result.record.active_version;
        report["offline"] = result.record.offline;
        report["counters"] = CountersJson(result.record.counters);
        report["durable_current"] = JsonString(result.record.durable_current);
        report["durable_previous"] = JsonString(result.record.durable_previous);
        report["last_attempt_ms"] = Json::Int64(result.record.last_attempt_ms);
        report["last_success_ms"] = Json::Int64(result.record.last_success_ms);
        report["next_attempt_ms"] = Json::Int64(result.record.next_attempt_ms);
        report["last_result"] = JsonString(result.record.last_result);
        report["last_diagnostic"] = JsonString(result.record.last_diagnostic);
        report["sources"] = Json::Value(Json::arrayValue);
        for (const auto& source : result.record.sources) {
            Json::Value item(Json::objectValue);
            item["name"] = JsonString(source.name);
            item["url_redacted"] = JsonString(source.url_redacted);
            item["etag"] = JsonString(source.etag);
            item["last_modified"] = JsonString(source.last_modified);
            item["sha256"] = JsonString(source.sha256);
            item["bytes"] = Json::UInt64(source.bytes);
            item["validated_at_ms"] = Json::Int64(source.validated_at_ms);
            report["sources"].append(std::move(item));
        }
    }
    return Emit(report, 0, json, output, error);
}

int HandleUpdate(const ParsedOptions& parsed, Json::Value& report, bool json,
    std::ostream& output, std::ostream& error) {
    if (!parsed.error.empty()) {
        AddDiagnostic(report, "E_POLICY_ARGUMENT", parsed.error);
        return Emit(report, 2, json, output, error);
    }
    const bool direct = parsed.values.count("--interface") != 0;
    const bool proxy = parsed.values.count("--proxy-endpoint") != 0;
    if (!parsed.values.count("--config") || direct == proxy) {
        AddDiagnostic(report, "E_POLICY_ARGUMENT", "--config and exactly one of --interface or --proxy-endpoint are required.");
        return Emit(report, 2, json, output, error);
    }
    policy::PolicyLoadResult loaded;
    if (!LoadPolicyDeclarations(parsed.values.at("--config"), loaded, report))
        return Emit(report, 2, json, output, error);
    const auto requested_via = direct ? policy::PolicyAction::Direct : policy::PolicyAction::Proxy;
    if (loaded.source.updates_via != requested_via) {
        AddDiagnostic(report, "E_POLICY_CONFIG", "The selected update transport must match client.policy.updates.via.");
        return Emit(report, 2, json, output, error);
    }
    std::shared_ptr<policy::PolicyUpdateSocketConnector> connector;
    if (direct) {
        policy::DirectPolicySocketOptions options;
        options.interface_name = parsed.values.at("--interface");
        if (parsed.values.count("--bootstrap") &&
            !ParseBootstrapEndpoints(parsed.values.at("--bootstrap"), options.bootstrap_nameservers)) {
            AddDiagnostic(report, "E_POLICY_ARGUMENT", "--bootstrap must be comma-separated udp://IPv4:PORT resolver URIs.");
            return Emit(report, 2, json, output, error);
        }
        if (!parsed.values.count("--bootstrap")) {
            for (const auto& bootstrap : loaded.source.updates_bootstrap) {
                std::vector<boost::asio::ip::udp::endpoint> parsed_endpoints;
                if (!ParseBootstrapEndpoints(bootstrap, parsed_endpoints)) continue;
                for (const auto& endpoint : parsed_endpoints) {
                    if (std::find(options.bootstrap_nameservers.begin(), options.bootstrap_nameservers.end(), endpoint) == options.bootstrap_nameservers.end())
                        options.bootstrap_nameservers.push_back(endpoint);
                }
            }
        }
        connector = std::make_shared<policy::DirectPolicySocketConnector>(std::move(options));
        report["via"] = "direct";
    } else {
        if (parsed.values.count("--bootstrap")) {
            AddDiagnostic(report, "E_POLICY_ARGUMENT", "--bootstrap is only valid with --interface.");
            return Emit(report, 2, json, output, error);
        }
        const auto& endpoint_text = parsed.values.at("--proxy-endpoint");
        const auto colon = endpoint_text.rfind(':');
        if (colon == std::string::npos || endpoint_text.substr(0, colon) != "127.0.0.1") {
            AddDiagnostic(report, "E_POLICY_ARGUMENT", "--proxy-endpoint must be a numeric IPv4 loopback SOCKS5 endpoint (127.0.0.1:PORT).");
            return Emit(report, 2, json, output, error);
        }
        const auto port_text = endpoint_text.substr(colon + 1);
        unsigned port = 0;
        if (port_text.empty() || port_text.size() > 5 ||
            !std::all_of(port_text.begin(), port_text.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) {
            AddDiagnostic(report, "E_POLICY_ARGUMENT", "--proxy-endpoint port must be from 1 through 65535.");
            return Emit(report, 2, json, output, error);
        }
        for (char c : port_text) port = port * 10 + static_cast<unsigned>(c - '0');
        if (!port || port > 65535) {
            AddDiagnostic(report, "E_POLICY_ARGUMENT", "--proxy-endpoint port must be from 1 through 65535.");
            return Emit(report, 2, json, output, error);
        }
        connector = std::make_shared<policy::LocalSocks5PolicySocketConnector>(
            boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), static_cast<unsigned short>(port)));
        report["via"] = "proxy";
        report["proxy_endpoint"] = JsonString("127.0.0.1:" + std::to_string(port));
    }
    const auto identity = policy::PolicyUpdateService::ImmutableFingerprint(loaded.source);
    const auto store_root = StoreRoot(parsed, parsed.values.at("--config"));
    const auto runtime_store_root = policy::PolicyStoreRootForConfig(parsed.values.at("--config"));
    const bool runtime_store_compatible = fs::absolute(store_root).lexically_normal() ==
        fs::absolute(runtime_store_root).lexically_normal();
    report["store_root"] = JsonString(store_root);
    report["runtime_store_root"] = JsonString(runtime_store_root);
    report["runtime_store_compatible"] = runtime_store_compatible;
    const auto status_path = (fs::path(store_root) /
        identity / "STATUS.json").string();
    policy::PolicyStatusWriterLease status_lease;
    std::string status_error;
    if (!status_lease.TryAcquire(status_path, identity, status_error)) {
        AddDiagnostic(report, "E_POLICY_STATUS_OWNED",
            "A runtime process owns the status writer lease; no update was attempted.");
        report["status_record"] = "runtime_owned";
        return Emit(report, 3, json, output, error);
    }
    std::uint64_t process_id = 0;
    std::string process_start;
    if (!policy::GetCurrentProcessIdentity(process_id, process_start, status_error)) {
        AddDiagnostic(report, "E_POLICY_STATUS_IDENTITY", status_error);
        return Emit(report, 3, json, output, error);
    }
    policy::PolicyRuntime runtime;
    auto store = std::make_shared<policy::FileDurablePolicyBundleStore>(store_root);
    auto fetcher = std::make_shared<policy::HttpsPolicyUpdateFetcher>(
        std::move(connector), loaded.source.updates_allow_http);
    policy::PolicyUpdateService service(runtime, std::move(loaded.source), std::move(store), std::move(fetcher));
    const auto result = service.RunOnce(policy::PolicyUpdateMode::PrepareOnly);
    const auto status = service.Status();
    report["update_state"] = result.code == policy::PolicyUpdateResultCode::Prepared
        ? (runtime_store_compatible ? "prepared_for_next_start" : "prepared_in_custom_store") :
        result.code == policy::PolicyUpdateResultCode::Unchanged ? "unchanged" : "failed";
    report["runtime_active_version"] = Json::UInt64(status.active_version);
    report["prepared_pending_commit"] = status.prepared_pending_commit;
    report["durable_current"] = status.durable_current;
    report["durable_previous"] = status.durable_previous;
    report["identity"] = JsonString(status.identity_fingerprint);
    report["update_status"] = StatusJson(status);
    const auto previous = policy::ReadStatus(status_path, identity, EpochMillis());
    auto record = policy::MakePolicyStatusRecord(status, process_id, process_start,
        previous.record.identity == identity ? previous.record.session_generation : 0,
        EpochMillis(), true);
    if (previous.record.identity == identity) {
        record.active_version = previous.record.active_version;
        record.counters = previous.record.counters;
    }
    if (status_lease.Write(record, status_error)) {
        report["status_record"] = "prepared_offline";
    } else {
        AddDiagnostic(report, "E_POLICY_STATUS_WRITE", status_error);
        report["status_record"] = "unavailable";
        return Emit(report, 3, json, output, error);
    }
    if (!result.Ok()) {
        AddDiagnostic(report, "E_POLICY_SOURCE_UNAVAILABLE",
            result.diagnostic.empty() ? "Policy update failed; durable and runtime state were preserved." : result.diagnostic);
        return Emit(report, 3, json, output, error);
    }
    return Emit(report, 0, json, output, error);
}
} // namespace

std::optional<int> ApplicationPolicyCommand::Dispatch(int argc, const char* const* argv,
    std::ostream& output, std::ostream& error) {
    if (argc < 2 || !argv || !argv[1] || std::string(argv[1]) != "policy") return std::nullopt;
    Json::Value report(Json::objectValue);
    report["schema"] = 1;
    report["command"] = argc > 2 && argv[2] ? argv[2] : "";
    report["plan_only"] = true;
    report["runtime_installed"] = false;
    report["capability_evidence"] = "current source paths; no platform runtime or VPN session verified";
    report["diagnostics"] = Json::Value(Json::arrayValue);
    bool json = false;
    for (int i = 3; i < argc; ++i) if (argv[i] && std::string(argv[i]) == "--json") json = true;
    auto argumentError = [&](const std::string& message) {
        AddDiagnostic(report, "E_POLICY_ARGUMENT", message);
        return Emit(report, 2, json, output, error);
    };
    const std::string command = report["command"].asCString();
    if (command == "init" || command == "migrate" || command == "export" ||
        command == "update" || command == "status") {
        std::set<std::string> values;
        std::set<std::string> flags = {"--json"};
        if (command == "init") values = {"--out", "--template", "--runtime", "--geoip", "--geosite"};
        else if (command == "migrate") values = {"--config", "--out", "--bypass", "--dns-rules", "--runtime", "--platform"};
        else if (command == "export") values = {"--config", "--out", "--store"};
        else if (command == "update") values = {"--config", "--store", "--interface", "--proxy-endpoint", "--bootstrap"};
        else values = {"--config", "--store"};
        auto parsed = ParseStrictOptions(argc, argv, values, flags);
        json = json || parsed.flags.count("--json") != 0;
        if (command == "init") return HandleInit(parsed, report, json, output, error);
        if (command == "migrate") return HandleMigrate(parsed, report, json, output, error);
        if (command == "export") return HandleExport(parsed, report, json, output, error);
        if (command == "update") return HandleUpdate(parsed, report, json, output, error);
        return HandleStatus(parsed, report, json, output, error);
    }
    if (command != "check" && command != "explain") return argumentError("Expected policy check or policy explain.");
    std::map<std::string, std::string> options;
    std::set<std::string> seen;
    const std::set<std::string> allowed = {"--config", "--runtime", "--platform", "--domain", "--ip", "--network", "--port", "--json"};
    for (int i = 3; i < argc; ++i) {
        if (!argv[i]) return argumentError("Null command argument.");
        std::string name = argv[i];
        if (!allowed.count(name)) return argumentError("Unknown policy option: " + name);
        if (!seen.insert(name).second) return argumentError("Duplicate policy option: " + name);
        if (name == "--json") continue;
        if (i + 1 >= argc || !argv[i + 1] || std::string(argv[i + 1]).rfind("--", 0) == 0)
            return argumentError("Missing value for " + name);
        options[name] = argv[++i];
        if (options[name].empty()) return argumentError("Empty value for " + name);
    }
    if (!options.count("--config") || !options.count("--runtime")) return argumentError("--config and --runtime are required.");
    const std::string runtime = options["--runtime"];
    const std::string platform = options.count("--platform") ? options["--platform"] : HostPlatform();
    const std::set<std::string> runtimes = {"tun", "http", "socks"};
    const std::set<std::string> platforms = {"linux", "windows", "macos", "android", "ios"};
    if (!runtimes.count(runtime)) return argumentError("--runtime must be tun, http or socks.");
    if (!platforms.count(platform)) return argumentError("Unknown --platform.");
    report["runtime"] = runtime.c_str();
    report["platform"] = platform.c_str();
    if (command == "check" && (options.count("--domain") || options.count("--ip") || options.count("--network") || options.count("--port")))
        return argumentError("Target options are only valid for policy explain.");
    const std::string network = options.count("--network") ? options["--network"] : "tcp";
    unsigned int port = 0;
    if (network != "tcp" && network != "udp") return argumentError("--network must be tcp or udp.");
    if (options.count("--port")) {
        const std::string& value = options["--port"];
        if (value.size() > 5 || !std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))
            return argumentError("--port must be an integer from 1 to 65535.");
        for (char c : value) port = port * 10 + static_cast<unsigned int>(c - '0');
        if (!port || port > 65535) return argumentError("--port must be an integer from 1 to 65535.");
    }
    const std::string domain = options["--domain"];
    const std::string ip = options["--ip"];
    if (command == "explain") {
        if (domain.empty() && ip.empty()) return argumentError("policy explain requires --domain or --ip.");
        if (!domain.empty() && !ValidDomain(domain)) return argumentError("Invalid domain; use ASCII/Punycode host names and --ip for IP literals.");
        if (!ip.empty()) {
            boost::system::error_code ec;
            const auto address = boost::asio::ip::make_address(ip, ec);
            if (ec) return argumentError("Invalid --ip address.");
            if (address.is_v6()) {
                AddDiagnostic(report, "E_POLICY_IPV6_UNSUPPORTED", "IPv6 target routing is outside the first policy version; configured block is only a plan.");
                return Emit(report, 4, json, output, error);
            }
        }
    }
    try {
        auto loaded = policy::PolicySourceLoader::LoadFile(options["--config"]);
        AddDiagnostics(report, loaded.diagnostics);
        if (!loaded.Ok()) return Emit(report, DiagnosticExit(loaded.diagnostics), json, output, error);
        auto compiled = policy::PolicyCompiler::Compile(loaded.source);
        AddDiagnostics(report, compiled.diagnostics);
        if (!compiled.Ok()) return Emit(report, DiagnosticExit(compiled.diagnostics), json, output, error);
        const auto& snapshot = *compiled.snapshot;
        report["config_version"] = loaded.source.version;
        report["policy_version"] = Json::UInt64(snapshot.Version());
        report["rule_count"] = Json::UInt64(snapshot.RuleCount());
        report["skipped_ipv6"] = Json::UInt64(snapshot.SkippedIpv6());
        report["dns_mode"] = loaded.source.dns_mode == "auto" ? (runtime == "tun" ? "fake-ip" : "original-domain") : loaded.source.dns_mode.c_str();
        report["tcp_domain_sniff"] = snapshot.TcpDomainSniff();
        report["tcp_domain_sniff_applicable"] = runtime == "tun";
        bool supported = true;
        if (snapshot.TcpDomainSniff()) {
            if (runtime == "tun" && platform == "ios") {
                AddDiagnostic(report, "E_POLICY_CAPABILITY_UNSUPPORTED", "iOS TUN does not support TCP domain sniffing.");
                supported = false;
            } else if (runtime != "tun") {
                AddDiagnostic(report, "W_POLICY_SETTING_NOT_APPLICABLE",
                    "TCP domain sniffing applies only to TUN; local HTTP/SOCKS preserve their original target domain.", "warning");
            }
        }
        if (runtime != "tun" && loaded.source.dns_mode == "fake-ip") {
            AddDiagnostic(report, "E_POLICY_CAPABILITY_UNSUPPORTED", "Explicit Fake-IP mode requires TUN DNS interception.");
            supported = false;
        }
        if (command == "check") {
            bool direct = policy::PolicyEvaluator::Evaluate(snapshot, "").action == policy::PolicyAction::Direct;
            for (const auto& rule : snapshot.Rules()) if (rule.resolver.empty() && rule.action == policy::PolicyAction::Direct) direct = true;
            if (direct) {
                supported = Capability(report, runtime, platform, "tcp", policy::PolicyAction::Direct) && supported;
                if (runtime != "http")
                    supported = Capability(report, runtime, platform, "udp", policy::PolicyAction::Direct) && supported;
            }
            std::set<std::string> dns_references;
            const auto fallback = policy::PolicyEvaluator::Evaluate(snapshot, "").action;
            if (fallback != policy::PolicyAction::Reject) dns_references.insert(snapshot.DnsResolverForAction(fallback));
            for (const auto& rule : snapshot.Rules()) {
                if (!rule.resolver.empty()) dns_references.insert(rule.resolver);
                else if (rule.condition != policy::PolicyCondition::Ipv4Cidr && rule.action != policy::PolicyAction::Reject)
                    dns_references.insert(snapshot.DnsResolverForAction(rule.action));
            }
            for (const auto& name : dns_references) {
                const auto resolver = snapshot.Resolvers().find(name);
                if (resolver != snapshot.Resolvers().end())
                    supported = DnsCapability(report, runtime, platform, resolver->second.via) && supported;
            }
        } else {
            const auto decision = policy::PolicyEvaluator::Evaluate(snapshot, domain, ip);
            Json::Value route(Json::objectValue);
            route["action"] = ActionName(decision.action);
            route["matched"] = decision.matched;
            route["needs_ip"] = decision.needs_ip_resolution;
            route["provisional"] = decision.needs_ip_resolution;
            route["rule_id"] = decision.rule_id.c_str();
            route["source"] = decision.source.c_str();
            route["file"] = decision.file.c_str();
            route["line"] = Json::UInt64(decision.line);
            route["reason"] = decision.reason.c_str();
            route["version"] = Json::UInt64(decision.version);
            report["route"] = route;
            const auto plan = policy::PolicyEvaluator::PlanDns(snapshot, domain);
            Json::Value dns(Json::objectValue);
            dns["applicable"] = !domain.empty();
            dns["action"] = ActionName(plan.action);
            dns["resolver"] = plan.resolver.c_str();
            dns["via"] = ActionName(plan.via);
            dns["rejected"] = plan.rejected;
            dns["rule_id"] = plan.rule_id.c_str();
            dns["source"] = plan.source.c_str();
            dns["file"] = plan.file.c_str();
            dns["line"] = Json::UInt64(plan.line);
            dns["version"] = Json::UInt64(plan.version);
            report["dns"] = dns;
            if (!domain.empty() && !plan.rejected)
                supported = DnsCapability(report, runtime, platform, plan.via) && supported;
            report["network"] = network.c_str();
            report["port"] = port;
            if (!decision.needs_ip_resolution || (runtime == "http" && network == "udp"))
                supported = Capability(report, runtime, platform, network, decision.action) && supported;
        }
        return Emit(report, supported ? 0 : 4, json, output, error);
    } catch (const std::exception&) {
        AddDiagnostic(report, "E_POLICY_CONFIG", "Policy processing failed; no runtime was started.");
        return Emit(report, 2, json, output, error);
    }
}
} // namespace ppp::app
