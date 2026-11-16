#include "PolicySourceLoader.h"
#include <ppp/Filesystem.h>
#include <ppp/dns/DnsProviderCatalog.h>
#include <openssl/sha.h>
#include <boost/asio/ip/address_v4.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>

namespace ppp::app::client::policy {
namespace {
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;

std::string Std(const Json::String& value) { return std::string(value.data(), value.size()); }

void Error(PolicyLoadResult& result, const std::string& code,
           const std::string& path, const std::string& message) {
    PolicyDiagnostic diagnostic;
    diagnostic.code = code;
    diagnostic.path = path;
    diagnostic.file = result.source.config_path;
    diagnostic.message = message;
    result.diagnostics.push_back(std::move(diagnostic));
}

bool Object(PolicyLoadResult& r, const Json::Value& v, const std::string& path,
            std::initializer_list<const char*> allowed) {
    if (!v.isObject()) {
        Error(r, "E_POLICY_CONFIG", path, "Expected an object.");
        return false;
    }
    std::set<std::string> fields;
    for (const auto* field : allowed) fields.insert(field);
    for (const auto& member : v.getMemberNames()) {
        const auto field = Std(member);
        if (!fields.count(field)) Error(r, "E_POLICY_CONFIG", path + "." + field, "Unknown policy field.");
    }
    return true;
}

std::string String(PolicyLoadResult& r, const Json::Value& v, const std::string& path) {
    const auto value = v.isString() ? Std(v.asString()) : std::string();
    if (!v.isString() || value.empty() || value.find('\0') != std::string::npos ||
        std::all_of(value.begin(), value.end(), [](char ch) {
            return std::isspace(static_cast<unsigned char>(ch));
        })) {
        Error(r, "E_POLICY_CONFIG", path, "Expected a nonempty string.");
        return {};
    }
    return value;
}

PolicyAction Via(PolicyLoadResult& r, const Json::Value& v, const std::string& path) {
    const auto value = String(r, v, path);
    if (value == "direct") return PolicyAction::Direct;
    if (value == "proxy") return PolicyAction::Proxy;
    if (!value.empty()) Error(r, "E_POLICY_CONFIG", path, "Expected direct or proxy.");
    return PolicyAction::Proxy;
}

bool Read(PolicyLoadResult& r, const std::string& file, const std::string& path, std::string& text) {
    error_code ec;
    if (!fs::is_regular_file(file, ec)) {
        Error(r, "E_POLICY_SOURCE_UNAVAILABLE", path, "Source must be an existing regular file.");
        return false;
    }
    std::ifstream stream(file, std::ios::binary);
    if (!stream) {
        Error(r, "E_POLICY_SOURCE_UNAVAILABLE", path, "Source could not be opened.");
        return false;
    }
    constexpr std::size_t max_source_bytes = 64u * 1024u * 1024u;
    std::string bytes;
    std::array<char, 64u * 1024u> buffer;
    while (stream) {
        stream.read(buffer.data(), buffer.size());
        const auto count = static_cast<std::size_t>(stream.gcount());
        if (count > max_source_bytes - bytes.size()) {
            Error(r, "E_POLICY_SOURCE_UNAVAILABLE", path, "Source exceeds the 64 MiB offline validation limit.");
            return false;
        }
        bytes.append(buffer.data(), count);
    }
    if (stream.bad() || !stream.eof()) {
        Error(r, "E_POLICY_SOURCE_UNAVAILABLE", path, "Source could not be read completely.");
        return false;
    }
    text = std::move(bytes);
    return true;
}

std::string Resolve(const PolicySource& source, const std::string& path) {
    fs::path value(path);
    if (!value.is_absolute()) value = fs::path(source.base_path) / value;
    return value.lexically_normal().string();
}

bool Host(const std::string& host) {
    if (host.empty() || host.size() > 253) return false;
    if (std::all_of(host.begin(), host.end(), [](char c) { return (c >= '0' && c <= '9') || c == '.'; })) {
        boost::system::error_code ec;
        return boost::asio::ip::make_address(host, ec).is_v4() && !ec;
    }
    std::size_t start = 0;
    while (start < host.size()) {
        const auto end = host.find('.', start);
        const auto length = (end == std::string::npos ? host.size() : end) - start;
        if (!length || length > 63 || host[start] == '-' || host[start + length - 1] == '-') return false;
        for (std::size_t i = start; i < start + length; ++i) {
            const auto c = host[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) return false;
        }
        if (end == std::string::npos) return true;
        start = end + 1;
    }
    return false;
}

// Validate the supported URI subset without resolving hosts or adding a newer Boost.URL dependency.
bool Endpoint(const std::string& server, bool resource) {
    const auto scheme = server.find("://");
    if (scheme == std::string::npos) return false;
    const auto protocol = server.substr(0, scheme);
    if (resource ? protocol != "http" && protocol != "https"
                 : protocol != "udp" && protocol != "tcp" && protocol != "tls" && protocol != "https") return false;
    const auto authority_end = server.find_first_of("/?#", scheme + 3);
    const auto authority = server.substr(scheme + 3, authority_end - scheme - 3);
    if (authority.empty() || authority.find('@') != std::string::npos || server.find('#') != std::string::npos) return false;
    for (std::size_t i = 0; i < server.size(); ++i) {
        const auto ch = static_cast<unsigned char>(server[i]);
        if (ch <= 32 || ch >= 127 || ch == '\\' || ch == '"' || ch == '<' || ch == '>' ||
            ch == '^' || ch == '`' || ch == '{' || ch == '|' || ch == '}') return false;
        if (ch == '%') {
            if (i + 2 >= server.size() || !std::isxdigit(static_cast<unsigned char>(server[i + 1])) ||
                !std::isxdigit(static_cast<unsigned char>(server[i + 2]))) return false;
            i += 2;
        }
    }
    const auto colon = authority.rfind(':');
    auto host = authority;
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        const auto port = authority.substr(colon + 1);
        if (port.empty() || port.size() > 5 || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) return false;
        const auto number = std::stoul(port);
        if (!number || number > 65535) return false;
    }
    if (!Host(host)) return false;
    if (protocol == "udp" || protocol == "tcp") {
        boost::system::error_code ec;
        const auto address = boost::asio::ip::make_address(host, ec);
        if (ec || !address.is_v4()) return false;
    }
    if (resource) return true;
    return protocol == "https" ? authority_end != std::string::npos && server[authority_end] == '/' && authority_end + 1 < server.size()
                               : authority_end == std::string::npos;
}

bool Server(const std::string& server) {
    if (ppp::dns::DnsProviderCatalog::HasProvider(ppp::string(server.data(), server.size()))) return true;
    if (!Endpoint(server, false)) return false;
    const auto scheme = server.find("://");
    const auto authority_end = server.find_first_of("/?#", scheme + 3);
    auto host = server.substr(scheme + 3, authority_end - scheme - 3);
    const auto colon = host.rfind(':');
    if (colon != std::string::npos) host.resize(colon);
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(host, ec);
    return !ec && address.is_v4();
}

bool V4Literal(const std::string& value) {
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(value, ec);
    return !ec && address.is_v4() && !address.is_unspecified();
}

std::string Digest(const std::string& bytes) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest);
    const char* hex = "0123456789abcdef";
    std::string result;
    for (auto ch : digest) { result += hex[ch >> 4]; result += hex[ch & 15]; }
    return result;
}

bool Name(const std::string& name) {
    return !name.empty() && std::all_of(name.begin(), name.end(), [](char ch) {
        return std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_';
    });
}

bool Cidr(const std::string& value, std::uint32_t& address, unsigned& prefix) {
    const auto slash = value.find('/');
    const auto ip_text = value.substr(0, slash);
    boost::system::error_code ec;
    const auto ip = boost::asio::ip::make_address_v4(ip_text, ec);
    if (ec) return false;
    prefix = 32;
    if (slash != std::string::npos) {
        const auto bits = value.substr(slash + 1);
        if (bits.empty() || bits.size() > 2 ||
            !std::all_of(bits.begin(), bits.end(), [](char ch) { return ch >= '0' && ch <= '9'; })) return false;
        prefix = static_cast<unsigned>(std::stoul(bits));
        if (prefix > 32) return false;
    }
    address = ip.to_uint();
    return true;
}
} // namespace

PolicyLoadResult PolicySourceLoader::LoadFile(const std::string& config_path) {
    return LoadFileInternal(config_path, false);
}

PolicyLoadResult PolicySourceLoader::LoadDeclarationsFile(const std::string& config_path) {
    return LoadFileInternal(config_path, true);
}

PolicyLoadResult PolicySourceLoader::LoadFileInternal(const std::string& config_path, bool declarations_only) {
    PolicyLoadResult result;
    result.source.config_path = config_path;
    if (config_path.empty() || config_path.find('\0') != std::string::npos) {
        Error(result, "E_POLICY_CONFIG", "$", "A valid configuration file path is required.");
        return result;
    }
    std::string text;
    if (!Read(result, config_path, "$", text)) return result;
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    builder["failIfExtra"] = true;
    builder["allowComments"] = false;
    builder["allowTrailingCommas"] = false;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value config;
    Json::String errors;
    if (!reader->parse(text.data(), text.data() + text.size(), &config, &errors)) {
        // JsonCpp errors can reproduce input values; keep diagnostics free of credentials.
        Error(result, "E_POLICY_JSON", "$", "Invalid JSON or duplicate object key.");
        return result;
    }
    return LoadInternal(config, config_path, declarations_only);
}

PolicyLoadResult PolicySourceLoader::Load(const Json::Value& config, const std::string& config_path) {
    return LoadInternal(config, config_path, false);
}

PolicyLoadResult PolicySourceLoader::LoadDeclarations(const Json::Value& config, const std::string& config_path) {
    return LoadInternal(config, config_path, true);
}

PolicyLoadResult PolicySourceLoader::LoadInternal(const Json::Value& config, const std::string& config_path,
    bool declarations_only) {
    PolicyLoadResult result;
    auto& source = result.source;
    error_code ec;
    const auto absolute = fs::weakly_canonical(fs::absolute(fs::path(config_path), ec), ec);
    if (config_path.empty() || config_path.find('\0') != std::string::npos || ec) {
        Error(result, "E_POLICY_CONFIG", "$", "A configuration file path is required to resolve resources.");
        return result;
    }
    source.config_path = absolute.lexically_normal().string();
    source.base_path = absolute.parent_path().lexically_normal().string();
    if (!config.isObject() || !config["client"].isObject()) {
        Error(result, "E_POLICY_CONFIG", "client", "Expected a client configuration object.");
        return result;
    }
    const auto& client = config["client"];
    const auto& policy = client["policy"];
    if (!Object(result, policy, "client.policy", {"version", "rules", "ipv6", "dns", "rule-sets", "updates", "tcp-domain-sniff"})) return result;
    const auto& version = policy["version"];
    if ((version.type() != Json::intValue && version.type() != Json::uintValue) ||
        !version.isInt() || version.asInt() != 2)
        Error(result, "E_POLICY_CONFIG", "client.policy.version", "Expected policy version 2.");
    if (policy.isMember("tcp-domain-sniff")) {
        if (!policy["tcp-domain-sniff"].isBool())
            Error(result, "E_POLICY_CONFIG", "client.policy.tcp-domain-sniff", "Expected a boolean.");
        else source.tcp_domain_sniff = policy["tcp-domain-sniff"].asBool();
    }

    for (const char* field : {"routing", "bypass", "dns-rules"}) {
        if (client.isMember(field)) Error(result, "E_POLICY_SOURCE_CONFLICT", std::string("client.") + field,
                                         "Legacy client policy and v2 policy cannot coexist.");
    }
    for (const char* field : {"routing", "geo-rules", "dns", "bypass", "dns-rules"}) {
        if (config.isMember(field)) Error(result, "E_POLICY_SOURCE_CONFLICT", field,
                                         "Legacy client policy and v2 policy cannot coexist.");
    }
    if (config["udp"].isObject() && config["udp"].isMember("dns"))
        Error(result, "E_POLICY_SOURCE_CONFLICT", "udp.dns", "Legacy DNS policy and v2 policy cannot coexist.");

    if (Object(result, policy["rules"], "client.policy.rules", {"path"})) {
        const auto path = String(result, policy["rules"]["path"], "client.policy.rules.path");
        if (!path.empty()) {
            source.rules_path = Resolve(source, path);
            if (!declarations_only) Read(result, source.rules_path, "client.policy.rules.path", source.rules_text);
        }
    }
    if (policy.isMember("ipv6")) {
        source.ipv6 = String(result, policy["ipv6"], "client.policy.ipv6");
        if (!source.ipv6.empty() && source.ipv6 != "block")
            Error(result, "E_POLICY_CAPABILITY_UNSUPPORTED", "client.policy.ipv6", "Only IPv6 block is supported in this phase.");
    }
    if (Object(result, policy["dns"], "client.policy.dns", {"mode", "resolvers", "fake-ip"})) {
        const auto& dns = policy["dns"];
        if (dns.isMember("mode")) {
            source.dns_mode = String(result, dns["mode"], "client.policy.dns.mode");
            if (!source.dns_mode.empty() && source.dns_mode != "auto" &&
                source.dns_mode != "real" && source.dns_mode != "fake-ip")
                Error(result, "E_POLICY_CONFIG", "client.policy.dns.mode", "Expected auto, real, or fake-ip.");
        }
        if (dns.isMember("fake-ip") && Object(result, dns["fake-ip"], "client.policy.dns.fake-ip",
                {"range", "storage", "identity"})) {
            const auto& fake_ip = dns["fake-ip"];
            if (fake_ip.isMember("range")) source.fake_ip_range = String(result, fake_ip["range"], "client.policy.dns.fake-ip.range");
            if (fake_ip.isMember("storage")) {
                const auto storage = String(result, fake_ip["storage"], "client.policy.dns.fake-ip.storage");
                if (!storage.empty()) source.fake_ip_storage = Resolve(source, storage);
                else Error(result, "E_POLICY_CONFIG", "client.policy.dns.fake-ip.storage", "Persistent storage path must not be empty.");
            }
            if (fake_ip.isMember("identity")) {
                source.fake_ip_identity = String(result, fake_ip["identity"], "client.policy.dns.fake-ip.identity");
                if (source.fake_ip_identity.empty() || source.fake_ip_identity.size() > 128 ||
                    !std::all_of(source.fake_ip_identity.begin(), source.fake_ip_identity.end(), [](unsigned char ch) {
                        return std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == ':';
                    }))
                    Error(result, "E_POLICY_CONFIG", "client.policy.dns.fake-ip.identity", "Expected a stable identifier using letters, digits, '.', '_', '-', or ':'.");
            }
        }
        if (source.fake_ip_storage == "./dns-fake-ip") source.fake_ip_storage = Resolve(source, source.fake_ip_storage);
        if (source.fake_ip_identity.empty()) source.fake_ip_identity = Digest(source.config_path);
        std::uint32_t pool_address = 0;
        unsigned pool_prefix = 0;
        if (!Cidr(source.fake_ip_range, pool_address, pool_prefix))
            Error(result, "E_POLICY_CONFIG", "client.policy.dns.fake-ip.range", "Expected a valid IPv4 CIDR.");
        if (source.dns_mode == "fake-ip" && source.fake_ip_storage.empty())
            Error(result, "E_POLICY_CONFIG", "client.policy.dns.fake-ip.storage", "Fake-IP mode requires durable storage.");
        const auto& resolvers = dns["resolvers"];
        if (!resolvers.isObject() || resolvers.empty())
            Error(result, "E_POLICY_CONFIG", "client.policy.dns.resolvers", "Expected a nonempty resolver object.");
        else for (const auto& member : resolvers.getMemberNames()) {
            const auto name = Std(member);
            const auto path = "client.policy.dns.resolvers." + name;
            if (!Name(name)) Error(result, "E_POLICY_CONFIG", path, "Invalid resource name.");
            const auto& value = resolvers[member];
            if (!Object(result, value, path, {"via", "servers"})) continue;
            PolicyResolver resolver;
            resolver.via = Via(result, value["via"], path + ".via");
            if (!value["servers"].isArray() || value["servers"].empty())
                Error(result, "E_POLICY_CONFIG", path + ".servers", "Expected a nonempty server array.");
            else {
                for (Json::ArrayIndex i = 0; i < value["servers"].size(); ++i) {
                    const auto item_path = path + ".servers[" + std::to_string(i) + "]";
                    const auto& item = value["servers"][i];
                    if (item.isString()) {
                        auto server = String(result, item, item_path);
                        if (!server.empty() && ppp::dns::DnsProviderCatalog::HasProvider(ppp::string(server.data(), server.size())) &&
                            !ppp::dns::DnsProviderCatalog::HasEncryptedEndpoint(ppp::string(server.data(), server.size())))
                            Error(result, "E_POLICY_CONFIG", item_path,
                                "Provider '" + server + "' has no DoH/DoT endpoint; policy resolvers need one. Use another provider or an explicit udp:// or tcp:// address.");
                        else if (!server.empty() && !Server(server))
                            Error(result, "E_POLICY_CONFIG", item_path,
                                "Expected a known provider or numeric-address DNS endpoint; hostname endpoints require structured addresses or bootstrap.");
                        if (!server.empty()) {
                            resolver.server_order.push_back({false, resolver.servers.size()});
                            resolver.servers.push_back(std::move(server));
                        }
                    } else if (item.isObject()) {
                        if (!Object(result, item, item_path, {"uri", "addresses", "bootstrap"})) continue;
                        PolicyResolver::Server server;
                        server.uri = String(result, item["uri"], item_path + ".uri");
                        if (!Endpoint(server.uri, false))
                            Error(result, "E_POLICY_CONFIG", item_path + ".uri", "Expected a valid DNS endpoint URI.");
                        const auto scheme = server.uri.find("://");
                        const auto authority_end = server.uri.find_first_of("/?#", scheme == std::string::npos ? 0 : scheme + 3);
                        auto host = scheme == std::string::npos ? std::string() :
                            server.uri.substr(scheme + 3, authority_end - scheme - 3);
                        const auto colon = host.rfind(':');
                        if (colon != std::string::npos) host.resize(colon);
                        boost::system::error_code host_error;
                        const auto uri_address = boost::asio::ip::make_address(host, host_error);
                        const bool hostname = !host.empty() && host_error;
                        if (item.isMember("addresses")) {
                            const auto& addresses = item["addresses"];
                            if (!addresses.isArray()) Error(result, "E_POLICY_CONFIG", item_path + ".addresses", "Expected an array of IPv4 literals.");
                            else for (Json::ArrayIndex j = 0; j < addresses.size(); ++j) {
                                const auto address_path = item_path + ".addresses[" + std::to_string(j) + "]";
                                auto address = String(result, addresses[j], address_path);
                                if (!V4Literal(address)) Error(result, "E_POLICY_CONFIG", address_path, "Expected an IPv4 literal.");
                                else server.addresses.push_back(std::move(address));
                            }
                        }
                        if (item.isMember("bootstrap")) {
                            const auto& bootstrap = item["bootstrap"];
                            if (!bootstrap.isArray()) Error(result, "E_POLICY_CONFIG", item_path + ".bootstrap", "Expected an array of explicit direct UDP resolver URIs.");
                            else for (Json::ArrayIndex j = 0; j < bootstrap.size(); ++j) {
                                const auto bootstrap_path = item_path + ".bootstrap[" + std::to_string(j) + "]";
                                auto endpoint = String(result, bootstrap[j], bootstrap_path);
                                const bool valid = Endpoint(endpoint, false) && endpoint.rfind("udp://", 0) == 0 &&
                                    [&] {
                                        const auto end = endpoint.find_first_of("/?#", 6);
                                        const auto authority = endpoint.substr(6, end - 6);
                                        const auto port_sep = authority.rfind(':');
                                        const auto address = authority.substr(0, port_sep);
                                        return V4Literal(address);
                                    }();
                                if (!valid) Error(result, "E_POLICY_CONFIG", bootstrap_path,
                                    "Bootstrap must be a numeric IPv4 UDP resolver; implicit hostname resolution is unsupported.");
                                else server.bootstrap.push_back(std::move(endpoint));
                            }
                        }
                        if (hostname && server.addresses.empty() && server.bootstrap.empty())
                            Error(result, "E_POLICY_CONFIG", item_path, "Hostname endpoints require addresses or an explicit bootstrap resolver.");
                        if (!server.uri.empty()) {
                            resolver.server_order.push_back({true, resolver.server_specs.size()});
                            resolver.server_specs.push_back(std::move(server));
                        }
                    } else {
                        Error(result, "E_POLICY_CONFIG", item_path, "Expected a server URI string or structured server object.");
                    }
                }
            }
            source.resolvers.emplace(name, std::move(resolver));
        }
    }
    if (policy.isMember("rule-sets")) {
        const auto& sets = policy["rule-sets"];
        if (!sets.isObject()) Error(result, "E_POLICY_CONFIG", "client.policy.rule-sets", "Expected a rule-set object.");
        else for (const auto& member : sets.getMemberNames()) {
            const auto name = Std(member);
            const auto path = "client.policy.rule-sets." + name;
            if (!Name(name)) Error(result, "E_POLICY_CONFIG", path, "Invalid resource name.");
            const auto& value = sets[member];
            if (!Object(result, value, path, {"format", "source", "tag", "sha256"})) continue;
            PolicyRuleSet set;
            set.format = String(result, value["format"], path + ".format");
            const bool dat = set.format == "geoip-dat" || set.format == "geosite-dat";
            const bool text = set.format == "geoip-text" || set.format == "geosite-text";
            if (!dat && !text) Error(result, "E_POLICY_CONFIG", path + ".format", "Unsupported rule-set format.");
            if (dat || value.isMember("tag")) set.tag = String(result, value["tag"], path + ".tag");
            if (value.isMember("sha256")) {
                set.sha256 = String(result, value["sha256"], path + ".sha256");
                if (set.sha256.size() != 64 || !std::all_of(set.sha256.begin(), set.sha256.end(), [](char c) {
                    return std::isxdigit(static_cast<unsigned char>(c));
                })) Error(result, "E_POLICY_CONFIG", path + ".sha256", "Expected a 64-digit SHA-256 value.");
            }
            const auto& resource = value["source"];
            if (Object(result, resource, path + ".source", {"path", "url"})) {
                if (resource.isMember("path") == resource.isMember("url"))
                    Error(result, "E_POLICY_CONFIG", path + ".source", "Specify exactly one of path or url.");
                else if (resource.isMember("path")) {
                    const auto local = String(result, resource["path"], path + ".source.path");
                    if (!local.empty()) {
                        set.path = Resolve(source, local);
                        std::string bytes;
                        if (!declarations_only && Read(result, set.path, path + ".source.path", bytes)) {
                            if (!set.sha256.empty()) {
                                auto expected = set.sha256;
                                std::transform(expected.begin(), expected.end(), expected.begin(), [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
                                if (Digest(bytes) != expected) Error(result, "E_POLICY_CONFIG", path + ".sha256", "Rule-set SHA-256 does not match the configured digest.");
                            }
                            set.text = std::move(bytes);
                            set.materialized = true;
                        }
                    }
                } else {
                    set.url = String(result, resource["url"], path + ".source.url");
                    if (!set.url.empty()) {
                        if (!Endpoint(set.url, true))
                            Error(result, "E_POLICY_CONFIG", path + ".source.url", "Expected an HTTP or HTTPS resource URL.");
                        else if (!declarations_only) Error(result, "E_POLICY_SOURCE_UNAVAILABLE", path + ".source.url", "Remote-only source is unavailable during offline validation.");
                    }
                }
            }
            source.rule_sets.emplace(name, std::move(set));
        }
    }
    if (policy.isMember("updates") && Object(result, policy["updates"], "client.policy.updates", {"enabled", "interval", "via", "bootstrap", "allow-http"})) {
        const auto& updates = policy["updates"];
        if (updates.isMember("enabled")) {
            if (!updates["enabled"].isBool()) Error(result, "E_POLICY_CONFIG", "client.policy.updates.enabled", "Expected a boolean.");
            else source.updates_enabled = updates["enabled"].asBool();
        }
        if (updates.isMember("interval")) {
            source.updates_interval = String(result, updates["interval"], "client.policy.updates.interval");
            const auto& interval = source.updates_interval;
            const bool valid = interval.size() >= 2 && std::string("smhd").find(interval.back()) != std::string::npos &&
                std::all_of(interval.begin(), interval.end() - 1, [](char c) { return c >= '0' && c <= '9'; }) &&
                interval.find_first_not_of('0') < interval.size() - 1;
            if (!valid) Error(result, "E_POLICY_CONFIG", "client.policy.updates.interval", "Expected a positive duration with s, m, h or d suffix.");
        }
        if (updates.isMember("via")) source.updates_via = Via(result, updates["via"], "client.policy.updates.via");
        if (updates.isMember("allow-http")) {
            if (!updates["allow-http"].isBool()) Error(result, "E_POLICY_CONFIG", "client.policy.updates.allow-http", "Expected a boolean.");
            else source.updates_allow_http = updates["allow-http"].asBool();
        }
        if (updates.isMember("bootstrap")) {
            const auto& bootstrap = updates["bootstrap"];
            if (!bootstrap.isArray()) Error(result, "E_POLICY_CONFIG", "client.policy.updates.bootstrap", "Expected an array of explicit direct UDP resolver URIs.");
            else for (Json::ArrayIndex i = 0; i < bootstrap.size(); ++i) {
                const auto path = "client.policy.updates.bootstrap[" + std::to_string(i) + "]";
                auto endpoint = String(result, bootstrap[i], path);
                const bool valid = Endpoint(endpoint, false) && endpoint.rfind("udp://", 0) == 0 &&
                    [&] {
                        const auto end = endpoint.find_first_of("/?#", 6);
                        const auto authority = endpoint.substr(6, end - 6);
                        const auto port_sep = authority.rfind(':');
                        if (port_sep == std::string::npos) return false;
                        const auto address = authority.substr(0, port_sep);
                        return V4Literal(address);
                    }();
                if (!valid) Error(result, "E_POLICY_CONFIG", path,
                    "Bootstrap must be a numeric IPv4 UDP resolver with an explicit port; implicit hostname resolution is unsupported.");
                else source.updates_bootstrap.push_back(std::move(endpoint));
            }
        }
    }
    return result;
}

} // namespace ppp::app::client::policy
