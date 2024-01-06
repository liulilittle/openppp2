#include <ppp/configurations/AppConfiguration.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/io/File.h>
#include <ppp/ssl/SSL.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>

using ppp::auxiliary::StringAuxiliary;
using ppp::auxiliary::JsonAuxiliary;
using ppp::cryptography::Ciphertext;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::net::Ipep;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::threading::Thread;
using ppp::threading::Executors;

static constexpr int         PPP_DEFAULT_DNS_TIMEOUT = 4;
static constexpr const char* PPP_DEFAULT_KEY_PROTOCOL = "aes-128-cfb";
static constexpr const char* PPP_DEFAULT_KEY_TRANSPORT = "aes-256-cfb";
static constexpr int         PPP_DEFAULT_HTTP_PROXY_PORT = 8080;

namespace ppp {
    namespace configurations {
        AppConfiguration::AppConfiguration() noexcept {
            Clear();
        }

        void AppConfiguration::Clear() noexcept {
            AppConfiguration& config = *this;
            config.concurrent = Thread::GetProcessorCount();
            config.cdn[0] = 40080;
            config.cdn[1] = 40443;

            config.ip.public_ = "";
            config.ip.interface_ = "";
            config.udp.dns.timeout = PPP_DEFAULT_DNS_TIMEOUT;
            config.udp.dns.redirect = "";
            config.udp.inactive.timeout = PPP_DEFAULT_UDP_TIMEOUT;

            config.tcp.turbo = false;
            config.tcp.backlog = PPP_LISTEN_BACKLOG;
            config.tcp.fast_open = false;
            config.tcp.listen.port = 20000;
            config.tcp.connect.timeout = PPP_TCP_CONNECT_TIMEOUT;
            config.tcp.inactive.timeout = PPP_DEFAULT_TCP_TIMEOUT;

            config.websocket.listen.ws = 50080;
            config.websocket.listen.wss = 50443;
            config.websocket.ssl.verify_peer = true;
            config.websocket.ssl.certificate_file = "";
            config.websocket.ssl.certificate_key_file = "";
            config.websocket.ssl.certificate_chain_file = "";
            config.websocket.ssl.certificate_key_password = "";
            config.websocket.ssl.ciphersuites = GetDefaultCipherSuites();
            config.websocket.host = "localhost";
            config.websocket.path = "/";

            config.key.kf = 154543927;
            config.key.kh = 128;
            config.key.kl = 10;
            config.key.kx = 12;
            config.key.protocol = PPP_DEFAULT_KEY_PROTOCOL;
            config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
            config.key.transport = PPP_DEFAULT_KEY_TRANSPORT;
            config.key.transport_key = BOOST_BEAST_VERSION_STRING;
            config.key.masked = true;
            config.key.plaintext = true;
            config.key.delta_encode = true;
            config.key.shuffle_data = true;

            config.server.node = 0;
            config.server.backend = "";

            config.client.guid = StringAuxiliary::Int128ToGuidString(Int128(UINT64_MAX, UINT64_MAX));
            config.client.server = "";
            config.client.reconnections.timeout = PPP_TCP_CONNECT_TIMEOUT;
            config.client.http_proxy.bind = "";
            config.client.http_proxy.port = PPP_DEFAULT_HTTP_PROXY_PORT;
#ifdef _WIN32
            config.client.paper_airplane.tcp = true;
#endif
        }

        template <class _Uty>
        static void LRTrim(_Uty* s, int length) noexcept {
            for (int i = 0; i < length; i++) {
                *s[i] = LTrim(RTrim(*s[i]));
            }
        }

        static void LRTrim(AppConfiguration& config, int level) noexcept {
            if (level) {
                ppp::string* strings[] = {
                    &config.ip.public_,
                    &config.ip.interface_,
                    &config.udp.dns.redirect,
                    &config.vmem.path,
                    &config.server.backend,
                    &config.client.guid,
                    &config.client.server,
                    &config.websocket.host,
                    &config.websocket.path,
                    &config.key.protocol,
                    &config.key.protocol_key,
                    &config.key.transport,
                    &config.key.transport_key,
                };
                LRTrim(strings, arraysizeof(strings));
            }
            else {
                std::string* strings[] = {
                    &config.websocket.ssl.certificate_file,
                    &config.websocket.ssl.certificate_key_file,
                    &config.websocket.ssl.certificate_chain_file,
                    &config.websocket.ssl.certificate_key_password,
                    &config.websocket.ssl.ciphersuites,
                };
                LRTrim(strings, arraysizeof(strings));
            }
        }

        bool AppConfiguration::Loaded() noexcept {
            AppConfiguration& config = *this;
            if (config.concurrent < 1) {
                config.concurrent = Thread::GetProcessorCount();
            }

            if (config.udp.dns.timeout < 1) {
                config.udp.dns.timeout = PPP_DEFAULT_DNS_TIMEOUT;
            }

            if (config.udp.inactive.timeout < 1) {
                config.udp.inactive.timeout = PPP_DEFAULT_UDP_TIMEOUT;
            }

            if (config.tcp.backlog < 1) {
                config.tcp.backlog = PPP_LISTEN_BACKLOG;
            }

            if (config.tcp.connect.timeout < 1) {
                config.tcp.connect.timeout = PPP_TCP_CONNECT_TIMEOUT;
            }

            if (config.tcp.inactive.timeout < 1) {
                config.tcp.inactive.timeout = PPP_DEFAULT_TCP_TIMEOUT;
            }

            LRTrim(config, 0);
            LRTrim(config, 1);

            if (config.client.guid.empty()) {
                config.client.guid = StringAuxiliary::Int128ToGuidString(Int128(UINT64_MAX, UINT64_MAX));
            }

            if (config.client.reconnections.timeout < 1) {
                config.client.reconnections.timeout = PPP_TCP_CONNECT_TIMEOUT;
            }

            int* pts[] = { &config.tcp.listen.port, &config.websocket.listen.ws, &config.websocket.listen.wss, &config.client.http_proxy.port };
            for (int i = 0; i < arraysizeof(pts); i++) {
                int& port = *pts[i];
                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }
            }

            for (int i = 0; i < arraysizeof(config.cdn); i++) {
                int& cdn = config.cdn[i];
                if (cdn < IPEndPoint::MinPort || cdn > IPEndPoint::MaxPort) {
                    cdn = IPEndPoint::MinPort;
                }
            }

            ppp::string* ips[] = { &config.ip.public_, &config.ip.interface_, &config.client.http_proxy.bind };
            for (int i = 0; i < arraysizeof(ips); i++) {
                ppp::string& ip = *ips[i];
                if (ip.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address address = boost::asio::ip::address::from_string(ip.data(), ec);
                if (ec) {
                    ip = "";
                }
                elif(IPEndPoint::IsInvalid(address) && !(address.is_unspecified() && (address.is_v4() || address.is_v6()))) {
                    ip = "";
                }
                else {
                    ip = Ipep::ToAddressString<ppp::string>(address);
                }
            }

            if (!Ciphertext::Support(config.key.protocol)) {
                config.key.protocol = PPP_DEFAULT_KEY_PROTOCOL;
            }

            if (!Ciphertext::Support(config.key.transport)) {
                config.key.transport = PPP_DEFAULT_KEY_TRANSPORT;
            }

            if (config.key.protocol_key.empty()) {
                config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
            }

            if (config.key.transport_key.empty()) {
                config.key.transport_key = BOOST_BEAST_VERSION_STRING;
            }

            if (config.websocket.path.empty() || config.websocket.path[0] != '/') {
                config.websocket.path = "/";
            }

            if (!Ipep::IsDomainAddress(config.websocket.host)) {
                config.websocket.host = "localhost";
            }

            if (config.websocket.ssl.ciphersuites.empty()) {
                config.websocket.ssl.ciphersuites = GetDefaultCipherSuites();
            }

            if (config.websocket.listen.wss == IPEndPoint::MinPort || !ppp::ssl::SSL::VerifySslCertificate(config.websocket.ssl.certificate_file, config.websocket.ssl.certificate_key_file, config.websocket.ssl.certificate_chain_file)) {
                config.websocket.ssl.certificate_file = "";
                config.websocket.ssl.certificate_key_file = "";
                config.websocket.ssl.certificate_chain_file = "";
                config.websocket.ssl.certificate_key_password = "";
            }

            if (ips) {
                int destinationPort = IPEndPoint::MinPort;
                ppp::string destinationIP;

                ppp::string& redirect_string = config.udp.dns.redirect;
                if (!Ipep::ParseEndPoint(redirect_string, destinationIP, destinationPort)) {
                    redirect_string = "";
                }
                else {
                    boost::system::error_code ec;
                    boost::asio::ip::address address = boost::asio::ip::address::from_string(destinationIP.data(), ec);
                    if (ec) {
                        if (!Ipep::IsDomainAddress(destinationIP)) {
                            redirect_string = "";
                        }
                    }
                    elif(IPEndPoint::IsInvalid(address)) {
                        redirect_string = "";
                    }
                }
            }

            if (config.vmem.path.empty() || config.vmem.size < 1) {
                config.vmem.size = 0;
                config.vmem.path = "";
            }
            return true;
        }

        bool AppConfiguration::Load(const ppp::string& path) noexcept {
            Clear();
            if (path.empty()) {
                return false;
            }

            ppp::string file_path = File::GetFullPath(File::RewritePath(path.data()).data());
            if (file_path.empty()) {
                return false;
            }

            ppp::string json_string = File::ReadAllText(path.data());
            if (json_string.empty()) {
                return false;
            }

            Json::Value json = JsonAuxiliary::FromString(json_string);
            if (json.isNull()) {
                return false;
            }
            else {
                return Load(json);
            }
        }

        /*
         * Author: Binjie09 (AI Assistant)
         *
         * Description: This code is generated by Binjie09, an AI assistant.
         *              It is designed to read JSON data into the C++ data structure AppConfiguration
         *              using the Jsoncpp library's Json::Value and JsonAuxiliary::AsValue<TValue> function.
         *
         * Date: 2023-06-28
         */
        bool AppConfiguration::Load(Json::Value& json) noexcept {
            Clear();
            if (!json.isObject()) {
                return false;
            }

            AppConfiguration& config = *this;
            config.concurrent = JsonAuxiliary::AsValue<int>(json["concurrent"]);
            config.cdn[0] = JsonAuxiliary::AsValue<int>(json["cdn"][0]);
            config.cdn[1] = JsonAuxiliary::AsValue<int>(json["cdn"][1]);

            config.ip.public_ = JsonAuxiliary::AsValue<ppp::string>(json["ip"]["public"]);
            config.ip.interface_ = JsonAuxiliary::AsValue<ppp::string>(json["ip"]["interface"]);

            config.vmem.size = JsonAuxiliary::AsValue<int64_t>(json["vmem"]["size"]);
            config.vmem.path = JsonAuxiliary::AsValue<ppp::string>(json["vmem"]["path"]);

            config.udp.inactive.timeout = JsonAuxiliary::AsValue<int>(json["udp"]["inactive"]["timeout"]);
            config.udp.dns.timeout = JsonAuxiliary::AsValue<int>(json["udp"]["dns"]["timeout"]);
            config.udp.dns.redirect = JsonAuxiliary::AsValue<ppp::string>(json["udp"]["dns"]["redirect"]);

            config.tcp.inactive.timeout = JsonAuxiliary::AsValue<int>(json["tcp"]["inactive"]["timeout"]);
            config.tcp.connect.timeout = JsonAuxiliary::AsValue<int>(json["tcp"]["connect"]["timeout"]);
            config.tcp.listen.port = JsonAuxiliary::AsValue<int>(json["tcp"]["listen"]["port"]);
            config.tcp.turbo = JsonAuxiliary::AsValue<bool>(json["tcp"]["turbo"]);
            config.tcp.backlog = JsonAuxiliary::AsValue<int>(json["tcp"]["backlog"]);
            config.tcp.fast_open = JsonAuxiliary::AsValue<bool>(json["tcp"]["fast-open"]);

            config.websocket.listen.ws = JsonAuxiliary::AsValue<int>(json["websocket"]["listen"]["ws"]);
            config.websocket.listen.wss = JsonAuxiliary::AsValue<int>(json["websocket"]["listen"]["wss"]);
            config.websocket.ssl.certificate_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-file"]);
            config.websocket.ssl.certificate_key_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-key-file"]);
            config.websocket.ssl.certificate_chain_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-chain-file"]);
            config.websocket.ssl.certificate_key_password = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-key-password"]);
            config.websocket.ssl.ciphersuites = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["ciphersuites"]);
            config.websocket.ssl.verify_peer = JsonAuxiliary::AsValue<bool>(json["websocket"]["ssl"]["verify-peer"]);
            config.websocket.host = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["host"]);
            config.websocket.path = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["path"]);

            config.key.kf = JsonAuxiliary::AsValue<int>(json["key"]["kf"]);
            config.key.kl = JsonAuxiliary::AsValue<int>(json["key"]["kl"]);
            config.key.kh = JsonAuxiliary::AsValue<int>(json["key"]["kh"]);
            config.key.kx = JsonAuxiliary::AsValue<int>(json["key"]["kx"]);
            config.key.protocol = JsonAuxiliary::AsValue<ppp::string>(json["key"]["protocol"]);
            config.key.protocol_key = JsonAuxiliary::AsValue<ppp::string>(json["key"]["protocol-key"]);
            config.key.transport = JsonAuxiliary::AsValue<ppp::string>(json["key"]["transport"]);
            config.key.transport_key = JsonAuxiliary::AsValue<ppp::string>(json["key"]["transport-key"]);
            config.key.masked = JsonAuxiliary::AsValue<bool>(json["key"]["masked"]);
            config.key.plaintext = JsonAuxiliary::AsValue<bool>(json["key"]["plaintext"]);
            config.key.delta_encode = JsonAuxiliary::AsValue<bool>(json["key"]["delta-encode"]);
            config.key.shuffle_data = JsonAuxiliary::AsValue<bool>(json["key"]["shuffle-data"]);

            config.server.node = JsonAuxiliary::AsValue<int>(json["server"]["node"]);
            config.server.backend = JsonAuxiliary::AsValue<ppp::string>(json["server"]["backend"]);

            config.client.reconnections.timeout = JsonAuxiliary::AsValue<int>(json["client"]["reconnections"]["timeout"]);
            config.client.guid = JsonAuxiliary::AsValue<ppp::string>(json["client"]["guid"]);
            config.client.server = JsonAuxiliary::AsValue<ppp::string>(json["client"]["server"]);
            config.client.http_proxy.port = JsonAuxiliary::AsValue<int>(json["client"]["http-proxy"]["port"]);
            config.client.http_proxy.bind = JsonAuxiliary::AsValue<ppp::string>(json["client"]["http-proxy"]["bind"]);
#ifdef _WIN32
            config.client.paper_airplane.tcp = JsonAuxiliary::AsValue<bool>(json["client"]["paper-airplane"]["tcp"]);
#endif
            return Loaded();
        }

        /*
         * Author: Binjie09 (AI Assistant)
         *
         * Description: This code is generated by Binjie09, an AI assistant.
         *              Convert AppConfiguration object to Json::Value object.
         *
         * Date: 2023-06-28
         */
        Json::Value AppConfiguration::ToJson() noexcept {
            Json::Value root;
            AppConfiguration& config = *this;

            // Set concurrent
            root["concurrent"] = config.concurrent;

            // Set cdn array
            Json::Value cdn(Json::arrayValue);
            cdn.append(config.cdn[0]);
            cdn.append(config.cdn[1]);
            root["cdn"] = cdn;

            // Set ip structure
            Json::Value ip;
            ip["public"] = config.ip.public_;
            ip["interface"] = config.ip.interface_;
            root["ip"] = ip;

            // Set vmem structure
            Json::Value vmem;
            vmem["size"] = config.vmem.size;
            vmem["path"] = config.vmem.path;
            root["vmem"] = vmem;

            // Set udp structure
            Json::Value udp;
            udp["inactive"]["timeout"] = config.udp.inactive.timeout;
            udp["dns"]["timeout"] = config.udp.dns.timeout;
            udp["dns"]["redirect"] = config.udp.dns.redirect;
            root["udp"] = udp;

            // Set tcp structure
            Json::Value tcp;
            tcp["inactive"]["timeout"] = config.tcp.inactive.timeout;
            tcp["connect"]["timeout"] = config.tcp.connect.timeout;
            tcp["listen"]["port"] = config.tcp.listen.port;
            tcp["turbo"] = config.tcp.turbo;
            tcp["backlog"] = config.tcp.backlog;
            tcp["fast-open"] = config.tcp.fast_open;
            root["tcp"] = tcp;

            // Set websocket structure
            Json::Value websocket;
            websocket["listen"]["ws"] = config.websocket.listen.ws;
            websocket["listen"]["wss"] = config.websocket.listen.wss;
            websocket["ssl"]["certificate-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_file);
            websocket["ssl"]["certificate-key-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_key_file);
            websocket["ssl"]["certificate-chain-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_chain_file);
            websocket["ssl"]["certificate-key-password"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_key_password);
            websocket["ssl"]["ciphersuites"] = stl::transform<ppp::string>(config.websocket.ssl.ciphersuites);
            websocket["ssl"]["verify-peer"] = config.websocket.ssl.verify_peer;
            websocket["host"] = config.websocket.host;
            websocket["path"] = config.websocket.path;
            root["websocket"] = websocket;

            // Set key structure
            Json::Value key;
            key["kf"] = config.key.kf;
            key["kl"] = config.key.kl;
            key["kh"] = config.key.kh;
            key["kx"] = config.key.kx;
            key["protocol"] = config.key.protocol;
            key["protocol-key"] = config.key.protocol_key;
            key["transport"] = config.key.transport;
            key["transport-key"] = config.key.transport_key;
            key["masked"] = config.key.masked;
            key["plaintext"] = config.key.plaintext;
            key["delta-encode"] = config.key.delta_encode;
            key["shuffle-data"] = config.key.shuffle_data;
            root["key"] = key;

            // Set server structure
            Json::Value server;
            server["node"] = config.server.node;
            server["backend"] = config.server.backend;
            root["server"] = server;

            // Set client structure
            Json::Value client;
            client["http-proxy"]["bind"] = config.client.http_proxy.bind;
            client["http-proxy"]["port"] = config.client.http_proxy.port;
            client["reconnections"]["timeout"] = config.client.reconnections.timeout;
            client["guid"] = config.client.guid;
            client["server"] = config.client.server;
#ifdef _WIN32
            client["paper-airplane"]["tcp"] = config.client.paper_airplane.tcp;
#endif
            root["client"] = client;

            return root;
        }

        /*
         * Author: Binjie09 (AI Assistant)
         *
         * Description: This code is generated by Binjie09, an AI assistant.
         *              Convert AppConfiguration object to json string.
         *
         * Date: 2023-06-28
         */
        ppp::string AppConfiguration::ToString() noexcept {
            Json::Value json = ToJson();
            return JsonAuxiliary::ToString(json);
        }
    }
}