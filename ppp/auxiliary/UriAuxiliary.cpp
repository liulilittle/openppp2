#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>

#include <iostream>
#include <string>
#include <cctype>
#include <sstream>

namespace ppp {
    namespace auxiliary {
#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
        static ppp::net::IPEndPoint UriAuxiliary_ResolveEndPoint(const ppp::string& host_string, const ppp::string& address_string, int port_number, ppp::coroutines::YieldContext& y) noexcept {
            ppp::net::IPEndPoint remoteEP(ppp::net::IPEndPoint::NoneAddress, port_number);
            if (address_string.empty()) {
                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(host_string.data(), ec);
                if (ec) {
                    ppp::coroutines::YieldContext* co = y.GetPtr();
                    if (co) {
                        boost::asio::ip::udp::resolver resolver(co->GetContext());
                        remoteEP = ppp::net::IPEndPoint::ToEndPoint(
                            ppp::coroutines::asio::GetAddressByHostName(resolver, host_string.data(), port_number, y));
                    }
                    else {
                        remoteEP = ppp::net::Ipep::GetEndPoint(host_string, port_number, true);
                    }
                }
                else {
                    remoteEP = ppp::net::IPEndPoint::ToEndPoint(boost::asio::ip::udp::endpoint(address, port_number));
                }
            }
            else {
                remoteEP = ppp::net::Ipep::GetEndPoint(address_string, port_number, false);
            }

            return remoteEP;
        }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif

        ppp::string UriAuxiliary::Parse(
            const ppp::string&      url,
            ppp::string&            hostname,
            ppp::string&            address,
            ppp::string&            path,
            int&                    port,
            ProtocolType&           protocol,
            YieldContext&           y) noexcept {

            ppp::string* abs = NULL;
            return UriAuxiliary::Parse(url, hostname, address, path, port, protocol, abs, y);
        }

        ppp::string UriAuxiliary::Parse(
            const ppp::string&      url,
            ppp::string&            hostname,
            ppp::string&            address,
            ppp::string&            path,
            int&                    port,
            ProtocolType&           protocol,
            ppp::string*            abs,
            YieldContext&           y) noexcept {

            typedef ppp::net::IPEndPoint IPEndPoint;
            typedef ppp::net::Ipep       Ipep;

            port = IPEndPoint::MinPort;
            hostname = "";
            path = "";
            address = "";
            protocol = ProtocolType_PPP;
            if (url.empty()) {
                return "";
            }

            ppp::string url_string = ToLower(LTrim(RTrim(url)));
            if (url_string.empty()) {
                return "";
            }

            std::size_t index_offset = 3;
            std::size_t index = url_string.find("://");
            if (index == ppp::string::npos) {
                index = url_string.find(":/");
                if (index == ppp::string::npos) {
                    return "";
                }
                else {
                    index_offset = 2;
                }
            }

            std::size_t n = index + index_offset;
            if (n >= url_string.size()) {
                return "";
            }

            int port_number = 0;
            ppp::string host_and_path = url_string.substr(n);
            ppp::string proto_string = url_string.substr(0, index);
            ppp::string host_string;
            ppp::string address_string;
            ppp::string path_string;

            ProtocolType protocol_type = ProtocolType_PPP;
            if (proto_string == "tcp") {
                protocol_type = ProtocolType_PPP;
            }
            elif(proto_string == BOOST_BEAST_VERSION_STRING) {
                protocol_type = ProtocolType_PPP;
            }
            elif(proto_string == "wss") {
                protocol_type = ProtocolType_WebSocketSSL;
            }
            elif(proto_string == "ws") {
                protocol_type = ProtocolType_WebSocket;
            }
            elif(proto_string == "https") {
                protocol_type = ProtocolType_HttpSSL;
            }
            elif(proto_string == "http") {
                protocol_type = ProtocolType_Http;
            }
            else {
                return "";
            }

            index = host_and_path.find_first_of('/');
            if (index != ppp::string::npos) {
                n = index + 1;
                if (url_string.size() > n) {
                    path_string = "/" + host_and_path.substr(n);
                }

                host_string = host_and_path.substr(0, index);
            }
            else {
                path_string = "/";
                host_string = host_and_path;
            }

            index = host_string.find_first_of('[');
            if (index != ppp::string::npos) {
                n = host_string.find_last_of(']');
                if (n == ppp::string::npos || index > n) {
                    return "";
                }

                std::size_t pos = index + 1;
                address_string = host_string.substr(pos, n - pos);
                host_string = host_string.substr(0, index) + host_string.substr(n + 1);
            }

            index = host_string.rfind(':');
            if (index != ppp::string::npos) {
                n = index + 1;
                if (n >= host_string.size()) {
                    return "";
                }

                ppp::string sz_ = host_string.substr(n);
                sz_ = LTrim(sz_);
                sz_ = RTrim(sz_);
                port_number = atoi(sz_.data());
                host_string = host_string.substr(0, index);
            }

            host_string = LTrim(RTrim(host_string));
            path_string = LTrim(RTrim(path_string));
            if (port_number <= IPEndPoint::MinPort || port_number > IPEndPoint::MaxPort) {
                if (protocol_type == ProtocolType_Http || protocol_type == ProtocolType_WebSocket) {
                    port_number = 80;
                }
                elif(protocol_type == ProtocolType_HttpSSL || protocol_type == ProtocolType_WebSocketSSL) {
                    port_number = 443;
                }
                else {
                    return "";
                }
            }

            IPEndPoint remoteEP = UriAuxiliary_ResolveEndPoint(host_string, address_string, port_number, y);
            if (!IPEndPoint::IsInvalid(remoteEP)) {
                address_string = remoteEP.ToAddressString();
            }

            hostname = host_string;
            address = address_string;
            path = path_string;
            port = port_number;
            protocol = protocol_type;

            url_string = proto_string + "://" + hostname;
            if (NULL != abs) {
                *abs = url_string + "[" + address_string + "]" + ":" + stl::to_string<ppp::string>(port) + path;
            }

            url_string += ":" + stl::to_string<ppp::string>(port) + path;
            return url_string;
        }

        ppp::string UriAuxiliary::Encode(const ppp::string& input) noexcept {
            ppp::string encoded;
            for (std::size_t i = 0, length = input.length(); i < length; i++) {
                if (std::isalnum((unsigned char)input[i]) || (input[i] == '-') || (input[i] == '_') || (input[i] == '.') || (input[i] == '~')) {
                    encoded += input[i];
                }
                elif(input[i] == ' ') {
                    encoded += "+";
                }
                else {
                    encoded += '%';
                    encoded += StringAuxiliary::ToHex((unsigned char)input[i] >> 4);
                    encoded += StringAuxiliary::ToHex((unsigned char)input[i] % 16);
                }
            }
            return encoded;
        }

        ppp::string UriAuxiliary::Decode(const ppp::string& input) noexcept {
            ppp::string decoded;
            for (std::size_t i = 0, length = input.length(); i < length; i++) {
                if (input[i] == '+') {
                    decoded += ' ';
                }
                elif(input[i] == '%') {
                    if ((i + 2) < length) {
                        unsigned char high = StringAuxiliary::FromHex((unsigned char)input[++i]);
                        unsigned char low = StringAuxiliary::FromHex((unsigned char)input[++i]);
                        decoded += high << 4 | low;
                    }
                    else {
                        break;
                    }
                }
                else {
                    decoded += input[i];
                }
            }
            return decoded;
        }
    }
}