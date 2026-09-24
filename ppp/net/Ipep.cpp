#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file Ipep.cpp
 * @brief Implementations for endpoint parsing, resolution, and address normalization helpers.
 */

#if defined(_WIN32)
#include <WinSock2.h>
#else
#include <netdb.h>
#endif

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/threading/Executors.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>
#include <ppp/net/native/checksum.h>

#if defined(_WIN32)
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#endif

namespace ppp {
    namespace net {
        /**
         * @brief Parses endpoint text and resolves host when needed.
         */
        IPEndPoint Ipep::GetEndPoint(const ppp::string& address, bool resolver) noexcept {
            int destinationPort = IPEndPoint::MinPort;
            ppp::string destinationIP;

            if (!Ipep::ParseEndPoint(address, destinationIP, destinationPort)) {
                return IPEndPoint(IPEndPoint::NoneAddress, IPEndPoint::MinPort);
            }
            else {
                return Ipep::GetEndPoint(destinationIP, destinationPort, resolver);
            }
        }

        /**
         * @brief Parses textual endpoint into host and port.
         * @details Supports IPv4/domain forms (`host:port`) and bracketed IPv6 forms (`[host]:port`).
         */
        bool Ipep::ParseEndPoint(const ppp::string& address, ppp::string& destinationAddress, int& destinationPort) noexcept {
            destinationPort = IPEndPoint::MinPort;
            destinationAddress.clear();

            if (address.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseEndpointInputEmpty);
                return false;
            }

            size_t leftBracket = address.find('[');
            if (leftBracket != ppp::string::npos) {
                size_t rightBracket = address.find(']', leftBracket);
                if (rightBracket == ppp::string::npos) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseEndpointMissingRightBracket);
                    return false;  
                }

                size_t hostLen = rightBracket - leftBracket - 1;
                if (hostLen == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false; 
                }

                ppp::string host = address.substr(leftBracket + 1, hostLen);
                if (host.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                // Strip the %<zone_id> scope suffix before the IsDomainAddress
                // check because inet_pton / StringToAddress do not understand
                // RFC 6874 zone identifiers (e.g. "fe80::1%eth0").
                ppp::string host_for_check = host;
                std::size_t pct = host_for_check.find('%');
                if (ppp::string::npos != pct) {
                    host_for_check = host_for_check.substr(0, pct);
                }

                if (!IsDomainAddress(host_for_check)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                size_t portPos = address.find(':', rightBracket);
                if (portPos == ppp::string::npos) {
                    destinationAddress = std::move(host);
                }
                else {
                    ppp::string portStr = address.substr(portPos + 1);
                    destinationAddress = std::move(host);
                    
                    /**
                     * @brief Validate port number using strtol.
                     * @note Port must be in range [1, 65535].
                     */
                    char* endptr = NULLPTR;
                    long parsed_port = strtol(portStr.c_str(), &endptr, 10);
                    if (NULLPTR == endptr || endptr == portStr.c_str() || *endptr != '\x0' || parsed_port <= ppp::net::IPEndPoint::MinPort || parsed_port > ppp::net::IPEndPoint::MaxPort) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                        return false;
                    }

                    destinationPort = static_cast<int>(parsed_port);
                }
            }
            else {
                size_t colonPos = address.rfind(':');
                if (colonPos == ppp::string::npos) {
                    if (!IsDomainAddress(address)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        return false;
                    }

                    destinationAddress = address;
                }
                else {
                    // 1) Try host:port interpretation (split at the last colon).
                    ppp::string host = address.substr(0, colonPos);
                    ppp::string portStr = address.substr(colonPos + 1);

                    if (IsDomainAddress(host)) {
                        destinationAddress = std::move(host);
                        
                        /**
                         * @brief Validate port number using strtol.
                         * @note Port must be in range [1, 65535].
                         */
                        char* endptr = NULLPTR;
                        long parsed_port = strtol(portStr.c_str(), &endptr, 10);
                        if (NULLPTR == endptr || endptr == portStr.c_str() || *endptr != '\x0' || parsed_port <= ppp::net::IPEndPoint::MinPort || parsed_port > ppp::net::IPEndPoint::MaxPort) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                            return false;
                        }

                        destinationPort = static_cast<int>(parsed_port);
                    }
                    elif (address.find(':') != colonPos) {
                        // 2) Host portion was invalid but there are multiple colons:
                        //    the whole thing might be a bare IPv6 address with no port.
                        if (!IsDomainAddress(address)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                            return false;
                        }

                        destinationAddress = address;
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseEndpointInvalidHostPortSeparator);
                        return false;
                    }
                }
            }

            return true;
        }

        /** @brief Parses endpoint text into a UDP endpoint. */
        boost::asio::ip::udp::udp::endpoint Ipep::ParseEndPoint(const ppp::string& address) noexcept {
            ppp::string* destinationAddress = NULLPTR;
            return Ipep::ParseEndPoint(address, destinationAddress);
        }

        /** @brief Parses endpoint text into a UDP endpoint and optional host output. */
        boost::asio::ip::udp::udp::endpoint Ipep::ParseEndPoint(const ppp::string& address, ppp::string* destinationAddress) noexcept {
            int destinationPort = IPEndPoint::MinPort;
            ppp::string destinationIP;

            boost::asio::ip::address ip = boost::asio::ip::address_v4::any();
            if (Ipep::ParseEndPoint(address, destinationIP, destinationPort)) {
                if (destinationIP.empty()) {
                    ip = boost::asio::ip::address_v4::any();
                }
                else {
                    ip = Ipep::ToAddress(destinationIP, true);
                    if (ip.is_multicast()) {
                        ip = boost::asio::ip::address_v4::any();
                    }
                }
            }

            if (destinationPort < IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                destinationPort = IPEndPoint::MinPort;
            }

            if (NULLPTR != destinationAddress) {
                *destinationAddress = std::move(destinationIP);
            }

            return boost::asio::ip::udp::udp::endpoint(ip, destinationPort);
        }

        /** @brief Converts endpoint to canonical printable `host:port` format. */
        ppp::string Ipep::ToIpepAddress(const IPEndPoint& ep) noexcept {
            const IPEndPoint* ip = addressof(ep);
            return ToIpepAddress(ip);
        }

        /** @brief Pointer overload for endpoint-to-string conversion. */
        ppp::string Ipep::ToIpepAddress(const IPEndPoint* ep) noexcept {
            if (NULLPTR == ep) {
                return "0.0.0.0:0";
            }

            int address_bytes_size;
            Byte* address_bytes = ep->GetAddressBytes(address_bytes_size);
            ppp::string address_text = IPEndPoint::ToAddressString<ppp::string>(ep->GetAddressFamily(), address_bytes, address_bytes_size);

            char sz[0xff];
            if (ep->GetAddressFamily() == AddressFamily::InterNetwork) {
                snprintf(sz, sizeof(sz), "%s:%u", address_text.data(), ep->Port);
                return sz;
            }
            else {
                snprintf(sz, sizeof(sz), "[%s]:%u", address_text.data(), ep->Port);
                return sz;
            }
        }

        /**
         * @brief Resolves host using native `getaddrinfo`.
         * @details Prefers IPv4 records and falls back to IPv6 records.
         */
        static IPEndPoint Ipep_GetEndPointWithNative(const ppp::string& host, int port) noexcept {
            struct AddrinfoDeleter final {
                void operator()(struct addrinfo* p) const noexcept {
                    if (p) {
                        freeaddrinfo(p);
                    }
                }
            };

            using AddrinfoPtr = std::unique_ptr<struct addrinfo, AddrinfoDeleter>;

            struct addrinfo req {};
            req.ai_family = AF_UNSPEC;
            req.ai_socktype = SOCK_STREAM;

            struct addrinfo* hints_raw = NULLPTR;
            if (getaddrinfo(host.data(), NULLPTR, &req, &hints_raw) != 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                return IPEndPoint(IPEndPoint::AnyAddress, port);
            }

            AddrinfoPtr hints(hints_raw);
            for (struct addrinfo* p = hints.get(); p != NULLPTR; p = p->ai_next) {
                if (p->ai_family == AF_INET) {
                    auto* ipv4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
                    return IPEndPoint(AddressFamily::InterNetwork,
                        reinterpret_cast<Byte*>(&ipv4->sin_addr),
                        sizeof(ipv4->sin_addr), port);
                }
            }

            for (struct addrinfo* p = hints.get(); p != NULLPTR; p = p->ai_next) {
                if (p->ai_family == AF_INET6) {
                    auto* ipv6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
                    return IPEndPoint(AddressFamily::InterNetworkV6,
                        reinterpret_cast<Byte*>(&ipv6->sin6_addr),
                        sizeof(ipv6->sin6_addr), port);
                }
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
            return IPEndPoint(IPEndPoint::AnyAddress, port);
        }

        /** @brief Resolves host using Boost resolver on provided io_context. */
        static IPEndPoint Ipep_GetEndPointWithBoost(boost::asio::io_context& context, const ppp::string& host, int port) noexcept {
            boost::asio::ip::tcp::resolver resolver(context);
            boost::asio::ip::tcp::endpoint result = ppp::net::asio::GetAddressByHostName(resolver, host.data(), port);
            return IPEndPoint::ToEndPoint(result);
        }

        /**
         * @brief Internal endpoint resolver shared by public overloads.
         * @details Tries direct IP parsing first, then optional DNS resolution via Boost or native APIs.
         */
        static IPEndPoint Ipep_GetEndPoint(boost::asio::io_context* pcontext, const ppp::string& host, int port, bool resolver) noexcept {
            if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                port = IPEndPoint::MinPort;
            }

            boost::system::error_code ec;
            ppp::string host_copy = RTrim(LTrim(host));
            if (host_copy.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return IPEndPoint(IPEndPoint::AnyAddress, port);
            }

            boost::asio::ip::address address = StringToAddress(host_copy, ec);
            if (ec && resolver) {
                if (NULLPTR != pcontext) {
                    return Ipep_GetEndPointWithBoost(*pcontext, host_copy, port);
                }
                else {
                    std::shared_ptr<boost::asio::io_context> context = ppp::threading::Executors::GetCurrent(false);
                    if (NULLPTR != context) {
                        return Ipep_GetEndPointWithBoost(*context, host_copy, port);
                    }
                }

                return Ipep_GetEndPointWithNative(host_copy, port);
            }

            if (address.is_v4() || address.is_v6()) {
                return IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(address, port));
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
            return IPEndPoint(IPEndPoint::AnyAddress, port);
        }

        /** @brief Resolves host using caller-provided io_context. */
        IPEndPoint Ipep::GetEndPoint(boost::asio::io_context& context, const ppp::string& host, int port, bool resolver) noexcept {
            boost::asio::io_context* pcontext = addressof(context);
            return Ipep_GetEndPoint(pcontext, host, port, resolver);
        }

        /** @brief Resolves host without explicit io_context. */
        IPEndPoint Ipep::GetEndPoint(const ppp::string& host, int port, bool resolver) noexcept {
            boost::asio::io_context* pcontext = NULLPTR;
            return Ipep_GetEndPoint(pcontext, host, port, resolver);
        }

        /**
         * @brief Validates whether input can be treated as host/domain text.
         * @details Accepts IP literals, `localhost`, and segmented domain-like names.
         */
        bool Ipep::IsDomainAddress(const ppp::string& domain) noexcept {
            if (domain.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            ppp::string address_string = RTrim(LTrim(domain));
            if (address_string == "localhost") {
                return true;
            }
            else {
                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(address_string.data(), ec);
                if (ec == boost::system::errc::success) {
                    if (address.is_v4() || address.is_v6()) {
                        return true;
                    }
                }
            }

            /* std::regex_match(address_string, std::regex("^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,63}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,63})+$")) */
            ppp::vector<ppp::string> segments;
            if (Tokenize<ppp::string>(domain, segments, ".") < 2) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            for (const ppp::string& segment : segments) {
                if (segment.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                std::size_t segment_size = segment.size();
                if (segment_size > 63) { /* 0x3f */
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                for (std::size_t i = 0; i < segment_size; i++) {
                    bool b = false;
                    char c = segment[i];
                    if (i != 0) {
                        b = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '-');
                    }
                    else {
                        b = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
                    }

                    if (!b) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        return false;
                    }
                }
            }
            return true;
        }

        /** @brief Parses comma-separated endpoint strings and emits normalized addresses. */
        bool Ipep::ToEndPoint(const ppp::string& addresses, ppp::vector<ppp::string>& out) noexcept {
            if (addresses.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepToEndpointListInputEmpty);
                return false;
            }

            ppp::string dns_addresses = ppp::auxiliary::StringAuxiliary::Lstrings(addresses);
            if (dns_addresses.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepToEndpointListTrimmedEmpty);
                return false;
            }

            ppp::vector<ppp::string> lines;
            Tokenize<ppp::string>(dns_addresses, lines, ",");
            if (lines.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepToEndpointListTokenizeFailed);
                return false;
            }

            bool success = false;
            for (size_t i = 0, l = lines.size(); i < l; i++) {
                ppp::string& line = lines[i];
                if (line.empty()) {
                    continue;
                }

                IPEndPoint localEP = Ipep::GetEndPoint(line);
                if (localEP.IsNone()) {
                    continue;
                }

                success = true;
                out.emplace_back(localEP.ToAddressString());
            }
            if (false == success) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
            }
            return success;
        }

        /** @brief Converts IPv4 integer value to Boost address. */
        boost::asio::ip::address Ipep::ToAddress(uint32_t ip) noexcept {
            IPEndPoint ipep(ip, IPEndPoint::MinPort);
            return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep).address();
        }

#if defined(_WIN32)
        /** @brief Sets interface DNS servers on Windows. */
        bool Ipep::SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& addresses) noexcept {
            return ppp::win32::network::SetDnsAddresses(interface_index, addresses);
        }
#else
        /** @brief Sets DNS servers on Unix-like systems. */
        bool Ipep::SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept {
            return ppp::unix__::UnixAfx::SetDnsAddresses(addresses);
        }
#endif

        /** @brief Converts IPv4 integers to textual address list. */
        void Ipep::ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<ppp::string>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const uint32_t& ip) noexcept -> ppp::string {
                    return inet_ntoa(*(struct in_addr*)&ip);
                });
        }

        /** @brief Converts textual IPv4 addresses to integer list. */
        void Ipep::ToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<uint32_t>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const ppp::string& ip) noexcept -> uint32_t {
                    return inet_addr(ip.data());
                });
        }

        /** @brief Converts IPv4 integer list to Boost address list. */
        void Ipep::ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<boost::asio::ip::address>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const uint32_t& ip) noexcept -> boost::asio::ip::address {
                    return Ipep::ToAddress(ip);
                });
        }

        /**
         * @brief Parses textual IP address and applies multicast/broadcast filtering.
         */
        boost::asio::ip::address Ipep::ToAddress(const ppp::string& ip, bool boardcast) noexcept {
            if (ip.empty()) {
                return boost::asio::ip::address_v4::any();
            }
            else {
                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(ip.data(), ec);
                if (ec) {
                    return boost::asio::ip::address_v4::any();
                }

                if (address.is_multicast()) {
                    return boost::asio::ip::address_v4::any();
                }

                if (boardcast) {
                    if (IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(address, IPEndPoint::MinPort)).IsBroadcast()) {
                        return boost::asio::ip::address_v4::any();
                    }
                }

                if (address.is_v4() || address.is_v6()) {
                    return address;
                }
                else {
                    return boost::asio::ip::address_v4::any();
                }
            }
        }

        /** @brief Joins addresses into comma-separated string representation. */
        ppp::string Ipep::ToAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept {
            ppp::string addresses_string;
            for (boost::asio::ip::address& address : addresses) {
                if (addresses_string.empty()) {
                    addresses_string = Ipep::ToAddressString<ppp::string>(address);
                }
                else {
                    addresses_string += ',' + Ipep::ToAddressString<ppp::string>(address);
                }
            }
            return addresses_string;
        }

        /** @brief Extracts addresses from text without additional predicate. */
        int Ipep::ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept {
            ppp::function<bool(boost::asio::ip::address&)> predicate;
            return ToAddresses(addresses, out, predicate);
        }

        /**
         * @brief Extracts unique IPv4/IPv6 literals from arbitrary input text.
         */
        int Ipep::ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept {
#if defined(_WIN32)
            using std_sregex_iterator = std::sregex_iterator;
#else
            using std_sregex_iterator = std::regex_iterator<ppp::string::const_iterator>;
#endif

            if (addresses.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepExtractAddressesInputEmpty);
                return -1;
            }

            std::regex pattern("[0-9A-F\\.:]+", std::regex_constants::icase);
            auto words_begin = std_sregex_iterator(addresses.begin(), addresses.end(), pattern);
            auto words_end = std_sregex_iterator();

            int events = 0;
            ppp::unordered_set<boost::asio::ip::address> sets;
            for (std_sregex_iterator it = words_begin; it != words_end; ++it) {
                std::string address_string = it->str();
                if (address_string.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(address_string.data(), ec);
                if (ec) {
                    continue;
                }

                if (!address.is_v4() && !address.is_v6()) {
                    continue;
                }

                if (predicate) {
                    if (!predicate(address)) {
                        continue;
                    }
                }

                auto r = sets.emplace(address);
                if (r.second) {
                    events++;
                    out.emplace_back(address);
                }
            }
            return events;
        }

        /** @brief Extracts valid unicast-like addresses from text. */
        int Ipep::ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept {
            ppp::function<bool(boost::asio::ip::address&)> predicate;
            return ToAddresses2(addresses, out, predicate);
        }

        /** @brief Predicate-aware overload that also excludes invalid endpoint addresses. */
        int Ipep::ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept {
            return ToAddresses(addresses, out,
                [&predicate](boost::asio::ip::address& address) noexcept -> bool {
                    if (IPEndPoint::IsInvalid(address)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        return false;
                    }

                    if (predicate) {
                        return predicate(address);
                    }
                    else {
                        return true;
                    }
                });
        }

        /**
         * @brief Parses DNS addresses and optionally guarantees at least two entries.
         */
        int Ipep::ToDnsAddresses(const ppp::string& s, ppp::vector<boost::asio::ip::address>& out, bool at_least_two) noexcept {
            static constexpr const char* DEFAULT_DNS_ADDRESSES[] = { PPP_PREFERRED_DNS_SERVER_1, PPP_PREFERRED_DNS_SERVER_2 };

            if (s.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return -1;
            }

            if (!at_least_two) {
                return Ipep::ToAddresses2(s, out);
            }

            ppp::vector<boost::asio::ip::address> addresses;
            Ipep::ToAddresses2(s, addresses);

            for (const char* dns_addresss_string : DEFAULT_DNS_ADDRESSES) {
                int addresses_size = addresses.size();
                if (addresses_size >= arraysizeof(DEFAULT_DNS_ADDRESSES)) {
                    break;
                }

                boost::asio::ip::address dns_address = Ipep::ToAddress(dns_addresss_string, false);
                if (std::find(addresses.begin(), addresses.end(), dns_address) == addresses.end()) {
                    addresses.emplace_back(dns_address);
                }
            }

            std::size_t last = out.size();
            for (boost::asio::ip::address& ip : addresses) {
                out.emplace_back(ip);
            }

            return static_cast<int>(out.size() - last);
        }

        /** @brief Converts prefix or netmask text into CIDR prefix length. */
        int Ipep::NetmaskToPrefix(const ppp::string& cidr_number_string) noexcept {
            static constexpr int ERR_PREFIX_VALUE = ppp::net::native::MIN_PREFIX_VALUE - 1;

            if (cidr_number_string.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepNetmaskPrefixInputEmpty);
                return ERR_PREFIX_VALUE;
            }

            if (ppp::auxiliary::StringAuxiliary::WhoisIntegerValueString(cidr_number_string)) {
                /**
                 * @brief Validate numeric prefix using strtol.
                 * @note Valid IPv4 prefix range: [0, 32], IPv6: [0, 128].
                 *       Use strtol to detect conversion errors (unlike atoi).
                 */
                char* endptr = NULLPTR;
                long parsed = strtol(cidr_number_string.data(), &endptr, 10);
                if (NULLPTR == endptr || endptr == cidr_number_string.data() || *endptr != '\x0' || parsed < 0 || parsed > 128) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                    return ERR_PREFIX_VALUE;
                }
                
                return static_cast<int>(parsed);
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(cidr_number_string.data(), ec);
            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return ERR_PREFIX_VALUE;
            }

            if (address.is_v4()) {
                return IPEndPoint::NetmaskToPrefix(address.to_v4().to_uint());
            }

            if (address.is_v6()) {
                auto bytes = address.to_v6().to_bytes();
                return IPEndPoint::NetmaskToPrefix(reinterpret_cast<unsigned char*>(bytes.data()), (int)bytes.size());
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
            return ERR_PREFIX_VALUE;
        }

        /** @brief Parses CIDR string into address and prefix components. */
        bool Ipep::ParseCidr(const ppp::string& cidr_ip_string, boost::asio::ip::address& destination, int& cidr) noexcept {
            destination = boost::asio::ip::address_v4::any();
            cidr = ppp::net::native::MIN_PREFIX_VALUE;

            if (cidr_ip_string.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseCidrInputEmpty);
                return false;
            }

            std::size_t index = cidr_ip_string.find('/');
            if (index == ppp::string::npos) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseCidrMissingSlash);
                return false;
            }

            int cidr_number = NetmaskToPrefix(cidr_ip_string.substr(index + 1));
            if (cidr_number < ppp::net::native::MIN_PREFIX_VALUE) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseCidrPrefixTooSmall);
                return false;
            }

            if (cidr_number > ppp::net::native::MAX_PREFIX_VALUE_V6) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseCidrPrefixTooLarge);
                return false;
            }

            ppp::string address_string = cidr_ip_string.substr(0, index);
            if (address_string.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepParseCidrAddressPartEmpty);
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(address_string.data(), ec);
            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            if (!address.is_v4() && !address.is_v6()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            cidr = cidr_number;
            destination = address;
            return true;
        }

        /** @brief Parses CIDR string into @ref AddressRange structure. */
        bool Ipep::ParseCidr(const ppp::string& cidr_ip_string, AddressRange& address_range) noexcept {
            return ParseCidr(cidr_ip_string, address_range.Address, address_range.Cidr);
        }

        /** @brief Parses all CIDR lines from a text block and deduplicates results. */
        int Ipep::ParseAllCidrs(const ppp::string& cidr_ip_strings, ppp::vector<AddressRange>& address_ranges) noexcept {
            if (cidr_ip_strings.empty()) {
                return 0;
            }

            ppp::vector<ppp::string> lines;
            if (Tokenize<ppp::string>(cidr_ip_strings, lines, "\r\n") < 1) {
                return 0;
            }

            int events = 0;
            ppp::unordered_set<ppp::string> sets;
            for (ppp::string& line : lines) {
                AddressRange address_range;
                if (!ParseCidr(line, address_range)) { // CIDR FORMAT.
                    continue;
                }

                ppp::string k = Ipep::ToAddressString<ppp::string>(address_range.Address) + "|" + stl::to_string<ppp::string>(address_range.Cidr);
                auto r = sets.emplace(k);
                if (!r.second) {
                    continue;
                }

                events++;
                address_ranges.emplace_back(address_range);
            }
            return events;
        }

        /** @brief Loads CIDR text from file and parses all entries. */
        int Ipep::ParseAllCidrsFromFileName(const ppp::string& file_name, ppp::vector<AddressRange>& address_ranges) noexcept {
            ppp::string cidr_ip_strings = ppp::io::File::ReadAllText(file_name.data());
            if (cidr_ip_strings.empty()) {
                return 0;
            }
            else {
                return ParseAllCidrs(cidr_ip_strings, address_ranges);
            }
        }

        /** @brief Converts address vector to string vector. */
        ppp::vector<ppp::string> Ipep::AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in) noexcept {
            ppp::vector<ppp::string> out;
            AddressesTransformToStrings(in, out);
            return out;
        }

        /** @brief Converts string vector to address vector. */
        ppp::vector<boost::asio::ip::address> Ipep::StringsTransformToAddresses(const ppp::vector<ppp::string>& in) noexcept {
            ppp::vector<boost::asio::ip::address> out;
            StringsTransformToAddresses(in, out);
            return out;
        }

        /** @brief In-place conversion from addresses to textual representations. */
        void Ipep::AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in, ppp::vector<ppp::string>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const boost::asio::ip::address& address) noexcept -> ppp::string {
                    return Ipep::ToAddressString<ppp::string>(address);
                });
        }

        /** @brief In-place parsing of textual addresses into Boost addresses. */
        void Ipep::StringsTransformToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<boost::asio::ip::address>& out) noexcept {
            out.clear();
            for (const ppp::string& address_string : in) {
                if (address_string.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(address_string.data(), ec);
                if (ec) {
                    continue;
                }

                if (address.is_v4() || address.is_v6()) {
                    out.emplace_back(address);
                }
            }
        }

        template <typename T>
        /** @brief Returns numeric address value, with Int128 specialization for IPv6 bytes. */
        static typename std::enable_if<std::is_same<T, Int128>::value, T>::type StaticGetIPAddressNumber(const IPEndPoint& ep) noexcept {
            int address_bytes_size = 0;
            Byte* address_bytes = ep.GetAddressBytes(address_bytes_size);

            boost::asio::ip::address_v6::bytes_type in;
            memset(in.data(), 0, in.size());
            memcpy(in.data(), address_bytes, address_bytes_size);

            return *((T*)(in.data()));
        }

        template <typename T>
        /** @brief Returns numeric address value for non-Int128 types (IPv4 path). */
        static typename std::enable_if<!std::is_same<T, Int128>::value, T>::type StaticGetIPAddressNumber(const IPEndPoint& ep) noexcept {
            return ep.GetAddress();
        }

        template <typename T>
        /**
         * @brief Normalizes host/gateway addresses inside subnet boundaries.
         * @details Chooses fallback host addresses when current values are out of usable range.
         */
        static boost::asio::ip::address StaticFixedIPAddress(IPEndPoint& ipEP, IPEndPoint& gwEP, IPEndPoint& maskEP, int MAX_PREFIX_ADDRESS, bool fixGw) noexcept {
            T __mask = StaticGetIPAddressNumber<T>(maskEP);
            int prefix = IPEndPoint::NetmaskToPrefix((unsigned char*)&reinterpret_cast<const char&>(__mask), sizeof(__mask));
            if (prefix > MAX_PREFIX_ADDRESS) {
                if (std::is_same<T, Int128>::value) {
                    return boost::asio::ip::address_v6::any();
                }
                else {
                    return boost::asio::ip::address_v4::any();
                }
            }

            __mask = Ipep::NetworkToHostOrder<T>(__mask);

            /**
             * @brief Compute usable host interval from network and mask.
             */
            T __ip = Ipep::NetworkToHostOrder<T>(StaticGetIPAddressNumber<T>(ipEP));
            T __networkIP = __ip & __mask;
            T __boardcastIP = __networkIP | (~__networkIP & 0xff);
            T __fistIP = __networkIP + 1;
            T __lastIP = __boardcastIP - 1;

            if (fixGw) {
                T __gw = Ipep::NetworkToHostOrder<T>(StaticGetIPAddressNumber<T>(gwEP));
                if (__gw != 0) {
                    return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(gwEP).address();
                }
                elif constexpr (std::is_same<T, Int128>::value) {
                    return IPEndPoint::WrapAddressV6<boost::asio::ip::tcp>(&__fistIP, sizeof(__fistIP), IPEndPoint::MinPort).address();
                }
                else {
                    uint32_t in = (uint32_t)Ipep::NetworkToHostOrder<T>(__fistIP);
                    return IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(in, IPEndPoint::MinPort).address();
                }
            }

            if (__ip > __fistIP && __ip <= __lastIP) {
                return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipEP).address();
            }

            T __nextip = Ipep::NetworkToHostOrder<T>(__fistIP + 1);
            if constexpr (std::is_same<T, Int128>::value) {
                return IPEndPoint::WrapAddressV6<boost::asio::ip::tcp>(&__nextip, sizeof(__nextip), IPEndPoint::MinPort).address();
            }
            else {
                uint32_t in = (uint32_t)__nextip;
                return IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(in, IPEndPoint::MinPort).address();
            }
        }

        /** @brief Fixes IP address based on mask and implicit gateway strategy. */
        boost::asio::ip::address Ipep::FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept {
            IPEndPoint ipEP = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip, IPEndPoint::MinPort));
            IPEndPoint maskEP = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(mask, IPEndPoint::MinPort));
            if (ipEP.GetAddressFamily() == AddressFamily::InterNetwork) {
                constexpr const int MAX_PREFIX_ADDRESS = 30;

                IPEndPoint gwEP = IPEndPoint::Any(IPEndPoint::MinPort);
                return StaticFixedIPAddress<uint32_t>(ipEP, gwEP, maskEP, MAX_PREFIX_ADDRESS, true);
            }
            else {
                constexpr const int MAX_PREFIX_ADDRESS = 126;

                IPEndPoint gwEP = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), IPEndPoint::MinPort));
                return StaticFixedIPAddress<Int128>(ipEP, gwEP, maskEP, MAX_PREFIX_ADDRESS, true);
            }
            return ip;
        }

        /** @brief Fixes IP address with explicit gateway and mask validation. */
        boost::asio::ip::address Ipep::FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& gw, const boost::asio::ip::address& mask) noexcept {
            IPEndPoint ipEP = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip, IPEndPoint::MinPort));
            IPEndPoint gwEP = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(gw, IPEndPoint::MinPort));
            IPEndPoint maskEP = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(mask, IPEndPoint::MinPort));
            if (ipEP.GetAddressFamily() != gwEP.GetAddressFamily()) {
                return ip;
            }

            if (gwEP.GetAddressFamily() != maskEP.GetAddressFamily()) {
                return ip;
            }

            if (ipEP.GetAddressFamily() == AddressFamily::InterNetwork) {
                constexpr const int MAX_PREFIX_ADDRESS = 30;

                return StaticFixedIPAddress<uint32_t>(ipEP, gwEP, maskEP, MAX_PREFIX_ADDRESS, false);
            }
            else {
                constexpr const int MAX_PREFIX_ADDRESS = 126;

                return StaticFixedIPAddress<Int128>(ipEP, gwEP, maskEP, MAX_PREFIX_ADDRESS, false);
            }
            return ip;
        }

        /**
         * @brief Performs lightweight QUIC packet structure validation.
         * @details Checks long-header shape for Initial/Handshake packets and validates bounds.
         */
        bool Ipep::PacketIsQUIC(const IPEndPoint& destinationEP, Byte* p, int length) noexcept {
            if (NULLPTR == p || length < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepQuicPacketInvalidInput);
                return false;
            }

            if (destinationEP.Port != PPP_HTTPS_SYS_PORT && destinationEP.Port != PPP_HTTP_SYS_PORT) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepQuicPacketPortNotApplicable);
                return false;
            }

            Byte* l = p + length; // QUIC IETF
            Byte kf = *p++;
            /** @brief Bounds-check helper for parser cursor. */
            auto require = [l](const Byte* current, int count) noexcept -> bool {
                return current <= l && count >= 0 && (l - current) >= count;
            };

            int F_Header_Form = ppp::net::native::GetBitValueAt(kf, 7);
            int F_Fixed_Bit = ppp::net::native::GetBitValueAt(kf, 6);
            int F_Packet_Type_Bit = ppp::net::native::GetBitValueAt(kf, 5) << 1 | ppp::net::native::GetBitValueAt(kf, 4);
            if (F_Header_Form != 0x01 || F_Fixed_Bit != 0x01) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            if (F_Packet_Type_Bit == 0x00) { // Initial(0)
                int F_Reserved_Bit = ppp::net::native::GetBitValueAt(kf, 3) << 1 | ppp::net::native::GetBitValueAt(kf, 3);
                int F_Packet_Number_Length_Bit = ppp::net::native::GetBitValueAt(kf, 1) << 1 | ppp::net::native::GetBitValueAt(kf, 0);
                if (F_Packet_Number_Length_Bit == 0x00 && F_Reserved_Bit == 0x00) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }
            }
            elif(F_Packet_Type_Bit != 0x02) { // Handshake(2)
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            if (!require(p, sizeof(UInt32))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            UInt32 version_network = 0;
            memcpy(&version_network, p, sizeof(version_network));

            UInt32 Version = ntohl(version_network);
            p += sizeof(UInt32);

            if (Version != 0x01) { // Version
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            if (!require(p, 1)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            int Destination_Connection_ID_Length = *p++;
            if (Destination_Connection_ID_Length < 0x01 || !require(p, Destination_Connection_ID_Length)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            p += Destination_Connection_ID_Length;

            if (!require(p, 1)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            int Source_Connection_ID_Length = *p++;
            if (!require(p, Source_Connection_ID_Length)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            p += Source_Connection_ID_Length;

            if (F_Packet_Type_Bit == 0x00) { // Initial(0)
                if (!require(p, 1)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }

                int Token_Length = *p++;
                if (Token_Length < 0x01 || !require(p, Token_Length)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }

                p += Token_Length;
            }

            if (!require(p, (int)sizeof(UInt16))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            UInt16 packet_length_network = 0;
            memcpy(&packet_length_network, p, sizeof(packet_length_network));

            int Packet_Length = ntohs(packet_length_network) & 0x3FFF;
            p += 0x02;
            
            if (Packet_Length < 0x01 || !require(p, Packet_Length)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }

            p += Packet_Length;
            if (l != p) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                return false;
            }
            return true;
        }

        /**
         * @brief Asynchronously resolves host and returns endpoint through callback.
         * @details Tries direct IP, optional virtual DNS, then system resolver.
         */
        bool Ipep::GetAddressByHostName(boost::asio::io_context& context, const ppp::string& hostname, int port, const GetAddressByHostNameCallback& callback) noexcept {
            if (NULLPTR == callback) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepResolveAsyncNullCallback);
                return false;
            }

            if (hostname.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(hostname, ec);
            if (ec == boost::system::errc::success) {
                std::shared_ptr<IPEndPoint> localEP = make_shared_object<IPEndPoint>(IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(address, port)));
                if (NULLPTR == localEP) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepResolveAsyncEndpointAllocFailed);
                    return false;
                }

                boost::asio::post(context,
                    [callback, localEP]() noexcept {
                        callback(localEP);
                    });
                return true;
            }
            elif(ppp::net::asio::vdns::enabled) {
                auto dns_servers = std::atomic_load(&ppp::net::asio::vdns::servers);
                if (NULLPTR != dns_servers && !dns_servers->empty()) {
                    return ppp::net::asio::vdns::ResolveAsync(context, hostname.data(), PPP_RESOLVE_DNS_TIMEOUT, *dns_servers,
                        [dns_servers, port, callback](const boost::asio::ip::address& ip) noexcept {
                            boost::asio::ip::tcp::endpoint endpoint(ip, port);
                            std::shared_ptr<IPEndPoint> addressEP = make_shared_object<IPEndPoint>(IPEndPoint::ToEndPoint(endpoint));
                            if (NULLPTR == addressEP || IPEndPoint::IsInvalid(*addressEP)) {
                                callback(NULLPTR);
                            }
                            else {
                                callback(addressEP);
                            }
                        });
                }
            }

            std::shared_ptr<boost::asio::ip::tcp::resolver> resolver = make_shared_object<boost::asio::ip::tcp::resolver>(context);
            if (NULLPTR == resolver) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IpepResolveAsyncResolverAllocFailed);
                return false;
            }

            ppp::string service = stl::to_string<ppp::string>(port);
            resolver->async_resolve(hostname, service,
                [resolver, callback, port](const boost::system::error_code& ec, const auto& r) noexcept {
                    if (ec) {
                        callback(NULLPTR);
                        return;
                    }

                    boost::asio::ip::tcp::endpoint endpoint = ppp::net::asio::internal::GetAddressByHostName<boost::asio::ip::tcp>(r, port);
                    std::shared_ptr<IPEndPoint> addressEP = make_shared_object<IPEndPoint>(IPEndPoint::ToEndPoint(endpoint));
                    if (NULLPTR == addressEP || IPEndPoint::IsInvalid(*addressEP)) {
                        callback(NULLPTR);
                    }
                    else {
                        callback(addressEP);
                    }
                });
            return true;
        }
    }
}
