#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <WinSock2.h>
#else
#include <netdb.h>
#endif

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/auxiliary/StringAuxiliary.h>
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

        bool Ipep::ParseEndPoint(const ppp::string& address, ppp::string& destinationAddress, int& destinationPort) noexcept {
            destinationPort = IPEndPoint::MinPort;
            destinationAddress.clear();

            if (address.empty()) {
                return false;
            }

            size_t index = address.find('[');
            if (index != ppp::string::npos) {
                size_t right = address.find(']', index);
                if (right == ppp::string::npos) {
                    return false;
                }

                size_t LENT = right - index - 1;
                if (LENT == 0) {
                    return false;
                }

                ppp::string host = address.substr(index + 1, LENT);
                if (host.empty()) {
                    return false;
                }

                if (!IsDomainAddress(host)) {
                    return false;
                }

                index = address.rfind(':');
                if (index == ppp::string::npos) {
                    destinationAddress = host;
                }
                else {
                    ppp::string port = address.substr(index + 1);
                    destinationAddress = std::move(host);
                    destinationPort = atoi(port.data());
                }
            }
            else {
                index = address.rfind(':');
                if (index == ppp::string::npos) {
                    if (!IsDomainAddress(address)) {
                        return false;
                    }

                    destinationAddress = address;
                }
                else {
                    ppp::string host = address.substr(0, index);
                    if (!IsDomainAddress(host)) {
                        return false;
                    }

                    ppp::string port = address.substr(index + 1);
                    destinationAddress = std::move(host);
                    destinationPort = atoi(port.data());
                }
            }
            return true;
        }

        boost::asio::ip::udp::udp::endpoint Ipep::ParseEndPoint(const ppp::string& address) noexcept {
            ppp::string* destinationAddress = NULL;
            return Ipep::ParseEndPoint(address, destinationAddress);
        }

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

            if (NULL != destinationAddress) {
                *destinationAddress = std::move(destinationIP);
            }

            return boost::asio::ip::udp::udp::endpoint(ip, destinationPort);
        }

        ppp::string Ipep::ToIpepAddress(const IPEndPoint& ep) noexcept {
            const IPEndPoint* ip = addressof(ep);
            return ToIpepAddress(ip);
        }

        ppp::string Ipep::ToIpepAddress(const IPEndPoint* ep) noexcept {
            if (NULL == ep) {
                return "0.0.0.0:0";
            }

            int address_bytes_size;
            Byte* address_bytes = ep->GetAddressBytes(address_bytes_size);
            ppp::string address_text = IPEndPoint::ToAddressString<ppp::string>(ep->GetAddressFamily(), address_bytes, address_bytes_size);

            char sz[0xff];
            if (ep->GetAddressFamily() == AddressFamily::InterNetwork) {
                sprintf(sz, "%s:%u", address_text.data(), ep->Port);
                return sz;
            }
            else {
                sprintf(sz, "[%s]:%u", address_text.data(), ep->Port);
                return sz;
            }
        }

        IPEndPoint Ipep::GetEndPoint(const ppp::string& host, int port, bool resolver) noexcept {
            if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                port = IPEndPoint::MinPort;
            }

            IPEndPoint localEP = IPEndPoint(host.data(), port);
            if (resolver && localEP.IsNone()) {
                struct addrinfo req, * hints, * p;
                memset(&req, 0, sizeof(req));

                req.ai_family = AF_UNSPEC;
                req.ai_socktype = SOCK_STREAM;

                if (getaddrinfo(host.data(), NULL, &req, &hints)) {
                    return IPEndPoint(0u, port);
                }

                for (p = hints; NULL != p; p = p->ai_next) {
                    if (p->ai_family == AF_INET) {
                        struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                        return IPEndPoint(AddressFamily::InterNetwork,
                            (Byte*)&(ipv4->sin_addr), sizeof(ipv4->sin_addr), port);
                    }
                }

                for (p = hints; NULL != p; p = p->ai_next) {
                    if (p->ai_family == AF_INET6) {
                        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                        return IPEndPoint(AddressFamily::InterNetworkV6,
                            (Byte*)&(ipv6->sin6_addr), sizeof(ipv6->sin6_addr), port);
                    }
                }
            }
            return localEP;
        }

        bool Ipep::IsDomainAddress(const ppp::string& domain) noexcept {
            if (domain.empty()) {
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
                return false;
            }

            for (const ppp::string& segment : segments) {
                if (segment.empty()) {
                    return false;
                }

                std::size_t segment_size = segment.size();
                if (segment_size > 63) { /* 0x3f */
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
                        return false;
                    }
                }
            }
            return true;
        }

        bool Ipep::ToEndPoint(const ppp::string& addresses, ppp::vector<ppp::string>& out) noexcept {
            if (addresses.empty()) {
                return false;
            }

            ppp::string dns_addresses = addresses;
            dns_addresses = Replace<ppp::string>(dns_addresses, ";", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, ":", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, " ", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "|", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "+", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "*", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "^", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "&", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "#", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "@", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "!", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "'", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\"", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, ":", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "?", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "%", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "[", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "]", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "{", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "}", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\\", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "/", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "-", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "_", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "=", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "`", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "~", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\r", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\n", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\t", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\a", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\b", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\v", ",");
            dns_addresses = Replace<ppp::string>(dns_addresses, "\f", ",");
            if (dns_addresses.empty()) {
                return false;
            }

            ppp::vector<ppp::string> lines;
            Tokenize<ppp::string>(dns_addresses, lines, ",");
            if (lines.empty()) {
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
            return success;
        }

        boost::asio::ip::address Ipep::ToAddress(uint32_t ip) noexcept {
            IPEndPoint ipep(ip, IPEndPoint::MinPort);
            return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep).address();
        }

#if defined(_WIN32)
        bool Ipep::SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& addresses) noexcept {
            return ppp::win32::network::SetDnsAddresses(interface_index, addresses);
        }
#else
        bool Ipep::SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept {
            return ppp::unix__::UnixAfx::SetDnsAddresses(addresses);
        }
#endif

        void Ipep::ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<ppp::string>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const uint32_t& ip) noexcept -> ppp::string {
                    return inet_ntoa(*(struct in_addr*)&ip);
                });
        }

        void Ipep::ToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<uint32_t>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const ppp::string& ip) noexcept -> uint32_t {
                    return inet_addr(ip.data());
                });
        }

        void Ipep::ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<boost::asio::ip::address>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const uint32_t& ip) noexcept -> boost::asio::ip::address {
                    return Ipep::ToAddress(ip);
                });
        }

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

        int Ipep::ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept {
            ppp::function<bool(boost::asio::ip::address&)> predicate;
            return ToAddresses(addresses, out, predicate);
        }

        int Ipep::ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept {
#if defined(_WIN32)
            using std_sregex_iterator = std::sregex_iterator;
#else
            using std_sregex_iterator = std::regex_iterator<ppp::string::const_iterator>;
#endif

            if (addresses.empty()) {
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

        int Ipep::ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept {
            ppp::function<bool(boost::asio::ip::address&)> predicate;
            return ToAddresses2(addresses, out, predicate);
        }

        int Ipep::ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept {
            return ToAddresses(addresses, out,
                [&predicate](boost::asio::ip::address& address) noexcept -> bool {
                    if (IPEndPoint::IsInvalid(address)) {
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

        int Ipep::NetmaskToPrefix(const ppp::string& cidr_number_string) noexcept {
            static constexpr int ERR_PREFIX_VALUE = ppp::net::native::MIN_PREFIX_VALUE - 1;

            if (cidr_number_string.empty()) {
                return ERR_PREFIX_VALUE;
            }

            if (ppp::auxiliary::StringAuxiliary::WhoisIntegerValueString(cidr_number_string)) {
                return atoi(cidr_number_string.data());
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(cidr_number_string.data(), ec);
            if (ec) {
                return ERR_PREFIX_VALUE;
            }

            if (address.is_v4()) {
                return IPEndPoint::NetmaskToPrefix(address.to_v4().to_ulong());
            }

            if (address.is_v6()) {
                auto bytes = address.to_v6().to_bytes();
                return IPEndPoint::NetmaskToPrefix(reinterpret_cast<unsigned char*>(bytes.data()), (int)bytes.size());
            }

            return ERR_PREFIX_VALUE;
        }

        bool Ipep::ParseCidr(const ppp::string& cidr_ip_string, boost::asio::ip::address& destination, int& cidr) noexcept {
            destination = boost::asio::ip::address_v4::any();
            cidr = ppp::net::native::MIN_PREFIX_VALUE;

            if (cidr_ip_string.empty()) {
                return false;
            }

            std::size_t index = cidr_ip_string.find('/');
            if (index == ppp::string::npos) {
                return false;
            }

            int cidr_number = NetmaskToPrefix(cidr_ip_string.substr(index + 1));
            if (cidr_number < ppp::net::native::MIN_PREFIX_VALUE) {
                return false;
            }

            if (cidr_number > ppp::net::native::MAX_PREFIX_VALUE_V6) {
                return false;
            }

            ppp::string address_string = cidr_ip_string.substr(index);
            if (address_string.empty()) {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(address_string.data(), ec);
            if (ec) {
                return false;
            }

            if (!address.is_v4() && !address.is_v6()) {
                return false;
            }

            cidr = cidr_number;
            destination = address;
            return true;
        }

        bool Ipep::ParseCidr(const ppp::string& cidr_ip_string, AddressRange& address_range) noexcept {
            return ParseCidr(cidr_ip_string, address_range.Address, address_range.Cidr);
        }

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

        int Ipep::ParseAllCidrsFromFileName(const ppp::string& file_name, ppp::vector<AddressRange>& address_ranges) noexcept {
            ppp::string cidr_ip_strings = ppp::io::File::ReadAllText(file_name.data());
            if (cidr_ip_strings.empty()) {
                return 0;
            }
            else {
                return ParseAllCidrs(cidr_ip_strings, address_ranges);
            }
        }

        ppp::vector<ppp::string> Ipep::AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in) noexcept {
            ppp::vector<ppp::string> out;
            AddressesTransformToStrings(in, out);
            return out;
        }

        ppp::vector<boost::asio::ip::address> Ipep::StringsTransformToAddresses(const ppp::vector<ppp::string>& in) noexcept {
            ppp::vector<boost::asio::ip::address> out;
            StringsTransformToAddresses(in, out);
            return out;
        }

        void Ipep::AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in, ppp::vector<ppp::string>& out) noexcept {
            out.resize(in.size());
            std::transform(in.begin(), in.end(), out.begin(),
                [](const boost::asio::ip::address& address) noexcept -> ppp::string {
                    return Ipep::ToAddressString<ppp::string>(address);
                });
        }

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
        static typename std::enable_if<std::is_same<T, Int128>::value, T>::type StaticGetIPAddressNumber(const IPEndPoint& ep) noexcept {
            int address_bytes_size = 0;
            Byte* address_bytes = ep.GetAddressBytes(address_bytes_size);

            boost::asio::ip::address_v6::bytes_type in;
            memset(in.data(), 0, in.size());
            memcpy(in.data(), address_bytes, address_bytes_size);

            return *((T*)(in.data()));
        }

        template <typename T>
        static typename std::enable_if<!std::is_same<T, Int128>::value, T>::type StaticGetIPAddressNumber(const IPEndPoint& ep) noexcept {
            return ep.GetAddress();
        }

        template <typename T>
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

        bool Ipep::PacketIsQUIC(const IPEndPoint& destinationEP, Byte* p, int length) noexcept {
            if (NULL == p || length < 1) {
                return false;
            }

            if (destinationEP.Port != 443 && destinationEP.Port != 80) {
                return false;
            }

            Byte* l = p + length; // QUIC IETF
            Byte kf = *p++;
            int F_Header_Form = ppp::net::native::GetBitValueAt(kf, 7);
            int F_Fixed_Bit = ppp::net::native::GetBitValueAt(kf, 6);
            int F_Packet_Type_Bit = ppp::net::native::GetBitValueAt(kf, 5) << 1 | ppp::net::native::GetBitValueAt(kf, 4);
            if (F_Header_Form != 0x01 || F_Fixed_Bit != 0x01) {
                return false;
            }

            if (F_Packet_Type_Bit == 0x00) { // Initial(0)
                int F_Reserved_Bit = ppp::net::native::GetBitValueAt(kf, 3) << 1 | ppp::net::native::GetBitValueAt(kf, 3);
                int F_Packet_Number_Length_Bit = ppp::net::native::GetBitValueAt(kf, 1) << 1 | ppp::net::native::GetBitValueAt(kf, 0);
                if (F_Packet_Number_Length_Bit == 0x00 && F_Reserved_Bit == 0x00) {
                    return false;
                }
            }
            else if (F_Packet_Type_Bit != 0x02) { // Handshake(2)
                return false;
            }

            p += 0x04;
            if (p > l) {
                return false;
            }

            UInt32 Version = ntohl(((UInt32*)p)[-1]);
            if (Version != 0x01) { // Version
                return false;
            }

            int Destination_Connection_ID_Length = *p++;
            p += Destination_Connection_ID_Length;
            if (p > l || Destination_Connection_ID_Length < 0x01) {
                return false;
            }

            int Source_Connection_ID_Length = *p++;
            p += Source_Connection_ID_Length;
            if (p > l) {
                return false;
            }

            if (F_Packet_Type_Bit == 0x00) { // Initial(0)
                int Token_Length = *p++;
                p += Token_Length;
                if (p > l || Token_Length < 0x01)
                {
                    return false;
                }
            }

            int Packet_Length = ntohs(*(UInt16*)p) & 0x3FFF;
            p += 0x02;
            if (p > l || Packet_Length < 0x01) {
                return false;
            }

            p += Packet_Length;
            return p == l;
        }
    }
}