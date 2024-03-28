#pragma once 

#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>

namespace ppp {
    namespace net {
        class Ipep final {
        public:
            typedef ppp::function<void(ppp::vector<IPEndPoint>&)>               GetAddressesByHostNameCallback;
            typedef ppp::function<void(IPEndPoint*)>                            GetAddressByHostNameCallback;

        public:
            static IPEndPoint                                                   GetEndPoint(const ppp::string& address, bool resolver = true) noexcept;
            static IPEndPoint                                                   GetEndPoint(const ppp::string& host, int port, bool resolver = true) noexcept;
            
        public:
            static boost::asio::ip::udp::udp::endpoint                          ParseEndPoint(const ppp::string& address) noexcept;
            static boost::asio::ip::udp::udp::endpoint                          ParseEndPoint(const ppp::string& address, ppp::string* destinationAddress) noexcept;
            static bool                                                         ParseEndPoint(const ppp::string& address, ppp::string& destinationAddress, int& destinationPort) noexcept;
            static bool                                                         PacketIsQUIC(const IPEndPoint& destinationEP, Byte* p, int length) noexcept;

        public:
            static ppp::string                                                  ToIpepAddress(const IPEndPoint& ep) noexcept;
            static ppp::string                                                  ToIpepAddress(const IPEndPoint* ep) noexcept;
            static bool                                                         ToEndPoint(const ppp::string& addresses, ppp::vector<ppp::string>& out) noexcept;
            static boost::asio::ip::address                                     ToAddress(const ppp::string& ip, bool boardcast) noexcept;
            static boost::asio::ip::address                                     ToAddress(uint32_t ip) noexcept;

        public:
            template <class TString, class TProtocol>
            static TString                                                      ToAddressString(const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept {
                IPEndPoint address_endpoint = IPEndPoint::ToEndPoint(destinationEP);
                int address_bytes_size;
                Byte* address_bytes = address_endpoint.GetAddressBytes(address_bytes_size);
                return IPEndPoint::ToAddressString<TString>(address_endpoint.GetAddressFamily(), address_bytes, address_bytes_size);
            }

            template <class TString>
            static TString                                                      ToAddressString(const boost::asio::ip::address& addressIP) noexcept { return ToAddressString<TString>(boost::asio::ip::tcp::endpoint(addressIP, IPEndPoint::MinPort)); }

        public:
            static bool                                                         IsDomainAddress(const ppp::string& domain) noexcept;
#if defined(_WIN32)
            static bool                                                         SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& addresses) noexcept;
#else
            static bool                                                         SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept;
#endif

        public:
            struct AddressRange {
                boost::asio::ip::address                                        Address;
                int                                                             Cidr = 0;
            };
            static bool                                                         ParseCidr(const ppp::string& cidr_ip_string, AddressRange& address_range) noexcept;
            static bool                                                         ParseCidr(const ppp::string& cidr_ip_string, boost::asio::ip::address& destination, int& cidr) noexcept;
            static int                                                          ParseAllCidrs(const ppp::string& path, ppp::vector<AddressRange>& address_ranges) noexcept;
            static int                                                          ParseAllCidrsFromFileName(const ppp::string& file_name, ppp::vector<AddressRange>& address_ranges) noexcept;

        public:
            static void                                                         ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<boost::asio::ip::address>& out) noexcept;
            static void                                                         ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<ppp::string>& out) noexcept;
            static void                                                         ToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<uint32_t>& out) noexcept;

        public:
            static ppp::string                                                  ToAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept;
            static int                                                          ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept;
            static int                                                          ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept;
            static int                                                          ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept;
            static int                                                          ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept;

        public:
            static ppp::vector<ppp::string>                                     AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in) noexcept;
            static void                                                         AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in, ppp::vector<ppp::string>& out) noexcept;
            static ppp::vector<boost::asio::ip::address>                        StringsTransformToAddresses(const ppp::vector<ppp::string>& in) noexcept;
            static void                                                         StringsTransformToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<boost::asio::ip::address>& out) noexcept;

        public:
            template <class TProtocol>
            static boost::asio::ip::basic_endpoint<TProtocol>                   V6ToV4(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept { return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(addressEP))); }

            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   V4ToV6(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept { return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V4ToV6(IPEndPoint::ToEndPoint(addressEP))); }

            template <class TProtocol>       
            static std::size_t                                                  GetHashCode(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept {
                auto address = addressEP.address().to_string();
                std::size_t h = ppp::GetHashCode(address.data(), address.size());
                h ^= addressEP.port();
                return h;
            }

        public:
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   LocalAddress(boost::asio::ip::basic_resolver<TProtocol>& resolver, int port) noexcept { return ppp::net::asio::GetAddressByHostName<TProtocol>(resolver, ppp::net::IPEndPoint::GetHostName(), port); }

        public:
            template <class TProtocol>       
            static bool                                                         GetAddressByHostName(const std::shared_ptr<boost::asio::ip::basic_resolver<TProtocol> >& resolver, const ppp::string& hostname, int port, const GetAddressByHostNameCallback& callback) noexcept {
                if (NULL == resolver) {
                    return false;
                }

                return GetAddressByHostName(*resolver, hostname, port, callback);
            }

            template <class TProtocol>       
            static bool                                                         GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const ppp::string& hostname, int port, const GetAddressByHostNameCallback& callback) noexcept {
                if (NULL == callback) {
                    return false;
                }

                return GetAddressesByHostName(resolver, hostname, port, 
                    [callback](ppp::vector<IPEndPoint>& addresses) noexcept {
                        IPEndPoint* address = NULL;
                        if (NULL == address) {
                            for (size_t i = 0, l = addresses.size(); i < l; i++) {
                                const IPEndPoint& r = addresses[i];
                                if (r.GetAddressFamily() == AddressFamily::InterNetwork) {
                                    address = (IPEndPoint*)&reinterpret_cast<const char&>(r);
                                    break;
                                }
                            }
                        }

                        if (NULL == address) {
                            for (size_t i = 0, l = addresses.size(); i < l; i++) {
                                const IPEndPoint& r = addresses[i];
                                if (r.GetAddressFamily() == AddressFamily::InterNetworkV6) {
                                    address = (IPEndPoint*)&reinterpret_cast<const char&>(r);
                                    break;
                                }
                            }
                        }
                        
                        callback(address);
                    });
            }

            template <class TProtocol>       
            static bool                                                         GetAddressesByHostName(const std::shared_ptr<boost::asio::ip::basic_resolver<TProtocol> >& resolver, const ppp::string& hostname, int port, const GetAddressesByHostNameCallback& callback) noexcept {
                if (NULL == resolver) {
                    return false;
                }

                return GetAddressesByHostName(*resolver, hostname, port, callback);
            }

            template <class TProtocol>       
            static bool                                                         GetAddressesByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const ppp::string& hostname, int port, const GetAddressesByHostNameCallback& callback) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                if (NULL == callback) {
                    return false;
                }

                IPEndPoint localEP = IPEndPoint(hostname.data(), port);
                if (!localEP.IsNone()) {
                    ppp::vector<IPEndPoint> addresses;
                    addresses.emplace_back(localEP);

                    callback(addresses);
                    return false;
                }

                auto completion_resolve = [](
                    ppp::vector<IPEndPoint>&              addresses,
                    typename protocol_resolver::iterator& i,
                    typename protocol_resolver::iterator& l,
                    const GetAddressesByHostNameCallback& callback) noexcept {
                        for (; i != l; ++i) {
                            boost::asio::ip::basic_endpoint<TProtocol> localEP = std::move(*i);
                            if (!localEP.address().is_v4()) {
                                continue;
                            }

                            addresses.emplace_back(IPEndPoint::ToEndPoint<TProtocol>(localEP));
                        }
                };

                typename protocol_resolver::query q(hostname.data(), stl::to_string<ppp::string>(port).data());
#if !defined(_WIN32)
                resolver.async_resolve(q,
                    [completion_resolve, callback](const boost::system::error_code& ec, typename protocol_resolver::iterator results) noexcept {
                        ppp::vector<IPEndPoint> addresses;
                        if (ec == boost::system::errc::success) {
                            typename protocol_resolver::iterator i = std::move(results);
                            typename protocol_resolver::iterator l;

                            completion_resolve(addresses, i, l, callback);
                        }

                        callback(addresses);
                    });
#else
                resolver.async_resolve(q,
                    [completion_resolve, callback](const boost::system::error_code& ec, typename protocol_resolver::results_type results) noexcept {
                        ppp::vector<IPEndPoint> addresses;
                        if (ec == boost::system::errc::success) {
                            if (!results.empty()) {
                                typename protocol_resolver::iterator i = results.begin();
                                typename protocol_resolver::iterator l = results.end();

                                completion_resolve(addresses, i, l, callback);
                            }
                        }

                        callback(addresses);
                    });
#endif
                return true;
            }

        public:     
            template <class T>      
            static T                                                            NetworkToHostOrder(const T& network) noexcept {
#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__) /* *((char*)(&__BYTE_ORDER__)) */
                return network;
#else
                T hostorder{};
                char* __dst = (char*)&reinterpret_cast<const char&>(hostorder);
                char* __src = (char*)&reinterpret_cast<const char&>(network);

                __src += sizeof(network);
                for (int i = 0; i < sizeof(network); i++) {
                    __src--;
                    *__dst = *__src;
                    __dst++; /* *__dst++ = *--__src; */
                }
                return hostorder;
#endif
            }
        
            template <class T>      
            static T                                                            HostToNetworkOrder(const T& host) noexcept { return NetworkToHostOrder<T>(host); }

        public:
            static int                                                          NetmaskToPrefix(const ppp::string& cidr_number_string) noexcept;
            static boost::asio::ip::address                                     FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept;
            static boost::asio::ip::address                                     FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& gw, const boost::asio::ip::address& mask) noexcept;
        };
    }
}

namespace std {
#if BOOST_VERSION < 107600
    template <>
    struct hash<boost::asio::ip::address_v4> {
    public:
        std::size_t operator()(const boost::asio::ip::address_v4& addr) const noexcept {
            return std::hash<unsigned int>()(addr.to_uint());
        }
    };

    template <>
    struct hash<boost::asio::ip::address_v6> {
    public:
        std::size_t operator()(const boost::asio::ip::address_v6& addr) const noexcept {
            const boost::asio::ip::address_v6::bytes_type bytes = addr.to_bytes();
            std::size_t result = static_cast<std::size_t>(addr.scope_id());
            combine_4_bytes(result, &bytes[0]);
            combine_4_bytes(result, &bytes[4]);
            combine_4_bytes(result, &bytes[8]);
            combine_4_bytes(result, &bytes[12]);
            return result;
        }
    
    private:
        static void combine_4_bytes(std::size_t& seed, const unsigned char* bytes) noexcept {
            const std::size_t bytes_hash =
                (static_cast<std::size_t>(bytes[0]) << 24) |
                (static_cast<std::size_t>(bytes[1]) << 16) |
                (static_cast<std::size_t>(bytes[2]) << 8) |
                (static_cast<std::size_t>(bytes[3]));
            seed ^= bytes_hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
    };

    template <>
    struct hash<boost::asio::ip::address> {
    public:
        std::size_t operator()(const boost::asio::ip::address& addr) const noexcept {
            return addr.is_v4()
                ? std::hash<boost::asio::ip::address_v4>()(addr.to_v4())
                : std::hash<boost::asio::ip::address_v6>()(addr.to_v6());
        }
    };
#endif

    template <>
    struct hash<boost::asio::ip::tcp::endpoint> {
    public:
        std::size_t operator()(const boost::asio::ip::tcp::endpoint& v) const noexcept {
            return ppp::net::Ipep::GetHashCode(v);
        }
    };

    template <>
    struct hash<boost::asio::ip::udp::endpoint> {
    public:
        std::size_t operator()(const boost::asio::ip::udp::endpoint& v) const noexcept {
            return ppp::net::Ipep::GetHashCode(v);
        }
    };
}