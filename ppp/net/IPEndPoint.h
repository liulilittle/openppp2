#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        enum AddressFamily {
            InterNetwork = AF_INET,
            InterNetworkV6 = AF_INET6,
        };

        struct IPEndPoint {
        private:
            mutable Byte                                                        _AddressBytes[sizeof(struct in6_addr)]; // 16
            AddressFamily                                                       _AddressFamily;

        public:
            const int                                                           Port;

        public:
            static constexpr int                                                MinPort          = 0;
            static constexpr int                                                MaxPort          = UINT16_MAX;
            static constexpr UInt32                                             AnyAddress       = INADDR_ANY;
            static constexpr UInt32                                             NoneAddress      = INADDR_NONE;
            static constexpr UInt32                                             LoopbackAddress  = INADDR_LOOPBACK;
            static constexpr UInt32                                             BroadcastAddress = INADDR_BROADCAST;

        public:
            IPEndPoint() noexcept
                : IPEndPoint(NoneAddress, IPEndPoint::MinPort) {

            }
            IPEndPoint(UInt32 address, int port) noexcept
                : _AddressFamily(AddressFamily::InterNetwork)
                , Port(port) {
                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                *(Int32*)&this->Port = port;
                *(UInt32*)this->_AddressBytes = address;
            }
            IPEndPoint(const char* address, int port) noexcept;
            IPEndPoint(AddressFamily af, const void* address_bytes, int address_size, int port) noexcept;

        public:
            static IPEndPoint                                                   Any(int port) noexcept {
                return IPEndPoint(IPEndPoint::AnyAddress, port);
            }
            static IPEndPoint                                                   Loopback(int port) noexcept {
                return IPEndPoint(IPEndPoint::LoopbackAddress, port);
            }
            static IPEndPoint                                                   Broadcast(int port) noexcept {
                return IPEndPoint(IPEndPoint::BroadcastAddress, port);
            }
            static IPEndPoint                                                   None(int port) noexcept {
                return IPEndPoint(IPEndPoint::NoneAddress, port);
            }
            static IPEndPoint                                                   IPv6Any(int port) noexcept {
                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v6::any(), port);
                return ToEndPoint(localEP);
            }
            static IPEndPoint                                                   IPv6Loopback(int port) noexcept {
                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v6::loopback(), port);
                return ToEndPoint(localEP);
            }
            static IPEndPoint                                                   IPv6None(int port) noexcept {
                return IPv6Any(port);
            }

        public:     
            bool                                                                IsBroadcast() noexcept {
                return this->IsNone();
            }
            bool                                                                IsNone() noexcept {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    int len;
                    Byte* p = this->GetAddressBytes(len);
                    return *p == 0xff;
                }
                else {
                    return this->GetAddress() == IPEndPoint::NoneAddress;
                }
            }
            bool                                                                IsAny() noexcept {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    int len;
                    Int64* p = (Int64*)this->GetAddressBytes(len);
                    return p[0] == 0 && p[1] == 0;
                }
                else {
                    return this->GetAddress() == IPEndPoint::AnyAddress;
                }
            }
            bool                                                                IsLoopback() noexcept {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    int len;
                    boost::asio::ip::address_v6::bytes_type* p =
                        (boost::asio::ip::address_v6::bytes_type*)this->GetAddressBytes(len); // IN6_IS_ADDR_LOOPBACK
                    return boost::asio::ip::address_v6(*p).is_loopback();
                }
                else {
                    return this->GetAddress() == ntohl(IPEndPoint::LoopbackAddress);
                }
            }
            bool                                                                IsMulticast() noexcept {
                return ToEndPoint<boost::asio::ip::tcp>(*this).address().is_multicast();
            }

        public:     
            ppp::string                                                         GetAddressBytes() const noexcept {
                int datalen;
                Byte* data = this->GetAddressBytes(datalen);
                return ppp::string((char*)data, datalen);
            }
            Byte*                                                               GetAddressBytes(int& len) const {
                if (this->_AddressFamily == AddressFamily::InterNetworkV6) {
                    len = sizeof(this->_AddressBytes);
                    return this->_AddressBytes;
                }
                else {
                    len = sizeof(UInt32);
                    return this->_AddressBytes;
                }
            }
            UInt32                                                              GetAddress() const noexcept {
                return *(UInt32*)this->_AddressBytes;
            }
            AddressFamily                                                       GetAddressFamily() const noexcept {
                return this->_AddressFamily;
            }
            bool                                                                Equals(const IPEndPoint& value) const {
                IPEndPoint* reft = (IPEndPoint*)&reinterpret_cast<const char&>(value);
                IPEndPoint* left = (IPEndPoint*)this;
                if (left == reft) {
                    return true;
                }

                return *left == *reft;
            }

        public:     
            bool                                                                operator == (const IPEndPoint& right) const noexcept {
                if (this->_AddressFamily != right._AddressFamily) {
                    return false;
                }

                Byte* x = this->_AddressBytes;
                Byte* y = right._AddressBytes;
                if (x == y) {
                    return true;
                }

                if (this->_AddressFamily == AddressFamily::InterNetworkV6) {
                    UInt64* qx = (UInt64*)x;
                    UInt64* qy = (UInt64*)y;
                    return qx[0] == qy[0] && qx[1] == qy[1];
                }
                return *(UInt32*)x == *(UInt32*)y;
            }
            bool                                                                operator != (const IPEndPoint& right) const noexcept {
                bool b = (*this) == right;
                return !b;
            }
            IPEndPoint&                                                         operator = (const IPEndPoint& right) {
                this->_AddressFamily = right._AddressFamily;
                constantof(this->Port) = right.Port;

                int address_bytes_size;
                Byte* address_bytes = right.GetAddressBytes(address_bytes_size);
                memcpy(this->_AddressBytes, address_bytes, address_bytes_size);

                return *this;
            }

        public:     
            template <typename TString>     
            static TString                                                      ToAddressString(AddressFamily af, const Byte* address_bytes, int address_size) noexcept {
                if (NULL == address_bytes || address_size < 1) {
                    return "0.0.0.0";
                }

                if (af == AddressFamily::InterNetworkV6) {
                    if (address_size < (int)sizeof(struct in6_addr)) {
                        return "0.0.0.0";
                    }

                    char sz[INET6_ADDRSTRLEN];
                    if (!inet_ntop(AF_INET6, (struct in6_addr*)address_bytes, sz, sizeof(sz))) {
                        return "0.0.0.0";
                    }
                    return sz;
                }
                else {
                    if (address_size < (int)sizeof(struct in_addr)) {
                        return "0.0.0.0";
                    }

                    char sz[INET_ADDRSTRLEN];
                    if (!inet_ntop(AF_INET, (struct in_addr*)address_bytes, sz, sizeof(sz))) {
                        return "0.0.0.0";
                    }
                    return sz; // inet_ntoa(*(struct in_addr*)address);
                }
            }

        public:     
            ppp::string                                                         ToAddressString() noexcept {
                int address_bytes_size;
                Byte* address_bytes = GetAddressBytes(address_bytes_size);
                return ToAddressString<ppp::string>(this->_AddressFamily, address_bytes, address_bytes_size);
            }
            int                                                                 GetHashCode() const noexcept {
                int h = this->GetAddressFamily() + this->Port;
                int l = 0;
                Byte* p = this->GetAddressBytes(l);
                for (int i = 0; i < l; i++) {
                    h += *p++;
                }
                return h;
            }
            ppp::string                                                         ToString() noexcept;

        public:
            static ppp::string                                                  GetHostName() noexcept;

        public:
            static ppp::string                                                  ToAddressString(UInt32 address) noexcept {
                return ToAddressString<ppp::string>(AddressFamily::InterNetwork, (Byte*)&address, sizeof(address));
            }
            static ppp::string                                                  ToAddressString(AddressFamily af, const ppp::string& address_bytes) noexcept {
                return ToAddressString<ppp::string>(af, (Byte*)address_bytes.data(), (int)address_bytes.size());
            }
            static UInt32                                                       PrefixToNetmask(int prefix) noexcept {
                UInt32 mask = prefix ? (-1L << (32L - prefix)) : 0L;
                return htonl(mask);
            }
            static int                                                          NetmaskToPrefix(UInt32 mask) noexcept {
                return NetmaskToPrefix(reinterpret_cast<unsigned char*>(&mask), sizeof(mask));
            }
            static int                                                          NetmaskToPrefix(unsigned char* bytes, int bytes_size) noexcept {
                if (NULL == bytes || bytes_size < 1) {
                    return 0;
                }

                int prefix = 0;
                for (int i = 0; i < bytes_size; i++) {
                    int b = bytes[i];
                    while (b) {
                        prefix += b & 1; 
                        b >>= 1;
                    }
                }
                return prefix;
            }
            static bool                                                         IsInvalid(const IPEndPoint* p) noexcept {
                IPEndPoint* __p = (IPEndPoint*)p;
                if (NULL == __p) {
                    return true;
                }

                if (__p->IsNone()) {
                    return true;
                }

                if (__p->IsAny()) {
                    return true;
                }

                if (__p->IsMulticast()) {
                    return true;
                }
                return false;
            }
            static bool                                                         IsInvalid(const IPEndPoint& value) noexcept {
                return IPEndPoint::IsInvalid(addressof(value));
            }
            static bool                                                         IsInvalid(const boost::asio::ip::address& address) noexcept {
                return IsInvalid(IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(address, IPEndPoint::MinPort + 1)));
            }
        
        public:     
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   Transform(AddressFamily addressFamily, const boost::asio::ip::basic_endpoint<TProtocol>& remoteEP) noexcept {
                boost::asio::ip::address address = remoteEP.address();
                if (addressFamily == AddressFamily::InterNetwork) {
                    if (address.is_v4()) {
                        return remoteEP;
                    }
                    else {
                        return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(remoteEP)));
                    }
                }
                else {
                    if (address.is_v6()) {
                        return remoteEP;
                    }
                    else {
                        return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V4ToV6(IPEndPoint::ToEndPoint(remoteEP)));
                    }
                }
            }
        
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   ToEndPoint(const IPEndPoint& endpoint) noexcept {
                AddressFamily af = endpoint.GetAddressFamily();
                if (af == AddressFamily::InterNetwork) {
                    return WrapAddressV4<TProtocol>(endpoint.GetAddress(), endpoint.Port);
                }
                else {
                    int len;
                    const Byte* address = endpoint.GetAddressBytes(len);
                    return WrapAddressV6<TProtocol>(address, len, endpoint.Port);
                }
            }
        
            template <class TProtocol>       
            static IPEndPoint                                                   ToEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& endpoint) noexcept {
                boost::asio::ip::address address = endpoint.address();
                if (address.is_v4()) {
                    return IPEndPoint(ntohl(address.to_v4().to_ulong()), endpoint.port());
                }
                elif(address.is_v6()) {
                    boost::asio::ip::address_v6::bytes_type bytes = address.to_v6().to_bytes();
                    return IPEndPoint(AddressFamily::InterNetworkV6, bytes.data(), (int)bytes.size(), endpoint.port());
                }
                else {
                    return IPEndPoint(IPEndPoint::AnyAddress, endpoint.port());
                }
            }
        
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   NewAddress(const char* address, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (NULL == address || *address == '\x0') {
                    address = "0.0.0.0";
                }

                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                boost::system::error_code ec_;
                boost::asio::ip::address ba_ = StringToAddress(address, ec_);
                if (ec_) {
                    ba_ = boost::asio::ip::address_v4(IPEndPoint::NoneAddress);
                }

                return protocol_endpoint(ba_, port);
            }
        
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   WrapAddressV4(UInt32 address, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                return protocol_endpoint(boost::asio::ip::address_v4(ntohl(address)), port);
            }
        
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   WrapAddressV6(const void* address, int size, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (size < 0) {
                    size = 0;
                }

                boost::asio::ip::address_v6::bytes_type address_bytes;
                unsigned char* p = address_bytes.data();
                memcpy(p, address, size);
                memset(p, 0, address_bytes.size() - size);

                return protocol_endpoint(boost::asio::ip::address_v6(address_bytes), port);
            }
        
            template <class TProtocol>       
            static boost::asio::ip::basic_endpoint<TProtocol>                   AnyAddressV4(int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                return protocol_endpoint(boost::asio::ip::address_v4::any(), port);
            }
        
            template <class TProtocol>       
            static bool                                                         Equals(const boost::asio::ip::basic_endpoint<TProtocol>& x, const boost::asio::ip::basic_endpoint<TProtocol>& y) noexcept {
                if (x != y) {
                    return false;
                }

                return x.address() == y.address() && x.port() == y.port();
            }
        
        public:     
            static IPEndPoint                                                   V6ToV4(const IPEndPoint& destinationEP) noexcept {
                if (destinationEP.GetAddressFamily() == AddressFamily::InterNetwork) {
                    return destinationEP;
                }

#pragma pack(push, 1)
                struct IPV62V4ADDR {
                    uint64_t R1;
                    uint16_t R2;
                    uint16_t R3;
                    uint32_t R4;
                };
#pragma pack(pop)

                int len;
                IPV62V4ADDR* in = (IPV62V4ADDR*)destinationEP.GetAddressBytes(len);
                if (in->R1 || in->R2 || in->R3 != UINT16_MAX) {
                    return destinationEP;
                }
                else {
                    return IPEndPoint(in->R4, destinationEP.Port);
                }
            }
            static IPEndPoint                                                   V4ToV6(const IPEndPoint& destinationEP) noexcept {
                if (destinationEP.GetAddressFamily() == AddressFamily::InterNetworkV6) {
                    return destinationEP;
                }

#pragma pack(push, 1)
                struct IPV62V4ADDR {
                    uint64_t R1;
                    uint16_t R2;
                    uint16_t R3;
                    uint32_t R4;
                };
#pragma pack(pop)

                IPV62V4ADDR in;
                in.R1 = 0;
                in.R2 = 0;
                in.R3 = UINT16_MAX;
                in.R4 = destinationEP.GetAddress();
                return IPEndPoint(AddressFamily::InterNetworkV6, &in, sizeof(IPV62V4ADDR), destinationEP.Port);
            }
        };
    }
}