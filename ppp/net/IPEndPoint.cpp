#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <string>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace net {
        IPEndPoint::IPEndPoint(const char* address, int port) noexcept
            : _AddressFamily(AddressFamily::InterNetwork)
            , Port(port) {
            
            if (NULL == address || *address == '\x0') {
                this->_AddressFamily = AddressFamily::InterNetwork;
                *(UInt32*)this->_AddressBytes = IPEndPoint::NoneAddress;
            }
            else {
                struct in_addr addr4;  /* char ipv6_buf[INET6_ADDRSTRLEN];                         */
                struct in6_addr addr6; /* inet_ntop(AF_INET6, &addr6, ipv6_buf, INET6_ADDRSTRLEN); */
                if (inet_pton(AF_INET6, address, &addr6) > 0) {
                    this->_AddressFamily = AddressFamily::InterNetworkV6;  
                    memcpy(this->_AddressBytes, addr6.s6_addr, sizeof(addr6.s6_addr));
                }
                else if (inet_pton(AF_INET, address, &addr4) > 0) {
                    *(UInt32*)this->_AddressBytes = addr4.s_addr;
                    this->_AddressFamily = AddressFamily::InterNetwork;
                }
                else {
                    this->_AddressFamily = AddressFamily::InterNetwork;
                    *(UInt32*)this->_AddressBytes = IPEndPoint::NoneAddress;
                }
            }
        }

        IPEndPoint::IPEndPoint(AddressFamily af, const void* address_bytes, int address_size, int port) noexcept
            : _AddressFamily(af)
            , Port(port) {
            int limit_size = 0;
            if (af == AddressFamily::InterNetworkV6) {
                limit_size = sizeof(struct in6_addr);
            }
            else {
                af = AddressFamily::InterNetwork;
                limit_size = sizeof(struct in_addr);
            }

            memset(this->_AddressBytes, 0, limit_size);
            if (NULL != address_bytes && address_size > 0) {
                memcpy(this->_AddressBytes, address_bytes, std::min<int>(address_size, limit_size));
            }
            
            this->_AddressFamily = af;
        }

        ppp::string IPEndPoint::GetHostName() noexcept {
            char hostname[256]; // 域名规定不超过64字节（但是几乎大部分实现为64-1字节）
            hostname[0x00] = '\x0';
            hostname[0xff] = '\x0';

            if (::gethostname(hostname, 0xff) != 0) {
                *hostname = '\x0';
            }

            if (*hostname != '\x0') {
                return hostname;
            }
            else {
                return "localhost";
            }
        }

        ppp::string IPEndPoint::ToString() noexcept {
            return Ipep::ToIpepAddress(this);
        }
    }
}