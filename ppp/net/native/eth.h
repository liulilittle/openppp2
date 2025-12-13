#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1) 
            struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            eth_addr {
            public:
                static const int    ETH_HWADDR_LEN  = 6;

            public:
                union {
                    uint8_t         s_data[ETH_HWADDR_LEN];
                    struct {
                        uint32_t    dw;
                        uint16_t    w;
                    }               s_zero;
                };

            public:
                bool                TryParse(const char* mac_string, struct eth_addr& mac) noexcept;
                ppp::string         ToString() noexcept;
                static ppp::string  ToString(const struct eth_addr& mac) noexcept;
                static ppp::string  BytesToMacAddress(const void* data, int size) noexcept;
            };

            struct 
#if !defined(_WIN32)
                __attribute__((packed)) 
#endif
            eth_hdr {
            public:
                eth_addr            dest;
                eth_addr            src;
                UInt16              type;

            public:
                static const int    ETHTYPE_IP      = 0x0800U;
                static const int    ETHTYPE_ARP     = 0x0806U;
            };
#pragma pack(pop) 
        }
    }
}