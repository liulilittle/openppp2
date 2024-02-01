#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1) 
            struct eth_addr {
            public:
                static const int    ETH_HWADDR_LEN  = 6;

            public:
                Byte                addr[ETH_HWADDR_LEN];
            };

            struct eth_hdr {
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