#pragma once

#include <ppp/net/native/ip.h>

namespace ppp {
    namespace net {
        namespace native {
            enum IcmpType {
                ICMP_ER     = 0,  /* echo reply */
                ICMP_DUR    = 3,  /* destination unreachable */
                ICMP_SQ     = 4,  /* source quench */
                ICMP_RD     = 5,  /* redirect */
                ICMP_ECHO   = 8,  /* echo */
                ICMP_TE     = 11, /* time exceeded */
                ICMP_PP     = 12, /* parameter problem */
                ICMP_TS     = 13, /* timestamp */
                ICMP_TSR    = 14, /* timestamp reply */
                ICMP_IRQ    = 15, /* information request */
                ICMP_IR     = 16, /* information reply */
                ICMP_AM     = 17, /* address mask request */
                ICMP_AMR    = 18, /* address mask reply */
            };

#pragma pack(push, 1)
            struct icmp_hdr {                           // RFC 792(http://www.faqs.org/rfcs/rfc792.html)
            public:
                unsigned char           icmp_type;      // icmp service type, 8 echo request, 0 echo reply
                unsigned char           icmp_code;      // icmp header code
                unsigned short          icmp_chksum;    // icmp header chksum
                unsigned short          icmp_id;        // icmp packet identification
                unsigned short          icmp_seq;       // icmp packet sequent

            public:
                static struct icmp_hdr* Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept;
            };
#pragma pack(pop)
        }
    }
}