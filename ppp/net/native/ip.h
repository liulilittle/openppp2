#pragma once

#include <stdio.h>
#include <stdint.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1)
            struct ip_hdr {
            public:
                enum Flags {
                    IP_RF                                                    = 0x8000,            /* reserved fragment flag */
                    IP_DF                                                    = 0x4000,            /* dont fragment flag */
                    IP_MF                                                    = 0x2000,            /* more fragments flag */
                    IP_OFFMASK                                               = 0x1fff,            /* mask for fragmenting bits */
                };

            public:
                 /* version / header length / type of service */
                 unsigned char                                               v_hl;
                 /* type of service */
                 unsigned char                                               tos;
                 /* total length */
                 unsigned short                                              len;
                 /* identification */
                 unsigned short                                              id;
                 /* fragment offset field */                                
                 unsigned short                                              flags;
                 /* time to live */
                 unsigned char                                               ttl;
                 /* protocol */
                 unsigned char                                               proto;
                 /* checksum */
                 unsigned short                                              chksum;
                 /* source and destination IP addresses */
                 unsigned int                                                src;
                 union
                 {
                     unsigned int                                            dst;
                     unsigned int                                            dest;
                 };

            public:
                static int                                                  IPH_V(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->v_hl >> 4);      
                }       
                static int                                                  IPH_HL(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->v_hl & 0x0f);        
                }       
                static int                                                  IPH_PROTO(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->proto & 0xff);       
                }       
                static int                                                  IPH_OFFSET(struct ip_hdr* hdr) noexcept {
                    return (hdr)->flags;        
                }       
                static int                                                  IPH_TTL(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->ttl & 0xff);
                }

            public:
                static struct ip_hdr*                                        Parse(const void* packet, int size) noexcept;
                static unsigned short                                        NewId() noexcept;

            public:
                static const int                                             IP_HLEN;
                static const unsigned char                                   IP_DFT_TTL;

            public:
                static const unsigned char                                   IP_VER                  = 4;
                static const unsigned int                                    IP_ADDR_ANY_VALUE       = 0x00000000;
                static const unsigned int                                    IP_ADDR_BROADCAST_VALUE = 0xffffffff;
                static const int                                             TOS_ROUTIN_MODE         = 0;
                static const unsigned char                                   IP_PROTO_IP             = 0;
                static const unsigned char                                   IP_PROTO_ICMP           = 1;
                static const unsigned char                                   IP_PROTO_UDP            = 17;
                static const unsigned char                                   IP_PROTO_TCP            = 6;
                static const int                                             MTU                     = 1500;
            };
#pragma pack(pop)
        }
    }
}