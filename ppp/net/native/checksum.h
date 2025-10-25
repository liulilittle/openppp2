#pragma once

#include <ppp/stdafx.h>

#if _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h> // Linux
#include <arpa/inet.h>  // MacOS(darwin)
#endif

namespace ppp {
    namespace net {
        namespace native {
            namespace dns {
#pragma pack(push, 1)
                struct 
#if defined(__GNUC__) || defined(__clang__)
                    __attribute__((packed)) 
#endif
                dns_hdr {
                    uint16_t                                                                usTransID;         // ��ʶ��
                    uint16_t                                                                usFlags;           // ���ֱ�־λ
                    uint16_t                                                                usQuestionCount;   // Question�ֶθ��� 
                    uint16_t                                                                usAnswerCount;     // Answer�ֶθ���
                    uint16_t                                                                usAuthorityCount;  // Authority�ֶθ���
                    uint16_t                                                                usAdditionalCount; // Additional�ֶθ���
                };
#pragma pack(pop)

                static constexpr int MAX_DOMAINNAME_LEN                                     = 255; /* MAX: 253 +. �� 254 BYTE or 254 CHAR+. �� 255 BYTE */
                static constexpr int DNS_PORT                                               = PPP_DNS_SYS_PORT;
                static constexpr int DNS_TYPE_SIZE                                          = 2;
                static constexpr int DNS_CLASS_SIZE                                         = 2;
                static constexpr int DNS_TTL_SIZE                                           = 4;
                static constexpr int DNS_DATALEN_SIZE                                       = 2;
                static constexpr int DNS_TYPE_A                                             = 0x0001; //1 a host address
                static constexpr int DNS_TYPE_AAAA                                          = 0x001c; //1 a host address
                static constexpr int DNS_TYPE_CNAME                                         = 0x0005; //5 the canonical name for an alias
                static constexpr int DNS_CLASS_IN                                           = 0x0001;
                static constexpr int DNS_PACKET_MAX_SIZE                                    = (sizeof(struct dns_hdr) + MAX_DOMAINNAME_LEN + DNS_TYPE_SIZE + DNS_CLASS_SIZE);

                ppp::string                                                                 ExtractHost(
                    const Byte*                                                             szPacketStartPos, 
                    int                                                                     nPacketLength) noexcept;

                ppp::string                                                                 ExtractHostX(
                    const Byte*                                                             szPacketStartPos, 
                    int                                                                     nPacketLength, 
                    const ppp::function<bool(dns_hdr*)>&                                    fPredicateB) noexcept;

                ppp::string                                                                 ExtractHostY(
                    const Byte*                                                             szPacketStartPos, 
                    int                                                                     nPacketLength, 
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>&  fPredicateE) noexcept;

                ppp::string                                                                 ExtractHostZ(
                    const Byte*                                                             szPacketStartPos, 
                    int                                                                     nPacketLength, 
                    const ppp::function<bool(dns_hdr*)>&                                    fPredicateB, 
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>&  fPredicateE) noexcept;
            }

            inline Byte                                                                     GetBitValueAt(Byte b, Byte offset, Byte length) noexcept {
                return (Byte)((b >> offset) & ~(0xff << length));
            }

            inline Byte                                                                     GetBitValueAt(Byte b, Byte offset) noexcept {
                return GetBitValueAt(b, offset, 1);
            }

            inline Byte                                                                     SetBitValueAt(Byte b, Byte offset, Byte length, Byte value) noexcept {
                int mask = ~(0xff << length);
                value = (Byte)(value & mask);

                return (Byte)((value << offset) | (b & ~(mask << offset)));
            }

            inline Byte                                                                     SetBitValueAt(Byte b, Byte offset, Byte value) noexcept {
                return SetBitValueAt(b, offset, 1, value);
            }

            unsigned short                                                                  ip_standard_chksum(void* dataptr, int len) noexcept;

            inline unsigned short                                                           inet_chksum(void* dataptr, int len) noexcept {
                return (unsigned short)~ip_standard_chksum(dataptr, len);
            }

            inline unsigned int                                                             FOLD_U32T(unsigned int u) noexcept {
                return ((unsigned int)(((u) >> 16) + ((u) & 0x0000ffffUL)));
            }

            inline unsigned int                                                             SWAP_BYTES_IN_WORD(unsigned int w) noexcept {
                return (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8);
            }

            inline unsigned short                                                           inet_cksum_pseudo_base(unsigned char* payload, unsigned int proto, unsigned int proto_len, unsigned int acc) noexcept {
                bool swapped = false;
                acc += ip_standard_chksum(payload, (int)proto_len);
                acc = FOLD_U32T(acc);

                if (proto_len % 2 != 0) {
                    swapped = !swapped;
                    acc = SWAP_BYTES_IN_WORD(acc);
                }

                if (swapped) {
                    acc = SWAP_BYTES_IN_WORD(acc);
                }

                acc += htons((unsigned short)proto);
                acc += htons((unsigned short)proto_len);

                acc = FOLD_U32T(acc);
                acc = FOLD_U32T(acc);

                return (unsigned short)~(acc & 0xffffUL);
            }

            inline unsigned short                                                           inet_chksum_pseudo(unsigned char* payload, unsigned int proto, unsigned int proto_len, unsigned int src, unsigned int dest) noexcept {
                unsigned int acc;
                unsigned int addr;

                addr = src;
                acc = (addr & 0xffff);
                acc = (acc + ((addr >> 16) & 0xffff));
                addr = dest;
                acc = (acc + (addr & 0xffff));
                acc = (acc + ((addr >> 16) & 0xffff));

                /* fold down to 16 bits */
                acc = FOLD_U32T(acc);
                acc = FOLD_U32T(acc);

                return inet_cksum_pseudo_base(payload, proto, proto_len, acc);
            }
        }
    }
}