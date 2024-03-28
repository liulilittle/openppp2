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
                ppp::string ExtractHost(const Byte* szPacketStartPos, int nPacketLength) noexcept;
            }

            inline Byte GetBitValueAt(Byte b, Byte offset, Byte length) noexcept {
                return (Byte)((b >> offset) & ~(0xff << length));
            }

            inline Byte GetBitValueAt(Byte b, Byte offset) noexcept {
                return GetBitValueAt(b, offset, 1);
            }

            inline Byte SetBitValueAt(Byte b, Byte offset, Byte length, Byte value) noexcept {
                int mask = ~(0xff << length);
                value = (Byte)(value & mask);

                return (Byte)((value << offset) | (b & ~(mask << offset)));
            }

            inline Byte SetBitValueAt(Byte b, Byte offset, Byte value) noexcept {
                return SetBitValueAt(b, offset, 1, value);
            }

            inline unsigned short ip_standard_chksum(void* dataptr, int len) noexcept {
                unsigned int acc;
                unsigned short src;
                unsigned char* octetptr;

                acc = 0;
                /* dataptr may be at odd or even addresses */
                octetptr = (unsigned char*)dataptr;
                while (len > 1) {
                    /* declare first octet as most significant
                       thus assume network order, ignoring host order */
                    src = (unsigned short)((*octetptr) << 8);
                    octetptr++;
                    /* declare second octet as least significant */
                    src |= (*octetptr);
                    octetptr++;
                    acc += src;
                    len -= 2;
                }
                if (len > 0) {
                    /* accumulate remaining octet */
                    src = (unsigned short)((*octetptr) << 8);
                    acc += src;
                }
                /* add deferred carry bits */
                acc = (unsigned int)((acc >> 16) + (acc & 0x0000ffffUL));
                if ((acc & 0xffff0000UL) != 0) {
                    acc = (unsigned int)((acc >> 16) + (acc & 0x0000ffffUL));
                }
                /* This maybe a little confusing: reorder sum using htons()
                   instead of ntohs() since it has a little less call overhead.
                   The caller must invert bits for Internet sum ! */
                return ntohs((unsigned short)acc);
            }

            inline unsigned short inet_chksum(void* dataptr, int len) noexcept {
                return (unsigned short)~ip_standard_chksum(dataptr, len);
            }

            inline unsigned int FOLD_U32T(unsigned int u) noexcept {
                return ((unsigned int)(((u) >> 16) + ((u) & 0x0000ffffUL)));
            }

            inline unsigned int SWAP_BYTES_IN_WORD(unsigned int w) noexcept {
                return (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8);
            }

            inline unsigned short inet_cksum_pseudo_base(unsigned char* payload, unsigned int proto, unsigned int proto_len, unsigned int acc) noexcept {
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

            inline unsigned short inet_chksum_pseudo(unsigned char* payload, unsigned int proto, unsigned int proto_len, unsigned int src, unsigned int dest) noexcept {
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