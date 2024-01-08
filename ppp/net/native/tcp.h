#pragma once

#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1)
            /*
             * typedef struct _tcp_hdr  
             * {  
             *     unsigned short src_port;    //源端口号   
             *     unsigned short dst_port;    //目的端口号   
             *     unsigned int seq_no;        //序列号   
             *     unsigned int ack_no;        //确认号   
             *     #if LITTLE_ENDIAN   
             *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
             *     unsigned char thl:4;        //tcp头部长度   
             *     unsigned char flag:6;       //6位标志   
             *     unsigned char reseverd_2:2; //保留6位中的2位   
             *     #else   
             *     unsigned char thl:4;        //tcp头部长度   
             *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
             *     unsigned char reseverd_2:2; //保留6位中的2位   
             *     unsigned char flag:6;       //6位标志    
             *     #endif   
             *     unsigned short wnd_size;    //16位窗口大小   
             *     unsigned short chk_sum;     //16位TCP检验和   
             *     unsigned short urgt_p;      //16为紧急指针   
             * } tcp_hdr;  
             */

            // https://android.googlesource.com/kernel/msm/+/android-msm-hammerhead-3.4-marshmallow-mr2/include/linux/tcp.h
            struct tcp_hdr {
            public:
                enum tcp_flags {
                    TCP_FIN                     = 0x01,
                    TCP_SYN                     = 0x02,
                    TCP_RST                     = 0x04,
                    TCP_PSH                     = 0x08,
                    TCP_ACK                     = 0x10,
                    TCP_UGR                     = 0x20,
                    TCP_ECE                     = 0x40,
                    TCP_CWR                     = 0x80,
                    TCP_FLAGS                   = 0x3f
                };

                enum tcp_state {
                    TCP_STATE_CLOSED,
                    TCP_STATE_SYN_SENT,
                    TCP_STATE_SYN_RECEIVED,
                    TCP_STATE_ESTABLISHED,
                    TCP_STATE_FIN_WAIT1,
                    TCP_STATE_FIN_WAIT2,
                    TCP_STATE_TIME_WAIT,
                    TCP_STATE_CLOSE_WAIT,
                    TCP_STATE_LAST_ACK,
                };

            public:
                unsigned short                  src;
                union {
                    unsigned short              dst;
                    unsigned short              dest;
                };
                unsigned int                    seqno;
                unsigned int                    ackno;
                unsigned short                  hdrlen_rsvd_flags;
                unsigned short                  wnd;
                unsigned short                  chksum;
                unsigned short                  urgp; // 应用层不可能出现“URGP/UGR or OPT”的协议；这类紧急协议数据报文直接RST链接即可。

            public:
                static unsigned short           TCPH_HDRLEN(struct tcp_hdr* phdr) noexcept {
                    return ((unsigned short)(ntohs((phdr)->hdrlen_rsvd_flags) >> 12));
                }
                static unsigned char            TCPH_HDRLEN_BYTES(struct tcp_hdr* phdr) noexcept {
                    return ((unsigned char)(TCPH_HDRLEN(phdr) << 2));
                }
                static unsigned char            TCPH_FLAGS(struct tcp_hdr* phdr) noexcept {
                    return ((unsigned char)((ntohs((phdr)->hdrlen_rsvd_flags) & (unsigned char)TCP_FLAGS)));
                }
                static unsigned short           TCPH_HDRLEN_SET(struct tcp_hdr* phdr, int len) noexcept {
                    int u = ((len) << 12) | TCPH_FLAGS(phdr);
                    return (phdr)->hdrlen_rsvd_flags = htons((unsigned short)u);
                }
                static unsigned short           TCPH_HDRLEN_BYTES_SET(struct tcp_hdr* phdr, int len) noexcept {
                    return TCPH_HDRLEN_SET(phdr, len >> 2);
                }
                static unsigned short           PP_HTONS(int x) noexcept {
                    return ((unsigned short)((((x) & (unsigned short)0x00ffU) << 8) | (((x) & (unsigned short)0xff00U) >> 8)));
                }
                static unsigned short           TCPH_FLAGS_SET(struct tcp_hdr* phdr, int flags) noexcept {
                    return (phdr)->hdrlen_rsvd_flags = (unsigned short)(((phdr)->hdrlen_rsvd_flags &
                        PP_HTONS(~(unsigned short)TCP_FLAGS)) | htons((unsigned short)flags));
                }

            public:
                static struct tcp_hdr*          Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept;

            public:
                static const int                TCP_HLEN;
            };
#pragma pack(pop)
        }
    }
}