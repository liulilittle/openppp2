#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>

namespace lwip {
    using ppp::net::native::ip_hdr;
    using ppp::net::native::tcp_hdr;

    std::shared_ptr<ppp::Byte>                              netstack_wrap_ipv4_tcp_syn_packet(
        boost::asio::ip::tcp::endpoint&                     dest, 
        boost::asio::ip::tcp::endpoint&                     src, 
        uint16_t                                            wnd, 
        uint32_t                                            ack, 
        uint32_t                                            seq,
        int&                                                outlen) noexcept {

        outlen = 0;

        boost::asio::ip::address dest_ip = dest.address();
        if (!dest_ip.is_v4()) {
            return NULLPTR;
        }

        boost::asio::ip::address src_ip = src.address();
        if (!src_ip.is_v4()) {
            return NULLPTR;  
        }
        else {
            outlen = ip_hdr::IP_HLEN + tcp_hdr::TCP_HLEN;
        }

        std::shared_ptr<ppp::Byte> packet = ppp::make_shared_alloc<ppp::Byte>(outlen);
        if (NULLPTR == packet) {
            return NULLPTR;
        }

        ip_hdr* iphdr = (ip_hdr*)packet.get();
        iphdr->dest   = *(uint32_t*)dest_ip.to_v4().to_bytes().data();
        iphdr->src    = *(uint32_t*)src_ip.to_v4().to_bytes().data();
        iphdr->ttl    = ip_hdr::IP_DFT_TTL;
        iphdr->proto  = ip_hdr::IP_PROTO_TCP;
        iphdr->v_hl   = 4 << 4 | ip_hdr::IP_HLEN >> 2;
        iphdr->tos    = 0; // Routine Mode
        iphdr->len    = htons(outlen);
        iphdr->id     = ntohs(ip_hdr::NewId());
        iphdr->flags  = htons(ip_hdr::IP_DF);
        iphdr->chksum = 0;

        iphdr->chksum = ppp::net::native::inet_chksum(iphdr, ip_hdr::IP_HLEN);
        if (iphdr->chksum == 0) {
            iphdr->chksum = 0xffff;
        }

        tcp_hdr* tcphdr           = (tcp_hdr*)(iphdr + 1);
        tcphdr->ackno             = htonl(ack);
        tcphdr->seqno             = htonl(seq);
        tcphdr->wnd               = htons(wnd);
        tcphdr->urgp              = 0;
        tcphdr->chksum            = 0;
        tcphdr->hdrlen_rsvd_flags = 0;
        tcphdr->dest              = htons(dest.port());
        tcphdr->src               = htons(src.port());
        
        tcp_hdr::TCPH_HDRLEN_BYTES_SET(tcphdr, tcp_hdr::TCP_HLEN);
        tcp_hdr::TCPH_FLAGS_SET(tcphdr, tcp_hdr::TCP_SYN);
        
        tcphdr->chksum = ppp::net::native::inet_chksum_pseudo((unsigned char*)tcphdr,
            (unsigned int)ip_hdr::IP_PROTO_TCP,
            (unsigned int)tcp_hdr::TCP_HLEN,
            iphdr->src,
            iphdr->dest);
        if (tcphdr->chksum == 0) {
            tcphdr->chksum = 0xffff;
        }

        return packet;
    }
}