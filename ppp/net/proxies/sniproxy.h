#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace net {
        namespace proxies {
            class sniproxy final : public std::enable_shared_from_this<sniproxy> {
                typedef ppp::io::MemoryStream                                       MemoryStream;
                typedef ppp::threading::Timer                                       Timer;
#pragma pack(push, 1)       
                struct 
#if defined(__GNUC__) || defined(__clang__)
                    __attribute__((packed)) 
#endif
                tls_hdr {        
                    Byte                                                            Content_Type = 0;
                    UInt16                                                          Version      = 0;
                    UInt16                                                          Length       = 0;
                };      
#pragma pack(pop)       
                static const int                                                    FORWARD_MSS = 65536;

            public:
                sniproxy(int                                                        cdn, 
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                    const std::shared_ptr<boost::asio::io_context>&                 context, 
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                ~sniproxy() noexcept;

            public:
                void                                                                close() noexcept;
                bool                                                                handshake() noexcept;
        
            private:        
                void                                                                clear_timeout() noexcept;
                UInt16                                                              fetch_uint16(Byte*& data) noexcept;
                int                                                                 fetch_length(Byte*& data) noexcept;
                ppp::string                                                         fetch_sniaddr(size_t tls_payload) noexcept;
                bool                                                                do_handshake(ppp::coroutines::YieldContext& y) noexcept;
                bool                                                                socket_is_open() noexcept;
                bool                                                                local_to_remote() noexcept;
                bool                                                                remote_to_local() noexcept;
        
            private:        
                static bool                                                         be_http(const void* p) noexcept;
                static bool                                                         be_host(ppp::string host, ppp::string domain) noexcept;
                bool                                                                do_tlsvd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;
                bool                                                                do_httpd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;
                bool                                                                do_httpd_handshake_host_trim(MemoryStream& messages_, ppp::string& host, int& port) noexcept;
                ppp::string                                                         do_httpd_handshake_host(MemoryStream& messages_) noexcept;
                bool                                                                do_read_http_request_headers(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;
                bool                                                                do_connect_and_forward_to_host(ppp::coroutines::YieldContext& y, const ppp::string hostname_, int self_websocket_port, int forward_connect_port, MemoryStream& messages_) noexcept;
                int                                                                 do_forward_websocket_port() noexcept;
        
            private:        
                int                                                                 cdn_           = 0;
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                std::shared_ptr<boost::asio::io_context>                            context_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                       local_socket_;
                boost::asio::ip::tcp::socket                                        remote_socket_;
                uint64_t                                                            last_         = 0;
                std::shared_ptr<Timer>                                              timeout_      = 0;
                char                                                                local_socket_buf_[FORWARD_MSS];
                char                                                                remote_socket_buf_[FORWARD_MSS];
            };
        }
    }
}