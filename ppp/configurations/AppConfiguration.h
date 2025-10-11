#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

#include <json/json.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration final {
        public:
            struct MappingConfiguration final {
                bool                                                        protocol_tcp_or_udp;
                ppp::string                                                 local_ip;
                int                                                         local_port;
                ppp::string                                                 remote_ip;
                int                                                         remote_port;
            };

            struct RouteConfiguration final {
#if defined(_LINUX)
                ppp::string                                                 nic;
#endif
                uint32_t                                                    ngw;
                ppp::string                                                 path;    
                ppp::string                                                 vbgp;                    
            };

        public:
            int                                                             concurrent;
            int                                                             cdn[2];
            struct {
                ppp::string                                                 public_;
                ppp::string                                                 interface_;
            }                                                               ip;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                    int                                                     ttl;
                    bool                                                    turbo;
                    bool                                                    cache;
                    ppp::string                                             redirect;
                }                                                           dns;
                struct {
                    int                                                     port;
                }                                                           listen;
                struct {
                    int                                                     keep_alived[2];
                    bool                                                    dns;
                    bool                                                    quic;
                    bool                                                    icmp;
                    int                                                     aggligator;
                    ppp::unordered_set<ppp::string>                         servers;
                }                                                           static_;
                int                                                         cwnd;
                int                                                         rwnd;
            }                                                               udp;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                    int                                                     nexcept;
                }                                                           connect;
                struct {
                    int                                                     port;
                }                                                           listen;
                bool                                                        turbo;
                int                                                         backlog;
                int                                                         cwnd;
                int                                                         rwnd;
                bool                                                        fast_open;
            }                                                               tcp;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                }                                                           connect;
                int                                                         congestions;
                int                                                         keep_alived[2];
            }                                                               mux;
            struct {
                struct {
                    int                                                     ws;
                    int                                                     wss;
                }                                                           listen;
                struct {
                    std::string                                             certificate_file;
                    std::string                                             certificate_key_file;
                    std::string                                             certificate_chain_file;
                    std::string                                             certificate_key_password;
                    std::string                                             ciphersuites;
                    bool                                                    verify_peer;
                }                                                           ssl;
                ppp::string                                                 host;
                ppp::string                                                 path;
                struct {
                    std::string                                             error;
                    ppp::map<ppp::string, ppp::string>                      request;
                    ppp::map<ppp::string, ppp::string>                      response;
                }                                                           http;
            }                                                               websocket;
            struct {
                int                                                         kf;
                int                                                         kh;
                int                                                         kl;
                int                                                         kx;
                int                                                         sb;
                ppp::string                                                 protocol;
                ppp::string                                                 protocol_key;
                ppp::string                                                 transport;
                ppp::string                                                 transport_key;
                bool                                                        masked;
                bool                                                        plaintext;
                bool                                                        delta_encode;
                bool                                                        shuffle_data;
            }                                                               key;
            struct {
                int64_t                                                     size;
                ppp::string                                                 path;
            }                                                               vmem;
            struct {
                int                                                         node;
                ppp::string                                                 log;
                bool                                                        subnet;
                bool                                                        mapping;
                ppp::string                                                 backend;
                ppp::string                                                 backend_key;
            }                                                               server;
            struct {
                ppp::string                                                 guid;
                ppp::string                                                 server;
                ppp::string                                                 server_proxy;
                int64_t                                                     bandwidth;
                struct {
                    int                                                     timeout;
                }                                                           reconnections;
#if defined(_WIN32)
                struct {
                    bool                                                    tcp;
                }                                                           paper_airplane;
#endif
                ppp::vector<MappingConfiguration>                           mappings;
                ppp::vector<RouteConfiguration>                             routes;
                struct {
                    int                                                     port;
                    ppp::string                                             bind;
                }                                                           http_proxy;
                struct {
                    int                                                     port;
                    ppp::string                                             bind;
                    ppp::string                                             username;
                    ppp::string                                             password;
                }                                                           socks_proxy;
            }                                                               client;

        public:
            AppConfiguration() noexcept;

        public:
            void                                                            Clear() noexcept;
            bool                                                            Load(Json::Value& json) noexcept;
            bool                                                            Load(const ppp::string& path) noexcept;

        public:
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept { return this->_BufferAllocator; }
            std::shared_ptr<ppp::threading::BufferswapAllocator>            SetBufferAllocator(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<ppp::threading::BufferswapAllocator> result = std::move(this->_BufferAllocator);
                this->_BufferAllocator = allocator;
                return result;
            }

        public:
            Json::Value                                                     ToJson() noexcept;
            ppp::string                                                     ToString() noexcept;

        private:
            bool                                                            Loaded() noexcept;

        private:
            std::shared_ptr<ppp::threading::BufferswapAllocator>            _BufferAllocator;
        };

        namespace extensions {
            bool                                                            IsHaveCiphertext(const AppConfiguration& configuration) noexcept;
            inline bool                                                     IsHaveCiphertext(const AppConfiguration* configuration) noexcept { return NULL != configuration ? IsHaveCiphertext(*configuration) : false; }
        }
    }
}