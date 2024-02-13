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
                    ppp::string                                             redirect;
                }                                                           dns;
            }                                                               udp;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                }                                                           connect;
                struct {
                    int                                                     port;
                }                                                           listen;
                bool                                                        turbo;
                int                                                         backlog;
                bool                                                        fast_open;
            }                                                               tcp;
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
                struct {
                    int                                                     port;
                    ppp::string                                             bind;
                }                                                           http_proxy;
            }                                                               client;

        public:
            AppConfiguration() noexcept;

        public:
            void                                                            Clear() noexcept;
            bool                                                            Load(Json::Value& json) noexcept;
            bool                                                            Load(const ppp::string& path) noexcept;

        public:
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept { 
                return this->_BufferAllocator; 
            }
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
    }
}