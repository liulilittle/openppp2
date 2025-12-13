#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        namespace http {
            class HttpClient final {
            public:
                HttpClient(const ppp::string& host, const ppp::string& cacert_path) noexcept;

            public:
                std::string                             Get(const ppp::string& api, int& status) noexcept { 
                    return this->HttpGetOrPostImpl(false, api, NULL, 0, status); 
                }
                std::string                             Post(const ppp::string& api, const char* data, size_t size, int& status) noexcept { 
                    return this->HttpGetOrPostImpl(true, api, data, size, status); 
                }
                static bool                             VerifyUri(const ppp::string& url, ppp::string* host, int* port, ppp::string* path, bool* https) noexcept;

            private:
                std::string                             HttpGetOrPostImpl(bool post, const ppp::string& api, const char* data, size_t size, int& status) noexcept;

            private:        
                ppp::string                             _host;
                ppp::string                             _cacert_path;
                bool                                    _cacert_exist = false;
            };
        }
    }
}