#pragma once

#include <ppp/stdafx.h>

class HttpClient {
public:
    HttpClient(const ppp::string& host, const ppp::string& cacert_path) noexcept;

public:
    ppp::string                             Get(const ppp::string& api, int& status) noexcept;
    ppp::string                             Post(const ppp::string& api, const char* data, size_t size, int& status) noexcept;

private:
    ppp::string                             HttpGetOrPostImpl(bool post, const ppp::string& api, const char* data, size_t size, int& status) noexcept;

private:        
    ppp::string                             _host;
    ppp::string                             _cacert_path;
    bool                                    _cacert_exist;
};