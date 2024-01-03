#pragma once

#include <string>

class HttpClient {
public:
    HttpClient(const std::string& host, const std::string& cacert_path) noexcept;

public:
    std::string                             Get(const std::string& api, int& status) noexcept { 
        return this->HttpGetOrPostImpl(false, api, NULL, 0, status);
    }
    std::string                             Post(const std::string& api, const char* data, size_t size, int& status) noexcept {
        return this->HttpGetOrPostImpl(true, api, data, size, status); 
    }

private:
    std::string                             HttpGetOrPostImpl(bool post, const std::string& api, const char* data, size_t size, int& status) noexcept;

private:        
    std::string                             _host;
    std::string                             _cacert_path;
    bool                                    _cacert_exist;
};