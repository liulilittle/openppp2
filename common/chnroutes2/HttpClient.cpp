#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "HttpClient.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef F_OK
#define F_OK 0
#endif

HttpClient::HttpClient(const std::string& host, const std::string& cacert_path) noexcept
    : _host(host)
    , _cacert_path(cacert_path) {
    if (!cacert_path.empty()) {
        this->_cacert_exist = access(cacert_path.data(), F_OK) == 0;
    }
}

std::string HttpClient::HttpGetOrPostImpl(bool post, const std::string& api, const char* data, size_t size, int& status) noexcept {
    status = 0;

    if (this->_host.empty() || (NULL == data && size != 0)) {
        return "";
    }

    httplib::Client cli(this->_host.data());
    if (this->_cacert_exist) {
        cli.set_ca_cert_path(this->_cacert_path.data());
        cli.enable_server_certificate_verification(true);
    }
    else {
        cli.enable_server_certificate_verification(false);
    }

    cli.set_read_timeout(10);
    cli.set_write_timeout(10);
    cli.set_connection_timeout(10);

    httplib::Headers headers;
    headers.insert(std::make_pair("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
    headers.insert(std::make_pair("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"));
    headers.insert(std::make_pair("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36"));

    auto res = post ? 
        cli.Post(api.data(), headers, data, size, "application/x-www-form-urlencoded; charset=UTF-8") : 
        cli.Get(api.data(), headers);
    if (!res) {
        return "";
    }

    status = res->status;
    return res->body;
}