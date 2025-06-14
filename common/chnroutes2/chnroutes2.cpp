#include <stdio.h>
#include <time.h>

#include <ctime>
#include <string>
#include <iostream>
#include <exception>
#include <thread>

#include <set>
#include <vector>

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

#include <common/libtcpip/netstack.h>

#ifdef _WIN32
#include <io.h>
#include <Windows.h>
#include <timeapi.h>
#include <mmsystem.h>
#endif

#define APNIC_IP_FILE "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
#define APNIC_KEY "apnic"
#define APNIC_NATION "CN"
#define APNIC_IP "ipv4"

#ifdef _WIN32
#define PATH_IIP_NAME ".\\ip.txt"
#else
#define PATH_IIP_NAME "./ip.txt"
#endif
#define SELF_APP_NAME "chnroutes2"

#ifndef F_OK 
#define F_OK 0
#endif

#ifdef _WIN32
#pragma comment(lib, "WinMm.lib")
#endif

#include "chnroutes2.h"

#ifdef CURLINC_CURL
typedef
enum {
    CURL_EASY_ERROR_Success = 0,
    CURL_EASY_ERROR_FailedToCurlEasyInit,
    CURL_EASY_ERROR_NotAllowOpenUrlIsNullReferences,
    CURL_EASY_ERROR_FailedToCurlEasyPerform,
    CURL_EASY_ERROR_FailedToCurlEasyGetInfo,
    CURL_EASY_ERROR_NotAllowResponseBodyIsNullReferences,
    CURL_EASY_ERROR_NotAllowResponseHeadersIsNullReferences,
    CURL_EASY_ERROR_NotAllowResponseBodySizeIsNullReferences,
    CURL_EASY_ERROR_NotAllowResponseHeadersSizeIsNullReferences,
    CURL_EASY_ERROR_NotAllowStatusCodeIsNullReferences,
} CURL_EASY_ERROR;

typedef
struct {
    unsigned char*  stream_;
    unsigned long   length_;
} WebResponseStream;

static size_t
curl_write_data(char* buf, size_t size, size_t nmemb, void* lpVoid) noexcept {
    size_t dw = size * nmemb;
    if (dw > 0 && NULL != lpVoid) {
        WebResponseStream* stream_ = (WebResponseStream*)lpVoid;
        if (NULL == stream_->stream_) {
            stream_->stream_ = (unsigned char*)ppp::Malloc(dw + 1);
            stream_->length_ += (unsigned long)dw;
            memcpy(stream_->stream_, buf, dw);
        }
        else {
            unsigned long length = stream_->length_;
            unsigned char* buffer = (unsigned char*)ppp::Malloc(length + dw);
            memcpy(buffer, stream_->stream_, length);
            stream_->stream_ = buffer;
            stream_->length_ = (unsigned long)dw + length;
            memcpy(buffer + length, buf, dw);
        }
    }
    return dw;
}

static int curl_easy_request(
    const char*     open_url,
    long            connect_timeout,
    long            request_timeout,
    const char*     request_headers,
    const char*     request_body,
    int             request_body_size,
    unsigned char** response_body,
    unsigned long*  response_body_size,
    unsigned char** response_headers,
    unsigned long*  response_headers_size,
    long*           status_code,
    const char*     cacert_file_path,
    bool            support_verbose,
    bool            support_keep_alive,
    const char*     request_user_agent,
    const char*     auth_user_and_password) noexcept {
    if (NULL == open_url || *open_url == '\x0') {
        return CURL_EASY_ERROR_NotAllowOpenUrlIsNullReferences;
    }

    if (NULL == response_body) {
        return CURL_EASY_ERROR_NotAllowResponseBodyIsNullReferences;
    }

    if (NULL == response_headers) {
        return CURL_EASY_ERROR_NotAllowResponseHeadersIsNullReferences;
    }

    if (NULL == response_body_size) {
        return CURL_EASY_ERROR_NotAllowResponseBodySizeIsNullReferences;
    }

    if (NULL == response_headers_size) {
        return CURL_EASY_ERROR_NotAllowResponseHeadersSizeIsNullReferences;
    }

    if (NULL == status_code) {
        return CURL_EASY_ERROR_NotAllowStatusCodeIsNullReferences;
    }

    *response_body = NULL;
    *response_headers = NULL;
    *response_body_size = 0;
    *response_headers_size = 0;
    *status_code = 0;

    if (connect_timeout <= 0) {
        connect_timeout = 20L;
    }

    if (request_timeout <= 0) {
        request_timeout = 20L;
    }

    CURL* pCurl = curl_easy_init();
    if (NULL == pCurl) {
        return CURL_EASY_ERROR_FailedToCurlEasyInit;
    }

    curl_slist* pslist = curl_slist_append(NULL, request_headers);
    if (NULL != pslist) {
        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pslist);
    }

    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, request_timeout); // 请求超时时长
    curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, connect_timeout);  // 连接超时时长 
    curl_easy_setopt(pCurl, CURLOPT_FOLLOWLOCATION, 1L); // 允许重定向
    curl_easy_setopt(pCurl, CURLOPT_HEADER, 1L);  // 若启用，会将头文件的信息作为数据流输出
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, curl_write_data);  // 得到请求结果后的回调函数

    WebResponseStream response_body_stream;
    WebResponseStream response_headers_stream;
    memset(&response_body_stream, 0, sizeof(response_body_stream));
    memset(&response_headers_stream, 0, sizeof(response_headers_stream));

    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &response_body_stream);
    curl_easy_setopt(pCurl, CURLOPT_HEADERDATA, &response_headers_stream);
    curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L); // 关闭中断信号响应
    if (support_verbose) {
        curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 1L); // 启用时会汇报所有的信息
    }

    curl_easy_setopt(pCurl, CURLOPT_URL, open_url);
    curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1L);
    if (NULL != auth_user_and_password && *auth_user_and_password != '\x0') {
        curl_easy_setopt(pCurl, CURLOPT_USERPWD, auth_user_and_password);
    }

    if (NULL != request_user_agent && *request_user_agent != '\x0') {
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, request_user_agent);
    }

    if (NULL != request_body && request_body_size >= 0) {
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, request_body);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, request_body_size);
    }

    if (support_keep_alive) {
        curl_easy_setopt(pCurl, CURLOPT_TCP_KEEPALIVE, 1L);
    }

    curl_easy_setopt(pCurl, CURLOPT_MAXREDIRS, 50L);
#ifdef _WIN32
    curl_easy_setopt(pCurl, CURLOPT_SSLENGINE_DEFAULT);
#else
    curl_easy_setopt(pCurl, CURLOPT_SSLENGINE_DEFAULT, 1);
    curl_easy_setopt(pCurl, CURLOPT_SSLENGINE, "default");
#endif
    
    ppp::string cacert_file_path_;
    if (NULL == cacert_file_path || *cacert_file_path == '\x0') {
        cacert_file_path_ = chnroutes2_cacertpath_default();
        cacert_file_path  = cacert_file_path_.data();
    }

    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (access(cacert_file_path, F_OK) == 0) {
        curl_easy_setopt(pCurl, CURLOPT_CAINFO, cacert_file_path);
    }

    CURL_EASY_ERROR error = CURL_EASY_ERROR_Success;
    do {
        if (curl_easy_perform(pCurl) != CURLE_OK) {
            error = CURL_EASY_ERROR_FailedToCurlEasyPerform;
            break;
        }

        if (curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, status_code) != CURLE_OK) {
            error = CURL_EASY_ERROR_FailedToCurlEasyGetInfo;
            break;
        }

        *response_body = response_body_stream.stream_;
        *response_body_size = response_body_stream.length_;
        *response_headers = response_headers_stream.stream_;
        *response_headers_size = response_headers_stream.length_;

        if (NULL != *response_body && *response_body_size > 0) {
            (*response_body)[*response_body_size] = '\x0';
        }

        if (NULL != *response_headers && *response_headers_size > 0) {
            (*response_headers)[*response_headers_size] = '\x0';
        }
    } while (false);

    if (NULL != pslist) {
        curl_slist_free_all(pslist);
    }

    if (error != CURL_EASY_ERROR_Success) {
        if (NULL != response_body_stream.stream_) {
            ppp::Mfree(response_body_stream.stream_);
        }

        if (NULL != response_headers_stream.stream_) {
            ppp::Mfree(response_headers_stream.stream_);
        }
    }

    curl_easy_cleanup(pCurl);
    return error;
}
#else
static constexpr int HTTP_EASY_OPEN_TIMEOUT = 20000;
static constexpr int HTTP_EASY_READ_TIMEOUT = 20000;
static constexpr int HTTP_EASY_SENT_TIMEOUT = 20000;

static ppp::function<void()> http_easy_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int milliseconds) noexcept {
    if (milliseconds < 0) {
        milliseconds = 0;
    }

    auto t = ppp::make_shared_object<boost::asio::deadline_timer>(socket->get_executor());
    if (NULL == t) {
        return NULL;
    }
    
    t->expires_from_now(ppp::threading::Timer::DurationTime(milliseconds));
    t->async_wait(
        [t, socket](const boost::system::error_code& ec) noexcept {
            if (ec == boost::system::errc::success) {
                ppp::net::Socket::Closesocket(socket);
            }
        });

    return [t]() noexcept
        {
            boost::system::error_code ec;
            try {
                t->cancel(ec);
            }
            catch (const std::exception&) {}
        };
}

static std::shared_ptr<boost::asio::ip::tcp::socket> http_easy_connect(const ppp::string& host, int port, ppp::coroutines::YieldContext& y) noexcept {
    if (host.empty() || port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
        return NULL;
    }

    auto remoteEP = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::tcp>(host.data(), port, y);
    auto remoteIP = remoteEP.address();
    if (ppp::net::IPEndPoint::IsInvalid(remoteIP)) {
        return NULL;
    }

    if (remoteIP.is_unspecified()) {
        return NULL;
    }

    if (remoteIP.is_multicast()) {
        return NULL;
    }

    auto socket = ppp::make_shared_object<boost::asio::ip::tcp::socket>(y.GetContext());
    if (!socket) {
        return NULL;
    }

    auto timeout = http_easy_timeout(socket, HTTP_EASY_OPEN_TIMEOUT);
    if (!timeout) {
        return NULL;
    }

    if (!ppp::coroutines::asio::async_connect(*socket, remoteEP, y)) {
        return NULL;
    }

    timeout();
    return socket;
}

static bool http_easy_request(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const ppp::string& host, int port, const ppp::string& path, bool http_or_ssl_httpd, ppp::coroutines::YieldContext& y) noexcept {
    auto timeout = http_easy_timeout(socket, HTTP_EASY_SENT_TIMEOUT);
    ppp::string headers =
        "GET {HTTP_HEADER_PATH} HTTP/1.1\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: max-age=0\r\n"
        "Connection: close\r\n"
        "DNT: 1\r\n"
        "Host: {HTTP_HEADER_HOST}\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0\r\n\r\n";

    headers = ppp::Replace<ppp::string>(headers, "{HTTP_HEADER_PATH}", path);
    if (http_or_ssl_httpd ? port == 80 : port == 443) {
        headers = ppp::Replace<ppp::string>(headers, "{HTTP_HEADER_HOST}", host);
    }
    else {
        ppp::string header_host = host + ":" + stl::to_string<ppp::string>(port);
        headers = ppp::Replace<ppp::string>(headers, "{HTTP_HEADER_HOST}", header_host.data());
    }

    return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(headers.data(), headers.size()), y);
}

static bool htpp_easy_response(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, ppp::string& response_text, ppp::coroutines::YieldContext& y) noexcept {
    auto timeout = http_easy_timeout(socket, HTTP_EASY_READ_TIMEOUT);
    for (;;) {
        char buf[1400];
        int transferred_bytes = ppp::coroutines::asio::async_read_some(*socket, boost::asio::buffer(buf, sizeof(buf)), y);
        if (transferred_bytes < 1) {
            break;
        }

        response_text.append(buf, transferred_bytes);
    }

    if (response_text.empty()) {
        return false;
    }

    int next[4];
    int index = ppp::FindIndexOf(next, (char*)response_text.data(), response_text.size(), (char*)("\r\n\r\n"), 4); // KMP
    if (index < 0) {
        return false;
    }

    response_text = response_text.substr(index + 4);
    return true;
}

static bool http_easy_query(const ppp::string& url, ppp::string& host, int& port, ppp::string& path, bool& http_or_ssl_httpd) noexcept {
    http_or_ssl_httpd = true;
    if (url.size() < 7) {
        return false;
    }

    int hard = 7;
    int default_port = 80;
    char* p = (char*)url.data();
    int status = strncasecmp(p, "http://", hard);
    if (status != 0) {
        if (url.size() < 8) {
            return false;
        }

        status = strncasecmp(p, "https://", ++hard);
        if (status != 0) {
            return false;
        }
        else {
            default_port = 443;
            http_or_ssl_httpd = false;
        }
    }
    else {
        default_port = 80;
        http_or_ssl_httpd = true;
    }

    char* c = (char*)strchr(p + hard, '/');
    if (NULL != c) {
        char t = *c;
        *c = '\x0';
        host = p + hard;
        *c = t;
        path = c;
    }
    else {
        path = "/";
        host = p + hard;
    }

    std::size_t i = host.rfind(':');
    if (i == std::string::npos) {
        port = default_port;
    }
    else {
        char* d = (char*)host.data();
        p = d + i;
        *p = '\x0';
        port = atoi(p + 1);
        host = d;
        if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
            port = default_port;
        }
    }

    return true;
}

static bool http_easy_get(const ppp::string& url, ppp::coroutines::YieldContext& y, ppp::string& response_text) noexcept {
    ppp::string host;
    ppp::string path;
    int port = 0;
    bool http_or_ssl_httpd = false;
    if (!http_easy_query(url, host, port, path, http_or_ssl_httpd)) {
        return false;
    }

    if (!http_or_ssl_httpd) {
        return false;
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket = http_easy_connect(host, port, y);
    if (!socket) {
        return false;
    }

    if (!http_easy_request(socket, host, port, path, http_or_ssl_httpd, y)) {
        return false;
    }

    return htpp_easy_response(socket, response_text, y);
}
#endif

const char* chnroutes2_filepath_default() noexcept {
    return PATH_IIP_NAME;
}

#ifdef CURLINC_CURL
ppp::string chnroutes2_getiplist() noexcept {
    unsigned char* response_body;
    unsigned long response_body_size;
    unsigned char* response_headers;
    unsigned long reponse_headers_size;
    long status_code;
    int call_err = curl_easy_request(APNIC_IP_FILE, 0L, 0L,
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
        "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36\r\n",
        NULL,
        0L,
        &response_body,
        &response_body_size,
        &response_headers,
        &reponse_headers_size,
        &status_code,
        NULL,
        false,
        true,
        NULL,
        NULL);

    ppp::string iplist;
    if (call_err != CURL_EASY_ERROR_Success) {
        return std::move(iplist);
    }

    if (response_headers) {
        ppp::Mfree(response_headers);
    }

    iplist = std::move(ppp::string((char*)response_body, response_body_size));
    if (response_body) {
        ppp::Mfree(response_body);
    }

    return std::move(iplist);
}
#else
ppp::string chnroutes2_getiplist() noexcept { // Must run on the default thread.
    bool dynamic_allocated = false;
    std::shared_ptr<boost::asio::io_context> context = ppp::threading::Executors::GetExecutor();
    if ((NULL == context || context->stopped()) || (context == ppp::threading::Executors::GetDefault())) {
        context = lwip::netstack::Executor;
        if (NULL == context || context->stopped()) {
            dynamic_allocated = true;
            context = ppp::make_shared_object<boost::asio::io_context>();
        }
    }

    if (NULL == context) {
        return ppp::string();
    }

    auto awaitable = ppp::make_shared_object<ppp::threading::Executors::Awaitable>();
    if (NULL == awaitable) {
        return ppp::string();
    }

    ppp::string iplist;
    bool ok = ppp::coroutines::YieldContext::Spawn(*context, 
        [awaitable, &iplist](ppp::coroutines::YieldContext& y) noexcept {
            bool b = http_easy_get(APNIC_IP_FILE, y, iplist);
            if (!b) {
                iplist.clear();
            }

            awaitable->Processed();
        });

    if (dynamic_allocated) {
        std::thread(
            [context]() noexcept {
                ppp::SetThreadName("apnic");
                boost::asio::io_context::work work(*context);
                boost::system::error_code ec;
                context->restart();
                context->run(ec);
            }).detach();
    }

    ok = ok && awaitable->Await();
    if (dynamic_allocated) {
        context->stop();
    }

    return ok ? iplist : ppp::string();
}
#endif

int chnroutes2_getiplist(ppp::set<ppp::string>& out_, const ppp::string& nation_, const ppp::string& iplist_) noexcept {
    if (iplist_.empty()) {
        return 0;
    }

    ppp::vector<ppp::string> lines_;
    if (ppp::Tokenize<ppp::string>(iplist_, lines_, "\r\n") < 1) {
        return 0;
    }

    ppp::string nation = ppp::ToUpper(ppp::RTrim(ppp::LTrim(nation_)));
    if (nation.empty()) {
        nation = APNIC_NATION;
    }

    char fmt[260];
    char sz[1000];
    snprintf(fmt, sizeof(fmt), "%s|%s|%s|%%d.%%d.%%d.%%d|%%d|%%d|allocated", APNIC_KEY, nation.data(), APNIC_IP);

    int ip[4];
    int cidr;

    int length_ = 0;
    for (size_t i = 0, l = lines_.size(); i < l; i++) {
        ppp::string& line_ = lines_[i];
        if (line_.empty()) {
            continue;
        }
        else {
            size_t pos = line_.find_first_of('#');
            if (pos != ppp::string::npos) {
                line_ = line_.substr(0, pos);
            }

            line_ = ppp::LTrim(ppp::RTrim(line_));
            if (line_.empty()) {
                continue;
            }

            int st = sscanf_s(line_.data(), "%d.%d.%d.%d/%d", ip, ip + 1, ip + 2, ip + 3, &cidr);
            if (st == 5 && cidr >= 0 && cidr <= 32) {
                snprintf(sz, sizeof(sz), "%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], cidr);
                if (out_.emplace(sz).second) {
                    length_++;
                    continue;
                }
            }
        }

        int tm;
        int by = sscanf_s(line_.data(), fmt, ip, ip + 1, ip + 2, ip + 3, &cidr, &tm);
        if (by != 6) {
            continue;
        }

        int prefix = cidr ? 33 : 32;
        while (cidr) {
            cidr = cidr >> 1;
            prefix = prefix - 1;
        }

        snprintf(sz, sizeof(sz), "%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], prefix);
        if (out_.emplace(sz).second) {
            length_++;
        }
    }
    return length_;
}

int chnroutes2_getiplist(ppp::set<ppp::string>& out_, const ppp::string& nation_) noexcept {
    ppp::string iplist_ = chnroutes2_getiplist();
    return chnroutes2_getiplist(out_, nation_, iplist_);
}

ppp::string chnroutes2_toiplist(const ppp::set<ppp::string>& ips_) noexcept {
    bool next = false;
    ppp::string news;
    for (const ppp::string& ip : ips_) {
        if (ip.empty()) {
            continue;
        }

        if (next) {
            news.append("\r\n");
        }
        else {
            next = true;
        }

        news.append(ip);
    }
    return news;
}

bool chnroutes2_saveiplist(const ppp::string& path_, const ppp::set<ppp::string>& ips_) noexcept {
    if (path_.empty()) {
        return false;
    }

    FILE* file_ = fopen(path_.c_str(), "wb+");
    if (NULL == file_) {
        return false;
    }

    bool n_ = false;
    ppp::string data_ = chnroutes2_toiplist(ips_);

    fwrite(data_.data(), data_.size(), 1, file_);
    fflush(file_);
    fclose(file_);
    return true;
}

void chnroutes2_getiplist_async(const ppp::function<void(ppp::string&)>& cb) noexcept(false) {
    if (NULL == cb) {
        throw std::runtime_error("cb not allow is null.");
    }

    auto w = 
        [cb]() noexcept {
            ppp::SetThreadName("apnic");
            ppp::string iplist = chnroutes2_getiplist();
            cb(iplist);
        };

    std::thread t(w);
    t.detach();
}

ppp::string chnroutes2_gettime(time_t time_) noexcept {
    if (time_ == 0) {
        time_ = time(NULL);
    }

    struct tm tm_;
#ifdef _WIN32
    localtime_s(&tm_, &time_);
#else
    localtime_r(&time_, &tm_);
#endif

    char sz[1000];
    snprintf(sz, sizeof(sz), "%04d-%02d-%02d %02d:%02d:%02d", 1900 + tm_.tm_year, 1 + tm_.tm_mon, tm_.tm_mday, tm_.tm_hour, tm_.tm_min, tm_.tm_sec);
    return sz;
}

time_t chnroutes2_gettime() noexcept {
    time_t tm_;

#ifdef _WIN32
    timeBeginPeriod(1);
    tm_ = time(NULL);
    timeEndPeriod(1);
#else
    tm_ = time(NULL);
#endif
    return tm_;
}

void chnroutes2_sleep(int milliseconds) noexcept {
    ppp::Sleep(milliseconds);
}

ppp::string chnroutes2_cacertpath_default() noexcept {
    using File = ppp::io::File;

#ifdef _WIN32
    return File::GetFullPath(".\\cacert.pem");
#else
    return File::GetFullPath("./cacert.pem");
#endif
}

bool chnroutes2_equals(const ppp::set<ppp::string>& xs, const ppp::set<ppp::string>& ys) noexcept {
    std::size_t count = xs.size();
    if (count != ys.size()) {
        return false;
    }

    if (count == 0) {
        return true;
    }

    for (const ppp::string& key : xs) {
        auto tail = ys.find(key);
        auto endl = ys.end();
        if (tail == endl) {
            return false;
        }
    }

    return true;
}