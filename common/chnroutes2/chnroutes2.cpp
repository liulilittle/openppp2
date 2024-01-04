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

#ifdef _WIN32
#include <io.h>
#include <Windows.h>
#include <timeapi.h>
#include <mmsystem.h>
#endif

#ifdef _CURLINC_CURL
#include <curl/curl.h>
#include <curl/easy.h>
#else
#include "HttpClient.h"
#endif

#ifdef _CURLINC_CURL
#define APNIC_IP_FILE "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
#else
#define APNIC_IP_FILE_HOST "http://ftp.apnic.net"
#define APNIC_IP_FILE_PATH "/apnic/stats/apnic/delegated-apnic-latest"
#endif

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

#ifdef _CURLINC_CURL
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
curl_write_data(char* buf, size_t size, size_t nmemb, void* lpVoid) {
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
    const char*     auth_user_and_password) {
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

    if (NULL == cacert_file_path || *cacert_file_path == '\x0') {
#ifdef _WIN32
        cacert_file_path = ".\\cacert.pem";
#else
        cacert_file_path = "./cacert.pem";
#endif
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
static int httplib_easy_request(bool post, const char* host, const char* path, const char* cacert_path, const char* data, size_t size, std::string& response_text) noexcept {
    if (!host) {
        return -1;
    }

    if (!data && size) {
        return -1;
    }

    size_t host_size = strlen(host);
    if (host_size < 7) {
        return -1;
    }

    if (strncasecmp(host, "http://", 7) != 0) {
        if (host_size < 8) {
            return -1;
        }

        if (strncasecmp(host, "https://", 8) != 0) {
            return -1;
        }
    }

    if (!path || (int)strlen(path) < 1) {
        path = "/";
    }

    if (*path != '/') {
        return -1;
    }

    int status = 0;
    if (!cacert_path) {
        cacert_path = "cacert.pem";
    }
    
    HttpClient http = HttpClient(host, cacert_path);
    if (post) {
        response_text = http.Post(path, data, size, status);
    }
    else {
        response_text = http.Get(path, status);
    }

    return status;
}
#endif

const char* chnroutes2_filepath_default() {
    return PATH_IIP_NAME;
}

#ifdef _CURLINC_CURL
std::string chnroutes2_getiplist() {
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

    std::string iplist;
    if (call_err != CURL_EASY_ERROR_Success) {
        return std::move(iplist);
    }

    if (response_headers) {
        ppp::Mfree(response_headers);
    }

    iplist = std::move(std::string((char*)response_body, response_body_size));
    if (response_body) {
        ppp::Mfree(response_body);
    }
    return std::move(iplist);
}
#else
std::string chnroutes2_getiplist() {
    std::string iplist;
    int status_code = httplib_easy_request(false, APNIC_IP_FILE_HOST, APNIC_IP_FILE_PATH, NULL, NULL, 0, iplist);
    if (status_code >= 200 && status_code < 300) {
        return std::move(iplist);
    }
    else {
        return std::string();
    }
}
#endif

int chnroutes2_getiplist(std::set<std::string>& out_, const std::string& iplist_) {
    if (iplist_.empty()) {
        return 0;
    }

    ppp::vector<std::string> lines_;
    ppp::Tokenize<std::string>(iplist_, lines_, "\r\n");

    char fmt[260];
    snprintf(fmt, sizeof(fmt), "%s|%s|%s|%%d.%%d.%%d.%%d|%%d|%%d|allocated", APNIC_KEY, APNIC_NATION, APNIC_IP);

    int length_ = 0;
    for (size_t i = 0, l = lines_.size(); i < l; i++) {
        std::string& line_ = lines_[i];
        if (line_.empty()) {
            continue;
        }

        size_t pos = line_.find_first_of('#');
        if (pos == 0 || pos == std::string::npos) {
            continue;
        }


        int ip[4];
        int cidr;
        int tm;

#ifdef _WIN32
        int by = sscanf_s(line_.data(), fmt, ip, ip + 1, ip + 2, ip + 3, &cidr, &tm);
#else
        int by = sscanf(line_.data(), fmt, ip, ip + 1, ip + 2, ip + 3, &cidr, &tm);
#endif
        if (by != 6) {
            continue;
        }

        int prefix = cidr ? 33 : 32;
        while (cidr) {
            cidr = cidr >> 1;
            prefix = prefix - 1;
        }

        char sz[1000];
        snprintf(sz, sizeof(sz), "%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], prefix);
        if (out_.insert(sz).second) {
            length_++;
        }
    }
    return length_;
}

int chnroutes2_getiplist(std::set<std::string>& out_) {
    std::string iplist_ = chnroutes2_getiplist();
    return chnroutes2_getiplist(out_, iplist_);
}

bool chnroutes2_saveiplist(const std::string& path_, const std::set<std::string>& ips_) {
    if (path_.empty()) {
        return false;
    }

    FILE* file_ = fopen(path_.c_str(), "wb+");
    if (NULL == file_) {
        return false;
    }

    std::string data_;
    std::set<std::string>::iterator tail_ = ips_.begin();
    std::set<std::string>::iterator endl_ = ips_.end();
    while (tail_ != endl_) {
        const std::string& line_ = *tail_++;
        data_.append(line_);
        data_.append("\r\n");
    }

    fwrite(data_.data(), data_.size(), 1, file_);
    fflush(file_);
    fclose(file_);
    return true;
}

void chnroutes2_getiplist_async(const ppp::function<void(std::string&)>& cb) {
    if (NULL == cb) {
        throw std::runtime_error("cb not allow is null.");
    }

    std::thread(
        [cb]() {
            std::string iplist = chnroutes2_getiplist();
            cb(iplist);
        }).detach();
}

std::string chnroutes2_gettime(time_t time_) {
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

time_t chnroutes2_gettime() {
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

void chnroutes2_sleep(int milliseconds) {
    if (milliseconds > 0) {
#ifdef _WIN32
        timeBeginPeriod(1);
        Sleep(milliseconds);
        timeEndPeriod(1);
#else
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
#endif
    }
}