#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <ppp/net/http/httplib.h>

#include <ppp/net/http/HttpClient.h>
#include <ppp/io/File.h>
#include <ppp/auxiliary/UriAuxiliary.h>

namespace ppp {
    namespace net {
        namespace http {
            HttpClient::HttpClient(const ppp::string& host, const ppp::string& cacert_path) noexcept
                : _host(host)
                , _cacert_exist(false)
                , _cacert_path(cacert_path) {

                if (!cacert_path.empty()) {
                    this->_cacert_exist = ppp::io::File::Exists(cacert_path.data()); /* ::access(cacert_path.data(), F_OK) == 0 */;
                }
            }

            std::string HttpClient::HttpGetOrPostImpl(bool post, const ppp::string& api, const char* data, size_t size, int& status) noexcept {
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

                cli.set_read_timeout(20);
                cli.set_write_timeout(20);
                cli.set_connection_timeout(5);

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

            bool HttpClient::VerifyUri(const ppp::string& url, ppp::string* host, int* port, ppp::string* path, bool* https) noexcept {
                using UriAuxiliary = ppp::auxiliary::UriAuxiliary;
                using ProtocolType = UriAuxiliary::ProtocolType;

                if (url.empty()) {
                    return false;
                }

                ppp::string final_url = LTrim(RTrim(url));
                if (final_url.empty()) {
                    return false;
                }

                ppp::string tmp_address;
                ppp::string tmp_host;
                ppp::string tmp_path;
                int tmp_port;
                ProtocolType protocol_type;

                ppp::string return_url = ppp::auxiliary::UriAuxiliary::Parse(final_url, tmp_host, tmp_address, tmp_path, tmp_port, protocol_type, NULL, nullof<ppp::coroutines::YieldContext>(), false);
                if (return_url.empty()) {
                    return false;
                }

                if (protocol_type != ProtocolType::ProtocolType_Http && protocol_type != ProtocolType::ProtocolType_HttpSSL) {
                    return false;
                }

                if (NULL != host) {
                    *host = tmp_host;
                }

                if (NULL != path) {
                    *path = tmp_path;
                }

                if (NULL != port) {
                    *port = tmp_port;
                }

                if (NULL != https) {
                    *https = protocol_type != ProtocolType::ProtocolType_Http;
                }

                return true;
            }
        }
    }
}