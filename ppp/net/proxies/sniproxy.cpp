#include <ppp/net/proxies/sniproxy.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

using ppp::net::Socket;
using ppp::threading::Timer;
using ppp::threading::Executors;

namespace ppp {
    namespace net {
        namespace proxies {
            sniproxy::sniproxy(int cdn, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                : cdn_(cdn)
                , configuration_(configuration)
                , context_(context)
                , local_socket_(socket)
                , remote_socket_(*context)
                , last_(Executors::GetTickCount()) {

                Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo);
                Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
            }

            sniproxy::~sniproxy() noexcept {
                close();
            }

            bool sniproxy::be_http(const void* p) noexcept {
                char* data = (char*)p;
                if (!data) {
                    return false;
                }
                return
                    strncasecmp(data, "GET ", 4) == 0 ||
                    strncasecmp(data, "HEAD ", 5) == 0 ||
                    strncasecmp(data, "POST ", 5) == 0 ||
                    strncasecmp(data, "PUT ", 4) == 0 ||
                    strncasecmp(data, "DELETE ", 7) == 0 ||
                    strncasecmp(data, "CONNECT ", 8) == 0 ||
                    strncasecmp(data, "TRACE ", 6) == 0 ||
                    strncasecmp(data, "PATCH ", 6) == 0;
            }

            bool sniproxy::be_host(ppp::string host, ppp::string domain) noexcept {
                if (host.empty() || domain.empty()) {
                    return false;
                }

                domain = ToLower(domain);
                host = ToLower(host);

                // Direct hit
                if (strcmp(domain.data(), host.data()) == 0) {
                    return true;
                }

                // Segment hit
                ppp::vector<ppp::string> lables;
                if (Tokenize<ppp::string>(domain, lables, ".") < 3) {
                    return false;
                }

                size_t lables_count = lables.size();
                for (size_t i = 0; i < lables_count; i++) {
                    const ppp::string& label = lables[i];
                    if (label.empty()) {
                        return false;
                    }
                }

                for (size_t i = 1, l = lables_count - 1; i < l; i++) {
                    ppp::string next;
                    for (size_t j = i; j < lables_count; j++) {
                        if (next.empty()) {
                            next += lables[j];
                        }
                        else {
                            next += "." + lables[j];
                        }
                    }

                    if (strcmp(next.data(), host.data()) == 0) {
                        return true;
                    }
                }
                return false;
            }

            bool sniproxy::do_tlsvd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept {
                struct tls_hdr* hdr = (struct tls_hdr*)local_socket_buf_;
                if (hdr->Content_Type != 0x16) { // Handshake
                    return false;
                }

                size_t tls_payload = ntohs(hdr->Length);
                if (!tls_payload) {
                    return false;
                }

                if (!ppp::coroutines::asio::async_read(*local_socket_, boost::asio::buffer(local_socket_buf_, tls_payload), y)) {
                    return false;
                }
                else {
                    messages_.Write(local_socket_buf_, 0, (int)tls_payload);
                }

                ppp::string hostname_ = fetch_sniaddr(tls_payload);
                return do_connect_and_forward_to_host(y, hostname_, configuration_->websocket.listen.wss, PPP_HTTPS_SYS_PORT, messages_);
            }

            bool sniproxy::do_httpd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept {
                if (!do_read_http_request_headers(y, messages_)) {
                    return false;
                }

                int port_;
                ppp::string hostname_;
                if (!do_httpd_handshake_host_trim(messages_, hostname_, port_)) {
                    return false;
                }

                return do_connect_and_forward_to_host(y, hostname_, do_forward_websocket_port(), port_, messages_);
            }

            bool sniproxy::do_httpd_handshake_host_trim(MemoryStream& messages_, ppp::string& host, int& port) noexcept {
                port = PPP_HTTP_SYS_PORT;
                host = do_httpd_handshake_host(messages_);
                if (host.empty()) {
                    return false;
                }

                host = RTrim(LTrim(host));
                if (host.empty()) {
                    return false;
                }

                std::size_t index = host.find(":");
                if (index == ppp::string::npos) {
                    return true;
                }

                ppp::string hoststr = host.substr(0, index);
                if (hoststr.empty()) {
                    return false;
                }

                ppp::string portstr = host.substr(index + 1);
                if (portstr.empty()) {
                    return false;
                }

                portstr = RTrim(LTrim(portstr));
                if (portstr.empty()) {
                    return false;
                }

                port = atoi(portstr.data());
                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    return false;
                }

                host = std::move(hoststr);
                return true;
            }

            ppp::string sniproxy::do_httpd_handshake_host(MemoryStream& messages_) noexcept {
                int headers_size = messages_.GetPosition();
                if (headers_size < 4) {
                    return "";
                }

                ppp::vector<ppp::string> headers;
                if (Tokenize<ppp::string>(ppp::string((char*)messages_.GetBuffer().get(), headers_size), headers, "\r\n") < 1) {
                    return "";
                }

                // GET / HTTP/1.1
                ppp::vector<ppp::string> protocols;
                if (Tokenize<ppp::string>(headers[0], protocols, " ") < 3) {
                    return "";
                }
                else {
                    ppp::string protocol = ToUpper(protocols[2]);
                    if (protocol != "HTTP/1.0" &&
                        protocol != "HTTP/1.1" &&
                        protocol != "HTTP/2.0") {
                        return "";
                    }

                    const ppp::string& url_or_path = protocols[1];
                    if (url_or_path.empty()) {
                        return "";
                    }

                    if (url_or_path[0] != '/') {
                        ppp::string url = ToLower(url_or_path);
                        do {
                            std::size_t leftIndex = url.find("://");
                            if (leftIndex == ppp::string::npos) {
                                break;
                            }

                            ppp::string schema = url.substr(0, leftIndex);
                            if (schema != "http") {
                                break;
                            }
                            else {
                                leftIndex += 3;
                            }

                            std::size_t nextIndex = url.find("/", leftIndex);
                            if (nextIndex == ppp::string::npos) {
                                return "";
                            }

                            std::size_t hostCount = nextIndex - leftIndex;
                            if (!hostCount) {
                                return "";
                            }

                            return protocols[1].substr(leftIndex, hostCount);
                        } while (false);
                    }
                }

                for (size_t i = 1, header_count = headers.size(); i < header_count; i++) {
                    const ppp::string& header = headers[i];
                    if (header.empty()) {
                        return "";
                    }

                    std::size_t leftIndex = header.find(": ");
                    if (!leftIndex || leftIndex == ppp::string::npos) {
                        return "";
                    }

                    std::size_t rightIndex = leftIndex + 2;
                    if (rightIndex > header.size()) {
                        return "";
                    }

                    ppp::string key = ToUpper(header.substr(0, leftIndex));
                    if (key == "HOST") {
                        return header.substr(rightIndex);
                    }
                }
                return "";
            }

            bool sniproxy::do_read_http_request_headers(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept {
                boost::system::error_code ec_;
                std::size_t length_;
                std::shared_ptr<boost::asio::streambuf> response_ = make_shared_object<boost::asio::streambuf>();
                if (NULL == response_) {
                    return false;
                }

                boost::asio::async_read_until(*local_socket_, *response_, "\r\n\r\n",
                    [&y, &ec_, &length_, response_](boost::system::error_code ec, std::size_t sz) noexcept {
                        ec_ = ec;
                        length_ = sz;
                        y.R();
                    });

                y.Suspend();
                if (ec_) {
                    return false;
                }

                if (!length_) {
                    return false;
                }

                boost::asio::const_buffers_1 buffers_ = response_->data();
                return messages_.Write(buffers_.data(), 0, (int)length_);
            }

            bool sniproxy::do_connect_and_forward_to_host(ppp::coroutines::YieldContext& y, const ppp::string hostname_, int self_websocket_port, int forward_connect_port, MemoryStream& messages_) noexcept {
                if (hostname_.empty() ||
                    forward_connect_port <= IPEndPoint::MinPort ||
                    forward_connect_port > IPEndPoint::MaxPort) {
                    return false;
                }

                boost::system::error_code ec_;
                boost::asio::ip::address address_;
                boost::asio::ip::tcp::endpoint remoteEP_;

                if (be_host(configuration_->websocket.host, hostname_)) {
                    if (self_websocket_port <= IPEndPoint::MinPort ||
                        self_websocket_port > IPEndPoint::MaxPort) {
                        return false;
                    }

                    address_ = boost::asio::ip::address_v6::loopback();
                    remoteEP_ = boost::asio::ip::tcp::endpoint(address_, self_websocket_port);
                }
                else {
                    address_ = StringToAddress(hostname_.data(), ec_);
                    if (ec_) {
                        address_ = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::tcp>(hostname_.data(), IPEndPoint::MinPort, y).address();
                    }

                    if (IPEndPoint::IsInvalid(address_) || address_.is_loopback()) {
                        return false;
                    }

                    if (configuration_->cdn[0] == forward_connect_port || configuration_->cdn[1] == forward_connect_port) {
                        boost::asio::ip::address interfaceIP_ = StringToAddress(configuration_->ip.interface_.data(), ec_);
                        boost::asio::ip::address publicIP_ = StringToAddress(configuration_->ip.public_.data(), ec_);
                        if (address_ == publicIP_ || address_ == interfaceIP_) {
                            return false;
                        }
                    }
                    
                    remoteEP_ = boost::asio::ip::tcp::endpoint(address_, forward_connect_port);
                }

                if (address_.is_v4()) {
                    remote_socket_.open(boost::asio::ip::tcp::v4(), ec_);
                }
                elif(address_.is_v6()) {
                    remote_socket_.open(boost::asio::ip::tcp::v6(), ec_);
                }
                else {
                    return false;
                }

                if (ec_) {
                    return false;
                }

                remote_socket_.set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec_);
                if (configuration_->tcp.fast_open) {
                    remote_socket_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec_);
                }

                int handle_ = remote_socket_.native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle_, remoteEP_.protocol() == boost::asio::ip::tcp::v4());
                ppp::net::Socket::SetTypeOfService(handle_);
                ppp::net::Socket::SetSignalPipeline(handle_, false);
                ppp::net::Socket::ReuseSocketAddress(handle_, true);
                Socket::SetWindowSizeIfNotZero(handle_, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                // [CONNECT]SSL VPN
                if (ppp::coroutines::asio::async_connect(remote_socket_, remoteEP_, y)) {
                    return false;
                }

                std::shared_ptr<Byte> buff_ = messages_.GetBuffer();
                if (!ppp::coroutines::asio::async_write(remote_socket_, boost::asio::buffer(buff_.get(), messages_.GetPosition()), y)) {
                    return false;
                }

                clear_timeout();
                return local_to_remote() && remote_to_local();
            }

            int sniproxy::do_forward_websocket_port() noexcept {
                return configuration_->websocket.listen.ws;
            }

            void sniproxy::clear_timeout() noexcept {
                std::shared_ptr<Timer> timeout = std::move(timeout_);
                timeout_.reset();

                if (timeout) {
                    timeout->Dispose();
                }
            }

            UInt16 sniproxy::fetch_uint16(Byte*& data) noexcept {
                int r_ = data[0] << 8 | data[1];
                data += 2;
                return r_;
            }

            int sniproxy::fetch_length(Byte*& data) noexcept {
                int r_ = data[0] << 16 | data[1] << 8 | data[2];
                data += 3;
                return r_;
            }

            ppp::string sniproxy::fetch_sniaddr(size_t tls_payload) noexcept {
                Byte* data = (Byte*)local_socket_buf_;
                if (*data++ != 0x01) { // Handshake Type: Client Hello (1)
                    return "";
                }

                int Length = std::max<int>(0, fetch_length(data));
                if ((Length + 4) != tls_payload) {
                    return "";
                }

                // Skip Version
                data += 2;

                // Skip Random
                data += 32;

                // Skip Session ID
                Byte Session_ID_Length = std::max<int>((Byte)0, *data++);
                data += Session_ID_Length;

                // Skip Cipher Suites
                int Cipher_Suites_Length = std::max<int>(0, fetch_uint16(data));
                data += Cipher_Suites_Length;

                // Skip Compression Methods Length
                int Compression_Methods_Length = *data++;
                data += Compression_Methods_Length;

                // Extensions Length
                int Extensions_Length = std::max<int>(0, fetch_uint16(data));
                Byte* Extensions_End = data + Extensions_Length;
                while (data < Extensions_End) {
                    int Extension_Type = fetch_uint16(data);
                    int Extension_Length = std::max<int>(0, fetch_uint16(data));
                    if (Extension_Type == 0x0000) { // RFC4366/6066(Server Name Indication extension)
                        int Server_Name_list_length = std::max<int>(0, fetch_uint16(data));
                        if ((data + Server_Name_list_length) >= Extensions_End) {
                            break;
                        }

                        int Server_Name_Type = *data++;
                        if (Server_Name_Type != 0x00) { // RFC6066 NameType::host_name(0)
                            data += 2;
                            continue;
                        }

                        int Server_Name_length = std::max<int>(0, fetch_uint16(data));
                        if ((data + Server_Name_length) > Extensions_End) {
                            break;
                        }
                        return ppp::string((char*)data, 0, Server_Name_length);
                    }
                    else {
                        data += Extension_Length;
                    }
                }
                return "";
            }

            bool sniproxy::do_handshake(ppp::coroutines::YieldContext& y) noexcept {
                const int header_size_ = sizeof(struct tls_hdr);
                if (!ppp::coroutines::asio::async_read(*local_socket_, boost::asio::buffer(local_socket_buf_, header_size_), y)) {
                    return false;
                }

                MemoryStream messages_;
                messages_.Write(local_socket_buf_, 0, header_size_);

                if (do_tlsvd_handshake(y, messages_)) {
                    return true;
                }

                if (!ppp::coroutines::asio::async_read(*local_socket_, boost::asio::buffer(local_socket_buf_ + header_size_, 3), y)) {
                    return false;
                }

                messages_.Write(local_socket_buf_, header_size_, 3);
                if (!be_http(local_socket_buf_)) {
                    return false;
                }

                return do_httpd_handshake(y, messages_);
            }

            bool sniproxy::socket_is_open() noexcept {
                if (!local_socket_ || !local_socket_->is_open()) {
                    return false;
                }
                else {
                    return remote_socket_.is_open();
                }
            }

            bool sniproxy::local_to_remote() noexcept {
                bool available_ = socket_is_open();
                if (!available_) {
                    return false;
                }

                std::shared_ptr<sniproxy> self = shared_from_this();
                local_socket_->async_read_some(boost::asio::buffer(local_socket_buf_, FORWARD_MSS),
                    [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        int by = std::max<int>(-1, ec ? -1 : sz);
                        if (by < 1) {
                            close();
                            return;
                        }

                        boost::asio::async_write(remote_socket_, boost::asio::buffer(local_socket_buf_, (size_t)by),
                            [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                                if (ec || !local_to_remote()) {
                                    close();
                                    return;
                                }

                                last_ = Executors::GetTickCount();
                            });
                        last_ = Executors::GetTickCount();
                    });
                return true;
            }

            bool sniproxy::remote_to_local() noexcept {
                bool available_ = socket_is_open();
                if (!available_) {
                    return false;
                }

                std::shared_ptr<sniproxy> self = shared_from_this();
                remote_socket_.async_read_some(boost::asio::buffer(remote_socket_buf_, FORWARD_MSS),
                    [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        int by = std::max<int>(-1, ec ? -1 : sz);
                        if (by < 1) {
                            close();
                            return;
                        }

                        boost::asio::async_write(*local_socket_.get(), boost::asio::buffer(remote_socket_buf_, by),
                            [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                                if (ec || !remote_to_local()) {
                                    close();
                                    return;
                                }

                                last_ = Executors::GetTickCount();
                            });
                        last_ = Executors::GetTickCount();
                    });
                return true;
            }

            void sniproxy::close() noexcept {
                boost::system::error_code ec_;
                std::shared_ptr<boost::asio::ip::tcp::socket> local_socket = local_socket_;

                Socket::Closesocket(remote_socket_);
                if (local_socket) {
                    Socket::Closesocket(*local_socket);
                }

                clear_timeout();
                last_ = Executors::GetTickCount();
            }

            bool sniproxy::handshake() noexcept {
                const std::shared_ptr<boost::asio::ip::tcp::socket> socket = local_socket_;
                if (!socket || !context_) {
                    return false;
                }

                const std::shared_ptr<sniproxy> self = shared_from_this();
                timeout_ = Timer::Timeout((uint64_t)configuration_->tcp.connect.timeout * 1000, 
                    [this, self](Timer*) noexcept {
                        close();
                    });
                if (!timeout_) {
                    return false;
                }
                
                auto context = context_;
                auto f = 
                    [self, this, context](ppp::coroutines::YieldContext& y) noexcept {
                        bool success_ = do_handshake(y);
                        if (!success_) {
                            close();
                        }
                        else {
                            clear_timeout();
                        }
                    };

                return ppp::coroutines::YieldContext::Spawn(*context, f);
            }
        }
    }
}