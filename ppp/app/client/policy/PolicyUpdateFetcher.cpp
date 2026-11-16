#include "PolicyUpdateFetcher.h"

#include "DurablePolicyBundle.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__APPLE__)
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#elif defined(__linux__)
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace ppp::app::client::policy {
namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using Tcp = asio::ip::tcp;
using Udp = asio::ip::udp;
using TlsStream = beast::ssl_stream<Tcp::socket&>;
constexpr std::size_t kHeaderLimit = 64u * 1024u;
constexpr int kRedirectLimit = 5;

template<class Timer>
void CancelTimer(Timer& timer) noexcept {
    try {
        timer.cancel();
    } catch (...) {
    }
}

struct ParsedUrl final {
    std::string scheme;
    std::string host;
    std::string authority;
    std::string target;
    std::uint16_t port = 0;
    bool secure = false;
};

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool ParseUrl(const std::string& input, bool allow_http, ParsedUrl& output, std::string& error) {
    if (input.empty() || input.find_first_of("\r\n") != std::string::npos || input.find('\0') != std::string::npos ||
        input.find('#') != std::string::npos) { error = "URL is malformed"; return false; }
    const auto sep = input.find("://");
    if (sep == std::string::npos) { error = "URL must use HTTPS"; return false; }
    output.scheme = Lower(input.substr(0, sep));
    output.secure = output.scheme == "https";
    if (!output.secure && !(allow_http && output.scheme == "http")) { error = "URL scheme is not permitted"; return false; }
    const auto authority_start = sep + 3;
    const auto authority_end = input.find_first_of("/?", authority_start);
    output.authority = input.substr(authority_start,
        (authority_end == std::string::npos ? input.size() : authority_end) - authority_start);
    if (output.authority.empty() || output.authority.find('@') != std::string::npos) {
        error = "URL authority is empty or contains credentials"; return false;
    }
    std::string port_text;
    if (output.authority.front() == '[') {
        const auto close = output.authority.find(']');
        if (close == std::string::npos) { error = "invalid IPv6 URL host"; return false; }
        output.host = output.authority.substr(1, close - 1);
        if (close + 1 < output.authority.size()) {
            if (output.authority[close + 1] != ':') { error = "invalid URL authority"; return false; }
            port_text = output.authority.substr(close + 2);
        }
    } else {
        const auto colon = output.authority.rfind(':');
        if (colon != std::string::npos) {
            if (output.authority.find(':') != colon) { error = "IPv6 URL host must be bracketed"; return false; }
            output.host = output.authority.substr(0, colon);
            port_text = output.authority.substr(colon + 1);
        } else output.host = output.authority;
    }
    if (output.host.empty() || output.host.size() > 253 ||
        std::any_of(output.host.begin(), output.host.end(), [](unsigned char ch) {
            return ch <= 32 || ch >= 127 || ch == '/' || ch == '\\';
        })) { error = "URL host is invalid"; return false; }
    output.host = Lower(output.host);
    if (port_text.empty()) output.port = output.secure ? 443 : 80;
    else {
        unsigned port = 0;
        for (unsigned char ch : port_text) {
            if (ch < '0' || ch > '9' || port > 6553) { error = "URL port is invalid"; return false; }
            port = port * 10 + static_cast<unsigned>(ch - '0');
        }
        if (port == 0 || port > 65535) { error = "URL port is invalid"; return false; }
        output.port = static_cast<std::uint16_t>(port);
    }
    output.target = authority_end == std::string::npos ? "/" : input.substr(authority_end);
    if (output.target.empty() || output.target.front() == '?') output.target.insert(output.target.begin(), '/');
    if (output.target.find_first_of("\r\n \t") != std::string::npos) { error = "URL path is invalid"; return false; }
    return true;
}

struct AsyncResult final {
    bool completed = false;
    boost::system::error_code error;
};

template<class Socket, class Start>
bool RunAsync(asio::io_context& io, Socket& socket, std::chrono::steady_clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled, Start&& start, std::string& error) {
    io.restart();
    auto result = std::make_shared<AsyncResult>();
    auto deadline_timer = std::make_shared<asio::steady_timer>(io);
    auto cancel_timer = std::make_shared<asio::steady_timer>(io);
    deadline_timer->expires_at(deadline);
    deadline_timer->async_wait([result, deadline_timer, cancel_timer, &socket](const boost::system::error_code& ec) {
        if (!ec && !result->completed) {
            result->error = asio::error::timed_out;
            result->completed = true;
            boost::system::error_code ignored;
            socket.cancel(ignored);
            socket.close(ignored);
            CancelTimer(*cancel_timer);
        }
    });
    auto poll = std::make_shared<std::function<void()>>();
    *poll = [result, deadline_timer, cancel_timer, &socket, cancelled, poll, io_ptr = &io]() {
        if (result->completed) return;
        if (cancelled && cancelled->load(std::memory_order_acquire)) {
            result->error = asio::error::operation_aborted;
            result->completed = true;
            boost::system::error_code ignored;
            socket.cancel(ignored); socket.close(ignored);
            CancelTimer(*deadline_timer); CancelTimer(*cancel_timer);
            return;
        }
        cancel_timer->expires_after(std::chrono::milliseconds(20));
        cancel_timer->async_wait([poll](const boost::system::error_code& ec) { if (!ec) (*poll)(); });
        (void)io_ptr;
    };
    (*poll)();
    start([result, deadline_timer, cancel_timer](const boost::system::error_code& ec, std::size_t = 0) {
        if (!result->completed) { result->error = ec; result->completed = true; }
        boost::system::error_code ignored;
        CancelTimer(*deadline_timer); CancelTimer(*cancel_timer);
    });
    io.run();
    *poll = {};
    if (!result->completed || result->error) {
        error = result->error == asio::error::timed_out ? "network operation timed out" :
            result->error == asio::error::operation_aborted ? "network operation cancelled" : "network operation failed";
        return false;
    }
    return true;
}

bool WaitReady(Tcp::socket& socket, Tcp::socket::wait_type wait, std::chrono::steady_clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled) {
    while (std::chrono::steady_clock::now() < deadline && !(cancelled && cancelled->load(std::memory_order_acquire))) {
        boost::system::error_code ec;
        socket.wait(wait, ec);
        if (!ec) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return false;
}

bool SetBoundInterface(Tcp::socket& socket, const DirectPolicySocketOptions& options, std::string& error) {
    if (options.unbound) return true;
    const auto handle = socket.native_handle();
#if defined(_ANDROID)
    if (!options.protect_socket || !options.protect_socket(
            static_cast<Tcp::socket::native_handle_type>(handle))) {
        error = "platform rejected policy socket protection"; return false;
    }
    return true;
#elif defined(__linux__)
    if (options.interface_name.empty()) { error = "direct policy fetch requires an explicit network interface"; return false; }
    if (::setsockopt(handle, SOL_SOCKET, SO_BINDTODEVICE, options.interface_name.c_str(),
            static_cast<socklen_t>(options.interface_name.size() + 1)) != 0) {
        error = "cannot bind policy socket to configured interface"; return false;
    }
#elif defined(_WIN32)
    if (options.interface_index == 0) { error = "direct policy fetch requires an explicit interface index"; return false; }
    const ULONG index = htonl(options.interface_index);
    if (::setsockopt(handle, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char*>(&index), sizeof(index)) != 0) {
        error = "cannot bind policy socket to configured interface"; return false;
    }
#elif defined(__APPLE__)
    if (options.interface_index == 0) { error = "direct policy fetch requires an explicit interface index"; return false; }
    const unsigned index = options.interface_index;
    if (::setsockopt(handle, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) != 0) {
        error = "cannot bind policy socket to configured interface"; return false;
    }
#else
    error = "direct policy socket binding is unsupported on this platform"; return false;
#endif
    if (options.protect_socket && !options.protect_socket(
            static_cast<Tcp::socket::native_handle_type>(handle))) {
        error = "platform rejected policy socket protection"; return false;
    }
    return true;
}

bool SetBoundInterface(Udp::socket& socket, const DirectPolicySocketOptions& options, std::string& error) {
    if (options.unbound) return true;
    const auto handle = socket.native_handle();
#if defined(_ANDROID)
    if (!options.protect_socket || !options.protect_socket(
            static_cast<Tcp::socket::native_handle_type>(handle))) {
        error = "platform rejected bootstrap DNS socket protection"; return false;
    }
    return true;
#elif defined(__linux__)
    if (options.interface_name.empty()) { error = "direct policy fetch requires an explicit network interface"; return false; }
    if (::setsockopt(handle, SOL_SOCKET, SO_BINDTODEVICE, options.interface_name.c_str(),
            static_cast<socklen_t>(options.interface_name.size() + 1)) != 0) {
        error = "cannot bind bootstrap DNS socket to configured interface"; return false;
    }
#elif defined(_WIN32)
    if (options.interface_index == 0) { error = "direct policy fetch requires an explicit interface index"; return false; }
    const ULONG index = htonl(options.interface_index);
    if (::setsockopt(handle, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char*>(&index), sizeof(index)) != 0) {
        error = "cannot bind bootstrap DNS socket to configured interface"; return false;
    }
#elif defined(__APPLE__)
    if (options.interface_index == 0) { error = "direct policy fetch requires an explicit interface index"; return false; }
    const unsigned index = options.interface_index;
    if (::setsockopt(handle, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) != 0) {
        error = "cannot bind bootstrap DNS socket to configured interface"; return false;
    }
#else
    error = "direct policy socket binding is unsupported on this platform"; return false;
#endif
    if (options.protect_socket && !options.protect_socket(
            static_cast<Tcp::socket::native_handle_type>(handle))) {
        error = "platform rejected bootstrap DNS socket protection"; return false;
    }
    return true;
}

bool EncodeDnsName(const std::string& host, std::vector<unsigned char>& packet) {
    if (host.empty() || host.size() > 253) return false;
    std::size_t begin = 0;
    while (begin < host.size()) {
        const auto end = host.find('.', begin);
        const auto count = (end == std::string::npos ? host.size() : end) - begin;
        if (count == 0 || count > 63) return false;
        packet.push_back(static_cast<unsigned char>(count));
        for (std::size_t i = 0; i < count; ++i) {
            const unsigned char ch = static_cast<unsigned char>(host[begin + i]);
            if (!(std::isalnum(ch) || ch == '-')) return false;
            packet.push_back(static_cast<unsigned char>(std::tolower(ch)));
        }
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    packet.push_back(0);
    return true;
}

bool ResolveDirect(const DirectPolicySocketOptions& options, const std::string& host,
    std::chrono::steady_clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    std::vector<asio::ip::address>& addresses, std::string& error) {
    boost::system::error_code ec;
    const auto literal = asio::ip::make_address(host, ec);
    if (!ec) { addresses.push_back(literal); return true; }
    if (options.bootstrap_nameservers.empty()) { error = "direct policy fetch requires configured bootstrap DNS servers"; return false; }
    static std::atomic_uint16_t query_id{0x4201};
    const std::string query_host = !host.empty() && host.back() == '.' ? host.substr(0, host.size() - 1) : host;
    for (const auto& server : options.bootstrap_nameservers) {
        const auto& nameserver = server.address();
        if (server.port() == 0 || nameserver.is_unspecified() || nameserver.is_multicast()) continue;
        for (std::uint16_t qtype : {std::uint16_t(1), std::uint16_t(28)}) {
            std::vector<unsigned char> query(12, 0);
            const std::uint16_t id = query_id.fetch_add(1, std::memory_order_relaxed);
            query[0] = static_cast<unsigned char>(id >> 8); query[1] = static_cast<unsigned char>(id);
            query[2] = 1; query[5] = 1;
            if (!EncodeDnsName(query_host, query)) { error = "direct policy source hostname is invalid"; return false; }
            query.push_back(static_cast<unsigned char>(qtype >> 8)); query.push_back(static_cast<unsigned char>(qtype));
            query.push_back(0); query.push_back(1);
            auto context = std::make_unique<asio::io_context>();
            Udp::socket socket(*context);
            const auto protocol = nameserver.is_v4() ? Udp::v4() : Udp::v6();
            socket.open(protocol, ec);
            if (ec || !SetBoundInterface(socket, options, error)) continue;
            if (!options.local_address.is_unspecified() && options.local_address.is_v4() == nameserver.is_v4()) {
                socket.bind(Udp::endpoint(options.local_address, 0), ec);
                if (ec) continue;
            }
            socket.non_blocking(true, ec);
            socket.send_to(asio::buffer(query), server, 0, ec);
            if (ec) continue;
            std::array<unsigned char, 4096> bytes{};
            Udp::endpoint sender;
            std::size_t got = 0;
            while (std::chrono::steady_clock::now() < deadline && !(cancelled && cancelled->load(std::memory_order_acquire))) {
                got = socket.receive_from(asio::buffer(bytes), sender, 0, ec);
                if (!ec) break;
                if (ec != asio::error::would_block && ec != asio::error::try_again) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            if (ec || sender != server || got < 12 || bytes[0] != query[0] || bytes[1] != query[1] ||
                (bytes[2] & 0x80) == 0 || (bytes[3] & 0x0f) != 0) continue;
            const unsigned answers = (static_cast<unsigned>(bytes[6]) << 8) | bytes[7];
            std::size_t offset = 12;
            bool valid_name = false;
            while (offset < got) {
                const unsigned char length = bytes[offset++];
                if (length == 0) { valid_name = true; break; }
                if ((length & 0xc0) == 0xc0) { if (offset >= got) offset = got; else { ++offset; valid_name = true; } break; }
                if (length > 63 || length > got - offset) { offset = got; break; }
                offset += length;
            }
            if (!valid_name || offset + 4 > got) continue;
            offset += 4;
            for (unsigned i = 0; i < answers && offset + 10 <= got; ++i) {
                if ((bytes[offset] & 0xc0) == 0xc0) offset += 2;
                else {
                    while (offset < got && bytes[offset]) {
                        const unsigned char length = bytes[offset++];
                        if ((length & 0xc0) == 0xc0) { ++offset; break; }
                        if (length > 63 || length > got - offset) { offset = got; break; }
                        offset += length;
                    }
                    if (offset < got && bytes[offset] == 0) ++offset;
                }
                if (offset + 10 > got) break;
                const auto type = (static_cast<unsigned>(bytes[offset]) << 8) | bytes[offset + 1];
                const auto klass = (static_cast<unsigned>(bytes[offset + 2]) << 8) | bytes[offset + 3];
                const auto length = (static_cast<unsigned>(bytes[offset + 8]) << 8) | bytes[offset + 9];
                offset += 10;
                if (length > got - offset) break;
                if (klass == 1 && type == 1 && length == 4) {
                    asio::ip::address_v4::bytes_type raw{bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]};
                    addresses.emplace_back(asio::ip::address_v4(raw));
                } else if (klass == 1 && type == 28 && length == 16) {
                    asio::ip::address_v6::bytes_type raw{};
                    std::copy(bytes.begin() + offset, bytes.begin() + offset + 16, raw.begin());
                    addresses.emplace_back(asio::ip::address_v6(raw));
                }
                offset += length;
            }
            if (!addresses.empty()) return true;
        }
    }
    error = "configured bootstrap DNS servers could not resolve the policy source";
    return false;
}

bool SocksExact(Tcp::socket& socket, void* data, std::size_t size,
    std::chrono::steady_clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    bool write, std::string& error) {
    socket.non_blocking(true);
    std::size_t offset = 0;
    while (offset < size && std::chrono::steady_clock::now() < deadline && !(cancelled && cancelled->load(std::memory_order_acquire))) {
        boost::system::error_code ec;
        const auto count = write ? socket.write_some(asio::buffer(static_cast<const char*>(data) + offset, size - offset), ec)
            : socket.read_some(asio::buffer(static_cast<char*>(data) + offset, size - offset), ec);
        if (!ec) { offset += count; continue; }
        if (ec != asio::error::would_block && ec != asio::error::try_again) break;
        if (!WaitReady(socket, write ? Tcp::socket::wait_write : Tcp::socket::wait_read, deadline, cancelled)) break;
    }
    if (offset != size) { error = cancelled && cancelled->load() ? "SOCKS5 connect cancelled" : "SOCKS5 negotiation timed out or failed"; return false; }
    return true;
}

bool ResolveRedirect(const ParsedUrl& from, const std::string& location, std::string& result) {
    if (location.empty() || location.find_first_of("\r\n") != std::string::npos || location.find('\0') != std::string::npos) return false;
    if (location.find("://") != std::string::npos) { result = location; return true; }
    const std::string origin = from.scheme + "://" + from.authority;
    if (location.rfind("//", 0) == 0) { result = from.scheme + ":" + location; return true; }
    if (location.front() == '/') { result = origin + location; return true; }
    const auto path = from.target.substr(0, from.target.find('?'));
    const auto slash = path.rfind('/');
    result = origin + (slash == std::string::npos ? "/" : path.substr(0, slash + 1)) + location;
    return true;
}

template<class Stream>
bool HttpExchange(Stream& stream, Tcp::socket& socket, const PolicyFetchRequest& request,
    const ParsedUrl& url, const std::string& etag, const std::string& modified,
    PolicyFetchResponse& response, std::string& error) {
    asio::io_context& io = static_cast<asio::io_context&>(socket.get_executor().context());
    io.restart();
    http::request<http::empty_body> message{http::verb::get, url.target, 11};
    message.set(http::field::host, url.authority);
    message.set(http::field::user_agent, "openppp2-policy-updater/1");
    message.set(http::field::accept, "*/*");
    message.set(http::field::accept_encoding, "identity");
    message.set(http::field::connection, "close");
    auto safe_header = [](const std::string& value) { return value.find_first_of("\r\n") == std::string::npos && value.find('\0') == std::string::npos; };
    if ((!etag.empty() && !safe_header(etag)) || (!modified.empty() && !safe_header(modified))) {
        error = "cached conditional header contains invalid characters"; return false;
    }
    if (!etag.empty()) message.set(http::field::if_none_match, etag);
    if (!modified.empty()) message.set(http::field::if_modified_since, modified);
    auto parser = std::make_shared<http::response_parser<http::string_body>>();
    parser->header_limit(kHeaderLimit);
    parser->body_limit(request.max_bytes);
    auto buffer = std::make_shared<beast::flat_buffer>();
    auto result = std::make_shared<AsyncResult>();
    auto deadline_timer = std::make_shared<asio::steady_timer>(io);
    auto cancel_timer = std::make_shared<asio::steady_timer>(io);
    deadline_timer->expires_at(request.deadline);
    deadline_timer->async_wait([result, deadline_timer, cancel_timer, &socket](const boost::system::error_code& ec) {
        if (!ec && !result->completed) {
            result->error = asio::error::timed_out; result->completed = true;
            boost::system::error_code ignored; socket.cancel(ignored); socket.close(ignored); CancelTimer(*cancel_timer);
        }
    });
    auto poll = std::make_shared<std::function<void()>>();
    *poll = [result, deadline_timer, cancel_timer, &socket, cancelled = request.cancelled, poll]() {
        if (result->completed) return;
        if (cancelled && cancelled->load(std::memory_order_acquire)) {
            result->error = asio::error::operation_aborted; result->completed = true;
            boost::system::error_code ignored; socket.cancel(ignored); socket.close(ignored);
            CancelTimer(*deadline_timer); CancelTimer(*cancel_timer); return;
        }
        cancel_timer->expires_after(std::chrono::milliseconds(20));
        cancel_timer->async_wait([poll](const boost::system::error_code& ec) { if (!ec) (*poll)(); });
    };
    (*poll)();
    http::async_write(stream, message, [&, parser, buffer, result, deadline_timer, cancel_timer](const boost::system::error_code& ec, std::size_t) {
        if (ec) { result->error = ec; result->completed = true; }
        else http::async_read_header(stream, *buffer, *parser,
            [&, parser, buffer, result, deadline_timer, cancel_timer](const boost::system::error_code& header_ec, std::size_t) {
                if (header_ec) { result->error = header_ec; result->completed = true; }
                else {
                    const auto status = parser->get().result_int();
                    if (status == 304 || (status >= 300 && status < 400)) { result->completed = true; }
                    else http::async_read(stream, *buffer, *parser,
                        [parser, result](const boost::system::error_code& body_ec, std::size_t) {
                            if (body_ec) result->error = body_ec;
                            result->completed = true;
                        });
                }
                if (result->completed) {
                    CancelTimer(*deadline_timer); CancelTimer(*cancel_timer);
                }
            });
        if (result->completed) { CancelTimer(*deadline_timer); CancelTimer(*cancel_timer); }
    });
    io.run();
    *poll = {};
    if (!result->completed || result->error) {
        error = result->error == http::error::body_limit ? "HTTP body exceeds configured size limit" :
            result->error == http::error::header_limit ? "HTTP headers exceed 64 KiB limit" :
            result->error == asio::error::timed_out ? "HTTP request exceeded 30 second deadline" :
            result->error == asio::error::operation_aborted ? "HTTP request cancelled" : "HTTP exchange failed";
        return false;
    }
    const auto& parsed = parser->get();
    response.status = parsed.result_int();
    if (parsed.base().count(http::field::etag)) { const auto value = parsed[http::field::etag]; response.etag.assign(value.data(), value.size()); }
    if (parsed.base().count(http::field::last_modified)) { const auto value = parsed[http::field::last_modified]; response.last_modified.assign(value.data(), value.size()); }
    if (parsed.base().count(http::field::location)) { const auto value = parsed[http::field::location]; response.redirect_location.assign(value.data(), value.size()); }
    if (parsed.base().count(http::field::content_encoding)) {
        const auto value = parsed[http::field::content_encoding];
        if (Lower(std::string(value.data(), value.size())) != "identity") {
        error = "compressed HTTP content is not supported"; return false;
        }
    }
    if (response.status >= 200 && response.status < 300) response.body = parsed.body();
    else if (response.status != 304 && (response.status < 300 || response.status >= 400)) {
        error = "HTTP response status is not successful"; return false;
    }
    return true;
}

bool FetchOne(PolicyUpdateSocketConnector& connector, const ParsedUrl& url,
    const PolicyFetchRequest& request, const std::string& etag, const std::string& modified,
    PolicyFetchResponse& response, std::string& error) {
    asio::io_context io;
    Tcp::socket socket(io);
    const PolicyUpdateEndpoint endpoint{url.host, url.port, request.via};
    if (!connector.Connect(endpoint, request.deadline, request.cancelled, socket, error)) return false;
    if (url.secure) {
        try {
            auto context = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_client);
            context->set_default_verify_paths();
            TlsStream stream(socket, *context);
            stream.set_verify_mode(asio::ssl::verify_peer);
            boost::system::error_code address_error;
            asio::ip::make_address(url.host, address_error);
            const bool hostname_configured = address_error
                ? SSL_set1_host(stream.native_handle(), url.host.c_str()) == 1
                : X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(stream.native_handle()), url.host.c_str()) == 1;
            if ((address_error && SSL_set_tlsext_host_name(stream.native_handle(), url.host.c_str()) != 1) ||
                !hostname_configured) {
                error = "TLS hostname verification setup failed"; return false;
            }
            auto result = std::make_shared<AsyncResult>();
            auto deadline_timer = std::make_shared<asio::steady_timer>(io);
            auto cancel_timer = std::make_shared<asio::steady_timer>(io);
            deadline_timer->expires_at(request.deadline);
            deadline_timer->async_wait([result, deadline_timer, cancel_timer, &socket](const boost::system::error_code& ec) {
                if (!ec && !result->completed) { result->error = asio::error::timed_out; result->completed = true;
                    boost::system::error_code ignored; socket.cancel(ignored); socket.close(ignored); CancelTimer(*cancel_timer); }
            });
            auto poll = std::make_shared<std::function<void()>>();
            *poll = [result, deadline_timer, cancel_timer, &socket, cancelled = request.cancelled, poll]() {
                if (result->completed) return;
                if (cancelled && cancelled->load(std::memory_order_acquire)) {
                    result->error = asio::error::operation_aborted; result->completed = true;
                    boost::system::error_code ignored; socket.cancel(ignored); socket.close(ignored);
                    CancelTimer(*deadline_timer); CancelTimer(*cancel_timer); return;
                }
                cancel_timer->expires_after(std::chrono::milliseconds(20));
                cancel_timer->async_wait([poll](const boost::system::error_code& ec) { if (!ec) (*poll)(); });
            };
            (*poll)();
            stream.async_handshake(asio::ssl::stream_base::client,
                [result, deadline_timer, cancel_timer](const boost::system::error_code& ec) {
                    if (!result->completed) { result->error = ec; result->completed = true; }
                    CancelTimer(*deadline_timer); CancelTimer(*cancel_timer);
                });
            io.restart();
            io.run();
            *poll = {};
            if (!result->completed || result->error) { error = "TLS handshake or certificate validation failed"; return false; }
            io.restart();
            return HttpExchange(stream, socket, request, url, etag, modified, response, error);
        } catch (...) { error = "TLS initialization failed"; return false; }
    }
    return HttpExchange(socket, socket, request, url, etag, modified, response, error);
}

} // namespace

DirectPolicySocketConnector::DirectPolicySocketConnector(DirectPolicySocketOptions options) : options_(std::move(options)) {}

bool DirectPolicySocketConnector::Connect(const PolicyUpdateEndpoint& endpoint,
    std::chrono::steady_clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    Tcp::socket& socket, std::string& error) {
    if (endpoint.via != PolicyUpdateVia::Direct) { error = "direct policy connector cannot satisfy proxy egress"; return false; }
    std::vector<asio::ip::address> addresses;
    if (!ResolveDirect(options_, endpoint.host, deadline, cancelled, addresses, error)) return false;
    for (const auto& address : addresses) {
        boost::system::error_code ec;
        const auto protocol = address.is_v4() ? Tcp::v4() : Tcp::v6();
        socket.open(protocol, ec);
        if (ec || !SetBoundInterface(socket, options_, error)) { socket.close(ec); continue; }
        if (!options_.local_address.is_unspecified() && options_.local_address.is_v4() == address.is_v4()) {
            socket.bind(Tcp::endpoint(options_.local_address, 0), ec);
            if (ec) { socket.close(ec); continue; }
        }
        asio::io_context& io = static_cast<asio::io_context&>(socket.get_executor().context());
        if (RunAsync(io, socket, deadline, cancelled, [&](auto done) {
                socket.async_connect(Tcp::endpoint(address, endpoint.port), done);
            }, error)) return true;
        socket.close(ec);
        if (cancelled && cancelled->load(std::memory_order_acquire)) return false;
        io.restart();
    }
    if (error.empty()) error = "no configured-interface endpoint could be connected";
    return false;
}

LocalSocks5PolicySocketConnector::LocalSocks5PolicySocketConnector(Tcp::endpoint endpoint)
    : loopback_endpoint_(std::move(endpoint)) {}

bool LocalSocks5PolicySocketConnector::Connect(const PolicyUpdateEndpoint& endpoint,
    std::chrono::steady_clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    Tcp::socket& socket, std::string& error) {
    if (endpoint.via != PolicyUpdateVia::Proxy) { error = "SOCKS5 policy connector cannot satisfy direct egress"; return false; }
    if (!loopback_endpoint_.address().is_loopback() || loopback_endpoint_.port() == 0 ||
        endpoint.host.empty() || endpoint.host.size() > 255) {
        error = "policy control SOCKS5 endpoint must be a numeric loopback address"; return false;
    }
    asio::io_context& io = static_cast<asio::io_context&>(socket.get_executor().context());
    boost::system::error_code ec;
    socket.open(loopback_endpoint_.protocol(), ec);
    if (ec || !RunAsync(io, socket, deadline, cancelled, [&](auto done) {
            socket.async_connect(loopback_endpoint_, done);
        }, error)) return false;
    std::array<unsigned char, 3> greeting{5, 1, 0};
    if (!RunAsync(io, socket, deadline, cancelled, [&](auto done) { asio::async_write(socket, asio::buffer(greeting), done); }, error)) return false;
    std::array<unsigned char, 2> method{};
    if (!RunAsync(io, socket, deadline, cancelled, [&](auto done) { asio::async_read(socket, asio::buffer(method), done); }, error)) return false;
    if (method[0] != 5 || method[1] != 0) {
        error = "local SOCKS5 endpoint rejected unauthenticated control connection"; return false;
    }
    std::vector<unsigned char> command{5, 1, 0, 3, static_cast<unsigned char>(endpoint.host.size())};
    command.insert(command.end(), endpoint.host.begin(), endpoint.host.end());
    command.push_back(static_cast<unsigned char>(endpoint.port >> 8));
    command.push_back(static_cast<unsigned char>(endpoint.port));
    if (!RunAsync(io, socket, deadline, cancelled, [&](auto done) { asio::async_write(socket, asio::buffer(command), done); }, error)) return false;
    std::array<unsigned char, 4> reply{};
    if (!RunAsync(io, socket, deadline, cancelled, [&](auto done) { asio::async_read(socket, asio::buffer(reply), done); }, error)) return false;
    if (reply[0] != 5 || reply[1] != 0) {
        error = "local SOCKS5 endpoint could not connect to policy source"; return false;
    }
    std::size_t tail = reply[3] == 1 ? 4 : reply[3] == 4 ? 16 : reply[3] == 3 ? 0 : std::numeric_limits<std::size_t>::max();
    if (reply[3] == 3) {
        unsigned char length = 0;
        if (!RunAsync(io, socket, deadline, cancelled, [&](auto done) { asio::async_read(socket, asio::buffer(&length, 1), done); }, error)) return false;
        tail = length;
    }
    if (tail == std::numeric_limits<std::size_t>::max()) { error = "invalid SOCKS5 address type"; return false; }
    std::vector<unsigned char> discard(tail + 2);
    return RunAsync(io, socket, deadline, cancelled, [&](auto done) { asio::async_read(socket, asio::buffer(discard), done); }, error);
}

HttpsPolicyUpdateFetcher::HttpsPolicyUpdateFetcher(std::shared_ptr<PolicyUpdateSocketConnector> connector,
    bool allow_plain_http) : connector_(std::move(connector)), allow_plain_http_(allow_plain_http) {}

bool HttpsPolicyUpdateFetcher::Fetch(const PolicyFetchRequest& request, PolicyFetchResponse& response) {
    response = {};
    if (!connector_ || request.url.empty() || request.max_bytes == 0 ||
        request.deadline <= std::chrono::steady_clock::now()) {
        response.diagnostic = "fetch request is incomplete or expired"; return false;
    }
    std::string current = request.url;
    std::string etag = request.etag;
    std::string modified = request.last_modified;
    bool original_https = false;
    std::string original_origin;
    for (int redirects = 0; redirects <= kRedirectLimit; ++redirects) {
        ParsedUrl parsed;
        std::string error;
        if (!ParseUrl(current, allow_plain_http_, parsed, error)) { response.diagnostic = error; return false; }
        if (redirects == 0) {
            original_https = parsed.secure;
            original_origin = parsed.scheme + "://" + parsed.authority;
        }
        PolicyFetchResponse hop;
        if (!FetchOne(*connector_, parsed, request, etag, modified, hop, error)) {
            response.diagnostic = error;
            response.effective_url_redacted = RedactPolicySourceUrl(current);
            return false;
        }
        if (hop.status == 301 || hop.status == 302 || hop.status == 303 || hop.status == 307 || hop.status == 308) {
            std::string next;
            if (!ResolveRedirect(parsed, hop.redirect_location, next)) { response.diagnostic = "redirect response has an invalid Location"; return false; }
            ParsedUrl next_url;
            if (!ParseUrl(next, allow_plain_http_, next_url, error)) { response.diagnostic = error; return false; }
            if (original_https && !next_url.secure) { response.diagnostic = "HTTPS downgrade redirect is forbidden"; return false; }
            const std::string next_origin = next_url.scheme + "://" + next_url.authority;
            const std::string previous_origin = parsed.scheme + "://" + parsed.authority;
            if (next_origin != previous_origin) { etag.clear(); modified.clear(); }
            current = std::move(next);
            if (redirects == kRedirectLimit) { response.diagnostic = "too many redirects"; return false; }
            continue;
        }
        if (hop.status == 304) {
            response = std::move(hop);
            response.effective_url_redacted = RedactPolicySourceUrl(current);
            return true;
        }
        response = std::move(hop);
        response.effective_url_redacted = RedactPolicySourceUrl(current);
        (void)original_origin;
        return true;
    }
    response.diagnostic = "too many redirects";
    return false;
}

} // namespace ppp::app::client::policy
