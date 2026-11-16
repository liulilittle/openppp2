#include <ppp/app/client/policy/PolicyUpdateFetcher.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
namespace asio = boost::asio;
using Tcp = asio::ip::tcp;
using Udp = asio::ip::udp;
using namespace std::chrono_literals;
using ppp::app::client::policy::DirectPolicySocketConnector;
using ppp::app::client::policy::DirectPolicySocketOptions;
using ppp::app::client::policy::LocalSocks5PolicySocketConnector;
using ppp::app::client::policy::HttpsPolicyUpdateFetcher;
using ppp::app::client::policy::PolicyFetchRequest;
using ppp::app::client::policy::PolicyFetchResponse;
using ppp::app::client::policy::PolicyUpdateEndpoint;
using ppp::app::client::policy::PolicyUpdateSocketConnector;
using ppp::app::client::policy::PolicyUpdateVia;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct LoopbackListener final {
    asio::io_context io;
    Tcp::acceptor acceptor;

    explicit LoopbackListener(asio::ip::address address = asio::ip::address_v4::loopback())
        : acceptor(io, Tcp::endpoint(std::move(address), 0)) {}

    Tcp::endpoint endpoint() const { return acceptor.local_endpoint(); }
};

Tcp::socket AcceptOne(LoopbackListener& listener) {
    listener.acceptor.non_blocking(true);
    Tcp::socket peer(listener.io);
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline) {
        boost::system::error_code ec;
        listener.acceptor.accept(peer, ec);
        if (!ec) return peer;
        if (ec != asio::error::would_block && ec != asio::error::try_again)
            throw boost::system::system_error(ec);
        std::this_thread::sleep_for(1ms);
    }
    throw std::runtime_error("loopback test peer accept timed out");
}

std::shared_ptr<PolicyUpdateSocketConnector> MakeLoopbackDirectConnector() {
    DirectPolicySocketOptions options;
#if defined(__linux__)
    options.interface_name = "lo";
#elif defined(_WIN32)
    options.interface_index = 1; // loopback interface index on Windows
#endif
    return std::make_shared<DirectPolicySocketConnector>(std::move(options));
}

bool FetchHttp(LoopbackListener& listener, const std::string& target,
    PolicyFetchResponse& response, std::size_t max_bytes = 64u * 1024u * 1024u,
    std::string etag = {}, std::string last_modified = {}) {
    HttpsPolicyUpdateFetcher fetcher(MakeLoopbackDirectConnector(), true);
    PolicyFetchRequest request;
    request.url = "http://127.0.0.1:" + std::to_string(listener.endpoint().port()) + target;
    request.via = PolicyUpdateVia::Direct;
    request.etag = std::move(etag);
    request.last_modified = std::move(last_modified);
    request.max_bytes = max_bytes;
    request.deadline = std::chrono::steady_clock::now() + 3s;
    return fetcher.Fetch(request, response);
}

std::string ReadHttpRequest(Tcp::socket& peer) {
    asio::streambuf request;
    asio::read_until(peer, request, "\r\n\r\n");
    return std::string(asio::buffers_begin(request.data()), asio::buffers_end(request.data()));
}

void WriteHttpResponse(Tcp::socket& peer, const std::string& response) {
    asio::write(peer, asio::buffer(response));
}

bool ConnectSocks(LocalSocks5PolicySocketConnector& connector,
    const PolicyUpdateEndpoint& endpoint, std::chrono::steady_clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled, std::string& error) {
    asio::io_context io;
    Tcp::socket socket(io);
    return connector.Connect(endpoint, deadline, cancelled, socket, error);
}

void SocketsDomainRequestAndRejectsAuthentication() {
    LoopbackListener listener;
    std::string requested_host;
    std::exception_ptr server_error;
    std::thread server([&] {
      try {
        Tcp::socket peer = AcceptOne(listener);
        std::array<unsigned char, 3> greeting{};
        asio::read(peer, asio::buffer(greeting));
        Require(greeting == std::array<unsigned char, 3>{5, 1, 0}, "SOCKS5 greeting must request no-auth");
        const std::array<unsigned char, 2> method{5, 0};
        asio::write(peer, asio::buffer(method));

        std::array<unsigned char, 5> request{};
        asio::read(peer, asio::buffer(request));
        Require(request[0] == 5 && request[1] == 1 && request[2] == 0 && request[3] == 3,
            "SOCKS5 CONNECT must preserve the upstream host as DOMAIN");
        std::vector<unsigned char> host(request[4]);
        asio::read(peer, asio::buffer(host));
        requested_host.assign(host.begin(), host.end());
        std::array<unsigned char, 2> port{};
        asio::read(peer, asio::buffer(port));
        const std::array<unsigned char, 10> reply{5, 0, 0, 1, 127, 0, 0, 1, 0, 0};
        asio::write(peer, asio::buffer(reply));
      } catch (...) { server_error = std::current_exception(); }
    });

    LocalSocks5PolicySocketConnector connector(listener.endpoint());
    std::string error;
    const bool connected = ConnectSocks(connector,
        {"rules.example", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 2s, {}, error);
    server.join();
    if (server_error) std::rethrow_exception(server_error);
    Require(connected, "SOCKS5 loopback CONNECT should succeed");
    Require(requested_host == "rules.example", "SOCKS5 must not resolve the upstream host locally");

    LoopbackListener reject_listener;
    std::exception_ptr reject_server_error;
    std::thread reject_server([&] {
      try {
        Tcp::socket peer = AcceptOne(reject_listener);
        std::array<unsigned char, 3> greeting{};
        asio::read(peer, asio::buffer(greeting));
        const std::array<unsigned char, 2> reject{5, 0xff};
        asio::write(peer, asio::buffer(reject));
      } catch (...) { reject_server_error = std::current_exception(); }
    });
    LocalSocks5PolicySocketConnector reject_connector(reject_listener.endpoint());
    error.clear();
    Require(!ConnectSocks(reject_connector,
        {"rules.example", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 2s, {}, error),
        "SOCKS5 authentication-method rejection must fail");
    reject_server.join();
    if (reject_server_error) std::rethrow_exception(reject_server_error);
    Require(error.find("rejected") != std::string::npos, "SOCKS5 rejection should produce a diagnostic");
}

void SocksDeadlineAndCancellationCloseTheSocket() {
    auto run_stalled = [](bool cancel) {
        LoopbackListener listener;
        std::atomic_bool peer_accepted{false};
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
            Tcp::socket peer = AcceptOne(listener);
            peer_accepted.store(true, std::memory_order_release);
            std::array<unsigned char, 3> greeting{};
            boost::system::error_code ec;
            asio::read(peer, asio::buffer(greeting), ec);
            std::this_thread::sleep_for(250ms);
          } catch (...) { server_error = std::current_exception(); }
        });

        LocalSocks5PolicySocketConnector connector(listener.endpoint());
        auto cancelled = std::make_shared<std::atomic_bool>(false);
        std::atomic_bool succeeded{true};
        std::string error;
        std::thread worker([&] {
            succeeded.store(ConnectSocks(connector,
                {"rules.example", 443, PolicyUpdateVia::Proxy},
                std::chrono::steady_clock::now() + (cancel ? 2s : 80ms), cancelled, error),
                std::memory_order_release);
        });
        const auto wait_until = std::chrono::steady_clock::now() + 1s;
        while (!peer_accepted.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < wait_until)
            std::this_thread::sleep_for(1ms);
        Require(peer_accepted.load(std::memory_order_acquire), "SOCKS5 test peer was not accepted");
        if (cancel) {
            std::this_thread::sleep_for(30ms);
            cancelled->store(true, std::memory_order_release);
        }
        worker.join();
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(!succeeded.load(std::memory_order_acquire), "stalled SOCKS5 negotiation must not succeed");
        if (error.find(cancel ? "cancelled" : "timed out") == std::string::npos)
            throw std::runtime_error("stalled SOCKS5 diagnostic was: " + error);
    };
    run_stalled(false);
    run_stalled(true);
}

void HttpFetcherHandlesFramingConditionalsRedirectsAndLimits() {
    {
        LoopbackListener listener;
        std::string request;
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
            Tcp::socket peer = AcceptOne(listener);
            request = ReadHttpRequest(peer);
            WriteHttpResponse(peer,
                "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nLast-Modified: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
          } catch (...) { server_error = std::current_exception(); }
        });
        PolicyFetchResponse response;
        const bool ok = FetchHttp(listener, "/policy", response, 32, "\"old\"", "Mon, 31 Dec 2029 00:00:00 GMT");
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(ok && response.status == 200 && response.body == "hello",
            "HTTP chunked response framing should produce the complete body");
        Require(request.find("If-None-Match: \"old\"") != std::string::npos &&
                request.find("If-Modified-Since: Mon, 31 Dec 2029 00:00:00 GMT") != std::string::npos,
            "HTTP request should preserve conditional headers");
        Require(response.etag == "\"v1\"" && response.last_modified == "Tue, 01 Jan 2030 00:00:00 GMT",
            "HTTP response should return validator headers");
    }
    {
        LoopbackListener listener;
        std::string request;
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
            Tcp::socket peer = AcceptOne(listener);
            request = ReadHttpRequest(peer);
            WriteHttpResponse(peer, "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
          } catch (...) { server_error = std::current_exception(); }
        });
        PolicyFetchResponse response;
        const bool ok = FetchHttp(listener, "/policy", response, 32, "\"v1\"");
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(ok && response.status == 304 && response.body.empty(), "HTTP 304 should remain a bodyless conditional response");
        Require(request.find("If-None-Match: \"v1\"") != std::string::npos, "HTTP 304 request should carry its ETag");
    }
    {
        LoopbackListener listener;
        std::vector<std::string> requests;
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
            Tcp::socket first = AcceptOne(listener);
            requests.push_back(ReadHttpRequest(first));
            WriteHttpResponse(first, "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            Tcp::socket second = AcceptOne(listener);
            requests.push_back(ReadHttpRequest(second));
            WriteHttpResponse(second, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata");
          } catch (...) { server_error = std::current_exception(); }
        });
        PolicyFetchResponse response;
        const bool ok = FetchHttp(listener, "/start", response);
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(ok && response.status == 200 && response.body == "data", "HTTP redirect should fetch the target body");
        Require(requests.size() == 2 && requests[0].find("GET /start ") != std::string::npos &&
                requests[1].find("GET /next ") != std::string::npos,
            "HTTP redirect should issue the follow-up request to the resolved path");
    }
    {
        LoopbackListener listener;
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
            Tcp::socket peer = AcceptOne(listener);
            (void)ReadHttpRequest(peer);
            WriteHttpResponse(peer, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
          } catch (...) { server_error = std::current_exception(); }
        });
        PolicyFetchResponse response;
        const bool ok = FetchHttp(listener, "/large", response, 4);
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(!ok && response.diagnostic.find("size limit") != std::string::npos,
            "HTTP body limit should reject an oversized response");
    }
}

void TlsRejectsAnUntrustedCertificateAndCancelsHandshake() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    Require(key_context && EVP_PKEY_keygen_init(key_context.get()) > 0 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(key_context.get(), 2048) > 0, "TLS test key initialization failed");
    EVP_PKEY* raw_key = nullptr;
    Require(EVP_PKEY_keygen(key_context.get(), &raw_key) > 0, "TLS test key generation failed");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    Require(certificate && X509_set_version(certificate.get(), 2) == 1 &&
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 7) == 1 &&
        X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0) != nullptr &&
        X509_gmtime_adj(X509_get_notAfter(certificate.get()), 3600) != nullptr &&
        X509_set_pubkey(certificate.get(), key.get()) == 1, "TLS test certificate initialization failed");
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    const unsigned char common_name[] = "127.0.0.1";
    Require(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1, -1, 0) == 1 &&
        X509_set_issuer_name(certificate.get(), subject) == 1, "TLS test certificate name setup failed");
    X509V3_CTX extension_context;
    X509V3_set_ctx(&extension_context, certificate.get(), certificate.get(), nullptr, nullptr, 0);
    X509_EXTENSION* raw_extension = X509V3_EXT_conf_nid(nullptr, &extension_context,
        NID_subject_alt_name, "IP:127.0.0.1");
    Require(raw_extension != nullptr, "TLS test IP SAN creation failed");
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(raw_extension, X509_EXTENSION_free);
    Require(X509_add_ext(certificate.get(), extension.get(), -1) == 1 &&
        X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0, "TLS test certificate signing failed");

    {
        LoopbackListener listener;
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
            asio::ssl::context server_context(asio::ssl::context::tls_server);
            Require(SSL_CTX_use_certificate(server_context.native_handle(), certificate.get()) == 1 &&
                SSL_CTX_use_PrivateKey(server_context.native_handle(), key.get()) == 1,
                "TLS server certificate installation failed");
            Tcp::socket peer = AcceptOne(listener);
            asio::ssl::stream<Tcp::socket> stream(std::move(peer), server_context);
            boost::system::error_code ec;
            stream.handshake(asio::ssl::stream_base::server, ec);
          } catch (...) { server_error = std::current_exception(); }
        });
        HttpsPolicyUpdateFetcher fetcher(MakeLoopbackDirectConnector());
        PolicyFetchRequest request;
        request.url = "https://127.0.0.1:" + std::to_string(listener.endpoint().port()) + "/policy";
        request.via = PolicyUpdateVia::Direct;
        request.deadline = std::chrono::steady_clock::now() + 3s;
        PolicyFetchResponse response;
        const bool ok = fetcher.Fetch(request, response);
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(!ok && response.diagnostic.find("TLS handshake") != std::string::npos,
            "TLS fetch must reject an untrusted certificate with a valid IP SAN");
    }
    {
        LoopbackListener listener;
        std::atomic_bool accepted{false};
        std::exception_ptr server_error;
        std::thread server([&] {
          try {
              Tcp::socket peer = AcceptOne(listener);
              accepted.store(true, std::memory_order_release);
              std::array<char, 4096> hello{};
              boost::system::error_code ec;
              peer.read_some(asio::buffer(hello), ec);
              std::this_thread::sleep_for(250ms);
          } catch (...) { server_error = std::current_exception(); }
        });
        auto cancelled = std::make_shared<std::atomic_bool>(false);
        std::atomic_bool succeeded{true};
        PolicyFetchResponse response;
        HttpsPolicyUpdateFetcher fetcher(MakeLoopbackDirectConnector());
        PolicyFetchRequest request;
        request.url = "https://127.0.0.1:" + std::to_string(listener.endpoint().port()) + "/policy";
        request.via = PolicyUpdateVia::Direct;
        request.deadline = std::chrono::steady_clock::now() + 2s;
        request.cancelled = cancelled;
        std::thread worker([&] { succeeded.store(fetcher.Fetch(request, response), std::memory_order_release); });
        const auto accepted_deadline = std::chrono::steady_clock::now() + 1s;
        while (!accepted.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < accepted_deadline)
            std::this_thread::sleep_for(1ms);
        Require(accepted.load(std::memory_order_acquire), "TLS cancellation peer was not accepted");
        std::this_thread::sleep_for(30ms);
        cancelled->store(true, std::memory_order_release);
        worker.join();
        server.join();
        if (server_error) std::rethrow_exception(server_error);
        Require(!succeeded.load(std::memory_order_acquire), "cancelled TLS handshake must fail");
    }
}

void RejectsNonLoopbackProxyAndDoesNotUseSystemDns() {
    LocalSocks5PolicySocketConnector non_loopback(
        Tcp::endpoint(asio::ip::make_address("192.0.2.1"), 1080));
    std::string error;
    Require(!ConnectSocks(non_loopback,
        {"rules.example", 443, PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 1s, {}, error),
        "non-loopback SOCKS5 control endpoint must be rejected");
    Require(error.find("loopback") != std::string::npos, "non-loopback rejection should identify the constraint");

    DirectPolicySocketOptions options;
#if defined(__linux__)
    options.interface_name = "lo";
#endif
    DirectPolicySocketConnector direct(std::move(options));
    asio::io_context io;
    Tcp::socket socket(io);
    error.clear();
    Require(!direct.Connect({"no-system-dns.invalid", 443, PolicyUpdateVia::Direct},
        std::chrono::steady_clock::now() + 1s, {}, socket, error),
        "hostname direct connector without explicit bootstrap must fail");
    Require(error.find("bootstrap DNS") != std::string::npos,
        "hostname without bootstrap must fail explicitly instead of using system DNS");

    Tcp::acceptor unused(io, Tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    const auto unused_endpoint = unused.local_endpoint();
    unused.close();
    DirectPolicySocketOptions direct_options;
#if defined(__linux__)
    direct_options.interface_name = "lo";
#endif
    DirectPolicySocketConnector direct_mismatch(std::move(direct_options));
    Tcp::socket direct_socket(io);
    error.clear();
    Require(!direct_mismatch.Connect({"127.0.0.1", unused_endpoint.port(), PolicyUpdateVia::Proxy},
        std::chrono::steady_clock::now() + 1s, {}, direct_socket, error),
        "direct connector must reject a proxy endpoint");
    Require(error.find("egress") != std::string::npos, "direct transport mismatch should be explicit");

    LocalSocks5PolicySocketConnector proxy_mismatch(
        Tcp::endpoint(asio::ip::address_v4::loopback(), unused_endpoint.port()));
    Tcp::socket proxy_socket(io);
    error.clear();
    Require(!proxy_mismatch.Connect({"127.0.0.1", unused_endpoint.port(), PolicyUpdateVia::Direct},
        std::chrono::steady_clock::now() + 1s, {}, proxy_socket, error),
        "SOCKS5 connector must reject a direct endpoint");
    Require(error.find("egress") != std::string::npos, "proxy transport mismatch should be explicit");
}

void NumericDirectSocketUsesInjectedProtection() {
#if defined(__linux__)
    LoopbackListener listener;
    std::exception_ptr server_error;
    std::thread server([&] {
      try {
        Tcp::socket peer = AcceptOne(listener);
      } catch (...) { server_error = std::current_exception(); }
    });
    std::atomic_int protected_sockets{0};
    DirectPolicySocketOptions options;
    options.interface_name = "lo";
    options.protect_socket = [&](Tcp::socket::native_handle_type) {
        protected_sockets.fetch_add(1, std::memory_order_relaxed);
        return true;
    };
    DirectPolicySocketConnector direct(std::move(options));
    asio::io_context io;
    Tcp::socket socket(io);
    std::string error;
    const auto endpoint = listener.endpoint();
    const bool connected = direct.Connect(
        {endpoint.address().to_string(), endpoint.port(), PolicyUpdateVia::Direct},
        std::chrono::steady_clock::now() + 2s, {}, socket, error);
    server.join();
    if (server_error) std::rethrow_exception(server_error);
    Require(connected, "numeric IPv4 direct loopback connect should succeed");
    Require(protected_sockets.load(std::memory_order_relaxed) == 1,
        "direct TCP socket must be protected before connect");
#endif
}

void DirectBootstrapAcceptsOnlyTheConfiguredResolver() {
#if defined(__linux__)
    asio::io_context dns_io;
    Udp::socket resolver(dns_io, Udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    Udp::socket spoof(dns_io, Udp::endpoint(asio::ip::make_address("127.0.0.2"),
        resolver.local_endpoint().port()));
    LoopbackListener target(asio::ip::address_v6::loopback());
    std::exception_ptr server_error;
    std::thread server([&] {
      try {
        for (int request_number = 0; request_number < 2; ++request_number) {
            std::array<unsigned char, 512> query{};
            Udp::endpoint client;
            const auto size = resolver.receive_from(asio::buffer(query), client);
            const auto qtype = static_cast<unsigned>((query[size - 4] << 8) | query[size - 3]);
            std::vector<unsigned char> reply(query.begin(), query.begin() + size);
            reply[2] = 0x81;
            reply[3] = 0x80;
            reply[6] = 0;
            reply[7] = 1;
            if (qtype == 1) {
                const std::array<unsigned char, 16> answer{
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1};
                reply.insert(reply.end(), answer.begin(), answer.end());
                auto spoof_reply = reply;
                spoof_reply.back() = 2;
                spoof.send_to(asio::buffer(spoof_reply), client);
            } else {
                const std::array<unsigned char, 28> answer{
                    0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                reply.insert(reply.end(), answer.begin(), answer.end());
                resolver.send_to(asio::buffer(reply), client);
            }
        }
        Tcp::socket peer = AcceptOne(target);
      } catch (...) { server_error = std::current_exception(); }
    });

    std::atomic_int protected_sockets{0};
    DirectPolicySocketOptions options;
    options.interface_name = "lo";
    options.bootstrap_nameservers.push_back(resolver.local_endpoint());
    options.protect_socket = [&](Tcp::socket::native_handle_type) {
        protected_sockets.fetch_add(1, std::memory_order_relaxed);
        return true;
    };
    DirectPolicySocketConnector direct(std::move(options));
    asio::io_context io;
    Tcp::socket socket(io);
    const auto endpoint = target.endpoint();
    std::string error;
    const bool connected = direct.Connect({"bootstrap-test.example", endpoint.port(), PolicyUpdateVia::Direct},
        std::chrono::steady_clock::now() + 2s, {}, socket, error);
    server.join();
    if (server_error) std::rethrow_exception(server_error);
    Require(connected, "hostname direct connect should use the configured bootstrap resolver");
    Require(protected_sockets.load(std::memory_order_relaxed) == 3,
        "both bootstrap DNS query sockets and direct TCP socket must be protected");
#endif
}
} // namespace

int main() {
    try {
        SocketsDomainRequestAndRejectsAuthentication();
        SocksDeadlineAndCancellationCloseTheSocket();
        HttpFetcherHandlesFramingConditionalsRedirectsAndLimits();
        TlsRejectsAnUntrustedCertificateAndCancelsHandshake();
        RejectsNonLoopbackProxyAndDoesNotUseSystemDns();
        NumericDirectSocketUsesInjectedProtection();
        DirectBootstrapAcceptsOnlyTheConfiguredResolver();
        std::cout << "policy_update_connectors_test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "policy_update_connectors_test failed: " << error.what() << '\n';
        return 1;
    }
}
