#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <vector>

namespace ppp::app::client::policy {

enum class PolicyUpdateVia { Direct, Proxy };

struct PolicyFetchRequest final {
    std::string source_name;
    std::string url;
    PolicyUpdateVia via = PolicyUpdateVia::Proxy;
    std::string etag;
    std::string last_modified;
    std::chrono::steady_clock::time_point deadline;
    std::size_t max_bytes = 64u * 1024u * 1024u;
    std::shared_ptr<std::atomic_bool> cancelled;
};

struct PolicyFetchResponse final {
    int status = 0;
    std::string body;
    std::string etag;
    std::string last_modified;
    std::string diagnostic;
    std::string effective_url_redacted;
    std::string redirect_location;
};

class PolicyUpdateFetcher {
public:
    virtual ~PolicyUpdateFetcher() = default;
    virtual bool Fetch(const PolicyFetchRequest& request, PolicyFetchResponse& response) = 0;
};

struct PolicyUpdateEndpoint final {
    std::string host;
    std::uint16_t port = 0;
    PolicyUpdateVia via = PolicyUpdateVia::Direct;
};

struct DirectPolicySocketOptions final {
    std::string interface_name;
    std::uint32_t interface_index = 0;
    boost::asio::ip::address local_address;
    std::vector<boost::asio::ip::udp::endpoint> bootstrap_nameservers;
    std::function<bool(boost::asio::ip::tcp::socket::native_handle_type)> protect_socket;
    // Desktop proxy-only runtimes install no TUN routes, so the default route is already
    // direct and there is no underlying interface to bind to.
    bool unbound = false;
};

class PolicyUpdateSocketConnector {
public:
    virtual ~PolicyUpdateSocketConnector() = default;
    // Direct connectors must protect/bind the socket; proxy connectors must use
    // the independent control bootstrap tunnel, never system route selection.
    virtual bool Connect(const PolicyUpdateEndpoint& endpoint,
        std::chrono::steady_clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled,
        boost::asio::ip::tcp::socket& socket, std::string& error) = 0;
};

class DirectPolicySocketConnector final : public PolicyUpdateSocketConnector {
public:
    explicit DirectPolicySocketConnector(DirectPolicySocketOptions options);
    bool Connect(const PolicyUpdateEndpoint& endpoint,
        std::chrono::steady_clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled,
        boost::asio::ip::tcp::socket& socket, std::string& error) override;

private:
    DirectPolicySocketOptions options_;
};

class LocalSocks5PolicySocketConnector final : public PolicyUpdateSocketConnector {
public:
    explicit LocalSocks5PolicySocketConnector(boost::asio::ip::tcp::endpoint loopback_endpoint);
    bool Connect(const PolicyUpdateEndpoint& endpoint,
        std::chrono::steady_clock::time_point deadline,
        const std::shared_ptr<std::atomic_bool>& cancelled,
        boost::asio::ip::tcp::socket& socket, std::string& error) override;

private:
    boost::asio::ip::tcp::endpoint loopback_endpoint_;
};

class HttpsPolicyUpdateFetcher final : public PolicyUpdateFetcher {
public:
    explicit HttpsPolicyUpdateFetcher(std::shared_ptr<PolicyUpdateSocketConnector> connector,
        bool allow_plain_http = false);
    bool Fetch(const PolicyFetchRequest& request, PolicyFetchResponse& response) override;

private:
    std::shared_ptr<PolicyUpdateSocketConnector> connector_;
    bool allow_plain_http_;
};

} // namespace ppp::app::client::policy
