#include "PolicyTunnelUpdateConnector.h"

#include <ppp/app/client/PolicyTunnelDnsStream.h>
#include <ppp/dns/DnsResolver.h>
#include <common/dnslib/message.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <future>
#include <thread>

namespace ppp::app::client::policy {
namespace {
using Address = boost::asio::ip::address;
using Tcp = boost::asio::ip::tcp;
using Udp = boost::asio::ip::udp;

bool IsActive(const PolicyTunnelUpdateConnector::Clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled) noexcept {
    return std::chrono::steady_clock::now() < deadline &&
        !(cancelled && cancelled->load(std::memory_order_acquire));
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool BuildAQuery(const std::string& hostname, std::vector<unsigned char>& packet) {
    std::string name = hostname;
    if (!name.empty() && name.back() == '.') name.pop_back();
    if (name.empty() || name.size() > 253 || name.front() == '.' || name.find("..") != std::string::npos ||
        std::any_of(name.begin(), name.end(), [](unsigned char ch) {
            return ch <= 32 || ch >= 127 || ch == '/' || ch == '\\' || ch == ':';
        })) return false;

    static std::atomic_uint16_t query_id{0x5e19};
    ::dns::Message query;
    query.mId = query_id.fetch_add(1, std::memory_order_relaxed);
    query.mRD = 1;
    query.questions.emplace_back(name, ::dns::RecordType::kA, ::dns::RecordClass::kIN);
    packet.resize(512);
    std::size_t length = 0;
    if (query.encode(reinterpret_cast<char*>(packet.data()), packet.size(), length) != ::dns::BufferResult::NoError ||
        length < 17 || length > packet.size()) return false;
    packet.resize(length);

    ::dns::Message check;
    return check.decode(packet.data(), packet.size()) == ::dns::BufferResult::NoError &&
        check.questions.size() == 1 && check.questions.front().mName == name &&
        check.questions.front().mType == ::dns::RecordType::kA &&
        check.questions.front().mClass == ::dns::RecordClass::kIN;
}

Address FirstARecord(const std::vector<unsigned char>& packet, const std::string& hostname) {
    ::dns::Message response;
    if (packet.size() < 12 || packet.size() > 65535 ||
        response.decode(packet.data(), packet.size()) != ::dns::BufferResult::NoError ||
        !response.mQr || response.mTC || response.mRCode != 0 || response.questions.size() != 1 ||
        response.questions.front().mType != ::dns::RecordType::kA ||
        response.questions.front().mClass != ::dns::RecordClass::kIN ||
        Lower(response.questions.front().mName) != Lower(hostname)) return {};
    for (auto& record : response.answers) {
        if (record.mType != ::dns::RecordType::kA || record.mClass != ::dns::RecordClass::kIN) continue;
        const auto data = record.getRData<::dns::RDataA>();
        if (!data) continue;
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy_n(data->getAddress(), bytes.size(), bytes.begin());
        Address address{boost::asio::ip::address_v4(bytes)};
        if (!address.is_unspecified() && !address.is_multicast()) return address;
    }
    return {};
}

struct ResolveCompletion final {
    std::promise<std::vector<unsigned char>> promise;
    std::atomic_bool completed{false};
};

struct TunnelCompletionState final {
    std::promise<boost::system::error_code> promise;
    std::atomic_bool completed{false};
    std::atomic_bool active{true};

    void Complete(boost::system::error_code error) noexcept {
        if (completed.exchange(true, std::memory_order_acq_rel)) return;
        try { promise.set_value(error); }
        catch (...) {}
    }
};

bool ResolveWithBootstrap(const std::string& hostname, const std::vector<Udp::endpoint>& bootstrap,
    PolicyTunnelUpdateConnector::Clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled,
    const PolicyTunnelUpdateConnector::SocketProtector& protect_socket,
    Address& address, std::string& error) {
    if (bootstrap.empty()) {
        error = "policy control hostname requires explicit direct bootstrap DNS servers";
        return false;
    }
    for (const auto& server : bootstrap) {
        if (!server.address().is_v4() || server.address().is_unspecified() ||
            server.address().is_multicast() || server.port() == 0) {
            error = "policy control bootstrap must use numeric IPv4 UDP endpoints";
            return false;
        }
    }

    std::vector<unsigned char> query;
    if (!BuildAQuery(hostname, query)) {
        error = "policy control source hostname is invalid";
        return false;
    }
    ppp::vector<ppp::dns::ServerEntry> entries;
    try {
        entries.reserve(bootstrap.size());
        for (const auto& server : bootstrap) {
            ppp::dns::ServerEntry entry;
            entry.protocol = ppp::dns::Protocol::UDP;
            const std::string text = server.address().to_string() + ":" + std::to_string(server.port());
            entry.address.assign(text.data(), text.size());
            entries.emplace_back(std::move(entry));
        }
    } catch (...) {
        error = "policy control bootstrap allocation failed";
        return false;
    }

    boost::asio::io_context context;
    auto resolver = std::make_shared<ppp::dns::DnsResolver>(context);
    resolver->SetProtectSocketCallback([protect_socket](ppp::dns::DnsResolver::NativeSocketHandle handle) {
        return protect_socket && protect_socket(
            static_cast<Udp::socket::native_handle_type>(handle));
    });
    ppp::function<bool()> active = [deadline, cancelled] { return IsActive(deadline, cancelled); };
    resolver->SetQueryActiveCheck(active);
    auto completion = std::make_shared<ResolveCompletion>();
    auto result = completion->promise.get_future();
    resolver->ResolveAsyncWithEntries(entries, false, query.data(), static_cast<int>(query.size()),
        [completion](ppp::vector<Byte> response) {
            if (completion->completed.exchange(true, std::memory_order_acq_rel)) return;
            try {
                completion->promise.set_value(std::vector<unsigned char>(response.begin(), response.end()));
            } catch (...) {
                try { completion->promise.set_value({}); } catch (...) {}
            }
        });
    while (result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
        if (!active()) {
            error = cancelled && cancelled->load(std::memory_order_acquire)
                ? "policy control bootstrap DNS cancelled" : "policy control bootstrap DNS timed out";
            return false;
        }
        context.run_one_for(std::chrono::milliseconds(5));
    }
    address = FirstARecord(result.get(), hostname);
    if (address.is_unspecified()) {
        error = "configured policy bootstrap DNS servers could not resolve the control source";
        return false;
    }
    return true;
}

} // namespace

PolicyTunnelUpdateConnector::PolicyTunnelUpdateConnector(
    std::shared_ptr<VEthernetExchanger> exchanger, std::vector<Udp::endpoint> bootstrap,
    SocketProtector protect_socket)
    : bootstrap_(std::move(bootstrap)) {
    test_hooks_.resolve_bootstrap = [protect_socket = std::move(protect_socket)](
        const std::string& hostname, const std::vector<Udp::endpoint>& servers,
        Clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
        Address& address, std::string& error) {
        return ResolveWithBootstrap(hostname, servers, deadline, cancelled, protect_socket, address, error);
    };
    test_hooks_.connect_tunnel = [exchanger = std::move(exchanger)](
        const PolicyUpdateEndpoint& endpoint, Tcp::socket& socket,
        const TunnelActiveCheck& active, const TunnelCompletion& completion) {
        if (!exchanger) {
            completion(boost::asio::error::operation_aborted);
            return;
        }
        ppp::app::client::dns::PolicyTunnelDnsStream::Connect(exchanger, socket,
            endpoint.host, endpoint.port, active, completion);
    };
}

PolicyTunnelUpdateConnector::PolicyTunnelUpdateConnector(
    std::vector<Udp::endpoint> bootstrap, TestHooks test_hooks)
    : bootstrap_(std::move(bootstrap)), test_hooks_(std::move(test_hooks)) {}

bool PolicyTunnelUpdateConnector::Connect(const PolicyUpdateEndpoint& endpoint,
    Clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    Tcp::socket& socket, std::string& error) {
    error.clear();
    if (endpoint.via != PolicyUpdateVia::Proxy) {
        error = "policy tunnel connector can only satisfy proxy egress";
        return false;
    }
    if (endpoint.host.empty() || endpoint.host.size() > 253 || endpoint.port == 0) {
        error = "policy tunnel endpoint is invalid";
        return false;
    }
    if (!IsActive(deadline, cancelled)) {
        error = cancelled && cancelled->load(std::memory_order_acquire)
            ? "policy control tunnel connection cancelled" : "policy control tunnel connection timed out";
        return false;
    }

    Address destination;
    boost::system::error_code parse_error;
    destination = boost::asio::ip::make_address(endpoint.host, parse_error);
    if (parse_error) {
        if (bootstrap_.empty()) {
            error = "policy control hostname requires explicit direct bootstrap DNS servers";
            return false;
        }
        for (const auto& server : bootstrap_) {
            if (!server.address().is_v4() || server.address().is_unspecified() ||
                server.address().is_multicast() || server.port() == 0) {
                error = "policy control bootstrap must use numeric IPv4 UDP endpoints";
                return false;
            }
        }
        if (!test_hooks_.resolve_bootstrap) {
            error = "policy control hostname requires explicit direct bootstrap DNS servers";
            return false;
        }
        try {
            if (!test_hooks_.resolve_bootstrap(endpoint.host, bootstrap_, deadline, cancelled, destination, error)) {
                if (error.empty()) {
                    error = cancelled && cancelled->load(std::memory_order_acquire)
                        ? "policy control bootstrap DNS cancelled"
                        : std::chrono::steady_clock::now() >= deadline
                            ? "policy control bootstrap DNS timed out"
                            : "configured policy bootstrap DNS servers could not resolve the control source";
                }
                return false;
            }
        } catch (...) {
            error = "policy control bootstrap DNS failed";
            return false;
        }
    }
    if (destination.is_unspecified() || destination.is_multicast()) {
        error = "policy control source resolved to an unusable address";
        return false;
    }

    PolicyUpdateEndpoint tunneled{destination.to_string(), endpoint.port, PolicyUpdateVia::Proxy};
    if (!ConnectThroughTunnel(tunneled, deadline, cancelled, socket, error)) return false;
    if (!IsActive(deadline, cancelled)) {
        boost::system::error_code ignored;
        socket.cancel(ignored);
        socket.close(ignored);
        error = cancelled && cancelled->load(std::memory_order_acquire)
            ? "policy control tunnel connection cancelled" : "policy control tunnel connection timed out";
        return false;
    }
    return true;
}

bool PolicyTunnelUpdateConnector::ConnectThroughTunnel(const PolicyUpdateEndpoint& endpoint,
    Clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    Tcp::socket& socket, std::string& error) {
    auto completion = std::make_shared<TunnelCompletionState>();
    auto result = completion->promise.get_future();
    const auto active = [completion, deadline, cancelled] {
        return completion->active.load(std::memory_order_acquire) && IsActive(deadline, cancelled);
    };
    const auto finished = [completion](boost::system::error_code error_code) {
        completion->Complete(error_code);
    };
    if (test_hooks_.connect_tunnel) {
        try { test_hooks_.connect_tunnel(endpoint, socket, active, finished); }
        catch (...) { completion->Complete(boost::asio::error::operation_aborted); }
    } else {
        error = "policy control exchanger is unavailable";
        return false;
    }

    auto& socket_context = static_cast<boost::asio::io_context&>(socket.get_executor().context());
    if (socket_context.stopped()) socket_context.restart();
    while (result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
        if (!active()) {
            completion->active.store(false, std::memory_order_release);
            boost::system::error_code ignored;
            socket.cancel(ignored);
            socket.close(ignored);
            error = cancelled && cancelled->load(std::memory_order_acquire)
                ? "policy control tunnel connection cancelled" : "policy control tunnel connection timed out";
            return false;
        }
        socket_context.run_one_for(std::chrono::milliseconds(5));
    }

    const auto connect_error = result.get();
    if (connect_error) {
        boost::system::error_code ignored;
        socket.cancel(ignored);
        socket.close(ignored);
        error = connect_error == boost::asio::error::timed_out
            ? "policy control tunnel connection timed out"
            : connect_error == boost::asio::error::operation_aborted
                ? "policy control tunnel connection cancelled"
                : "policy control tunnel connection failed";
        return false;
    }
    return true;
}

} // namespace ppp::app::client::policy
