#pragma once

#include <ppp/app/client/dns/DnsSessionContext.h>
#include <ppp/app/client/dns/PolicyTelemetry.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/dns/DnsResolver.h>
#include <chrono>
#include <functional>
#include <unordered_map>

namespace ppp::app::client::dns {

class PolicyResolverService final : public std::enable_shared_from_this<PolicyResolverService> {
public:
    using Callback = ppp::dns::DnsResolver::ResolveCallback;
    using Clock = std::chrono::steady_clock;
    using NowFunction = std::function<Clock::time_point()>;
    static constexpr std::size_t kCacheCapacityEntries = 4096;
    using Exchange = ppp::function<void(const ppp::dns::ServerEntry&, policy::PolicyAction,
        const ppp::vector<Byte>&, const std::shared_ptr<const DnsSessionContext>&, const Callback&)>;

    class RequestHandle final {
    public:
        RequestHandle() = default;
        void Cancel() const noexcept { if (cancel_) cancel_(); }
        explicit operator bool() const noexcept { return static_cast<bool>(cancel_); }
    private:
        explicit RequestHandle(std::function<void()> cancel) : cancel_(std::move(cancel)) {}
        std::function<void()> cancel_;
        friend class PolicyResolverService;
    };

    PolicyResolverService(boost::asio::io_context& context,
        ppp::dns::DnsResolver::ProtectSocketCallback protect, Exchange exchange = {}, NowFunction now = {},
        std::shared_ptr<PolicyTelemetry> telemetry = {});
    RequestHandle Resolve(const std::shared_ptr<const policy::PolicySnapshot>& snapshot,
        const std::shared_ptr<const DnsSessionContext>& session,
        const ppp::vector<Byte>& query, const Callback& callback);
    void Close() noexcept;
    static ppp::vector<Byte> BuildQuery(const std::string& domain);
    static boost::asio::ip::address FirstAddress(const ppp::vector<Byte>& response);
    static ppp::vector<Byte> ErrorResponse(const ppp::vector<Byte>& query, unsigned code);

private:
    struct Operation;
    struct CacheEntry {
        ppp::vector<Byte> response;
        Clock::time_point created;
        Clock::time_point expires;
        std::uint64_t last_use = 0;
        std::size_t bytes = 0;
    };
    void ExchangePacket(const ppp::dns::ServerEntry&, policy::PolicyAction,
        const ppp::vector<Byte>&, const std::shared_ptr<const DnsSessionContext>&,
        const std::function<bool()>&, const Callback&);
    boost::asio::io_context& context_;
    ppp::dns::DnsResolver::ProtectSocketCallback protect_;
    Exchange exchange_;
    bool custom_exchange_ = false;
    NowFunction now_;
    std::shared_ptr<PolicyTelemetry> telemetry_;
    std::atomic_bool closed_{false};
    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<Operation>> operations_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::size_t cache_bytes_ = 0;
    std::size_t pending_bytes_ = 0;
    std::uint64_t cache_clock_ = 0;
    std::uint64_t next_waiter_id_ = 1;
};

}
