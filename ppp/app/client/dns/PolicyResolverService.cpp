#include "PolicyResolverService.h"
#include <ppp/dns/DnsProviderCatalog.h>
#include <common/dnslib/message.h>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <algorithm>
#include <charconv>
#include <limits>
#include <cctype>

namespace ppp::app::client::dns {
namespace {
using Action = policy::PolicyAction;
using Entry = ppp::dns::ServerEntry;
using Packet = ppp::vector<Byte>;

struct EntryPlan {
    Entry endpoint;
    std::vector<Entry> bootstrap;
    std::string target_hostname;
    bool bootstrap_resolved = false;
};

Packet Encode(::dns::Message& message) {
    Packet result(65535);
    std::size_t size = 0;
    if (message.encode(reinterpret_cast<char*>(result.data()), result.size(), size) != ::dns::BufferResult::NoError) return {};
    result.resize(size);
    return result;
}

bool Decode(const Packet& bytes, ::dns::Message& message) {
    return bytes.size() >= 12 && bytes.size() <= 65535 &&
        message.decode(bytes.data(), bytes.size()) == ::dns::BufferResult::NoError;
}

bool SameQuestion(const Packet& query, const Packet& response) {
    ::dns::Message q, r;
    if (!Decode(query, q) || !Decode(response, r) || !r.mQr || r.mId != q.mId ||
        r.mOpCode != q.mOpCode || r.questions.size() != 1 || q.questions.size() != 1) return false;
    const auto& a = q.questions.front();
    const auto& b = r.questions.front();
    auto lower = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    };
    return lower(a.mName) == lower(b.mName) && a.mType == b.mType && a.mClass == b.mClass;
}

void AppendKeyPart(std::string& key, const std::string& value) {
    const std::uint64_t size = value.size();
    key.append(reinterpret_cast<const char*>(&size), sizeof(size));
    key.append(value);
}

bool CacheTtl(const Packet& query, const Packet& response, std::uint32_t& ttl) {
    ::dns::Message q, r;
    if (!Decode(query, q) || !Decode(response, r) || !SameQuestion(query, response) ||
        r.mTC || (r.mRCode != 0 && r.mRCode != 3)) return false;
    if (r.mRCode == 3) {
        if (r.authorities.empty()) return false;
        std::uint32_t negative = 300;
        bool found_soa = false;
        for (auto& record : r.authorities) {
            if (record.mType != ::dns::RecordType::SOA || record.mClass != q.questions.front().mClass) continue;
            auto owner = record.mName;
            auto name = q.questions.front().mName;
            auto lower = [](std::string& value) {
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (!value.empty() && value.back() == '.') value.pop_back();
            };
            lower(owner); lower(name);
            if (!(owner.empty() || name == owner ||
                (name.size() > owner.size() && name.compare(name.size() - owner.size(), owner.size(), owner) == 0 &&
                    name[name.size() - owner.size() - 1] == '.'))) continue;
            const auto soa = record.getRData<::dns::RDataSOA>();
            if (!soa) return false;
            negative = std::min(negative, std::min(record.mTtl, soa->mMinimum));
            found_soa = true;
        }
        if (!found_soa || !negative) return false;
        ttl = negative;
        return true;
    }
    const auto requested_type = static_cast<std::uint16_t>(q.questions.front().mType);
    const bool has_requested = std::any_of(r.answers.begin(), r.answers.end(), [requested_type](const auto& record) {
        return static_cast<std::uint16_t>(record.mType) == requested_type;
    });
    if (has_requested) {
        std::uint32_t minimum = std::numeric_limits<std::uint32_t>::max();
        for (auto& record : r.answers) {
            if (record.mType == q.questions.front().mType || record.mType == ::dns::RecordType::kCNAME)
                minimum = std::min(minimum, record.mTtl);
        }
        if (minimum == std::numeric_limits<std::uint32_t>::max() || !minimum) return false;
        ttl = minimum;
        return true;
    }
    for (auto& record : r.authorities) {
        if (record.mType != ::dns::RecordType::SOA || record.mClass != q.questions.front().mClass) continue;
        auto owner = record.mName;
        auto name = q.questions.front().mName;
        auto lower = [](std::string& value) {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (!value.empty() && value.back() == '.') value.pop_back();
        };
        lower(owner); lower(name);
        if (!(owner.empty() || name == owner ||
            (name.size() > owner.size() && name.compare(name.size() - owner.size(), owner.size(), owner) == 0 &&
                name[name.size() - owner.size() - 1] == '.'))) continue;
        const auto soa = record.getRData<::dns::RDataSOA>();
        if (!soa) return false;
        ttl = std::min<std::uint32_t>(300, std::min(record.mTtl, soa->mMinimum));
        return ttl != 0;
    }
    return false;
}

void DecrementTtls(::dns::Message& message, std::uint32_t elapsed) {
    auto decrement = [elapsed](auto& records) {
        for (auto& record : records) {
            if (record.mType != ::dns::RecordType::kOPT)
                record.mTtl = record.mTtl > elapsed ? record.mTtl - elapsed : 0;
        }
    };
    decrement(message.answers);
    decrement(message.authorities);
    decrement(message.additions);
}

bool BuildSemanticKey(const Packet& query, ::dns::Message& message,
    const policy::PolicyResolver& resolver, Action via, const std::vector<EntryPlan>& entries,
    std::string& key) {
    if (query.size() < 12 || message.questions.size() != 1 || !message.answers.empty() ||
        !message.authorities.empty() || (query[2] & 0x06) != 0 || (query[3] & 0xEF) != 0) return false;
    key.clear();
    auto name = message.questions.front().mName;
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    AppendKeyPart(key, name);
    const auto& question = message.questions.front();
    key.append(reinterpret_cast<const char*>(&question.mType), sizeof(question.mType));
    key.append(reinterpret_cast<const char*>(&question.mClass), sizeof(question.mClass));
    const std::uint8_t flags[] = {static_cast<std::uint8_t>(message.mRD),
        static_cast<std::uint8_t>((query[3] >> 4) & 1)};
    key.append(reinterpret_cast<const char*>(flags), sizeof(flags));
    const auto actual_via = static_cast<std::uint8_t>(via);
    key.push_back(static_cast<char>(actual_via));
    const auto configured_via = static_cast<std::uint8_t>(resolver.via);
    key.push_back(static_cast<char>(configured_via));
    const std::uint64_t server_count = resolver.servers.size();
    key.append(reinterpret_cast<const char*>(&server_count), sizeof(server_count));
    for (const auto& server : resolver.servers) AppendKeyPart(key, server);
    const std::uint64_t spec_count = resolver.server_specs.size();
    key.append(reinterpret_cast<const char*>(&spec_count), sizeof(spec_count));
    for (const auto& server : resolver.server_specs) {
        AppendKeyPart(key, server.uri);
        const std::uint64_t address_count = server.addresses.size();
        key.append(reinterpret_cast<const char*>(&address_count), sizeof(address_count));
        for (const auto& address : server.addresses) AppendKeyPart(key, address);
        const std::uint64_t bootstrap_count = server.bootstrap.size();
        key.append(reinterpret_cast<const char*>(&bootstrap_count), sizeof(bootstrap_count));
        for (const auto& bootstrap : server.bootstrap) AppendKeyPart(key, bootstrap);
    }
    const std::uint64_t order_count = resolver.server_order.size();
    key.append(reinterpret_cast<const char*>(&order_count), sizeof(order_count));
    for (const auto& ref : resolver.server_order) {
        key.push_back(ref.structured ? '\1' : '\0');
        const auto index = static_cast<std::uint64_t>(ref.index);
        key.append(reinterpret_cast<const char*>(&index), sizeof(index));
    }
    const std::uint64_t entry_count = entries.size();
    key.append(reinterpret_cast<const char*>(&entry_count), sizeof(entry_count));
    for (const auto& plan : entries) {
        const auto& entry = plan.endpoint;
        key.push_back(static_cast<char>(entry.protocol));
        AppendKeyPart(key, std::string(entry.url.data(), entry.url.size()));
        AppendKeyPart(key, std::string(entry.hostname.data(), entry.hostname.size()));
        AppendKeyPart(key, std::string(entry.address.data(), entry.address.size()));
        const std::uint64_t count = entry.bootstrap_ips.size();
        key.append(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& ip : entry.bootstrap_ips) AppendKeyPart(key, ip.to_string());
        AppendKeyPart(key, plan.target_hostname);
        const std::uint64_t bootstrap_count = plan.bootstrap.size();
        key.append(reinterpret_cast<const char*>(&bootstrap_count), sizeof(bootstrap_count));
        for (const auto& bootstrap : plan.bootstrap) {
            key.push_back(static_cast<char>(bootstrap.protocol));
            AppendKeyPart(key, std::string(bootstrap.address.data(), bootstrap.address.size()));
        }
    }
    bool saw_opt = false;
    bool saw_ecs = false;
    for (auto& record : message.additions) {
        if (record.mType != ::dns::RecordType::kOPT || saw_opt || !record.mName.empty()) return false;
        saw_opt = true;
        const auto opt = record.getRData<::dns::RDataOPT>();
        if (!opt) return false;
        const auto& data = opt->mData;
        std::size_t offset = 0;
        while (offset < data.size()) {
            if (data.size() - offset < 4) return false;
            const auto code = (static_cast<unsigned>(data[offset]) << 8) | data[offset + 1];
            const auto size = (static_cast<unsigned>(data[offset + 2]) << 8) | data[offset + 3];
            offset += 4;
            if (code != 8 || saw_ecs || size > data.size() - offset || size < 4) return false;
            saw_ecs = true;
            const auto family = (static_cast<unsigned>(data[offset]) << 8) | data[offset + 1];
            const auto source = data[offset + 2];
            const auto scope = data[offset + 3];
            if ((family != 1 && family != 2) || source > (family == 1 ? 32 : 128) ||
                scope > (family == 1 ? 32 : 128) || size != 4 + (source + 7) / 8) return false;
            offset += size;
        }
        key.append(reinterpret_cast<const char*>(&record.mClass), sizeof(record.mClass));
        key.append(reinterpret_cast<const char*>(&record.mTtl), sizeof(record.mTtl));
        if (!data.empty()) key.append(reinterpret_cast<const char*>(data.data()), data.size());
    }
    return true;
}

std::vector<EntryPlan> Entries(const policy::PolicyResolver& resolver) {
    std::vector<EntryPlan> result;
    auto add_string = [&result](const std::string& text) {
        const auto* provider = ppp::dns::DnsProviderCatalog::GetProvider(ppp::string(text.data(), text.size()));
        if (provider) {
            for (const auto& entry : *provider)
                if (entry.protocol == ppp::dns::Protocol::DoH || entry.protocol == ppp::dns::Protocol::DoT)
                    result.push_back({entry, {}, {}});
            return;
        }
        const auto scheme = text.find("://");
        if (scheme == std::string::npos) return;
        const auto protocol = text.substr(0, scheme);
        const auto end = text.find_first_of("/?#", scheme + 3);
        const auto authority = text.substr(scheme + 3, end - scheme - 3);
        Entry entry;
        if (protocol == "udp") entry.protocol = ppp::dns::Protocol::UDP;
        else if (protocol == "tcp") entry.protocol = ppp::dns::Protocol::TCP;
        else if (protocol == "tls") entry.protocol = ppp::dns::Protocol::DoT;
        else if (protocol == "https") entry.protocol = ppp::dns::Protocol::DoH;
        else return;
        entry.address.assign(authority.data(), authority.size());
        const auto colon = authority.find(':');
        entry.hostname.assign(authority.data(), colon == std::string::npos ? authority.size() : colon);
        if (protocol == "https") entry.url.assign(text.data(), text.size());
        result.push_back({std::move(entry), {}, {}});
    };
    auto add_spec = [&result](const policy::PolicyResolver::Server& spec) {
            const auto scheme = spec.uri.find("://");
            if (scheme == std::string::npos) return;
            const auto protocol = spec.uri.substr(0, scheme);
            const auto end = spec.uri.find_first_of("/?#", scheme + 3);
            const auto authority = spec.uri.substr(scheme + 3, end - scheme - 3);
            Entry base;
            if (protocol == "udp") base.protocol = ppp::dns::Protocol::UDP;
            else if (protocol == "tcp") base.protocol = ppp::dns::Protocol::TCP;
            else if (protocol == "tls") base.protocol = ppp::dns::Protocol::DoT;
            else if (protocol == "https") base.protocol = ppp::dns::Protocol::DoH;
            else return;
            const auto colon = authority.find(':');
            base.hostname.assign(authority.data(), colon == std::string::npos ? authority.size() : colon);
            if (protocol == "https") base.url.assign(spec.uri.data(), spec.uri.size());
            if (spec.addresses.empty()) {
                boost::system::error_code address_error;
                const auto literal = boost::asio::ip::make_address(base.hostname, address_error);
                if (!address_error && literal.is_v4()) {
                    base.address.assign(authority.data(), authority.size());
                    result.push_back({std::move(base), {}, {}});
                    return;
                }
                EntryPlan plan;
                plan.endpoint = base;
                plan.target_hostname.assign(base.hostname.data(), base.hostname.size());
                if (colon != std::string::npos) {
                    plan.endpoint.address.assign(authority.data() + colon + 1, authority.size() - colon - 1);
                    plan.endpoint.address.insert(0, ":");
                }
                for (const auto& text : spec.bootstrap) {
                    const auto bootstrap_scheme = text.find("://");
                    if (bootstrap_scheme == std::string::npos || text.substr(0, bootstrap_scheme) != "udp") continue;
                    const auto bootstrap_end = text.find_first_of("/?#", bootstrap_scheme + 3);
                    const auto bootstrap_authority = text.substr(bootstrap_scheme + 3, bootstrap_end - bootstrap_scheme - 3);
                    Entry bootstrap;
                    bootstrap.protocol = ppp::dns::Protocol::UDP;
                    bootstrap.address.assign(bootstrap_authority.data(), bootstrap_authority.size());
                    plan.bootstrap.push_back(std::move(bootstrap));
                }
                if (!plan.bootstrap.empty()) result.push_back(std::move(plan));
                return;
            }
            for (const auto& address : spec.addresses) {
                EntryPlan plan;
                plan.endpoint = base;
                plan.endpoint.address.assign(address.data(), address.size());
                if (colon != std::string::npos) {
                    plan.endpoint.address.push_back(':');
                    plan.endpoint.address.append(authority.data() + colon + 1, authority.size() - colon - 1);
                }
                result.push_back(std::move(plan));
            }
    };
    if (resolver.server_order.empty()) {
        for (const auto& text : resolver.servers) add_string(text);
        for (const auto& spec : resolver.server_specs) add_spec(spec);
    } else {
        for (const auto& ref : resolver.server_order) {
            if (ref.structured) {
                if (ref.index < resolver.server_specs.size()) add_spec(resolver.server_specs[ref.index]);
            } else if (ref.index < resolver.servers.size()) add_string(resolver.servers[ref.index]);
        }
    }
    return result;
}
}

struct PolicyResolverService::Operation : std::enable_shared_from_this<Operation> {
    struct Waiter {
        std::uint64_t id = 0;
        Packet query;
        Callback callback;
        std::shared_ptr<const DnsSessionContext> session;
        std::shared_ptr<const policy::PolicySnapshot> snapshot;
    };
    std::shared_ptr<PolicyResolverService> owner;
    std::shared_ptr<const policy::PolicySnapshot> snapshot;
    std::shared_ptr<const DnsSessionContext> session;
    Packet query;
    Action via = Action::Proxy;
    std::vector<EntryPlan> entries;
    std::size_t index = 0;
    std::size_t bootstrap_index = 0;
    std::uint64_t attempt = 0;
    std::atomic_bool done{false};
    std::atomic_bool active{true};
    std::atomic_bool closing{false};
    bool saw_timeout_attempt = false;
    bool request_timeout_recorded = false;
    bool cacheable = true;
    std::string key;
    std::string operation_key;
    std::size_t pending_size = 0;
    std::vector<Waiter> waiters;
    boost::asio::steady_timer deadline;
    boost::asio::steady_timer retry;
    boost::asio::strand<boost::asio::io_context::executor_type> strand;
    explicit Operation(const std::shared_ptr<PolicyResolverService>& service)
        : owner(service), deadline(service->context_), retry(service->context_), strand(service->context_.get_executor()) {}

    void RecordRequestTimeout() {
        if (request_timeout_recorded) return;
        request_timeout_recorded = true;
        if (owner->telemetry_) owner->telemetry_->RecordDnsTimeout();
    }

    Packet ForWaiter(const Packet& response, const Packet& request) {
        ::dns::Message answer, query_message;
        if (!Decode(response, answer) || !Decode(request, query_message) ||
            answer.questions.size() != 1 || query_message.questions.size() != 1) return {};
        answer.mId = query_message.mId;
        answer.questions.front().mName = query_message.questions.front().mName;
        return Encode(answer);
    }
    void Complete(Packet response) {
        if (done.exchange(true)) return;
        active = false;
        try { deadline.cancel(); }
        catch (...) {}
        try { retry.cancel(); }
        catch (...) {}
        std::vector<Waiter> pending;
        {
            std::lock_guard<std::mutex> lock(owner->mutex_);
            pending.swap(waiters);
            owner->pending_bytes_ -= std::min(owner->pending_bytes_, pending_size);
            pending_size = 0;
            const auto it = owner->operations_.find(operation_key);
            if (it != owner->operations_.end() && it->second.get() == this) owner->operations_.erase(it);
            std::uint32_t ttl = 0;
            if (cacheable && !owner->closed_ && session && session->IsActive() && !response.empty() &&
                CacheTtl(query, response, ttl) && key.size() + response.size() <= 16 * 1024 * 1024) {
                auto& cache = owner->cache_;
                const auto old = cache.find(key);
                if (old != cache.end()) {
                    owner->cache_bytes_ -= old->second.bytes;
                    cache.erase(old);
                }
                CacheEntry entry;
                entry.response = response;
                ::dns::Message cached_message, query_message;
                if (Decode(entry.response, cached_message) && Decode(query, query_message)) {
                    const auto requested = query_message.questions.front().mType;
                    const bool has_requested = std::any_of(cached_message.answers.begin(), cached_message.answers.end(),
                        [requested](const auto& record) { return record.mType == requested; });
                    if (cached_message.mRCode == 3 || !has_requested) {
                        auto domain = query_message.questions.front().mName;
                        std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                        if (!domain.empty() && domain.back() == '.') domain.pop_back();
                        for (auto& record : cached_message.authorities) {
                            if (record.mType != ::dns::RecordType::SOA || record.mClass != query_message.questions.front().mClass) continue;
                            auto zone = record.mName;
                            std::transform(zone.begin(), zone.end(), zone.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                            if (!zone.empty() && zone.back() == '.') zone.pop_back();
                            const bool covers = zone.empty() || domain == zone ||
                                (domain.size() > zone.size() && domain.compare(domain.size() - zone.size(), zone.size(), zone) == 0 &&
                                    domain[domain.size() - zone.size() - 1] == '.');
                            if (!covers) continue;
                            if (record.getRData<::dns::RDataSOA>()) record.mTtl = ttl;
                        }
                        auto normalized = Encode(cached_message);
                        if (!normalized.empty()) entry.response = std::move(normalized);
                    }
                }
                const auto bytes = key.size() + entry.response.size();
                while (!cache.empty() && (cache.size() >= PolicyResolverService::kCacheCapacityEntries ||
                    owner->cache_bytes_ + bytes > 16 * 1024 * 1024)) {
                    auto oldest = std::min_element(cache.begin(), cache.end(), [](const auto& a, const auto& b) {
                        return a.second.last_use < b.second.last_use;
                    });
                    owner->cache_bytes_ -= oldest->second.bytes;
                    cache.erase(oldest);
                }
                entry.created = owner->now_();
                entry.expires = entry.created + std::chrono::seconds(ttl);
                entry.last_use = ++owner->cache_clock_;
                entry.bytes = bytes;
                owner->cache_bytes_ += bytes;
                cache[key] = std::move(entry);
            }
        }
        for (auto& waiter : pending) {
            Packet result;
            if (!owner->closed_ && waiter.session && waiter.session->IsActive())
                result = ForWaiter(response, waiter.query);
            waiter.callback(std::move(result));
        }
    }
    void Cancel(std::uint64_t id) {
        Waiter canceled;
        bool found = false;
        bool last = false;
        {
            std::lock_guard<std::mutex> lock(owner->mutex_);
            const auto it = std::find_if(waiters.begin(), waiters.end(), [id](const Waiter& waiter) { return waiter.id == id; });
            if (it != waiters.end()) {
                canceled = std::move(*it);
                waiters.erase(it);
                owner->pending_bytes_ -= std::min(owner->pending_bytes_, canceled.query.size());
                pending_size -= std::min(pending_size, canceled.query.size());
                found = true;
                last = waiters.empty();
                if (last) {
                    closing = true;
                    active = false;
                    ++attempt;
                    const auto operation = owner->operations_.find(operation_key);
                    if (operation != owner->operations_.end() && operation->second.get() == this)
                        owner->operations_.erase(operation);
                }
            }
        }
        if (!found) return;
        if (owner->telemetry_) owner->telemetry_->RecordDnsCancelled();
        if (last) Complete({});
        canceled.callback({});
    }
    void Advance() {
        ++index;
        bootstrap_index = 0;
    }
    void Send(const Entry& entry, Action exit, const Packet& request, std::uint64_t current,
        const std::function<void(Packet)>& on_response) {
        const auto self = shared_from_this();
        const std::function<bool()> active_check = [weak = std::weak_ptr<Operation>(self)] {
            const auto operation = weak.lock();
            return operation && operation->active && !operation->done && !operation->closing &&
                !operation->owner->closed_ && operation->session && operation->session->IsActive();
        };
        const auto complete = [self, current, on_response](Packet response) {
            boost::asio::post(self->strand, [self, current, on_response, response = std::move(response)]() mutable {
                if (self->done || !self->active || current != self->attempt) return;
                on_response(std::move(response));
            });
        };
        if (owner->custom_exchange_) owner->exchange_(entry, exit, request, session, complete);
        else owner->ExchangePacket(entry, exit, request, session, active_check, complete);
    }
    void ScheduleRetry(std::uint64_t current, const std::function<void()>& timeout) {
        const auto self = shared_from_this();
        retry.expires_after(std::chrono::milliseconds(1000));
        retry.async_wait(boost::asio::bind_executor(strand, [self, current, timeout](boost::system::error_code ec) {
            if (!ec && !self->done && self->active && current == self->attempt) {
                self->saw_timeout_attempt = true;
                if (self->owner->telemetry_) self->owner->telemetry_->RecordDnsTimeoutAttempt();
                timeout();
            }
        }));
    }
    void ExchangeCurrent() {
        const auto current = ++attempt;
        ScheduleRetry(current, [self = shared_from_this()] { self->Advance(); self->Next(); });
        const auto self = shared_from_this();
        Send(entries[index].endpoint, via, query, current, [self](Packet response) {
            try { self->retry.cancel(); }
            catch (...) {}
            if (SameQuestion(self->query, response) && !(response[2] & 0x02) &&
                ((response[3] & 15) == 0 || (response[3] & 15) == 3)) self->Complete(std::move(response));
            else {
                if (self->owner->telemetry_) self->owner->telemetry_->RecordDnsUpstreamFailure();
                self->Advance(); self->Next();
            }
        });
    }
    void BootstrapNext() {
        if (done) return;
        if (owner->closed_ || !active || !session || !session->IsActive()) { Complete({}); return; }
        auto& plan = entries[index];
        if (bootstrap_index >= plan.bootstrap.size()) { Advance(); Next(); return; }
        const auto current = ++attempt;
        const auto bootstrap = plan.bootstrap[bootstrap_index++];
        const auto bootstrap_query = PolicyResolverService::BuildQuery(plan.target_hostname);
        if (bootstrap_query.empty()) { BootstrapNext(); return; }
        ScheduleRetry(current, [self = shared_from_this()] { self->BootstrapNext(); });
        const auto self = shared_from_this();
        Send(bootstrap, Action::Direct, bootstrap_query, current, [self, bootstrap_query](Packet response) {
            try { self->retry.cancel(); }
            catch (...) {}
            const auto address = SameQuestion(bootstrap_query, response) && !(response[2] & 0x02) &&
                (response[3] & 15) == 0 ? PolicyResolverService::FirstAddress(response) : boost::asio::ip::address{};
            if (!address.is_v4() || address.is_unspecified()) {
                if (self->owner->telemetry_) self->owner->telemetry_->RecordDnsUpstreamFailure();
                self->BootstrapNext();
                return;
            }
            auto& endpoint = self->entries[self->index].endpoint;
            const auto port = endpoint.address;
            const auto resolved = address.to_string();
            endpoint.address.assign(resolved.data(), resolved.size());
            endpoint.address.append(port);
            self->entries[self->index].bootstrap_resolved = true;
            self->ExchangeCurrent();
        });
    }
    void Next() {
        if (done) return;
        if (owner->closed_ || !active || !session || !session->IsActive()) { Complete({}); return; }
        if (index == entries.size()) {
            if (saw_timeout_attempt) RecordRequestTimeout();
            Complete(ErrorResponse(query, 2));
            return;
        }
        if (!entries[index].bootstrap.empty() && !entries[index].bootstrap_resolved) {
            BootstrapNext();
            return;
        }
        ExchangeCurrent();
    }
};

PolicyResolverService::PolicyResolverService(boost::asio::io_context& context,
    ppp::dns::DnsResolver::ProtectSocketCallback protect, Exchange exchange, NowFunction now,
    std::shared_ptr<PolicyTelemetry> telemetry)
    : context_(context), protect_(std::move(protect)), exchange_(std::move(exchange)), custom_exchange_(static_cast<bool>(exchange_)),
      now_(now ? std::move(now) : NowFunction([] { return Clock::now(); })),
      telemetry_(telemetry ? std::move(telemetry) : std::make_shared<PolicyTelemetry>()) {
}

Packet PolicyResolverService::ErrorResponse(const Packet& query, unsigned code) {
    ::dns::Message message;
    if (!Decode(query, message) || message.questions.size() != 1) return {};
    message.mQr = 1; message.mRA = 1; message.mAA = 0; message.mTC = 0; message.mRCode = code;
    message.answers.clear(); message.authorities.clear(); message.additions.clear();
    return Encode(message);
}

Packet PolicyResolverService::BuildQuery(const std::string& domain) {
    ::dns::Message message;
    static std::atomic_uint next{0};
    message.mId = static_cast<std::uint16_t>(++next); message.mRD = 1;
    message.questions.emplace_back(domain);
    auto encoded = Encode(message);
    ::dns::Message verified;
    std::string expected = domain;
    if (!expected.empty() && expected.back() == '.') expected.pop_back();
    // The legacy wire encoder can encode interior empty labels as terminators.
    if (!Decode(encoded, verified) || verified.questions.size() != 1 ||
        verified.questions.front().mName != expected ||
        verified.questions.front().mType != ::dns::RecordType::kA ||
        verified.questions.front().mClass != ::dns::RecordClass::kIN) return {};
    return encoded;
}

boost::asio::ip::address PolicyResolverService::FirstAddress(const Packet& response) {
    ::dns::Message message;
    if (!Decode(response, message) || !message.mQr || message.mRCode) return {};
    for (auto& record : message.answers) if (record.mType == ::dns::RecordType::kA && record.mClass == ::dns::RecordClass::kIN) {
        const auto data = record.getRData<::dns::RDataA>();
        if (data) {
            boost::asio::ip::address_v4::bytes_type bytes;
            std::copy_n(data->getAddress(), 4, bytes.begin());
            return boost::asio::ip::address_v4(bytes);
        }
    }
    return {};
}

PolicyResolverService::RequestHandle PolicyResolverService::Resolve(const std::shared_ptr<const policy::PolicySnapshot>& snapshot,
    const std::shared_ptr<const DnsSessionContext>& session, const Packet& query, const Callback& callback) {
    if (!callback) return {};
    ::dns::Message message;
    if (closed_ || !snapshot || !session || !session->IsActive() || !Decode(query, message) ||
        message.questions.size() != 1 || message.mQr || message.mOpCode ||
        message.questions.front().mClass != ::dns::RecordClass::kIN) { callback({}); return {}; }
    const auto& question = message.questions.front();
    const auto plan = policy::PolicyEvaluator::PlanDns(*snapshot, question.mName);
    if (telemetry_) telemetry_->RecordPolicyDecision(plan.rejected ? policy::PolicyAction::Reject : plan.action);
    if (plan.rejected) { callback(ErrorResponse(query, 5)); return {}; }
    if (question.mType == ::dns::RecordType::kAAAA) { callback(ErrorResponse(query, 0)); return {}; }
    const auto selected = snapshot->Resolvers().find(plan.resolver);
    if (selected == snapshot->Resolvers().end()) { callback(ErrorResponse(query, 2)); return {}; }
    auto entries = Entries(selected->second);
    std::string key;
    const bool semantic = BuildSemanticKey(query, message, selected->second, plan.via, entries, key);
    std::shared_ptr<Operation> operation;
    bool start = false;
    std::uint64_t waiter_id = 0;
    Packet cached;
    bool unavailable = false;
    std::uint32_t cached_elapsed = 0;
    std::string operation_key = key;
    if (semantic) {
        const auto session_identity = reinterpret_cast<std::uintptr_t>(session.get());
        operation_key.append(reinterpret_cast<const char*>(&session_identity), sizeof(session_identity));
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) unavailable = true;
        if (!unavailable && semantic) {
            const auto it = cache_.find(key);
            if (it != cache_.end()) {
                const auto now = now_();
                if (it->second.expires <= now) {
                    cache_bytes_ -= it->second.bytes;
                    cache_.erase(it);
                } else {
                    auto response = it->second.response;
                    const auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.created).count();
                    if (age > 0) cached_elapsed = static_cast<std::uint32_t>(std::min<std::int64_t>(age, UINT32_MAX));
                    it->second.last_use = ++cache_clock_;
                    cached = std::move(response);
                    if (telemetry_) telemetry_->RecordDnsCacheHit();
                }
            }
        }
        if (!unavailable && semantic && cached.empty() && telemetry_) telemetry_->RecordDnsCacheMiss();
        if (!unavailable && cached.empty()) {
            auto found = semantic ? operations_.find(operation_key) : operations_.end();
            if (found != operations_.end() && (found->second->done || found->second->closing)) {
                operations_.erase(found);
                found = operations_.end();
            }
            if (found != operations_.end() && found->second->waiters.size() >= 256) unavailable = true;
            else if ((found == operations_.end() && operations_.size() >= 1024) ||
                pending_bytes_ + query.size() > 16 * 1024 * 1024) unavailable = true;
            else {
                if (found != operations_.end()) {
                    operation = found->second;
                    if (telemetry_) telemetry_->RecordDnsCacheCoalesced();
                }
                else {
                    if (!semantic) {
                        operation_key.assign(1, static_cast<char>(0xff));
                        operation_key.append(reinterpret_cast<const char*>(&next_waiter_id_), sizeof(next_waiter_id_));
                    }
                    operation = std::make_shared<Operation>(shared_from_this());
                    operation->snapshot = snapshot; operation->session = session; operation->query = query;
                    operation->via = plan.via; operation->entries = std::move(entries); operation->key = key;
                    operation->operation_key = operation_key;
                    operation->cacheable = semantic;
                    operations_[operation_key] = operation;
                    start = true;
                }
                waiter_id = next_waiter_id_++;
                if (!waiter_id) waiter_id = next_waiter_id_++;
                operation->waiters.push_back({waiter_id, query, callback, session, snapshot});
                operation->pending_size += query.size();
                pending_bytes_ += query.size();
            }
        }
    }
    if (unavailable) { callback(ErrorResponse(query, 2)); return {}; }
    if (!cached.empty()) {
        ::dns::Message response;
        if (Decode(cached, response)) {
            const auto it_name = message.questions.front().mName;
            response.mId = message.mId;
            response.questions.front().mName = it_name;
            DecrementTtls(response, cached_elapsed);
            cached = Encode(response);
        }
        callback(!closed_ && session->IsActive() ? std::move(cached) : Packet{});
        return {};
    }
    if (start) boost::asio::post(operation->strand, [operation] {
        if (operation->done) return;
        operation->deadline.expires_after(std::chrono::seconds(5));
        operation->deadline.async_wait(boost::asio::bind_executor(operation->strand, [operation](boost::system::error_code ec) {
            if (!ec && !operation->done) {
                operation->RecordRequestTimeout();
                operation->Complete(ErrorResponse(operation->query, 2));
            }
        }));
        operation->Next();
    });
    std::weak_ptr<Operation> weak_operation = operation;
    const auto waiter = waiter_id;
    return RequestHandle([weak_operation, waiter] {
        if (const auto pending = weak_operation.lock()) {
            try { boost::asio::post(pending->strand, [pending, waiter] { pending->Cancel(waiter); }); }
            catch (...) {}
        }
    });
}

void PolicyResolverService::Close() noexcept {
    if (closed_.exchange(true)) return;
    std::vector<std::shared_ptr<Operation>> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& item : operations_) pending.push_back(item.second);
    }
    for (const auto& operation : pending) boost::asio::post(operation->strand, [operation] { operation->Complete({}); });
}

void PolicyResolverService::ExchangePacket(const Entry& entry, Action via, const Packet& query,
    const std::shared_ptr<const DnsSessionContext>& session,
    const std::function<bool()>& active, const Callback& callback) {
    const auto transport = session ? session->Transport() : nullptr;
    if (via == Action::Proxy && entry.protocol == ppp::dns::Protocol::UDP) {
        const std::string address(entry.address.data(), entry.address.size());
        const auto colon = address.find(':');
        boost::system::error_code ec;
        const auto ip = boost::asio::ip::make_address(address.substr(0, colon), ec);
        if (!transport || ec || !ip.is_v4()) { callback({}); return; }
        unsigned port = 53;
        if (colon != std::string::npos) {
            const auto first = address.data() + colon + 1;
            const auto last = address.data() + address.size();
            const auto parsed = std::from_chars(first, last, port);
            if (parsed.ec != std::errc{} || parsed.ptr != last || port == 0 || port > 65535) { callback({}); return; }
        }
        const auto remote = boost::asio::ip::udp::endpoint(ip, static_cast<unsigned short>(port));
        struct UdpOperation : std::enable_shared_from_this<UdpOperation> {
            boost::asio::ip::udp::socket socket;
            boost::asio::steady_timer timer;
            boost::asio::steady_timer activity;
            boost::asio::strand<boost::asio::io_context::executor_type> strand;
            std::atomic_bool done{false};
            std::function<bool()> active;
            std::function<void(Packet)> finish;
            explicit UdpOperation(boost::asio::io_context& io) : socket(io), timer(io), activity(io), strand(io.get_executor()) {}
            void Watch() {
                if (done) return;
                const auto self = shared_from_this();
                activity.expires_after(std::chrono::milliseconds(25));
                activity.async_wait(boost::asio::bind_executor(strand, [self](boost::system::error_code error) {
                    if (error || self->done) return;
                    if (!self->active || !self->active()) self->finish({});
                    else self->Watch();
                }));
            }
        };
        const auto operation = std::make_shared<UdpOperation>(context_);
        boost::asio::post(operation->strand, [operation, transport, session, query, remote, active, callback] {
        boost::system::error_code ec;
        operation->socket.open(boost::asio::ip::udp::v4(), ec);
        if (!ec) operation->socket.bind({boost::asio::ip::address_v4::loopback(), 0}, ec);
        const auto local = !ec ? operation->socket.local_endpoint(ec) : boost::asio::ip::udp::endpoint{};
        if (ec) { callback({}); return; }
        const auto finish = [operation, transport, local, active, callback](Packet response) {
            boost::asio::post(operation->strand, [operation, transport, local, active, callback, response = std::move(response)]() mutable {
            if (operation->done.exchange(true)) return;
            transport->ReleaseDatagramHandler(local);
            try { operation->timer.cancel(); }
            catch (...) {}
            try { operation->activity.cancel(); }
            catch (...) {}
            boost::system::error_code ignored;
            operation->socket.close(ignored);
            if (!active()) response.clear();
            operation->active = {};
            operation->finish = {};
            callback(std::move(response));
            });
        };
        operation->active = active;
        operation->finish = finish;
        if (!active() || !transport->RegisterDatagramHandler(local, [remote, query, active, finish](const auto&, const auto& from, void* packet, int length) {
            if (!active() || from != remote || !packet || length < 12) return true;
            Packet response(static_cast<Byte*>(packet), static_cast<Byte*>(packet) + length);
            if (SameQuestion(query, response)) finish(std::move(response));
            return true;
        })) { finish({}); return; }
        operation->timer.expires_after(std::chrono::milliseconds(1000));
        operation->timer.async_wait(boost::asio::bind_executor(operation->strand,
            [finish](boost::system::error_code error) { if (!error) finish({}); }));
        operation->Watch();
        if (!active() || !session->IsActive() || !transport->SendDnsDatagram(local, remote, query.data(), static_cast<int>(query.size()))) finish({});
        });
        return;
    }
    auto resolver = std::make_shared<ppp::dns::DnsResolver>(context_);
    const std::weak_ptr<PolicyResolverService> weak_self = shared_from_this();
    const auto attempt_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    resolver->SetQueryActiveCheck([weak_self, session, attempt_deadline, active] {
        const auto service = weak_self.lock();
        return service && !service->closed_ && active() && session && session->IsActive() &&
            std::chrono::steady_clock::now() < attempt_deadline;
    });
    resolver->SetTlsVerifyPeer(true);
    resolver->SetAllowIPv6Response(false);
    resolver->SetEcsConfig(false, "");
    if (via == Action::Proxy) {
        if (!transport) { callback({}); return; }
        resolver->SetTcpConnectCallback([transport, session, active](auto& socket, const auto& endpoint,
            const auto& resolver_active, const auto& cb) {
            const auto live = [session, active, resolver_active] {
                return session->IsActive() && active() && (!resolver_active || resolver_active());
            };
            if (!live()) { cb(boost::asio::error::operation_aborted); return; }
            transport->ConnectDnsStream(socket, endpoint, live, [live, cb](boost::system::error_code ec) {
                cb(live() ? ec : boost::system::error_code(boost::asio::error::operation_aborted));
            });
        });
    } else {
        if (!protect_) { callback({}); return; }
        resolver->SetProtectSocketCallback(protect_);
    }
    ppp::vector<Entry> entries{entry};
    resolver->ResolveAsyncWithEntries(entries, false, query.data(), static_cast<int>(query.size()),
        [resolver, callback](Packet response) { callback(std::move(response)); });
}

}
