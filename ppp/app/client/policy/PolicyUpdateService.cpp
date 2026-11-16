#include "PolicyUpdateService.h"
#include <ppp/Filesystem.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <limits>
#include <sstream>

namespace ppp::app::client::policy {
namespace {
namespace fs = ppp::filesystem::fs;
using ppp::filesystem::error_code;
constexpr std::size_t kSourceLimit = 64u * 1024u * 1024u;
constexpr std::size_t kAggregateLimit = 256u * 1024u * 1024u;
constexpr auto kRequestLimit = std::chrono::seconds(30);
constexpr auto kMinBackoff = std::chrono::seconds(60);
constexpr auto kMaxBackoff = std::chrono::hours(1);
constexpr auto kStatusHeartbeat = std::chrono::seconds(30);

void Part(std::string& target, const std::string& value) {
    target += std::to_string(value.size()); target.push_back(':'); target += value; target.push_back('\n');
}

std::int64_t Millis(std::chrono::system_clock::time_point point) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(point.time_since_epoch()).count();
}

std::string BundleDigest(const DurablePolicyBundle& bundle) {
    std::string canonical = PolicySha256(bundle.rules);
    for (const auto& entry : bundle.rule_sets) {
        Part(canonical, entry.first);
        Part(canonical, PolicySha256(entry.second.bytes));
    }
    return PolicySha256(canonical);
}

bool ReadBytes(const std::string& path, std::size_t max_size, std::string& bytes) {
    error_code ec;
    const auto size_before = fs::file_size(path, ec);
    if (ec || size_before > max_size || size_before > std::numeric_limits<std::size_t>::max()) return false;
    const auto modified_before = fs::last_write_time(path, ec);
    if (ec) return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    bytes.resize(static_cast<std::size_t>(size_before));
    if (size_before) input.read(bytes.data(), static_cast<std::streamsize>(size_before));
    if (static_cast<std::uint64_t>(input.gcount()) != size_before) return false;
    char extra = 0;
    if (input.get(extra)) return false;
    if (!input.eof()) return false;
    const auto size_after = fs::file_size(path, ec);
    if (ec || size_after != size_before) return false;
    const auto modified_after = fs::last_write_time(path, ec);
    return !ec && modified_after == modified_before;
}

std::string LowerHex(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool CheckedAdd(std::chrono::system_clock::time_point now, std::chrono::seconds delta,
    std::chrono::system_clock::time_point& result) {
    if (delta.count() < 0) return false;
    using Duration = std::chrono::system_clock::duration;
    using Rep = Duration::rep;
    const long double ticks_per_second = static_cast<long double>(Duration::period::den) /
        static_cast<long double>(Duration::period::num);
    const long double ticks = static_cast<long double>(delta.count()) * ticks_per_second;
    if (ticks > static_cast<long double>(std::numeric_limits<Rep>::max())) return false;
    const Duration addition = std::chrono::duration_cast<Duration>(delta);
    const auto since_epoch = now.time_since_epoch();
    if (since_epoch > Duration::max() - addition) return false;
    result = std::chrono::system_clock::time_point(since_epoch + addition);
    return true;
}

bool ParseInterval(const std::string& value, std::chrono::seconds& result) {
    if (value.empty()) return false;
    std::size_t digits = 0;
    while (digits < value.size() && value[digits] >= '0' && value[digits] <= '9') ++digits;
    if (digits == 0 || digits == value.size()) return false;
    std::uint64_t amount = 0;
    for (std::size_t i = 0; i < digits; ++i) {
        const unsigned digit = static_cast<unsigned>(value[i] - '0');
        if (amount > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) return false;
        amount = amount * 10 + digit;
    }
    const std::string unit = value.substr(digits);
    std::uint64_t multiplier = 0;
    if (unit == "s") multiplier = 1;
    else if (unit == "m") multiplier = 60;
    else if (unit == "h") multiplier = 3600;
    else if (unit == "d") multiplier = 86400;
    else return false;
    if (amount > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / multiplier) return false;
    result = std::chrono::seconds(static_cast<std::int64_t>(amount * multiplier));
    return result.count() > 0;
}

PolicyUpdateResult Failure(std::string diagnostic) {
    PolicyUpdateResult result;
    result.code = PolicyUpdateResultCode::Failed;
    result.diagnostic = std::move(diagnostic);
    return result;
}

} // namespace

struct PolicyUpdateService::Materialized final {
    PolicySource source;
    DurablePolicyBundle bundle;
};

PolicyBootstrapState PolicyBootstrapGate::State() const noexcept {
    return state_.load(std::memory_order_acquire);
}
bool PolicyBootstrapGate::AllowsBusiness() const noexcept { return State() == PolicyBootstrapState::Ready; }
void PolicyBootstrapGate::Open() noexcept { state_.store(PolicyBootstrapState::Ready, std::memory_order_release); }
void PolicyBootstrapGate::Fail() noexcept { state_.store(PolicyBootstrapState::Failed, std::memory_order_release); }
void PolicyBootstrapGate::Close() noexcept { state_.store(PolicyBootstrapState::Closed, std::memory_order_release); }

std::chrono::system_clock::time_point SystemPolicyUpdateClock::Now() const { return std::chrono::system_clock::now(); }
void SystemPolicyUpdateClock::WaitUntil(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
    std::chrono::system_clock::time_point deadline, const std::function<bool()>& interrupted) {
    cv.wait_until(lock, deadline, interrupted);
}

PolicyUpdateService::PolicyUpdateService(PolicyRuntime& runtime, PolicySource declared_source,
    std::shared_ptr<DurablePolicyBundleStore> store, std::shared_ptr<PolicyUpdateFetcher> fetcher,
    std::shared_ptr<PolicyUpdateClock> clock, std::function<PolicyLoadResult()> declaration_loader)
    : runtime_(runtime), declared_source_(std::move(declared_source)), store_(std::move(store)),
      fetcher_(std::move(fetcher)), clock_(clock ? std::move(clock) : std::make_shared<SystemPolicyUpdateClock>()),
      declaration_loader_(std::move(declaration_loader)),
      identity_fingerprint_(ImmutableFingerprint(declared_source_)),
      cancellation_(std::make_shared<std::atomic_bool>(false)) {
    status_.identity_fingerprint = identity_fingerprint_;
}

PolicyUpdateService::~PolicyUpdateService() { Close(); }

std::string PolicyUpdateService::ImmutableFingerprint(const PolicySource& source) {
    std::string canonical;
    Part(canonical, std::to_string(source.version));
    Part(canonical, source.config_path);
    Part(canonical, source.base_path);
    Part(canonical, source.rules_path);
    Part(canonical, source.ipv6);
    Part(canonical, source.dns_mode);
    Part(canonical, source.fake_ip_range);
    Part(canonical, source.fake_ip_storage);
    Part(canonical, source.fake_ip_identity);
    Part(canonical, source.tcp_domain_sniff ? "1" : "0");
    Part(canonical, source.updates_enabled ? "1" : "0");
    Part(canonical, source.updates_interval);
    Part(canonical, std::to_string(static_cast<int>(source.updates_via)));
    Part(canonical, source.updates_allow_http ? "1" : "0");
    for (const auto& bootstrap : source.updates_bootstrap) Part(canonical, bootstrap);
    for (const auto& resolver : source.resolvers) {
        Part(canonical, resolver.first);
        Part(canonical, std::to_string(static_cast<int>(resolver.second.via)));
        for (const auto& server : resolver.second.servers) Part(canonical, server);
        for (const auto& server : resolver.second.server_specs) {
            Part(canonical, server.uri);
            for (const auto& address : server.addresses) Part(canonical, address);
            for (const auto& bootstrap : server.bootstrap) Part(canonical, bootstrap);
        }
        for (const auto& reference : resolver.second.server_order) {
            Part(canonical, reference.structured ? "structured" : "legacy");
            Part(canonical, std::to_string(reference.index));
        }
    }
    for (const auto& entry : source.rule_sets) {
        Part(canonical, entry.first);
        Part(canonical, entry.second.format);
        Part(canonical, entry.second.path);
        Part(canonical, entry.second.url);
        Part(canonical, entry.second.tag);
        Part(canonical, entry.second.sha256);
    }
    return PolicySha256(canonical);
}

bool PolicyUpdateService::LoadDeclaration(PolicySource& source, std::string& error) const {
    if (!declaration_loader_) { source = declared_source_; return true; }
    PolicyLoadResult loaded;
    try { loaded = declaration_loader_(); }
    catch (...) { error = "policy declaration loader failed"; return false; }
    bool has_remote_source = false;
    for (const auto& entry : loaded.source.rule_sets) has_remote_source = has_remote_source || !entry.second.url.empty();
    for (const auto& diagnostic : loaded.diagnostics) {
        if (diagnostic.severity != "error") continue;
        bool remote_unavailable = diagnostic.code == "E_POLICY_SOURCE_UNAVAILABLE" && has_remote_source &&
            diagnostic.path.rfind("client.policy.rule-sets.", 0) == 0;
        if (remote_unavailable) {
            const auto start = std::string("client.policy.rule-sets.").size();
            const auto end = diagnostic.path.find('.', start);
            const auto name = diagnostic.path.substr(start, end == std::string::npos ? std::string::npos : end - start);
            const auto found = loaded.source.rule_sets.find(name);
            remote_unavailable = found != loaded.source.rule_sets.end() && !found->second.url.empty();
        }
        if (!remote_unavailable) {
            error = "policy declaration validation failed (" + diagnostic.code + ")";
            return false;
        }
    }
    source = std::move(loaded.source);
    return true;
}

PolicyUpdateResult PolicyUpdateService::RestoreBundle(const DurablePolicyLoad& loaded, bool fallback,
    const PolicySource& declaration) {
    if (!loaded.Ok() || loaded.bundle.identity_fingerprint != identity_fingerprint_) return Failure("durable policy bundle failed integrity or identity validation");
    if (loaded.bundle.rule_sets.size() != declaration.rule_sets.size()) return Failure("durable policy bundle is missing a declared rule-set");
    PolicySource materialized = declaration;
    materialized.rules_text = loaded.bundle.rules;
    for (auto& entry : materialized.rule_sets) {
        auto found = loaded.bundle.rule_sets.find(entry.first);
        if (found == loaded.bundle.rule_sets.end() || found->second.format != entry.second.format ||
            found->second.tag != entry.second.tag || (!entry.second.sha256.empty() &&
                PolicySha256(found->second.bytes) != LowerHex(entry.second.sha256))) {
            return Failure("durable policy bundle does not match declared rule-set metadata");
        }
        entry.second.text = found->second.bytes;
        entry.second.materialized = true;
    }
    auto candidate = runtime_.Prepare(materialized);
    if (!candidate.Ok()) return Failure("durable policy bundle failed compiler validation");
    if (fallback) {
        std::string repair_error;
        if (!store_->RestorePreviousAsCurrent(identity_fingerprint_, repair_error))
            return Failure("previous policy bundle validated but durable current pointer repair failed");
    }
    if (!runtime_.Commit(candidate)) return Failure("durable policy candidate could not be committed to runtime");
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        status_.active_version = candidate.snapshot->Version();
        status_.identity_fingerprint = identity_fingerprint_;
        status_.durable_current = true;
        status_.durable_previous = fallback;
        status_.prepared_pending_commit = false;
        status_.prepared_version = 0;
        status_.prepared_digest.clear();
        status_.offline = false;
        status_.last_result = fallback ? "restored_previous" : "restored_current";
        status_.last_diagnostic = fallback ? "Current policy bundle was rejected; previous validated bundle restored." : std::string();
        status_.sources.clear();
        for (const auto& entry : loaded.bundle.rule_sets) {
            const auto& source = entry.second;
            status_.sources.push_back({entry.first, source.url_redacted, source.etag, source.last_modified,
                PolicySha256(source.bytes), source.bytes.size(), source.validated_at_ms});
        }
    }
    PolicyUpdateResult result;
    result.code = PolicyUpdateResultCode::Updated;
    result.version = candidate.snapshot->Version();
    result.diagnostic = fallback ? "restored previous validated bundle" : "restored current validated bundle";
    PublishStatus();
    return result;
}

PolicyUpdateResult PolicyUpdateService::RestoreAndPrepare() {
    std::lock_guard<std::mutex> operation(operation_mutex_);
    if (closed_) return {PolicyUpdateResultCode::Closed, 0, "policy updater is closed"};
    PolicySource declaration;
    std::string declaration_error;
    if (!LoadDeclaration(declaration, declaration_error)) return Failure(declaration_error);
    if (ImmutableFingerprint(declaration) != identity_fingerprint_)
        return {PolicyUpdateResultCode::RequiresReconnect, 0, "policy configuration changed and requires reconnect"};
    if (!store_) return Failure("durable policy store is unavailable");
    std::string lock_error;
    auto writer = store_->AcquireWriterLock(lock_error);
    if (!writer) return Failure("durable policy store lock failed");
    auto current = store_->LoadCurrent(identity_fingerprint_);
    if (current.Ok()) {
        auto restored = RestoreBundle(current, false, declaration);
        if (restored.Ok()) { gate_.Open(); return restored; }
        current.error = restored.diagnostic;
    }
    auto previous = store_->LoadPrevious(identity_fingerprint_);
    if (previous.Ok()) {
        auto restored = RestoreBundle(previous, true, declaration);
        if (restored.Ok()) {
            gate_.Open();
            return restored;
        }
    }
    gate_.Close();
    return Failure(current.found ? "no complete, valid durable policy bundle could be restored" : "no durable policy bundle is available");
}

PolicyUpdateResult PolicyUpdateService::BootstrapUpdate() {
    gate_.Close();
    auto result = RunOnce(PolicyUpdateMode::CommitRuntime);
    if (result.Ok() && runtime_.GetSnapshot()) gate_.Open();
    else gate_.Fail();
    return result;
}

PolicyUpdateResult PolicyUpdateService::RunOnce(PolicyUpdateMode mode) {
    std::lock_guard<std::mutex> operation(operation_mutex_);
    if (closed_) return {PolicyUpdateResultCode::Closed, 0, "policy updater is closed"};
    auto result = RunOnceLocked(mode);
    RecordResult(result, true);
    return result;
}

PolicyUpdateResult PolicyUpdateService::CheckImmutableConfiguration(const PolicySource& candidate) const {
    if (ImmutableFingerprint(candidate) == identity_fingerprint_) {
        return {PolicyUpdateResultCode::Unchanged, 0, "immutable policy configuration matches"};
    }
    return {PolicyUpdateResultCode::RequiresReconnect, 0, "policy configuration changed and requires reconnect"};
}

PolicyUpdateResult PolicyUpdateService::RunOnceLocked(PolicyUpdateMode mode) {
    std::shared_ptr<PolicyUpdateFetcher> fetcher;
    {
        std::lock_guard<std::mutex> lock(fetcher_mutex_);
        fetcher = fetcher_;
    }
    PolicySource current_source;
    std::string declaration_error;
    if (!LoadDeclaration(current_source, declaration_error)) return Failure(declaration_error);
    if (ImmutableFingerprint(current_source) != identity_fingerprint_)
        return {PolicyUpdateResultCode::RequiresReconnect, 0, "policy configuration changed and requires reconnect"};
    if (!store_) return Failure("durable policy store is unavailable");
    std::string lock_error;
    auto writer = store_->AcquireWriterLock(lock_error);
    if (!writer) return Failure("durable policy store lock failed");
    auto old_load = store_->LoadCurrent(identity_fingerprint_);
    DurablePolicyBundle old_bundle;
    bool has_old = old_load.Ok();
    if (has_old) old_bundle = old_load.bundle;

    Materialized materialized;
    materialized.source = current_source;
    materialized.bundle.schema = 1;
    materialized.bundle.identity_fingerprint = identity_fingerprint_;
    const auto now = clock_->Now();
    const std::int64_t now_ms = Millis(now);
    if (!current_source.rules_path.empty()) {
        if (!ReadBytes(current_source.rules_path, kSourceLimit, materialized.bundle.rules))
            return Failure("cannot read complete policy rules file");
    } else {
        materialized.bundle.rules = current_source.rules_text;
        if (materialized.bundle.rules.size() > kSourceLimit) return Failure("policy rules exceed per-source size limit");
    }
    materialized.bundle.rules_validated_at_ms = now_ms;
    materialized.source.rules_text = materialized.bundle.rules;
    std::size_t aggregate = materialized.bundle.rules.size();
    const auto deadline = std::chrono::steady_clock::now() + kRequestLimit;

    for (auto& entry : materialized.source.rule_sets) {
        auto& declared = entry.second;
        if (declared.url.empty() && !declared.path.empty()) {
            std::string local_bytes;
            if (!ReadBytes(declared.path, kSourceLimit, local_bytes))
                return Failure("cannot read complete local rule-set");
            declared.text = std::move(local_bytes);
            declared.materialized = true;
        }
        DurablePolicySource cached;
        bool has_cached = false;
        if (has_old) {
            const auto found = old_bundle.rule_sets.find(entry.first);
            if (found != old_bundle.rule_sets.end() && found->second.format == declared.format && found->second.tag == declared.tag) {
                cached = found->second;
                has_cached = declared.sha256.empty() || PolicySha256(cached.bytes) == LowerHex(declared.sha256);
            }
        }
        DurablePolicySource source;
        source.name = entry.first; source.format = declared.format; source.tag = declared.tag;
        source.sha256 = declared.sha256;
        if (!declared.url.empty()) source.url_fingerprint = PolicySha256(declared.url);
        if (!declared.url.empty()) {
            if (!fetcher) {
                if (!has_cached || cached.url_fingerprint != source.url_fingerprint)
                    return Failure("remote policy fetcher is unavailable and no verified cached source matches");
                source.bytes = cached.bytes;
                source.etag = cached.etag;
                source.last_modified = cached.last_modified;
                source.url_redacted = cached.url_redacted;
            } else {
                PolicyFetchRequest request;
                request.source_name = entry.first;
                request.url = declared.url;
                request.via = current_source.updates_via == PolicyAction::Direct ? PolicyUpdateVia::Direct : PolicyUpdateVia::Proxy;
                request.deadline = deadline;
                request.max_bytes = kSourceLimit;
                request.cancelled = cancellation_;
                if (has_cached && cached.url_fingerprint == source.url_fingerprint) {
                    request.etag = cached.etag; request.last_modified = cached.last_modified;
                }
                PolicyFetchResponse response;
                if (!fetcher->Fetch(request, response)) return Failure(response.diagnostic.empty() ? "policy source fetch failed" : response.diagnostic);
                if (response.status == 304) {
                    if (!has_cached || request.etag.empty() && request.last_modified.empty()) return Failure("304 response has no verified matching cached source");
                    source.bytes = cached.bytes;
                    source.etag = response.etag.empty() ? cached.etag : response.etag;
                    source.last_modified = response.last_modified.empty() ? cached.last_modified : response.last_modified;
                } else if (response.status >= 200 && response.status < 300) {
                    if (response.body.size() > kSourceLimit) return Failure("policy source exceeds 64 MiB limit");
                    source.bytes = std::move(response.body);
                    source.etag = std::move(response.etag);
                    source.last_modified = std::move(response.last_modified);
                } else return Failure("policy source returned an unsuccessful status");
                source.url_redacted = response.effective_url_redacted.empty()
                    ? RedactPolicySourceUrl(declared.url) : response.effective_url_redacted;
            }
            source.url_fingerprint = PolicySha256(declared.url);
        } else {
            source.bytes = declared.text;
            if (!declared.materialized) return Failure("declared local rule-set is not materialized");
            source.url_redacted = declared.path.empty() ? std::string() : "[local-source]";
        }
        if (source.bytes.size() > kSourceLimit) return Failure("policy source exceeds 64 MiB limit");
        if (!declared.sha256.empty() && PolicySha256(source.bytes) != LowerHex(declared.sha256)) return Failure("policy source does not match configured SHA-256 pin");
        if (aggregate > kAggregateLimit - source.bytes.size()) return Failure("policy bundle exceeds 256 MiB aggregate limit");
        aggregate += source.bytes.size();
        source.validated_at_ms = now_ms;
        declared.text = source.bytes;
        declared.materialized = true;
        materialized.bundle.rule_sets.emplace(entry.first, std::move(source));
    }

    bool changed = !has_old || old_bundle.rules != materialized.bundle.rules ||
        old_bundle.rule_sets.size() != materialized.bundle.rule_sets.size();
    if (!changed && has_old) {
        for (const auto& entry : materialized.bundle.rule_sets) {
            const auto old = old_bundle.rule_sets.find(entry.first);
            if (old == old_bundle.rule_sets.end() || old->second.bytes != entry.second.bytes) { changed = true; break; }
        }
    }
    auto active = runtime_.GetSnapshot();
    const bool must_compile = changed || !active;
    PolicyPreparedPolicy candidate;
    if (must_compile) {
        candidate = runtime_.Prepare(materialized.source);
        if (!candidate.Ok()) return Failure("candidate policy bundle failed complete compiler validation");
    }
    DurablePolicyPointerState pointer_state;
    if (!store_->CapturePointerState(identity_fingerprint_, pointer_state, lock_error))
        return Failure("durable pointer state could not be captured before publication");
    if (must_compile) {
        if (!store_->Commit(materialized.bundle, lock_error)) {
            std::string rollback_error;
            if (!store_->RestorePointerState(identity_fingerprint_, pointer_state, rollback_error)) {
                return Failure("durable policy bundle commit failed; pointer rollback failed: " +
                    (rollback_error.empty() ? std::string("unspecified storage error") : rollback_error));
            }
            return Failure("durable policy bundle commit failed: " + lock_error);
        }
    } else if (!store_->RefreshCurrent(materialized.bundle, lock_error)) {
        std::string rollback_error;
        if (!store_->RestorePointerState(identity_fingerprint_, pointer_state, rollback_error)) {
            return Failure("durable policy freshness update failed; pointer rollback failed: " +
                (rollback_error.empty() ? std::string("unspecified storage error") : rollback_error));
        }
        return Failure("durable policy freshness update failed: " + lock_error);
    }
    std::unique_lock<std::mutex> publication(publication_mutex_);
    if (closed_ || (cancellation_ && cancellation_->load(std::memory_order_acquire))) {
        std::string rollback_error;
        if (!store_->RestorePointerState(identity_fingerprint_, pointer_state, rollback_error)) {
            return {PolicyUpdateResultCode::Closed, 0,
                "policy update cancelled before publication; pointer rollback failed: " +
                (rollback_error.empty() ? std::string("unspecified storage error") : rollback_error)};
        }
        return {PolicyUpdateResultCode::Closed, 0, "policy update cancelled before publication"};
    }
    if (mode == PolicyUpdateMode::PrepareOnly) {
        PolicyUpdateResult result;
        result.code = changed ? PolicyUpdateResultCode::Prepared : PolicyUpdateResultCode::Unchanged;
        result.version = active ? active->Version() : 0;
        result.diagnostic = changed ? "validated durable candidate prepared without runtime publication" : "policy bytes are unchanged";
        {
            std::lock_guard<std::mutex> lock(status_mutex_);
            status_.prepared_pending_commit = must_compile;
            status_.prepared_version = must_compile ? candidate.snapshot->Version() : 0;
            status_.prepared_digest = must_compile ? BundleDigest(materialized.bundle) : std::string();
            status_.offline = true;
            status_.sources.clear();
            for (const auto& entry : materialized.bundle.rule_sets) {
                const auto& source = entry.second;
                status_.sources.push_back({entry.first, source.url_redacted, source.etag, source.last_modified,
                    PolicySha256(source.bytes), source.bytes.size(), source.validated_at_ms});
            }
        }
        PublishStatus();
        return result;
    }
    if (!must_compile) {
        PolicyUpdateResult result;
        result.code = PolicyUpdateResultCode::Unchanged;
        result.version = active ? active->Version() : 0;
        result.diagnostic = "policy bytes are unchanged";
        {
            std::lock_guard<std::mutex> lock(status_mutex_);
            status_.prepared_pending_commit = false;
            status_.prepared_version = 0;
            status_.prepared_digest.clear();
            status_.offline = false;
            status_.sources.clear();
            for (const auto& entry : materialized.bundle.rule_sets) {
                const auto& source = entry.second;
                status_.sources.push_back({entry.first, source.url_redacted, source.etag, source.last_modified,
                    PolicySha256(source.bytes), source.bytes.size(), source.validated_at_ms});
            }
        }
        PublishStatus();
        return result;
    }
    if (!runtime_.Commit(candidate)) {
        std::string rollback_error;
        if (!store_->RestorePointerState(identity_fingerprint_, pointer_state, rollback_error)) {
            return Failure("runtime rejected prepared policy; pointer rollback failed: " +
                (rollback_error.empty() ? std::string("unspecified storage error") : rollback_error));
        }
        return Failure("runtime rejected prepared policy; durable pointers were restored");
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        status_.active_version = candidate.snapshot->Version();
        status_.durable_current = true;
        status_.durable_previous = has_old;
        status_.prepared_pending_commit = false;
        status_.prepared_version = 0;
        status_.prepared_digest.clear();
        status_.offline = false;
        status_.sources.clear();
        for (const auto& entry : materialized.bundle.rule_sets) {
            const auto& source = entry.second;
            status_.sources.push_back({entry.first, source.url_redacted, source.etag, source.last_modified,
                PolicySha256(source.bytes), source.bytes.size(), source.validated_at_ms});
        }
    }
    PolicyUpdateResult result;
    result.code = PolicyUpdateResultCode::Updated;
    result.version = candidate.snapshot->Version();
    result.diagnostic = "complete durable policy bundle committed to runtime";
    PublishStatus();
    return result;
}

bool PolicyUpdateService::Start() {
    {
        std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
        std::int64_t next_attempt_ms = 0;
        {
            std::lock_guard<std::mutex> lock(worker_mutex_);
            if (closed_) return false;
            if (started_) return true;
            std::chrono::seconds interval;
            if (!ParseInterval(declared_source_.updates_interval, interval)) interval = std::chrono::hours(24);
            if (declared_source_.updates_enabled) {
                if (!CheckedAdd(clock_->Now(), interval, next_attempt_)) return false;
                next_attempt_ms = Millis(next_attempt_);
            } else next_attempt_ = std::chrono::system_clock::time_point::max();
        }
        {
            std::lock_guard<std::mutex> status_lock(status_mutex_);
            status_.next_attempt_ms = next_attempt_ms;
        }
        {
            std::lock_guard<std::mutex> lock(worker_mutex_);
            if (closed_) return false;
            started_ = true;
            try { worker_ = std::thread([this] { Worker(); }); }
            catch (...) { started_ = false; return false; }
        }
    }
    PublishStatus();
    return true;
}

void PolicyUpdateService::Trigger() {
    {
        std::lock_guard<std::mutex> lock(worker_mutex_);
        if (closed_ || !started_) return;
        triggered_ = true;
    }
    worker_cv_.notify_one();
}

void PolicyUpdateService::Worker() {
    auto next_heartbeat = clock_->Now();
    if (!CheckedAdd(next_heartbeat, kStatusHeartbeat, next_heartbeat)) next_heartbeat = std::chrono::system_clock::time_point::max();
    for (;;) {
        bool do_update = false;
        {
            std::unique_lock<std::mutex> lock(worker_mutex_);
            const auto wake = declared_source_.updates_enabled ? std::min(next_attempt_, next_heartbeat) : next_heartbeat;
            clock_->WaitUntil(worker_cv_, lock, wake, [&] { return closed_ || triggered_; });
            if (closed_) return;
            do_update = triggered_ || (declared_source_.updates_enabled && clock_->Now() >= next_attempt_);
            triggered_ = false;
        }
        if (do_update) {
            const auto result = RunOnce(PolicyUpdateMode::CommitRuntime);
            const auto now = clock_->Now();
            std::chrono::seconds interval;
            if (!ParseInterval(declared_source_.updates_interval, interval)) interval = std::chrono::hours(24);
            std::chrono::system_clock::time_point candidate_time;
            bool time_ok;
            if (result.Ok()) {
                backoff_ = kMinBackoff;
                time_ok = CheckedAdd(now, interval, candidate_time);
            } else {
                time_ok = CheckedAdd(now, backoff_, candidate_time);
                backoff_ = std::min(backoff_ * 2, std::chrono::duration_cast<std::chrono::seconds>(kMaxBackoff));
            }
            next_attempt_ = time_ok ? candidate_time : std::chrono::system_clock::time_point::max();
        }
        const auto now = clock_->Now();
        if (!CheckedAdd(now, kStatusHeartbeat, next_heartbeat)) next_heartbeat = std::chrono::system_clock::time_point::max();
        std::int64_t next_attempt_ms = 0;
        {
            std::lock_guard<std::mutex> lock(worker_mutex_);
            if (declared_source_.updates_enabled && next_attempt_ != std::chrono::system_clock::time_point::max())
                next_attempt_ms = Millis(next_attempt_);
        }
        {
            std::lock_guard<std::mutex> lock(status_mutex_);
            status_.next_attempt_ms = next_attempt_ms;
        }
        PublishStatus();
    }
}

void PolicyUpdateService::Close() noexcept {
    if (cancellation_) cancellation_->store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
        {
            std::lock_guard<std::mutex> publication(publication_mutex_);
            std::lock_guard<std::mutex> lock(worker_mutex_);
            if (!closed_.exchange(true, std::memory_order_acq_rel)) {
                triggered_ = false;
            }
        }
        gate_.Close();
        worker_cv_.notify_all();
        if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) worker_.join();
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        status_.offline = true;
        status_.last_result = "closed";
    }
    PublishStatus();
}

PolicyUpdateStatus PolicyUpdateService::Status() const {
    std::lock_guard<std::mutex> lock(status_mutex_);
    auto status = status_;
    if (auto active = runtime_.GetSnapshot()) status.active_version = active->Version();
    status.identity_fingerprint = identity_fingerprint_;
    return status;
}

void PolicyUpdateService::RecordResult(const PolicyUpdateResult& result, bool attempt) {
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        const auto now = Millis(clock_->Now());
        if (attempt) status_.last_attempt_ms = now;
        switch (result.code) {
            case PolicyUpdateResultCode::Updated: status_.last_result = "updated"; status_.last_success_ms = now; break;
            case PolicyUpdateResultCode::Unchanged: status_.last_result = "unchanged"; status_.last_success_ms = now; break;
            case PolicyUpdateResultCode::Prepared: status_.last_result = "prepared"; status_.last_success_ms = now; break;
            case PolicyUpdateResultCode::RequiresReconnect: status_.last_result = "requires_reconnect"; break;
            case PolicyUpdateResultCode::Closed: status_.last_result = "closed"; break;
            default: status_.last_result = "failed"; break;
        }
        status_.last_diagnostic = result.diagnostic;
        if (auto active = runtime_.GetSnapshot()) status_.active_version = active->Version();
        status_.next_attempt_ms = declared_source_.updates_enabled ? status_.next_attempt_ms : 0;
    }
    PublishStatus();
}

void PolicyUpdateService::SetStatusSink(std::function<void(const PolicyUpdateStatus&)> sink) {
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        status_sink_ = std::move(sink);
    }
    PublishStatus();
}

void PolicyUpdateService::SetFetcher(std::shared_ptr<PolicyUpdateFetcher> fetcher) {
    std::lock_guard<std::mutex> lock(fetcher_mutex_);
    if (!closed_) fetcher_ = std::move(fetcher);
}

void PolicyUpdateService::PublishStatus() {
    std::function<void(const PolicyUpdateStatus&)> sink;
    PolicyUpdateStatus snapshot;
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        sink = status_sink_;
        snapshot = status_;
    }
    if (sink) {
        try { sink(snapshot); }
        catch (...) {}
    }
}

} // namespace ppp::app::client::policy
