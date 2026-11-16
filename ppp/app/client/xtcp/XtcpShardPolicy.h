#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace ppp::app::client::xtcp {

inline bool ParseUnsigned(const std::string& text, std::uint64_t& value) noexcept {
    if (text.empty()) return false;
    value = 0;
    for (char c : text) {
        if (c < '0' || c > '9' || value > (UINT64_MAX - (c - '0')) / 10) return false;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    return true;
}

struct XtcpCpuInputs final {
    unsigned online = 1;
    std::vector<unsigned> allowed;
    unsigned quota_cpus = 1;
    bool affinity_known = false;
    bool quota_known = false;
    unsigned Effective() const noexcept {
        if (!affinity_known || !quota_known || allowed.empty()) return 1;
        return std::max(1u, std::min({online, static_cast<unsigned>(allowed.size()), quota_cpus}));
    }
};

struct XtcpShardPolicy final {
    unsigned shards = 1;
    std::string requested;
    std::string reason = "default-one";
    bool invalid = false;
};

inline XtcpShardPolicy SelectXtcpShards(const std::string& requested,
    const std::string& rollback, const XtcpCpuInputs& cpus, bool linux_desktop) {
    XtcpShardPolicy result;
    result.requested = requested.empty() ? "unset" : requested;
    std::uint64_t count = 0;
    if (ParseUnsigned(requested, count) && count >= 1 && count <= 8) {
        result.shards = static_cast<unsigned>(count);
        result.reason = "explicit";
    } else if (!requested.empty() && requested != "auto") {
        result.invalid = true;
        result.reason = "invalid-shards";
    } else if (rollback == "0") {
        result.reason = "auto-rollback";
    } else if (!rollback.empty() && rollback != "1") {
        result.invalid = true;
        result.reason = "invalid-auto-switch";
    } else if (requested == "auto" && linux_desktop) {
        result.shards = std::max(1u, std::min(8u, cpus.Effective() / 2));
        result.reason = cpus.affinity_known && cpus.quota_known
            ? "auto-opt-in" : "cpu-discovery-incomplete";
    } else if (requested == "auto") {
        result.reason = "platform-default-one";
    }
    return result;
}

inline bool ParseXtcpCpuList(const std::string& text, std::vector<unsigned>& result) {
    result.clear();
    if (text.empty()) return false;
    std::size_t begin = 0;
    for (;;) {
        const auto end = text.find(',', begin);
        std::uint64_t cpu = 0;
        if (!ParseUnsigned(text.substr(begin, end == std::string::npos ? end : end - begin), cpu)
            || cpu > std::numeric_limits<unsigned>::max()
            || std::find(result.begin(), result.end(), static_cast<unsigned>(cpu)) != result.end()) {
            result.clear();
            return false;
        }
        result.push_back(static_cast<unsigned>(cpu));
        if (end == std::string::npos) return true;
        begin = end + 1;
    }
}

struct XtcpWorkerAffinity final {
    bool enabled = false;
    bool queues = false; // Stage B: per-shard executor + pinned worker
    bool strict = false;
    bool valid = true;
    std::string reason = "off";
    std::vector<unsigned> cpus;
    bool CanStart(bool all_pinned) const noexcept {
        return !strict || (valid && (!enabled || all_pinned));
    }
};

// Stage A uses an ordered, distinct, exact N-worker map; no shared-set syntax.
inline XtcpWorkerAffinity SelectXtcpWorkerAffinity(const std::string& mode,
    const std::string& list, const std::string& strict, unsigned workers,
    const XtcpCpuInputs& envelope, bool supported) {
    XtcpWorkerAffinity result;
    result.strict = strict == "1";
    if (!strict.empty() && strict != "0" && strict != "1") {
        result.valid = false;
        result.reason = "invalid-strict-switch";
        return result;
    }
    if (mode.empty() || mode == "off") return result;
    result.queues = mode == "queues";
    if (result.queues && supported && workers == 0) {
        // A single shard has no per-shard executor to bind: report it as
        // unsupported instead of pretending the worker is pinned.
        result.reason = "queues-unsupported-single-shard";
        return result;
    }
    result.valid = supported && (mode == "workers" || result.queues) && workers != 0
        && envelope.affinity_known && ParseXtcpCpuList(list, result.cpus)
        && result.cpus.size() == workers;
    if (result.valid) {
        for (unsigned cpu : result.cpus)
            if (std::find(envelope.allowed.begin(), envelope.allowed.end(), cpu) == envelope.allowed.end())
                result.valid = false;
        if (envelope.quota_known && workers > envelope.Effective()) result.valid = false;
    }
    result.enabled = result.valid;
    result.reason = result.valid ? mode : (result.queues ? "invalid-queue-map" : "invalid-worker-map");
    return result;
}

template<class Pin, class Readback>
inline bool ApplyXtcpWorkerAffinity(unsigned cpu, Pin&& pin, Readback&& readback) noexcept {
    return pin(cpu) && readback(cpu);
}

} // namespace ppp::app::client::xtcp
