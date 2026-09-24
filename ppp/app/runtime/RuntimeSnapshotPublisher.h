#pragma once

#include <ppp/app/runtime/RuntimeSnapshot.h>

#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ppp::app::runtime {

class RuntimeSnapshotPublisher final {
public:
    using Listener = std::function<void(const RuntimeSnapshot&)>;

    bool Publish(RuntimeSnapshot snapshot) noexcept {
        RuntimeSnapshot published;
        std::vector<Listener> listeners;
        try {
            std::lock_guard<std::mutex> scope(mutex_);
            if (has_latest_ &&
                (snapshot.generation < latest_.generation ||
                 (snapshot.generation == latest_.generation &&
                  snapshot.monotonic_ms <= latest_.monotonic_ms))) {
                return false;
            }

            latest_ = std::move(snapshot);
            has_latest_ = true;
            published = latest_;
            listeners.reserve(listeners_.size());
            for (const auto& item : listeners_) {
                listeners.emplace_back(item.second);
            }
        }
        catch (...) {
            return false;
        }

        for (const Listener& listener : listeners) {
            if (!listener) {
                continue;
            }
            try {
                listener(published);
            }
            catch (...) {
            }
        }
        return true;
    }

    std::uint64_t Subscribe(Listener listener) noexcept {
        if (!listener) {
            return 0;
        }
        try {
            std::lock_guard<std::mutex> scope(mutex_);
            std::uint64_t token = next_listener_token_++;
            if (token == 0) {
                token = next_listener_token_++;
            }
            listeners_.emplace(token, std::move(listener));
            return token;
        }
        catch (...) {
            return 0;
        }
    }

    void Unsubscribe(std::uint64_t token) noexcept {
        if (token == 0) {
            return;
        }
        std::lock_guard<std::mutex> scope(mutex_);
        listeners_.erase(token);
    }

    RuntimeSnapshot GetLatest() const noexcept {
        try {
            std::lock_guard<std::mutex> scope(mutex_);
            return latest_;
        }
        catch (...) {
            return RuntimeSnapshot();
        }
    }

private:
    mutable std::mutex mutex_;
    RuntimeSnapshot latest_;
    std::unordered_map<std::uint64_t, Listener> listeners_;
    std::uint64_t next_listener_token_ = 1;
    bool has_latest_ = false;
};

}
