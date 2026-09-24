#pragma once

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace ppp
{
    namespace net
    {
        class ProtectorNetworkRequest final
        {
        public:
            typedef std::function<void()> WakeHandler;

            enum class State
            {
                Pending,
                Running,
                Completed,
                Cancelled
            };

            explicit ProtectorNetworkRequest(std::uint64_t generation, WakeHandler wake) noexcept
                : generation_(generation)
                , wake_(std::move(wake))
            {
            }

            bool Begin() noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                if (state_ != State::Pending)
                {
                    return false;
                }

                state_ = State::Running;
                return true;
            }

            bool Complete(bool result) noexcept
            {
                WakeHandler wake;
                {
                    std::lock_guard<std::mutex> scope(lock_);
                    if (state_ != State::Running)
                    {
                        return false;
                    }

                    state_ = State::Completed;
                    result_ = result;
                    wake = std::move(wake_);
                }
                Wake(std::move(wake));
                return true;
            }

            bool Cancel() noexcept
            {
                WakeHandler wake;
                {
                    std::lock_guard<std::mutex> scope(lock_);
                    if (state_ != State::Pending)
                    {
                        return false;
                    }

                    state_ = State::Cancelled;
                    wake = std::move(wake_);
                }
                Wake(std::move(wake));
                return true;
            }

            bool Result() const noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                return state_ == State::Completed && result_;
            }

            bool IsResolved() const noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                return state_ == State::Completed || state_ == State::Cancelled;
            }

            State GetState() const noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                return state_;
            }

            std::uint64_t Generation() const noexcept
            {
                return generation_;
            }

        private:
            static void Wake(WakeHandler wake) noexcept
            {
                if (wake)
                {
                    try
                    {
                        wake();
                    }
                    catch (...)
                    {
                    }
                }
            }

        private:
            const std::uint64_t generation_;
            mutable std::mutex lock_;
            State state_ = State::Pending;
            bool result_ = false;
            WakeHandler wake_;
        };

        class ProtectorNetworkRequestSession final
        {
        public:
            typedef std::shared_ptr<ProtectorNetworkRequest> RequestPtr;
            typedef std::unordered_map<ProtectorNetworkRequest*, RequestPtr> RequestRegistry;

            explicit ProtectorNetworkRequestSession(std::uint64_t generation) noexcept
                : generation_(generation)
            {
            }

            ~ProtectorNetworkRequestSession() noexcept
            {
                Deactivate();
            }

            RequestPtr Create(ProtectorNetworkRequest::WakeHandler wake) noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                if (!active_)
                {
                    return nullptr;
                }

                RequestPtr request;
                try
                {
                    const std::size_t capacity = pending_.size() + running_.size() + 1;
                    pending_.reserve(capacity);
                    running_.reserve(capacity);
                    request = std::make_shared<ProtectorNetworkRequest>(generation_, std::move(wake));
                    pending_.emplace(request.get(), request);
                }
                catch (...)
                {
                    return nullptr;
                }
                return request;
            }

            bool Begin(const RequestPtr& request) noexcept
            {
                if (!request || request->Generation() != generation_)
                {
                    return false;
                }

                std::lock_guard<std::mutex> scope(lock_);
                auto entry = pending_.find(request.get());
                if (!active_ || entry == pending_.end() || !request->Begin())
                {
                    return false;
                }

                running_.insert(pending_.extract(entry));
                return true;
            }

            bool Cancel(const RequestPtr& request) noexcept
            {
                if (!request || request->Generation() != generation_)
                {
                    return false;
                }

                RequestPtr cancelled;
                {
                    std::lock_guard<std::mutex> scope(lock_);
                    auto entry = pending_.find(request.get());
                    if (entry == pending_.end())
                    {
                        return false;
                    }

                    cancelled = std::move(entry->second);
                    pending_.erase(entry);
                }
                return cancelled->Cancel();
            }

            bool Finish(const RequestPtr& request) noexcept
            {
                if (!request || request->Generation() != generation_)
                {
                    return false;
                }

                std::lock_guard<std::mutex> scope(lock_);
                auto entry = running_.find(request.get());
                if (entry == running_.end())
                {
                    return false;
                }

                running_.erase(entry);
                if (running_.empty())
                {
                    drained_.notify_all();
                }
                return true;
            }

            void Deactivate() noexcept
            {
                RequestRegistry pending;
                {
                    std::lock_guard<std::mutex> scope(lock_);
                    active_ = false;
                    pending.swap(pending_);
                }

                for (const auto& entry : pending)
                {
                    entry.second->Cancel();
                }

                std::unique_lock<std::mutex> scope(lock_);
                drained_.wait(scope, [this]() noexcept { return running_.empty(); });
            }

            std::uint64_t Generation() const noexcept
            {
                return generation_;
            }

            std::size_t PendingCount() const noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                return pending_.size();
            }

            std::size_t RunningCount() const noexcept
            {
                std::lock_guard<std::mutex> scope(lock_);
                return running_.size();
            }

        private:
            const std::uint64_t generation_;
            mutable std::mutex lock_;
            std::condition_variable drained_;
            bool active_ = true;
            RequestRegistry pending_;
            RequestRegistry running_;
        };
    }
}
