#pragma once

#include <cstdint>
#include <limits>
#include <type_traits>

namespace ppp {
    namespace app {
        namespace server {

            class SessionRecoveryState final {
            public:
                enum class State : std::uint8_t {
                    Active,
                    Suspended,
                    Expired,
                };

                State GetState() const noexcept {
                    return state_;
                }

                std::uint64_t GetGeneration() const noexcept {
                    return generation_;
                }

                std::uint64_t GetDeadline() const noexcept {
                    return deadline_;
                }

                bool Suspend(std::uint64_t expected_generation, std::uint64_t now,
                    std::uint64_t grace) noexcept {
                    if (state_ != State::Active || generation_ != expected_generation ||
                        reservation_token_ != 0) {
                        return false;
                    }

                    const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
                    deadline_ = grace > maximum - now ? maximum : now + grace;
                    state_ = State::Suspended;
                    return true;
                }

                bool CanResume(std::uint64_t expected_generation, std::uint64_t now) const noexcept {
                    return state_ == State::Suspended && reservation_token_ == 0 &&
                        generation_ == expected_generation && now < deadline_;
                }

                bool ReserveResume(std::uint64_t expected_generation, std::uint64_t now,
                    std::uint64_t reservation_token) noexcept {
                    if (reservation_token == 0 || !CanResume(expected_generation, now)) {
                        return false;
                    }

                    reservation_token_ = reservation_token;
                    return true;
                }

                bool CanCommitResume(std::uint64_t expected_generation, std::uint64_t now,
                    std::uint64_t reservation_token) const noexcept {
                    return state_ == State::Suspended && reservation_token != 0 &&
                        reservation_token_ == reservation_token &&
                        generation_ == expected_generation && now < deadline_;
                }

                bool CommitResume(std::uint64_t expected_generation, std::uint64_t now,
                    std::uint64_t reservation_token) noexcept {
                    if (!CanCommitResume(expected_generation, now, reservation_token) ||
                        generation_ == std::numeric_limits<std::uint64_t>::max()) {
                        return false;
                    }

                    ++generation_;
                    deadline_ = 0;
                    reservation_token_ = 0;
                    state_ = State::Active;
                    return true;
                }

                /**
                 * @brief Marks the reservation as committed-awaiting-publish and
                 *        extends the deadline by a short publish grace.
                 * @details The committed control frame is sent between the commit
                 *          validation and the data-plane publication; without the
                 *          extension a grace deadline expiring inside that window
                 *          would fail the publish after the client already accepted
                 *          the commit (dual-state divergence).  The extension is
                 *          bounded so an unpublished commit still expires.
                 */
                bool MarkResumeCommitted(std::uint64_t reservation_token, std::uint64_t now,
                    std::uint64_t publish_grace) noexcept {
                    if (reservation_token == 0 || reservation_token_ != reservation_token ||
                        state_ != State::Suspended) {
                        return false;
                    }

                    const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
                    const std::uint64_t extended =
                        publish_grace > maximum - now ? maximum : now + publish_grace;
                    if (extended > deadline_) {
                        deadline_ = extended;
                    }
                    return true;
                }

                bool CancelResume(std::uint64_t reservation_token) noexcept {
                    if (reservation_token == 0 || reservation_token_ != reservation_token ||
                        state_ != State::Suspended) {
                        return false;
                    }

                    reservation_token_ = 0;
                    return true;
                }

                bool HasResumeReservation() const noexcept {
                    return reservation_token_ != 0;
                }

                bool IsExpired(std::uint64_t now) noexcept {
                    if (state_ == State::Suspended && now >= deadline_) {
                        reservation_token_ = 0;
                        state_ = State::Expired;
                    }
                    return state_ == State::Expired;
                }

                bool IsSuspended(std::uint64_t now) noexcept {
                    return !IsExpired(now) && state_ == State::Suspended;
                }

            private:
                State state_ = State::Active;
                std::uint64_t generation_ = 1;
                std::uint64_t deadline_ = 0;
                std::uint64_t reservation_token_ = 0;
            };

            template <typename Publication>
            bool CommitSessionResumeAndPublish(SessionRecoveryState& state,
                std::uint64_t expected_generation, std::uint64_t now,
                std::uint64_t reservation_token, Publication&& publication) noexcept {
                static_assert(std::is_nothrow_invocable_v<Publication&, std::uint64_t>,
                    "resume publication must not fail after state commit");
                if (!state.CommitResume(expected_generation, now, reservation_token)) {
                    return false;
                }

                publication(state.GetGeneration());
                return true;
            }

        }
    }
}
