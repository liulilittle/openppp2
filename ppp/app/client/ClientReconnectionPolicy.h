#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

namespace ppp {
    namespace app {
        namespace client {

            class ClientReconnectionPolicy final {
            public:
                ClientReconnectionPolicy(std::uint64_t base_delay_ms,
                    std::uint64_t max_delay_ms, std::uint32_t jitter_percent,
                    std::uint64_t initial_attempt = 0) noexcept
                    : base_delay_ms_(std::max<std::uint64_t>(1, base_delay_ms))
                    , max_delay_ms_(std::max<std::uint64_t>(base_delay_ms_, max_delay_ms))
                    , jitter_percent_(std::min<std::uint32_t>(100, jitter_percent))
                    , attempt_(initial_attempt) {
                }

                std::uint64_t OnFailure(std::uint64_t entropy) noexcept {
                    std::uint64_t delay = base_delay_ms_;
                    std::uint64_t remaining = attempt_;
                    while (remaining > 0 && delay < max_delay_ms_) {
                        delay = delay > max_delay_ms_ / 2 ? max_delay_ms_ : delay * 2;
                        --remaining;
                    }

                    const std::uint64_t spread =
                        (delay / 100) * jitter_percent_ +
                        ((delay % 100) * jitter_percent_) / 100;
                    const std::uint64_t lower = delay - spread;
                    const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
                    const std::uint64_t upper = spread > maximum - delay
                        ? maximum
                        : delay + spread;
                    const std::uint64_t span = upper - lower;
                    const std::uint64_t result = span == std::numeric_limits<std::uint64_t>::max()
                        ? entropy
                        : lower + entropy % (span + 1);

                    if (attempt_ != std::numeric_limits<std::uint64_t>::max()) {
                        ++attempt_;
                    }
                    return result;
                }

                void Reset() noexcept {
                    attempt_ = 0;
                }

                std::uint64_t GetAttempt() const noexcept {
                    return attempt_;
                }

            private:
                std::uint64_t base_delay_ms_;
                std::uint64_t max_delay_ms_;
                std::uint32_t jitter_percent_;
                std::uint64_t attempt_;
            };

        }
    }
}
