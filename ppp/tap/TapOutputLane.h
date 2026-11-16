#pragma once

/**
 * @file TapOutputLane.h
 * @brief Thread-local hint naming the producer lane whose TUN output is in flight.
 *
 * A multi-threaded producer (for example one XTCP shard per worker) marks its
 * output calls with a stable lane index. A TAP that supports output lanes can
 * then give each lane its own queue descriptor and GSO coalescer, so producers
 * running in parallel do not serialize on one lock or interleave flows in one
 * merge buffer. Without a scope the lane is -1 and the shared path is used.
 */

namespace ppp {
    namespace tap {
        /** @brief Upper bound on lanes a TAP keeps; larger indices use the shared path. */
        static constexpr int kMaxTapOutputLanes = 16;

        /** @brief Current thread's output lane, or -1 when none is bound. */
        inline int& TapOutputLaneSlot() noexcept {
            static thread_local int lane = -1;
            return lane;
        }

        /** @brief Binds the calling thread to an output lane for the scope's lifetime. */
        class TapOutputLaneScope final {
        public:
            explicit TapOutputLaneScope(int lane) noexcept
                : previous_(TapOutputLaneSlot()) {
                TapOutputLaneSlot() = lane;
            }
            ~TapOutputLaneScope() noexcept { TapOutputLaneSlot() = previous_; }

            TapOutputLaneScope(const TapOutputLaneScope&) = delete;
            TapOutputLaneScope& operator=(const TapOutputLaneScope&) = delete;

        private:
            int previous_;
        };
    }
}
