#pragma once

#include <ppp/tap/TapOutputLane.h>

namespace ppp {
    namespace tap {
        /** @brief Maps a producer slot to an output lane, or -1 for the shared path. */
        inline int SelectTapOutputLane(int slot, bool lanes_enabled) noexcept {
            if (!lanes_enabled || slot < 0 || slot >= kMaxTapOutputLanes) {
                return -1;
            }
            return slot;
        }
    }
}
