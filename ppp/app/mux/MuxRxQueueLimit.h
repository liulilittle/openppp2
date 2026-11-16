// Hard bound for a vmux socket's inbound queue, plus the empty-PUSH rule.
//
// The soft rx_congestions XOFF only asks a cooperative peer to stop; a hostile
// peer can ignore it, so the queue also needs a hard cap that fails the flow.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ppp {
    namespace app {
        namespace mux {
            static constexpr std::size_t   kMuxRxQueueHardMaxPackets   = 16384;
            static constexpr int64_t       kMuxRxQueueHardMaxBytesNoFc = (int64_t)256 << 20;

            /** @brief Hard byte cap derived from the soft congestion threshold (0 = flow control off). */
            inline int64_t MuxRxQueueHardMaxBytes(int soft_congestions) noexcept {
                if (soft_congestions < 1) {
                    return kMuxRxQueueHardMaxBytesNoFc;
                }
                return (int64_t)soft_congestions * 2;
            }

            /** @brief True when accepting one more payload would exceed the hard cap. */
            inline bool MuxRxQueueOverflows(std::size_t queued_packets, int64_t queued_bytes, int incoming_bytes, int soft_congestions) noexcept {
                if (queued_packets >= kMuxRxQueueHardMaxPackets) {
                    return true;
                }
                return queued_bytes + (int64_t)(incoming_bytes > 0 ? incoming_bytes : 0) > MuxRxQueueHardMaxBytes(soft_congestions);
            }

            /** @brief A zero-length PUSH carries no data and must never be read as FIN. */
            inline bool MuxIsNoopPush(int payload_size) noexcept {
                return payload_size <= 0;
            }
        }
    }
}
