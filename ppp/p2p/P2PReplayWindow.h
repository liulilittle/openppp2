#pragma once

/**
 * @file P2PReplayWindow.h
 * @brief Bitmap-based sliding window for P2P packet replay protection.
 *
 * Fixed-size 144 bytes per channel (1024-bit window). O(1) accept and
 * duplicate check. No heap allocation.
 *
 * Bitmap convention: bit 0 = base (newest accepted), bit N = base - N.
 * When base advances, existing bits shift toward higher indices (older
 * sequences move to higher bit positions), and low bits are cleared.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <cstring>

namespace ppp {
    namespace p2p {

        /**
         * @brief Compact bitmap replay window for sequence number validation.
         *
         * Tracks the highest accepted sequence number (`base_`) and a 1024-bit
         * bitmap covering sequences [base_ - 1023, base_]. Each bit represents
         * whether a particular sequence number has been seen.
         *
         * Initialization is tracked separately from `base_`, so sequence zero
         * remains a valid first packet.
         *
         * Thread safety: caller must ensure single-writer discipline. The struct
         * is intentionally lock-free for the hot path (check + set) and can be
         * protected by the channel's strand/mutex externally.
         */
        struct P2PReplayWindow {
            static constexpr uint32_t SequenceHalfRange = 0x80000000u;

            uint64_t    base_ = 0;                              ///< Highest accepted extended sequence.
            uint8_t     bitmap_[REPLAY_BITMAP_SIZE] = {};       ///< 1024-bit window bitmap.
            bool        initialized_ = false;                   ///< Whether any sequence has been accepted.

            /** @brief Resets the replay window to initial state. */
            void Reset() noexcept {
                base_ = 0;
                std::memset(bitmap_, 0, sizeof(bitmap_));
                initialized_ = false;
            }

            /** @brief Tests whether a sequence number has already been accepted. */
            bool IsDuplicate(uint32_t seq) const noexcept {
                if (!initialized_) {
                    return false;
                }
                const uint32_t base_seq = static_cast<uint32_t>(base_);
                const uint32_t forward = seq - base_seq;
                if (forward != 0 && forward < SequenceHalfRange) {
                    return false;
                }
                const uint32_t delta = base_seq - seq;
                if (delta >= REPLAY_WINDOW_SIZE) {
                    return true;
                }
                uint64_t byte_idx = delta / 8;
                uint64_t bit_idx  = delta % 8;
                return (bitmap_[byte_idx] & (1u << bit_idx)) != 0;
            }

            /** @brief Accepts a sequence number into the window. */
            bool Accept(uint32_t seq) noexcept {
                if (!initialized_) {
                    base_ = seq;
                    bitmap_[0] = 1u;
                    initialized_ = true;
                    return true;
                }

                const uint32_t base_seq = static_cast<uint32_t>(base_);
                const uint32_t forward = seq - base_seq;
                if (forward != 0 && forward < SequenceHalfRange) {
                    const uint64_t shift = forward;
                    if (shift >= REPLAY_WINDOW_SIZE) {
                        std::memset(bitmap_, 0, sizeof(bitmap_));
                    } else {
                        ShiftBitmapLeft(static_cast<int>(shift));
                    }
                    base_ += shift;
                    bitmap_[0] |= 1u;
                    return true;
                }

                const uint32_t delta = base_seq - seq;
                if (delta >= REPLAY_WINDOW_SIZE) {
                    return false;
                }

                uint64_t byte_idx = delta / 8;
                uint64_t bit_idx  = delta % 8;
                uint8_t  mask     = static_cast<uint8_t>(1u << bit_idx);

                if (bitmap_[byte_idx] & mask) {
                    return false;
                }

                bitmap_[byte_idx] |= mask;
                return true;
            }

        private:
            /** @brief Shifts the bitmap toward higher delta indices. */
            void ShiftBitmapLeft(int n) noexcept {
                if (n <= 0) {
                    return;
                }
                if (n >= REPLAY_WINDOW_SIZE) {
                    std::memset(bitmap_, 0, sizeof(bitmap_));
                    return;
                }

                int whole_bytes = n / 8;
                int extra_bits  = n % 8;

                if (whole_bytes > 0) {
                    for (int i = REPLAY_BITMAP_SIZE - 1; i >= whole_bytes; --i) {
                        bitmap_[i] = bitmap_[i - whole_bytes];
                    }
                    for (int i = 0; i < whole_bytes && i < REPLAY_BITMAP_SIZE; ++i) {
                        bitmap_[i] = 0;
                    }
                }

                if (extra_bits > 0) {
                    uint8_t carry = 0;
                    for (int i = 0; i < REPLAY_BITMAP_SIZE; ++i) {
                        uint8_t new_carry = static_cast<uint8_t>(
                            bitmap_[i] >> (8 - extra_bits));
                        bitmap_[i] = static_cast<uint8_t>(
                            (bitmap_[i] << extra_bits) | carry);
                        carry = new_carry;
                    }
                }
            }
        };

        static_assert(sizeof(P2PReplayWindow) <= 144,
                      "P2PReplayWindow must fit in minimal memory (144 bytes expected)");

    }
}
