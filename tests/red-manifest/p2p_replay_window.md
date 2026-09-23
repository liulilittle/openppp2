# RED manifest: p2p_replay_window_test

| test | break implementation | expected failure |
|------|------------------------|------------------|
| replay_empty_window_accepts_first | omit `initialized_ = true` on first accept | window remains uninitialized |
| replay_rejects_duplicate_zero | treat `base_ == 0` as the empty-window sentinel | duplicate zero accepted |
| replay_reset_after_zero_accepts_zero_once_again | leave `initialized_` set in `Reset()` | zero remains duplicate after reset |
| replay_accepts_zero_after_uint32_max | compare raw uint32 sequence directly with the uint64 base | rollover zero rejected |
| replay_rejects_duplicate_inside_window | return true from Accept for same seq | duplicate accepted |
| replay_rejects_seq_older_than_window | treat delta>=window as not duplicate | stale seq accepted |
| replay_accepts_window_size_minus_one_behind | reject delta>=window-1 | oldest in-window packet rejected |
| replay_far_ahead_resets_window_and_rejects_old_base | retain the old bitmap after a far-ahead jump | old base accepted again or new base lost |
| replay_accepts_reordered_sequences_across_uint32_wrap_once | use non-modular sequence deltas | reordered rollover packets rejected or replayed |
| replay_rejects_ambiguous_half_range_jump | treat a half-range jump as newer | ambiguous sequence accepted |
