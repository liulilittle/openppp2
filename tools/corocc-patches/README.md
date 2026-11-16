# Pinned L0 Patches

Patches here are applied in filename order by `tools/prepare_corocc.sh`.
Only the L0 context/stack implementation is used by OpenPPP2.

`0001-inline-tsan-fiber-switch-bridges.patch` forces the two TSan switching
helpers inline, including at `-O0`. A helper that switches the active fiber and
then returns otherwise emits its function exit against the destination's shadow
stack. Keep these bodies in the caller so its entry/exit remain on the same
fiber. Load/store instrumentation stays enabled; non-TSan code is unchanged.
The validation record retains the failing run and the focused/full retests.
