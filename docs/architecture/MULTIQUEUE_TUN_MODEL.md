# Linux Single Virtual NIC Multi-Queue Model
> Status: Experimental / proposed evolution
> Type: Linux implementation note and design proposal
> Last verified: Linux TAP, client SSMT, and server IPv6-transit sources, 2026-07-22
>
> **Purpose:** Separate implemented Linux multi-queue behavior from a proposed cleaner queue model.
> **Audience:** Contributors working on Linux device performance or lifecycle.
> **Parent index:** [Architecture](README.md) · **Chinese:** [Linux 单虚拟网卡多队列模型](MULTIQUEUE_TUN_MODEL_CN.md)

## Status boundary

This is not a completed first-class queue-object architecture. The current source has Linux multi-queue/SSMT mechanisms, while explicit queue identities, flow maps, CPU affinity, and a unified server/client queue API remain design work. Kernel support and performance effects require runtime validation on the target host.

## Implemented Linux behavior

- `TapLinux::OpenDriver()` attempts to open a TUN device with `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE`; when that ioctl path fails, it falls back to single-queue behavior.
- `--tun-ssmt` supplies a worker count. An `m` or `q` marker enables the associated `SsmtMQ` behavior.
- Client SSMT workers create an `io_context`/thread and call `TapLinux::Ssmt(context)`. That method opens another file descriptor on the same named device and starts a read loop for it.
- Server multi-queue work is limited to the Linux IPv6 transit TAP path and requires both configured SSMT count and SSMT multi-queue mode.

Android uses a `VpnService`-provided descriptor in its normal path. This document does not claim that Android has validated Linux-style multi-queue behavior.

## Current affinity boundary

Current file-descriptor affinity is best-effort and implicit:

- a Linux read callback stores its queue FD in thread-local state;
- `TapLinux::Output()` prefers that FD;
- client TCP dispatch captures/restores the FD when it moves work;
- server IPv6 transit can retain a preferred FD per exchanger.

This is not a strict per-flow scheduling model. The special client SSMT dispatch path is TCP-oriented; UDP and ICMP continue through their normal fragment/input paths.

## What the source does not provide

Do not claim any of the following as current behavior:

- an `ITapQueue`/`TapLinuxQueue` first-class object model;
- stable queue IDs exposed to flows;
- a strict 5-tuple-to-queue map or guaranteed write-back affinity;
- CPU/NUMA pinning, dynamic queue scaling, or per-queue observability;
- a measured throughput or latency improvement;
- a shared client/server queue lifecycle interface.

## Proposed direction

If future work is approved, the source suggests making the existing device-level `TapLinux` owner retain explicit queue instances. A queue instance would own an FD/stream descriptor, reader lifecycle, and optional accounting, while flow state could record a preferred queue with a defined migration policy.

That direction is a proposal, not an interface commitment. It must preserve single-device semantics, establish teardown ordering, and be validated independently for client and Linux server IPv6-transit paths before it is promoted to current architecture.

## Source anchors

- `linux/ppp/tap/TapLinux.cpp`
- `ppp/ethernet/VEthernet.cpp`
- `ppp/app/ApplicationConfig.cpp`
- `ppp/app/ApplicationClientBootstrap.cpp`
- `ppp/app/server/VirtualEthernetSwitcher.cpp`
