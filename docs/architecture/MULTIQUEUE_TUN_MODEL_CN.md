# Linux 单虚拟网卡多队列模型
> Status: Experimental / proposed evolution
> Type: Linux implementation note and design proposal
> Last verified: Linux TAP, client SSMT, and server IPv6-transit sources, 2026-07-22
>
> **用途：**区分已实现的 Linux 多队列行为与建议中的更清晰队列模型。
> **适用对象：**从事 Linux 设备性能或生命周期工作的贡献者。
> **上一层索引：**[架构](README_CN.md) · **English:** [Linux Single Virtual NIC Multi-Queue Model](MULTIQUEUE_TUN_MODEL.md)

## 状态边界

这不是已完成的一等 queue-object 架构。当前源码具有 Linux multi-queue/SSMT 机制，但显式 queue identity、flow map、CPU 亲和性与统一 client/server queue API 仍是设计工作。内核支持和性能效果需要在目标宿主上进行运行时验证。

## 已实现的 Linux 行为

- `TapLinux::OpenDriver()` 尝试使用 `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE` 打开 TUN 设备；该 ioctl 路径失败时会回退为 single-queue 行为。
- `--tun-ssmt` 提供 worker 数量。包含 `m` 或 `q` 的标记启用相关的 `SsmtMQ` 行为。
- client SSMT worker 创建 `io_context`/thread 并调用 `TapLinux::Ssmt(context)`。该方法在同名设备上打开另一个文件描述符，并为其启动 read loop。
- server multi-queue 工作只限 Linux IPv6 transit TAP 路径，且要求同时配置 SSMT 数量和 SSMT multi-queue mode。

Android 的普通路径使用 `VpnService` 提供的文件描述符。本文不宣称 Android 已验证 Linux 式 multi-queue 行为。

## 当前 affinity 边界

当前文件描述符 affinity 是 best-effort 且隐式的：

- Linux read callback 把 queue FD 保存到 thread-local 状态；
- `TapLinux::Output()` 优先使用该 FD；
- client TCP dispatch 在移动工作时捕获/恢复 FD；
- server IPv6 transit 可以按 exchanger 保存 preferred FD。

这不是严格的 per-flow scheduling 模型。特殊 client SSMT dispatch 路径面向 TCP；UDP 与 ICMP 继续走正常 fragment/input 路径。

## 源码没有提供的能力

以下都不能写成当前行为：

- `ITapQueue`/`TapLinuxQueue` 一等对象模型；
- 向 flow 暴露的稳定 queue ID；
- 严格 5 元组到 queue 映射或保证 write-back affinity；
- CPU/NUMA 绑定、动态 queue 缩放或 per-queue 可观测性；
- 已测量的吞吐量或延迟改进；
- 共享的 client/server queue 生命周期接口。

## 建议方向

若未来工作获批，源码可演进为让设备级 `TapLinux` owner 保存显式 queue instance。一个 queue instance 可持有 FD/stream descriptor、reader 生命周期和可选统计；flow state 可记录 preferred queue，并定义迁移策略。

该方向是建议，不是接口承诺。它必须保留 single-device 语义，建立 teardown 顺序，并在 client 和 Linux server IPv6-transit 路径上分别独立验证后，才可升格为当前架构。

## 源码锚点

- `linux/ppp/tap/TapLinux.cpp`
- `ppp/ethernet/VEthernet.cpp`
- `ppp/app/ApplicationConfig.cpp`
- `ppp/app/ApplicationClientBootstrap.cpp`
- `ppp/app/server/VirtualEthernetSwitcher.cpp`
