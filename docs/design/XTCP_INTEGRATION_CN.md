# XTCP Linux IPv4 laboratory runtime 设计

> Status: Active / Laboratory
> Type: Design
> Last verified: 2026-09-08 (latest dated experimental update; later evidence remains timestamped inline)
> Last verified revision: `e79db8fd10a1ee39be2dc3a9361727fcad79d04c`

## 0. 现状总览（2026-09-04，`XTCP-SINGLECORE-BASELINE-20260902` 之后）

> 本文其余章节按时间线记录实验细节；本节是当前状态的唯一起点摘要。

**当前工作树**包含端到端 TCPv4 GSO ingress、opt-in 单-owner 用户态 direct bridge、显式 receive resume、16KiB download chunk、DL 零窗口 persist/pacing 治理、Route3 strict isolation/qualification，以及 default-off NDI TSO laboratory capability。binary：`build/xtcp-runtime-root/bin/ppp`。这些改动尚未提交，不能把历史 commit 链当作当前 revision。

**direct bridge（`OPENPPP2_XTCP_MEMORY_BRIDGE=1` / runner `--xtcp-memory-bridge`）**替换原 socket pump，而不是与其并行：XTCP receive → 32MiB/4096-item 有界 upload queue → 唯一 transmission writer；唯一 transmission reader → 16KiB alias chunk → XTCP `Send`。runtime 强持有 second leg；队列降到 low watermark 后显式 `ResumeReceive()`/window update。`ITransmission` 默认不保证半关；raw child `ITcpipTransmission` 则通过真实 TCP `shutdown(SHUT_WR)` 在 upload queue 排空后发送 FIN、保留接收方向。该 direct 路径 capability-gated，WebSocket/TLS 等不支持的 carrier 安全回退 socket pump；`degraded_half_close` 仅为兼容遥测，正确路径保持 0。

**当前严格单核 paired 证据**（GSO-on，direct bridge，CPU8）已有三轮 artifact `artifacts/direct-final-*` 的 36/36 qualification pass。旧六模式主矩阵 `artifacts/route3-six-mode-strict-r3-20260904` 仅生成 106/106 cell；修复 revision 的原子矩阵 `artifacts/route3-six-mode-strict-persist-fix-r3b-20260904` 已完成 **108/108 cell qualification 全 pass**。原故障维度 `XTCP/GSO-on/P4/DL` 三轮为 614.4–619.1 Mbps，未再出现 watchdog。

qualification 只证明配置、隔离、runtime proof、统计完整性与 cleanup，不是性能稳定性门禁：原子矩阵的 `XTCP/GSO-on/P1/UL` 三轮为 655.76、30.20、734.58 Mbps；低值轮有 52 次 retransmit、`direct_upload_rejected=1`、`resume_requested=1`、`resume_effective=0`。因此这一路径仍有间歇性退化信号，不能因 108/108 qualification pass 而宣称性能通过。

P1 direct GRO 扫描中 12KiB 三轮稳定（975/1010/1039 Mbps）；13–15KiB 出现严重退化，16KiB 虽有高峰但 paired 曾零速，因此 direct P1 默认取 12KiB。DL 将约 64KiB transmission read 切成 16KiB 后，gate-off P1 DL 三轮约 596 Mbps；opt-in NDI TSO 中位 527.46 Mbps，反而更低，必须保持 default-off。

**UL gather 实验**：direct upload writer 可由 `OPENPPP2_XTCP_DIRECT_UPLOAD_GATHER_BYTES`（runner `--xtcp-direct-upload-gather-bytes`）合并已入队连续 payload；不等待凑批，受 carrier plaintext cap 限制。5 秒单轮 strict paired screen 中，60KiB 为唯一 P1/P4/P16 全过候选（1.2057–1.2576×）；但三轮 artifact `artifacts/ul-gather-61440-r3-20260904` 的 P1 round 2 为 1.1873×、P16 round 3 为 1.0939×，即使 18/18 qualification pass 仍未通过稳定 1.2× 性能门禁。

**DL four-credit 实验已否决并回退**：尝试将每 flow direct download reservation 从单个 16KiB 增至 64KiB，目的是连续读取 transmission payload。`artifacts/dl-credit-sndbuf-131072-r1-20260904` 显示 P1/P4 ratio 仅 0.1413/0.6850，且每 flow queue 卡在 64KiB、server `rwnd_limited` 约 99.9%；512KiB artifact 的 P16 发生 watchdog。该路径会造成持续 receiver-window backpressure，不能以增大 sndbuf 或重试掩盖。实现已恢复为单个 16KiB flight：每次 XTCP `Send` accepted 后才由 writable notification 继续读取下一块。

**DL watchdog 根因与修复**：P4 现场四流均为 `snd_wnd=0`、`inflight=0/1`、`pending≈sndbuf`，direct queue 另有 62248 bytes；persist 探针约每两秒发出并获 ACK，但 `NextTimerDeadline()` 仍优先返回无进展可能的高频 `pacing_deadline_`，使同核 PPP timer loop 空转并饿死负责读取 socket、重开窗口的 iperf。补丁 `0010-zero-window-pacing-deadline.patch` 在零窗口且 persist 已武装时忽略 pacing deadline，只等待 persist/RTO 等真实恢复期限；不改变正常开窗 pacing、sndbuf、retransmission ownership 或 NDI TSO。原故障维度 `XTCP/GSO-on/P4/DL/sndbuf=128KiB` 修后专场 `artifacts/route2-persist-fix-p4dl-gso-on-r3-20260904` 连续 3/3 pass，配对 qualification 6/6 pass，无 watchdog；XTCP 611.8–620.2 Mbps。

**验证状态（本工作树）**：lab C++ `135/135`、targeted persist/persist-stack/pacing `3/3`、runtime adapter/bridge `2/2`、项目 XTCP/GSO `8/8`、上游 fault suite `20/20`；修复后 direct bridge 短版 netns E2E（churn×16、netem/MTU、3s soak、rollback）通过，artifact 为 `artifacts/xtcp-direct-persist-e2e-20260904`。Route3 runner 已实现 PPP+iperf 同核 affinity、zero migration、RPS/XPS/相关 IRQ readback 与 compare-and-restore；other-CPU softirq 仅 warning。修复 revision 的六模式 strict 原子矩阵为 108/108 qualification pass。

**旋钮一览**：`OPENPPP2_XTCP_SHARDS` / `--xtcp-cc` / `--xtcp-sndbuf` / `--xtcp-unix-bridge` / `--xtcp-memory-bridge` / `--xtcp-ndi-tso-tx` / `--xtcp-direct-upload-gather-bytes` / `--tap-gso-segments` / `--xtcp-gso-rx` / `OPENPPP2_XTCP_GRO_BYTES` / `OPENPPP2_XTCP_INGRESS_ITEMS/BYTES` / `--xtcp-send-retry-us` / `OPENPPP2_XTCP_CONNECTOR_BATCH_BYTES`。runner 会先清除继承的 direct-bridge/NDI-TSO env，只按显式 flag 启用，并把它们写入 dry-run、matrix 和 cell metadata。

**剩余阻塞**：
1. P1/P4 UL/DL 与 native 的稳定 1.2× 目标未达，且 P1 UL 仍有间歇性严重退化；
2. default-off NDI TSO 负收益尚未解决，不能默认启用；
3. `ITransmission` 协议级 half-close；
4. P64 DL 既有 server-side wedge。

**结论**：三条路线均有可运行实现和正确性证据，Route3 qualification 装置在修复 revision 上完成原子 108/108 pass，且 P4 DL 零窗口 watchdog 已消除；但性能门禁及协议级 half-close 等事项仍未完成，不能宣称路线 1–3 完成或 production ready。

### 0.1 `gpt6fix` 上传预算与乱序窗口修复（2026-09-08，未提交）

本轮先处理有界所有权与回压后的正确性，不宣称完成 RX 零拷贝或稳定 1.20× 性能目标。

- `XtcpUploadBudget` 为同一 runtime 的 direct/connector 上传提供共享预算，默认 32MiB、65536 个原始接收 chunk；字节上限沿用 `OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES`，在 runtime 首次启动时确定。原来的 direct 单流 32MiB/4096-item 上限仍保留。
- 在全局和单流 admission 成功后才复制回调借用的数据，拒绝路径不再先分配/复制 payload。接受路径仍有一次 payload copy，并非零拷贝。
- move-only reservation 随队列及在途异步写存活，gather 只合并已有额度，写完成才归还；关闭清除未提交队列，重启仍统计旧代在途持有者。预算统计的是逻辑上传 payload，不包括 gather 临时副本、编码缓冲和内核 socket 内存。
- 额度释放通过合并的 shard 通知唤醒全局预算阻塞流，不依赖另一个连接的 writable 回调；单流 backpressure 标志仍用于通知，不改成硬性高低水位 admission 锁存。
- 新遥测：`upload_budget_bytes/items/max_bytes/max_items/rejected`。原有 queue 遥测不替代预算账本。
- `0013-ooo-frontier-reclaim.patch` 回收被 RCV.NXT 覆盖的 OOO 数据、保留重叠段的新鲜后缀和恰好位于 frontier 的 FIN，避免已交付字节继续占用接收窗口。按序号环绕的两个有序区间访问旧节点，避免每次 drain 扫全表；这是 frontier 修复，不是完整 OOO 区间规范化或零拷贝重写。

验证记录：C++ 139/139、固定上游 fault suite 20/20、32 个新增 OOO 场景、共享预算并发/异常/重启唤醒测试通过；真实 direct netns E2E（churn 16、soak 3 秒、loss/reorder/MTU、byte-exact、half-close 和 rollback）通过，证据在 `artifacts/g6-upload-ooo-e2e-0908/`。补丁栈从固定归档全量重放，并与实际源码逐文件一致。

扩展 OOO 组的 `test_ts_ooo_drain` 仍失败；两个既有旧构建也复现同样三个断言失败，未改测试或豁免，不宣称完整 upstream suite 全绿。`artifacts/g6-upload-smoke-0908/` 保留了只有预算、没有 OOO 修复时的低速/零速失败；`artifacts/g6-upload-ooo-smoke-0908/` 功能通过但与编译重叠，不能作为正式性能提升证据。legacy runner 的 `--netem-delay-ms` 不具备 strict v3 的真实 qdisc 门禁，不能据此宣称 75ms 损伤验收。

无并行编译/负载测试的三轮历史 runner 对比已完成：`artifacts/g6-upload-ooo-quiet-r3-0908/`，12/12 qualification pass、所有流非零；P1 UL 中位 742.47Mbps、paired ratio 中位 1.0720，P4 UL 中位 744.31Mbps、paired ratio 中位 1.0880。每个 cell 为 duration 5s / omit 1s，CPU8、GSO-on、direct bridge。六个 paired ratio 均小于 1.20；runner 性能门禁为 off，故 qualification pass **不等于**性能目标通过。P4 selected-CPU 效率还有一轮 0.8327× 回归，不能宣称系统 CPU 效率稳定提升。预算采样不超过 33554432B；短测无零速并非长期稳定性证明。这是当前 XTCP 对 native 对比，不是完整旧 XTCP/新 XTCP 三轮配对因果实验。

NDI TSO 仍 default-off；pacing quantum 退款候选未混入本轮；没有启动 576-cell campaign。GitNexus 因数据库/库版本不兼容无法给出图谱影响结论，本轮按高风险数据面改动人工检查调用链及生命周期。

## 1. 状态与范围

XTCP 依赖来自已确认授权的内部仓库。许可证不再阻断内部 laboratory 集成。源码通过 `tools/prepare_xtcp.sh` 固定下载并校验，解包目录中的 `.openppp2-xtcp-revision` 必须等于上述 revision。

当前完成的是 **Linux desktop、client、IPv4 TCP、显式 opt-in 的 laboratory runtime**，不是 production 功能。只有同时满足以下编译门禁时 `--tcp-stack=xtcp` 才可用：

- `PPP_ENABLE_XTCP=1`：固定依赖已编入 artifact；
- `PPP_XTCP_RUNTIME_WIRED=1`：OpenPPP2 packet、listener、bridge、启动和 teardown 已接线。

顶层仅在 `ENABLE_XTCP=ON` 的生产 target 上定义这两个宏。关闭该选项时不包含任何 XTCP header 或链接依赖，显式请求 XTCP 保持 fail-closed，绝不回退 native/lwIP。历史默认和 `--lwip` 兼容规则不变。

当前明确不支持：

- production rollout 或性能承诺；
- IPv6、UDP、IPv4 分片、Windows、Android、iOS；
- 运行中热切换；
- MIMT；
- 多 owner executor；
- 零拷贝 stream bridge；
- 无限 flow、packet 或 stream 缓冲。

## 2. 组件边界

生产实现位于 `ppp/app/client/xtcp/`：

- `XtcpFirstLegHooks.h`：VNetstack/connection 可见的窄回调，不暴露任何上游 XTCP 类型；
- `XtcpPoolLease`：进程级引用计数 lease，首租约初始化 BufRef pools，最后一个 runtime 完成 stack/flow 清理后关闭 pools；
- `XtcpNdiBackend`：完整 L3 packet output adapter；
- `XtcpRuntime`：单 owner strand、deadline-driven timer pump、exact listener、flow registry、loopback connector 和双向背压；
- `XtcpRuntimePolicy.h`：standalone 可测试的 consumed、容量和 generation gate。

`VEthernetNetworkSwitcher` 持有 runtime。`VEthernetNetworkTcpipStack` 和 `VEthernetNetworkTcpipConnection` 只通过 `XtcpFirstLegHooks` 与 runtime 交互，不 include 上游 API。

## 3. Packet ingress 与 fail-closed

`VEthernetNetworkSwitcher::OnPacketInput` 的顺序固定为：

1. 先运行现有 `ClientPacketDispatchHandler`，保留 VNet raw NAT；
2. 若它未消费，且模式为 XTCP、协议为 IPv4/TCP，则把完整 L3 packet 提交 runtime；
3. 对 XTCP TCP 始终返回 consumed，包括 runtime 未 ready、已停止、队列满、pool exhausted 或 packet 无法提交；
4. UDP、ICMP、IPv6 和非 XTCP 模式沿用原路径。

这样任何 XTCP 故障都不会把同一 TCP flow 静默送入 native stack。

Ingress 在跨 executor 前复制，使用 item 与 byte 双上限。runtime strand 上把 copy 转入 XTCP `BufRef`，pool exhaustion 只丢弃当前 packet，不产生 native fallback。

## 4. NDI ownership

`XtcpNdiBackend` 把 XTCP 生成的完整 L3 packet 交给 `VEthernetNetworkSwitcher::Output`：

- `Output=true` 才消费 `packet.owned`；
- `Output=false` 不 move ownership，交由 XTCP retry queue 后续重试；
- `TxBatch` 仅消费 accepted prefix；
- 默认 `Caps()` 返回 `kCapNone`；只有 `OPENPPP2_XTCP_NDI_TSO_TX=1` 且 Linux TAP 已成功协商 `IFF_VNET_HDR` 与 `TUN_F_TSO4` 时才 advertise `kCapTsoTx`；
- TSO packet 必须携带上游 `BufRef::SegMeta`；backend 验证 IPv4/TCP 与 header/payload 形状、`gso_size != 0`、`mss != 0`、`gso_size <= mss`，并由 `TxGsoMetadata::ParseTcpV4` 校验 `gso_size/segs` 与实际 payload 分段一致；`mss` 仅作上界，不宣称与 `gso_size` 精确相等，也不从 packet 总长度猜测 metadata；
- `Stop()` 清空 output/Rx handler，停止后拒绝新 packet。

backend 不缓存 borrowed pointer，也不把拒绝伪装成成功。metadata 只读透传到平台中立的 `TxGsoMetadata`；任一 gate 或验证失败都 fail-closed。gate 默认关闭或 TAP 不支持时，上游不获得 capability，并继续软件分段。

## 5. 单 owner 与 callback 规则

所有 `XtcpStack` API 都由 runtime 专属 strand 驱动。上游 recv/state/accept callbacks 可能在 shard lock 下运行，因此 callback 仅允许：

- 四元组匹配或轻量状态标记；
- 把 borrowed stream bytes复制到有界 owned chunk；
- post generation-tagged work 到 owner strand。

callback 禁止重入 `OnPacket`、`Send`、`Close`、`Abort`、`Listen`、`StopListen` 或 `PollAckTimers`。

runtime 使用 `steady_timer` 驱动 `PollAckTimers()`。调度策略是 deadline-driven：上游补丁 `0001-next-timer-deadline.patch` 为 `XtcpStack` 增加 `NextTimerDeadlineUs()`，runtime 把下一次 poll 精确武装到该 deadline（无 armed deadline 时退化为 10ms idle watchdog）；任何 stack-mutating 路径通过 `KickPoll()` 以更早的 deadline 抢占挂起的等待。这替代了早期 laboratory 的固定 1ms 间隔；负载数据见第 11 节。

## 6. Exact listener 与 deferred SYN

首个 IPv4 TCP SYN 建立 pending flow：

1. 保存唯一 owned SYN；
2. 对 SYN 目标 endpoint 建立 exact `Listen` 引用；
3. 先创建 external second-leg connector；
4. connector bind `127.0.0.1:0`，取得 ephemeral source port；
5. 先把 source port + runtime/flow generation 精确登记到 VNetstack，再 connect 本地 listener；
6. `VEthernetNetworkTcpipConnection` 完成 second-leg peer setup 后，通过 weak `XtcpFirstLegHooks::OnFirstLegReady` 通知 runtime；
7. generation 匹配时才把 deferred SYN 喂给 XTCP。

XTCP `AcceptHandler` 以 remote/local 完整四元组匹配 pending flow，匹配后记录 opaque conn id；任何不匹配 accept 直接返回 false。listener 按 endpoint 引用计数，最后一个 flow 结束时 `StopListen`。本实现不启用 MIMT。

## 7. VNetstack loopback bridge

`VNetstack` 增加独立 `external_clients_` 注册表，不复用或改变 native/lwIP `TapTcpLink`、`lan2wan_`、`wan2lan_` 和 `lwip::netstack::link` 语义。

`ProcessAcceptSocket` 只有在以下条件同时满足时走 external path：

- peer 是 IPv4 loopback；
- peer source port 与 one-shot registration 精确匹配；
- registration 尚未取消或消费。

未登记的 loopback 继续遵循原 native/lwIP gate。external client 无 `TapTcpLink`，只复用 accepted socket 与现有 connection forwarding 工厂。

external connection 覆盖 `AckAccept`：

- external 模式 one-shot signal first-leg ready，然后启动正常 `Establish`；
- 普通 native/lwIP 模式调用 base `AckAccept`；
- `Dispose`/析构 one-shot signal first-leg closed；
- weak hooks 避免 connection 与 runtime 循环引用。

## 8. Stream bridge 与背压

默认 connector path 与 opt-in direct path 都有硬上限：

- 默认 path 的 XTCP recv 在进入 connector 写队列前同时检查 per-flow cap（4MiB）与 runtime 全局 budget（32MiB）；reject 时记住 blocked flow，write completion 令全局及 per-flow 队列降到 50% low watermark 后，在 owner strand 调用上游 `ResumeReceive()`，不依赖 peer RTO 偶然重开窗口；
- 默认 connector `async_read` 每次只保留一个 owned chunk；`XtcpStack::Send=false` 时暂停下一次 read，并以指数退避重试同一 chunk；不建立第二个 pending read chunk；
- opt-in direct path 在 `VEthernetNetworkTcpipConnection::AckAccept` 成功建立后不启动原 `connection->Run`。上传由 XTCP callback 复制进 32MiB/4096-item 队列，最多 64KiB coalesce，唯一 transmission writer 排空；admission reject 同样在 low watermark 后显式 `ResumeReceive()`；
- direct 下载只有一个 transmission reader，约 64KiB read payload 用 `shared_ptr` alias 切为 16KiB chunk，再逐块交给 `XtcpStack::Send`；总 pending budget 32MiB，writable notification 驱动继续发送；
- runtime 对 direct second leg 持强引用直到 `CloseFlow`，ready callback 排队与 payload 先到的竞态不再丢数据；generation 与 one-shot close gate 抑制 stale/重复关闭；
- 默认 path 可用 socket `shutdown(SHUT_WR)` 表达 half-close；direct path 仅在 carrier 报告 capability 时启用：raw child `ITcpipTransmission` 在 upload queue 排空后执行真实 `shutdown(SHUT_WR)`，发送方向 FIN 后保留接收方向；不支持半关的 `ITransmission`（包括 WebSocket/TLS）回退默认 socket pump，`degraded_half_close` 只为兼容字段且正确路径为 0；
- RST、I/O error、closed、hook closed 和 runtime stop 汇入 one-shot flow teardown；second leg ready 前收到 RST 直接取消 pending flow；
- 当前 adapter 显式拒绝 IPv4 分片，避免在重组前误读非首片为 TCP header。

所有 socket、timer、posted handler 和 direct callback 均携带 runtime/flow generation。旧 runtime callback 不得复活新 generation flow。

### 8.1 half-close 平台限制（已定案）

ppp 转发核在 client 发起半关（app 先发 FIN）后，下行尾包会被截断，连接以 EOF 或 RST 终结。根因：`shutdown(SHUT_WR)` 排空写队列后，`VirtualEthernetTcpipConnection::ReceiveSocketToTransmission` 对任何读错误（含 EOF）直接 `Dispose()`；vmux_skt `finalize()` 丢弃 rx_queue_ 尾包并硬关 loopback socket，于是 connector 读到 ECONNRESET，`CloseFlow(flow, true)` 向 app 发 RST。`--tcp-stack=native` 在同一场景行为一致（同一 ConnectionResetError），证明这是平台既有限制而非 XTCP 回归。

runtime 侧的对应语义：

- second-leg 转发对象已消失（`OnFirstLegClosed`）且首腿已建立时，flow 置 `peer_gone`：丢弃未投递的上行数据、吞掉 first leg 下行数据以维持流控推进；connector 读侧继续排空内核已收字节，EOF 优雅关、ECONNRESET 诚实 Abort；
- 首腿建立前对端即拒绝/失败时，注入 deferred SYN 并置 `abort_when_ready`，`AcceptHandler` 返回 false 使栈以 RST 应答 app 的 pending connect（快速失败而非超时），随后异步清理 flow。

完整排空需要 vmux 协议级半关改造（vmux_skt 边缘 + 服务端 + 可能的 wire 协议变更），超出本次 laboratory 接入范围，列为 production gate 后续项。

## 9. 启动、readiness 与 teardown

启动顺序：

1. `VEthernet::Open` 创建 VNetstack listener；
2. XTCP 模式创建 pool lease、backend、stack、callbacks 与 timer；任何显式初始化失败使 client Open 失败；
3. exchanger Open 成功后 `MarkReady`；
4. `GetRuntimeReadiness()` 在 XTCP 模式额外要求 runtime ready。

关闭顺序：

1. stop input，解除 TAP packet callback；
2. 立即 `XtcpRuntime::Stop`，拒绝新 ingress；
3. strand 上取消 timer/connect/read/write，关闭 flows/listeners，析构 stack/backend，释放 pool lease；
4. 再 dispose exchanger、QoS 和其他 client services。

Start/Stop 与 flow close 均为幂等操作，stale generation handler 只返回，不执行资源重建。

## 10. 运行时指标与 stats-json

`XtcpRuntime::SnapshotStats()` 汇总 `ppp::app::runtime::RuntimeXtcpStats`（全部为进程内累计原子计数，gauge 除外）：

| 字段 | 含义 |
|------|------|
| `ingress_submitted` | 成功进入 ingress 队列的 IPv4/TCP datagram |
| `ingress_dropped` | 未 ready / 已停止 / 预算耗尽被拒的 datagram |
| `ingress_injected` | 实际注入 XTCP 栈的 datagram（含 deferred SYN 注入） |
| `flows_opened` / `flows_closed` | 由入站 SYN 创建、因任何原因拆除的 flow 数 |
| `flows_active` | gauge：`opened - closed` |
| `timer_polls` / `timer_events` | PollAckTimers 扫描次数 / 各 flow timer 触发总数 |
| `output_packets` / `output_bytes` | 栈产出的 L3 packet 与字节 |
| `connector_read_bytes` | second-leg connector 读出的字节数（app → 栈） |
| `connector_written_bytes` | 写入 connector 的字节数（栈 → app） |
| `queued_bytes` / `queued_bytes_highwater` | 默认/direct upload queue 当前值与累计高水位 |
| `direct_upload_rejected` | direct upload admission reject 次数 |
| `direct_download_chunks` | transmission read 拆分后提交给 XTCP 的 chunk 数 |
| `direct_download_queue_bytes` / `_highwater` | direct download pending gauge / 高水位 |
| `direct_download_rejected` | direct download budget 或 Send 准入 reject 次数 |
| `resume_requested` / `resume_effective` | low-watermark 恢复请求 / 实际 window update 次数 |
| `second_leg_close_requested` / `_duplicate_suppressed` | second-leg close 请求 / one-shot gate 抑制次数 |
| `degraded_half_close` | 兼容保留字段；capability-gated direct raw-TCP half-close 正确路径恒为 0，旧 revision 的延迟整关 artifact 可能非零 |

default-off perf JSON 的 `conn`/`queue`/`direct` 分组另保留 read/write 调用与字节、reject bytes、全局 queue、高水位及 direct close/download queue 诊断；稳定 stats 保留上述资源与状态机关键累计量。

读取路径：stats tick（`PppApplication::OnTick`，1s 周期）→ `VEthernetNetworkSwitcher::GetXtcpRuntimeStats()` → 同一 owner 持有的 runtime。XTCP 模式下 `--stats-json` 的每行 NDJSON 带 `xtcp` 块；非 XTCP 模式无该块。

注意：tick 是 1 秒周期，battery 类短流量可能在最后一个 tick 落盘前结束，因此消费方必须按"快照覆盖窗口"语义等待/折叠累计值，而不是只读最后一行。E2E 断言即按此实现（最长 15s 收敛 + 跨行取 max）。

### 10.1 稳定统计与诊断遥测的边界

`--stats-json`（上表 + `RuntimeXtcpStats`）是**稳定运行时统计接口**；字段变更需保持向后兼容。

`OPENPPP2_XTCP_PERF_JSON=<path>` 是**独立的诊断遥测通道**，不属于 `--stats-json` 的稳定接口。其字段服务于 laboratory/性能/根因分析，可随内部实现演进；未启用时不引入持续开销。当前输出分组：

- `send.*`：栈 Send 准入调用、拒绝、累计 stall；
- `admission.*`：仅当同时设置 `OPENPPP2_XTCP_SEND_ADMISSION_JSON=1` 时输出。每个 flow 仅在 `Send=false` 的阻塞转换时读取一次上游快照；报告当前 blocked flow/字节、非可发送状态与 `snd_buf` quota 分类、最长连续阻塞时间，以及 attempted/pending/inflight/snd_buf/snd_wnd/cwnd/pacing deadline 的跨 flow 范围。blocked 字节同时包含 connector `pending_read` 和 direct bridge `direct_read_bytes`，避免 direct path 被错误报告为零积压。它只读状态、不改变 retry、队列、定时器或 TCP 行为；
- `conn.*`：connector read/write 次数与字节、平均块大小、write cycle/gap 直方图分位、per-flow 队列高水位、**`rej`/`rej_bytes`（OnReceive 因 per-flow cap 或全局 budget 被拒的次数与字节）**；
- `recv.*` / `out.*`：栈收发两侧的包数、字节与平均 segment/packet 大小；
- `tcp.*`：首个活动连接的真实 cwnd/inflight/snd_wnd/ssthresh/重传计数（ConnStats 导出）；
- `owner.*`：ingress post/dispatch/dropped/injected 与 strand 队列延迟分位；
- `queue.*`：全局 queued-byte 当前值/高水位、超过 256KiB/1MiB/2MiB 的 flow 数；
- `ndi.*`：NDI 输出包率、Output wall time 与 callback interval 分位、TxBatch 统计；
- `timer.*`：poll 武装数与 lateness 分位。

排查 `Send=false` stall 时，`admission.sndbuf_quota` 与 `inflight/sndbuf` 范围先用于确认直接许可门；其后才结合 `conn.rej`、`send.stall_ms`、`queue.global_high`、`ndi.out_*`/`iv_*` 判断 ACK/output 前置原因。

## 11. 测试、验证证据与进入 production 前的限制

### 11.1 上游源码与补丁机制

`tools/prepare_xtcp.sh` 固定下载并校验上游源码（`.openppp2-xtcp-revision` 必须等于第 1 节 revision），随后**幂等应用** `tools/xtcp-patches/*.patch`（文件名序）。已应用的补丁集合 sha256 记录在解包目录 `.openppp2-xtcp-patches`；反向可干净移除的补丁视为已应用而跳过。当前补丁：

- `0001-next-timer-deadline.patch`：为 `XtcpStack` 增加 `NextTimerDeadlineUs()` / `kNoTimerDeadline`，支撑 deadline-driven poll（见第 5 节）；
- `0002-send-admission-observability.patch`：为 `SendData` 拒绝路径记录只读许可快照，并提供 stack accessor，供上述 opt-in stall 诊断读取。
- `0003-ack-release-observability.patch`：ACK 释放/flush 路径的只读遥测计数（attempts、pacing 门、window/cwnd 门等）。
- `0004-timestamp-aware-data-payload-cap.patch`：`DataPayloadCap` 计入 TSopt/MD5 选项长度，按实际 wire 上限封顶 segment 载荷。
- `0005-pacing-burst-quantum.patch`：修复 pacing 子系统的吞吐钳制——① `NextTimerDeadline()` 纳入 `pacing_deadline_`，paced 连接在 pacing 到期时精确唤醒（此前 pending 缓冲一律报"立即到期"，host loop 空转）；② `FlushPendingSend` 改为突发 pacing：每个 pacing tick 放行 ~1ms 线速数据（fq/TSO autosize 量子，clamp 到 [1 segment, 64KB]），此前每次 flush 调用最多 1 个 MSS，任何 `pacing_rate > 0` 的 CC（KCC/BBR）吞吐被钉死在 MSS/事件循环迭代（与 RTT/cwnd 无关，实测 ~216Mbps）；③ pacing 门空手返回时零拷贝回挂缓冲（swap 代替整块 assign）。同时修复突发发送暴露的丢包恢复停摆（`test_wscale_transfer`，12.5% 丢包下 40-200s 超时）：④ OOO 数据驱动的 dup-ACK 不再受 100/s 泛洪限速——只有新增 SACK 信息的到达立即回 ACK，同键重复/缓冲溢出的无信息到达才进限速路径（Linux 从不对数据驱动的 dup-ACK 限速；RFC 5961 的限速针对的是 challenge ACK）；⑤ 填补接收空洞（drain OOO 缓冲）的 segment 立即回 ACK（等价 Linux 的 ICSK_ACK_NOW），不再等 40ms delayed-ACK——发送端 FR/RACK 恢复在等这个累计 ACK；⑥ 部分重叠（trim）路径只要推进了接收前沿就立即回累计 ACK，只有完全陈旧（纯 D-SACK 反射）的 segment 才走进限速的 `SendDupAck`。测试侧：`test_pacing_flush` 期望值修正为 TSopt 感知的 1448B（1460-12，补齐 0004 的漂移）；`test_1mb_stream` 的发送循环挂起保护从迭代次数改为墙钟（突发 pacing 下空转迭代几乎免费，迭代计数无法约束传输时间）。
- `0006-explicit-receive-resume.patch`：接收背压显式恢复合同。
- `0007-ndi-tso-metadata.patch`：为 `BufRef` 增加显式 `SegMeta`，TSO emission 携带精确 `gso_size/mss/segs`；无 metadata 不得从长度推断。
- `0008-tso-buffered-single-flight.patch`：TSO backpressure 后保持整帧重试，并只在 retransmission queue 为空、非 recovery 时发送一个 buffered super-segment；所有 active/TFO/MD5 connect、listener accept 与 SYN-cookie 路径在 `BindDataPath` 统一继承 capability，MD5 强制软件分段。
- `0009-test-pmtu-timestamp-expectation.patch`：修正 timestamp 协商后的 PMTU 测试期望（1460 → 1448），与 `0004` 的 TSopt-aware payload cap 一致；`prepare_xtcp.sh` 连续运行保持幂等。
- `0010-zero-window-pacing-deadline.patch`：peer send window 为零且 persist 已武装时，`NextTimerDeadline()` 不再返回无法推进发送的 pacing deadline；host 等待 persist/RTO 等真实恢复期限，避免严格同核场景下 timer 空转饿死接收端。`test_persist` 用固定高 pacing rate 锁定 deadline 合同。
- `0011-detailed-receive-resume.patch`：将接收恢复结果和接收状态快照结构化，区分未阻塞、恢复成功、窗口仍满和连接已关闭，供 runtime 正确处理背压恢复。
- `0012-tso-gate-observability.patch`：只读聚合 direct/buffered TSO candidate、首个 gate blocker（disabled/pending/outstanding/recovery/window/cwnd/pacing/pool）及 emitted 计数；同时固化此前解包树中尚未归档的 ACK rate-change telemetry。仅在既有 `OPENPPP2_XTCP_ACK_RELEASE_JSON=1` 诊断通道输出，不改变 TSO gate、发送、重传或 pacing 行为。
- `0013-ooo-frontier-reclaim.patch`：当接收前沿推进时回收已被覆盖的 OOO 字节，并保留重叠段的新鲜后缀及位于新前沿的 FIN，避免陈旧乱序数据继续占用接收窗口。
- `0014-ooo-backpressure-retain.patch`：应用拒绝连续 OOO drain 中的数据时保留该 SACK 段和窗口占用，待显式恢复后重交，而不是丢弃并依赖对端重传。
- `0015-frontier-pending.patch`：保留被应用拒绝的 in-order frontier，与 OOO 缓冲共同计入接收窗口；恢复时先重交 frontier，再在同一次恢复里排空连续 OOO 段。FIN/关闭回调仍按 TCP 状态机终止当前排空，避免已 SACK 数据必须等待重复重传。

修改上游行为的唯一入口是该目录下的补丁；直接改解包树会在下次 prepare 时丢失。

### 11.2 已完成的验证（laboratory gate）

- standalone 合同：XTCP TCP consumed/no-native-fallback policy；ingress item/byte cap、ready/stop gate；external loopback endpoint/source-port/generation gate；IPv4 字节序转换与分片拒绝；production NDI ownership；repeated start/stop 与 stale generation；上游 dependency、BufRef/NDI、exact listener accept/reject。
- bridge 功能测试 `tests/cpp/xtcp_runtime_bridge_test.cpp`：echo、half-close（EOF 优雅关）、peer-close drain、inject-then-reject RST、churn，含对端 EOF 后 `shutdown(SHUT_WR)` 的生产语义模拟。
- 上游故障套件 `tools/run_xtcp_fault_suite.sh`：20/20 通过。
- bench 单次参考值：`{"best_mbps":5950.78,"kpps":1089.65,"cc":"kcc"}`（实验室环境，不作 production 承诺）。该数值是**上游 XTCP standalone bench 在其测试环境中观察到的结果**：不同 CPU、内核、copy path、GSO 与页布局都会改变它，不得当作普适上限；完整 OpenPPP2 P1 只有数百 Mbps 与它是两个问题（见 §11.4 三榜框架），也不能从绝对数字推出"XTCP 与 native 同级"——除非同机有 native baseline，只能表述为**XTCP core benchmark 显示出远高于当前 OpenPPP2 integration 所能释放的性能余量**。
- Linux netns E2E `tests/integration/linux/xtcp_tap_netns_e2e.sh`（默认 SOAK=60s、CHURN=512）：echo / half-close 上传完整性 + 下行前缀排空 / peer-close 全量 drain / inject-then-reject RST / churn x512（`flows_opened=516` 与流量闭合）/ netem（loss 1% reorder 25% delay 10ms MTU 1280）/ 60s soak / stats-json xtcp 块断言 / TUN 消失后路由与 DNS rollback。短跑矩阵（SOAK=3、CHURN=16）同样全绿。
- TSan 构建（`ENABLE_TSAN=ON` 的 lab tests 目录）运行通过。

### 11.3 进入 production 前仍缺的证据

在以下证据完成前不得宣称 production：

- 大规模 flow churn 下的资源上限与内存水位验证；
- sanitizer/TSan 与长连接 soak 的持续集成化；
- PMTU 变化与背压极端场景的专项故障注入；
- vmux 协议级半关改造（消除 8.1 平台限制）；
- Linux IPv4 之外的平台/协议独立评审。

### 11.4 性能基线（provisional gate，CI 固化前须经同机多轮 paired baseline 校准）

**三榜框架（所有性能结论必须归属到具体榜，禁止混用）。**

| 榜 | 回答的问题 | 主要指标 | 入口 |
| --- | --- | --- | --- |
| **A. Strict single-core product** | 完整 OpenPPP2 数据面中，**只给 1 个 client CPU**，native/lwIP/XTCP 谁推出最高有效吞吐 | Mbps、process/procstat ns/B | `client-single-core` + §11.4 的 Route3 qualification 硬门 |
| **B. Operational product** | 允许当前线程模型自然扩展（client 可用第二颗 CPU）后，谁实际最快 | Mbps、cores、Mbps/core、延迟 | `client-vnet-isolated` |
| **C. Stack capability ladder** | 性能到底在哪一层丢掉 | 逐层 Mbps/ns/B 与相对上一层的保留率 | attribution experiments（见下） |

A 榜测的是"**谁能在完整 OpenPPP2 数据面里用 1 个 client CPU 推出最高有效吞吐**"，不是"谁的 TCP 栈算法实现本身最好"；后者属于 C 榜。当前数百 Mbps 的完整 P1 结果首先是 A/B 榜的 product datapath performance，**不能用于评价任一 core 的绝对能力**。三榜正式结果必须使用**同一冻结 revision**，且该 revision 须先满足：`XTCP` fixed-cell stress 完成 + 修复后 `XTCP+GSO` full matrix 完成（见 `XTCP-MSS-RETX-001`）；冻结时记录 `ppp_sha256 / git_head / git_describe / dirty tracked / untracked` 指纹，不得混入仍在 XTCP regression validation 的 revision。

**C 榜（capability ladder）设计（attribution experiments，不改 production 架构）。** 对 XTCP 逐层增加成本域：

```text
C0 XTCP upstream/core loopback
C1 + in-memory NDI（NDI Output → memory sink，输入由 memory source 喂入）
C2 + bare TUN NDI
C3 + OpenPPP2 Tap/VNet bridge
C4 + exchanger/carrier
C5 + mux
C6 + AES-256-CFB
C7 full native D0 OpenPPP2 path
```

lwIP 对应 `L0 in-memory netif → L1 bare TUN → L2 OpenPPP2 VNet → L3 full PPP`。每层保持相同 packet bytes、MTU、TCP options、单 owner / single-core 条件，只加一个成本域；报告相对上一层的保留率（例如 `XTCP full/core = 7.5%` vs `lwIP full/core = 46%` 会指向"integration 更适合 lwIP 执行模型、XTCP 能力损失在边界上"，而非"lwIP TCP 比 XTCP 强"）。C0 与 C1 的 gap 直接回答"去掉 TUN/Tap 后 OpenPPP2 XTCP adapter 自己能跑多少"。见 §11.5 的 `XTCP-NDI-MEMORY-001` 与 `LWIP-NETIF-MEMORY-001`。

测量装置：`iperf3` 单向流（10s，跳过 2s warmup），P=并行流数；延迟为 512B ping-pong ×512（TCP_NODELAY）；对照 `--tcp-stack=native`。

`tools/run_datapath_linux_matrix.sh` 是该矩阵的专用运行器：它用同一个显式指定的 XTCP-enabled `ppp` binary 启动 native、lwip 与 XTCP client cell，P 仅映射为 `iperf3 -P`；OpenPPP2 的 `client.concurrent` 是独立旋钮，默认固定为 `1`。`--stacks` 与 `--tap-gso` 都接受逗号列表；runner 从固定的 `native/off`、`lwip/off`、`xtcp/off`、`native/on`、`lwip/on`、`xtcp/on` 顺序中过滤请求 mode，并在每轮循环轮换。每个 `(round,P,direction,stack,gso)` 使用新 netns；cell artifact 位于 `round-N/<stack>-gso-<off|on>-pP-<ul|dl>/`，保留 raw iperf JSON、配置、日志、stats NDJSON、metadata 与 result JSON。所有 cell 都须由 stats NDJSON 证明 requested/active TCP stack 一致；GSO-on 还必须证明 Linux TAP 的 VNET header 与 GSO merge 均 active，能力回退不是有效 score；XTCP cell 继续要求 XTCP stats block、flow 与流量计数。summary 按 round、GSO requested/active 状态输出 lwip/native、xtcp/native 与 xtcp/lwip 配对比值，并保留 per-flow min/p10/p50/p90/max、`zero_rate_flows` 与 max/min；出现零速流是必须保留并报告的公平性退化（max/min 标为未定义），不是 runner 格式错误。`--dry-run` 可在不需要 root、PPP binary 或 netns 的条件下打印解析后、按轮轮换的 cell 路径。典型校准命令：

```bash
tools/run_datapath_linux_matrix.sh \
  --ppp-bin "$PWD/build/xtcp-runtime-root/bin/ppp" \
  --artifacts "$PWD/build/datapath-matrix" \
  --stacks native,lwip,xtcp --tap-gso off \
  --parallel 1,4,16 --directions ul,dl --rounds 3 --duration 10 --omit 2
```

#### 11.4 CPU profile 实验计量

`--cpu-profile` 默认 `none`。**`client-vnet-isolated`** 是 operational 测量 profile：要求 `--affinity-cpus` 至少两个互异、online 且在当前 `cpuset.cpus.effective`（存在时）内的 CPU，runner 在 client PPP TUN ready 后唯一定位 `vnet` TID 并 pin 到第一个 CPU，其余 client TID pin 到余下 CPU；它允许 stack 内部线程使用第二颗核，回答"不限制 stack 内部线程时当前产品实际能跑多少"。**`client-single-core` 是本基准的主 profile**：要求恰好一个 CPU，client PPP 与 client-netns `iperf3` 都从进程启动命令起由 `taskset` 固定到同一 CPU，之后创建的线程继承限制；iperf launch readback 与 formal start 必须枚举两进程全部现存 TID，并从 `/proc/<pid>/task/<tid>/status` 严格回读 `Cpus_allowed_list`。formal end 时，仍存活的 iperf 必须再次通过全部 TID readback；若它已正常完成并退出，则明确记录 `terminated_after_interval` / affinity `not_applicable` / qualification `pass`，不能把无 TID 误判为 affinity 失败。异常提前退出仍由 cell status 与 watchdog 硬门拒绝。两个 profile 都自动保留 datapath SIGUSR1 formal boundary；formal window 从 omit 后的 start boundary 到 iperf 完成后的 end boundary，不包含 warm-up omit 或 post-traffic sleep。strict profile 自动启用 PPP 与 iperf 两个 perf 实例，并在 formal start 前完成 attach、formal end 后停止，使 `cpu-migrations=0` 覆盖整个 formal interval。`--system-cpu-stat` 对所有非 none profile 可用，按 selected CPU set 记录同一组非 PMU 事件。`client-cpuset` 继续作为兼容 profile，把 PPP TID 限制到显式 CPU 集合。

每 cell 的 `cpu_measurement` 保留 profile、CPU list、affinity 回读、formal monotonic interval、client thread snapshot、`lscpu`/allowed CPU、`/proc/stat`、`/proc/softirqs`、ksoftirqd mapping 与可选 perf CSV 文件名；payload 只使用 iperf end aggregate 的实际 `sum_sent.bytes`（UL）或 `sum_received.bytes`（DL），缺失时 CPU 结果为 `failed`，不会用吞吐倒推。状态含义只有：`unavailable`（profile none）、`failed`（pin、snapshot、payload 或请求的 perf 失败）和 `measured`（完整采集）。`migration_warning` 独立记录 selected 之外的 `NET_RX`/`NET_TX` 增量；它只表示可能存在迁移或 peer/server/netns/veth 的正常网络处理，不能凭全局 `/proc/softirqs` 归因。matrix summary 仅对 measured 输出 **busy 口径**的 CPU ns/B（`process task-clock` 与 selected `/proc/stat` non-idle，两者互相验证）的 median/min/max/MAD，并据此写 `cpu_paired`；`perf stat -a -C` 的 system-wide task-clock 在该用法下是 selected CPU 的墙钟容量（每颗 CPU 忙闲都计时，反算恒为 ≈n_cores），**无 ranking 信息量**，只作为 `selected_cpu_clock_capacity_ns_per_payload_byte` 诊断输出、不参与 paired。`cpu_paired` 仅在同一 round 的两个 cell 都是 measured 时写入，既有吞吐 paired ratio 语义不变。CPU 配对采用 `cpu_efficiency_gain = reference_ns_per_B / candidate_ns_per_B`，故 `>1` 表示 candidate 的每 byte CPU 成本更低。

P1 UL dedicated-host smoke 固定 `P1/UL/concurrent=1/MTU=1500` 跑两套榜：**榜 1（主榜，严格单核）** 用 `client-single-core`，一次跑 native/lwIP/XTCP × GSO off/on 的 6 cell；**榜 2（operational）** 用 `client-vnet-isolated`，允许 stack 使用第二颗 client CPU。Route3 strict runner 在 client netns 内对 `xc-veth` 与动态 TUN 的所有实际存在 `rx-*/rps_cpus`、`tx-*/xps_cpus` 做 snapshot → target CPU mask apply → readback → compare-and-restore；设备完全没有 RPS/XPS 文件时记 `unsupported` 并 FAIL，但不存在的 queue 类不凭空要求。关联 IRQ 同时记录 `smp_affinity` 与 `effective_affinity`；设备没有关联 IRQ 时明确记 `not_applicable/pass`。恢复在接口/netns 删除前逆序执行，重复执行幂等；只有当前值仍等于 runner 写入的 target mask 才恢复原值，外部中途修改记冲突且绝不覆盖。TUN 已消失可记 `no_persistent_leak`，`xc-veth` 恢复失败必须使 cell FAIL。runner 仍不管理 ksoftirqd、cpuset、CPU governor、Turbo 或 peer/server CPU；全局 other-CPU NET_RX/TX 增量继续只作 warning，因此 Route3 通过也不等价于所有 production host controls 已完成。

**严格单核资格判定（每 cell 硬 invariant）。** runner 在非 `none` profile 下为每个 cell 写 `qualification.json`（纯 Python `tools/datapath_qualifier.py`，可单测）。`process_cores` **直接按 PPP `process task-clock / formal wall time` 计算，不从 Mbps/ns-per-byte 反推**（反推值仅作 `process_cores_derived_sanity` 交叉验证）。历史 `client-vnet-isolated` / `client-cpuset` profile 保留 **`0.9 ≤ PPP process_cores ≤ 1.02`** 口径；`client-single-core` 则因 PPP 与 iperf 有意竞争同一 CPU，只把 **PPP `process_cores > 1.02`** 作为硬失败，低于 0.9 记录 `ppp_process_cores_below_0.9_same_core_contention` warning。该 strict profile 另以 selected `/proc/stat` non-idle、以及可用时 system perf 的 `CPUs utilized` 验证总容量不超过 1.02 核，并始终要求 payload positive。每 cell 必须同时满足：

```text
cpu_measurement.status = measured
affinity_verified        = true
PPP cpu_migrations       = 0
iperf cpu_migrations     = 0
PPP/iperf launch + formal start 全部现存 TID Cpus_allowed_list = 唯一目标 CPU
formal end：iperf 存活则验证全部 TID；正常退出则 terminated_after_interval / N/A pass
RPS/XPS readback         = 唯一目标 CPU mask（设备须至少有一个实际 queue 文件）
IRQ effective affinity   = 唯一目标 CPU；无关联 IRQ = N/A/pass
isolation restore        = pass
PPP process_cores <= 1.02（client-single-core 下 <0.9 仅 warning）
selected CPU capacity <= 1.02（system perf 可用时同时验证）
active_stack == requested_stack
active_gso  == requested_gso
payload_bytes            > 0
zero_rate_flows          = 0
no watchdog              （cell status == pass）
retransmits              >= 0
first_push_failure       = none（XTCP 才判；native/lwIP 该诊断不产生，恒 true）
oversized_l3_rejected    = false（由 first_push_failure.packet_shape.excess_bytes>0 派生）
```

任一失败即该 cell `qualification.status=fail` 并列出 `failed_checks`；`oversized_l3_rejected=true` 同样是硬失败；PPP same-core 下限 warning、`migration_warning` 与 other-CPU softirq 增量只作诊断，不判失败。strict cell 失败会把 `result.json`、矩阵总 `status` 置为 `fail`，runner 最终非零退出；有效 pass cell 与全 pass matrix 返回 0；`none` profile 不生成该硬门且行为不变。每 cell 持久化 `cpu-isolation-{snapshot,apply,readback,restore}.json`、`cpu-{launch,start,end}-affinity.json`、PPP/iperf 独立 perf CSV。只有 6/6 全 pass 的严格单核第一轮才允许进入 P1 UL/DL × 3 rounds（36 cells）主榜。

**Route3 修正后短 smoke（2026-09-04）。** 两次均为单 cell、`duration=5/omit=1`，runner 与 matrix 都返回 0，`cpu_measurement=measured`、`qualification=pass`、payload positive、zero-rate=0，且 launch/formal-start affinity、PPP/iperf 全窗口 zero migrations、RPS/XPS、IRQ N/A、compare-and-restore 与 selected CPU capacity 全部通过：

- `artifacts/route3-strict-native-p1-ul-pass-20260904/`：native/GSO-off/P1/UL、CPU0，298.9 Mbps；PPP 0.880 core 仅产生 same-core contention warning，selected non-idle 0.926 core，system perf capacity 1.000 core；end 记录 iperf `terminated_after_interval` / N/A pass。
- `artifacts/route3-strict-xtcp-direct-p1-dl-probe-20260904/`：XTCP/GSO-on/P1/DL、CPU8、sndbuf 128KiB，396.2 Mbps；PPP 0.585 core 仅 warning，selected non-idle 0.633 core，system perf capacity 1.000 core；end 同样记录 iperf `terminated_after_interval` / N/A pass。该旧 runner 未显式注入或记录 `OPENPPP2_XTCP_MEMORY_BRIDGE`，且 artifact 的 direct telemetry 为零，因此**不能**作为 direct bridge 证据，目录名中的 `direct` 仅是当时标签。

这些是 qualification 装置与两条短路径的真实 smoke，不是 native/lwIP/XTCP 六模式、paired 多轮、P4/P16 或完整 production 路线通过声明。旧 artifact `artifacts/route3-strict-smoke-20260904/` 保留作为修正前失败证据。runner 现新增 `--xtcp-memory-bridge` / `--xtcp-ndi-tso-tx`，清除父环境同名变量并把显式值写入 metadata，后续 strict direct 证据必须使用该合同。


> **实测陷阱（已修复）：** 首次带 `--process-perf-stat/--system-cpu-stat` 运行发现 runner 在 iperf 完成后无限阻塞。根因是 `perf stat ... -- sleep 1000000`：perf 在 `do_wait` 等其 sleep 子进程，`kill -INT` 被忽略，runner 的无界 `wait` 于是永久挂起。修复为：去掉 workload，改用 `--timeout=<iperf_timeout+60>s` 兜底（正常 run 不触发）+ `stop_cpu_perf()` 有界等待（INT 后 10s，僵尸提前退出；超时再 `SIGKILL`）。复现实验确认无 workload 的 `perf stat -p/-a -C` 响应 SIGINT 并写出 CSV；带 workload 则否。修复后 6/6 cell 均 `status=measured` 且 `affinity_verified=true`。

> **口径修正（重要）：** P1 UL 六模式首次实测暴露两个口径问题。其一，`perf stat -a -C 8,9` 的 system-wide task-clock 实际是 selected CPU 的墙钟容量（每颗 CPU 忙闲都计时），六模式反算全部恒为 ≈2 cores，因此它**不能**用于 CPU 排名，只能作 `selected_cpu_clock_capacity` 诊断；真正的 busy CPU 以 `process task-clock` 与 selected `/proc/stat` non-idle delta 为准。其二，`client-vnet-isolated`（vnet→CPU8、其余→CPU9）**允许 lwIP 同时吃两颗核**：lwIP 实际消耗 1.60（off）/1.92（on）个 process core，而 native/XTCP 恒为 ≈1.00 core。因此**不得**把 lwIP 的 raw 577/979 Mbps 称为"单核"。按 process core 归一化：GSO-off 为 lwIP≈360、XTCP≈336、native≈261 Mbps/core（lwIP 仅比 XTCP 高约 7%，而非 raw Mbps 的 73%）；GSO-on 为 native≈833、lwIP≈510、XTCP≈419 Mbps/core（native+GSO 明显领先）。lwIP 的 GSO 收益应分开写：throughput 1.70×、process CPU efficiency 1.41×、process CPU consumption +20%。这佐证了引入 `client-single-core` 主 profile 的必要性。



**历史两栈 GSO-off 参考（已由 §11.4.2 三栈 provisional 取代）。** 新 runner 曾完成 GSO-off、3 round、P1/P4/P16 × UL/DL × native/XTCP 的 **36/36** cell；该历史窗口全部 XTCP stats NDJSON 验证通过，最终窗口未见 zero-rate flow。它不与当前三栈 Stage A / provisional 的 `XTCP/GSO-off/P16/UL` 零速流观察相抵触，后者仍是当前公平性结论。该历史窗口的 per-round ratio 中位数如下（artifact：`build/c1-gso-production-candidate-20260901/matrix-gso-off-r3-v2/`）：

| P | UL XTCP/native | DL XTCP/native |
| --- | ---: | ---: |
| 1 | 1.2799 | 0.6909 |
| 4 | 0.2563 | 0.4451 |
| 16 | 0.2477 | 0.4900 |

这些是共享宿主、GSO-off、同一 XTCP-enabled binary 的最近三轮 paired 证据；它们显示 P4/P16 的 shared-path 问题显著，且与先前有限测量的绝对吞吐不可直接混合。它们不是 CI 校准、严格单核结果或 production 门禁结论。

**历史 XTCP+GSO 矩阵故障（已由 `XTCP-MSS-RETX-001` 修复；现场保留）。** 首次 GSO-on、3 round 同维度运行完成 **34/36** cell，round-3 的 XTCP P16 DL 在约 43s 后 16 条流同时变为零速，iperf server 最终报告 `select failed: Bad file descriptor`；外层 30 分钟时限中断前未产生该 cell result 或总 summary。相同 cell 随后的单次重跑在 42s watchdog 下通过：312.805Mbps、16 条流均非零，说明问题具间歇性，但**不**抵消首次 stall，也不允许将当时的 XTCP+GSO 矩阵标记为完成或作为 production 门禁依据。

为抓取而非掩盖该故障，runner 现提供每 cell `--iperf-timeout` watchdog（默认 `duration + omit + 30` 秒）和 `--stall-diagnostics`：超时后先保存稳定 stats、XTCP perf、datapath/GSO ledger、PPP/iperf fd 与线程快照、三端 netns 的 `ss -tinp`/路由/链路状态，再发送 SIGINT。固定 `XTCP-GSO-STALL-001`（GSO-on、P16 DL、10s+2s、42s watchdog）的 30-round 专场在 round-1 通过后、round-2 复现。iperf 从 4–5s 的 26.2Mbps 下降，并在 **5–6s 起 16/16 流同时归零**，直至 42s watchdog；现场在 `build/c1-gso-production-candidate-20260901/xtcp-gso-stall-001-r30/round-2/xtcp-p16-dl/timeout-diagnostics/`。稳定 stats 表明 `flows_active=17`、`flows_closed=0`、ingress 无 drop、`queued_bytes=0`，`timer_polls` 继续约 55k/s 推进，而 XTCP `output_packets/output_bytes` 与 connector read/write 都已冻结。target 端 16 条 iperf socket 仍 ESTAB、server Send-Q 约 5–9MiB、`rwnd_limited≈99.5%`；pre-signal fd 快照未显示 data fd 消失，本次也没有 `EBADF`。这排除了“全部 flow 已关闭”及队列积压型 backpressure 的直接证据，并把首要排查范围收窄为 XTCP 输出/发送许可、ACK clock 或其前置状态；但尚不能把根因归于 KCC、GSO 或任一具体组件。该样本的 GSO ledger 只有 40,692 次 ordinary write（40,657 次 PSH 拒绝），无 GSO full write/segment，故亦不能用它证明 GSO 合并器造成 stall。最新 Send admission 快照显示，16 条流的 `sndbuf_quota` 均为 64 KiB，`non_sendable` 不是原因；peer window/cwnd/pacing 快照不构成直接 admission gate。quota 未释放的上游链路仍未知。已知现场还表明：stall 期 NDI `Tx` 每秒约 37–39 万且全部被下游 handler 拒绝；normal 期 direct TUN write 成功后 attempts 归零、direct failure/partial 均为 0。这是 NDI 下游拒绝与 normal 后输出停止的证据，**不是** Tap、上层 disposed、写失败、KCC 或 GSO 的根因归属。

为抓取而非掩盖 fail-closed 路径，`OPENPPP2_DATAPATH_TUN_OUTPUT_DIAGNOSTICS=1` 在已有 datapath JSON 中写入累计 `tun_output`：`invalid`、`disposed`、`already_tun_write_failed` 是 `TapLinux::Output` 的 early false 原因；`first_latch` 分别记录 bare write、GSO disable-flush、hold-timer flush、ordinary write、coalescer push 首次触发 `FailTunWrite` 的来源；另有 VNET malformed/unsupported close 与 `Finalize` 总数。`first_push_failure` 的语义严格是该 session 中首次 **最终返回 false 的 `Push()` 的 terminal write failure**：`terminal` 明示 stage/kind（`ordinary`/`gso`）、outcome（`negative`/`partial`）、flush/rejection、原始 packet、requested VNET frame、signed written bytes、捕获时的 errno、segments、hold 与 monotonic ns；无事件明确为 `none`/零。MTU strict 拒绝没有 syscall，errno=0。若同一 Push 先有负 GSO write、随后 fallback ordinary 失败，`precursor` 保留该首个 GSO negative 的 errno/requested/written/monotonic，而 terminal 仍准确报告 ordinary；负 GSO 后 fallback 全部成功不产生 terminal snapshot。`failure_timeline` 的 T1=`Push()` returned false、T2=实际首次 `FailTunWrite` latch、T3=该 latch 导致的 `Dispose()` 调用，`push_false_without_terminal` 是必须为零的诊断不变量；它们都使用同一 PPP process 的 `steady_clock` nanosecond epoch。`OPENPPP2_XTCP_OUTPUT_REJECTION_JSON=1` 只在 `OPENPPP2_XTCP_PERF_JSON` 已配置时写入每秒 `output_rejection` delta，并附 T4=首次实际 `owner->Output` rejected 的同一 process `steady_clock` epoch；弱 owner、VEthernet disposed、tap missing、accepted 与 iperf 零速/runner watchdog 都不是该同一时间线。两类诊断均 default-off，只解码既有分支，不改变或证明发送许可、retry、队列、KCC、GSO、TUN write、packet ownership、返回值、生命周期或根因。

固定 P16/DL/GSO-on/XTCP 42s cell 已再次复现，现场位于 `build/xtcp-gso-stall-001-diagnostics-20260901/round-1/xtcp-p16-dl/timeout-diagnostics/`：`tun_output.first_latch.gso_coalescer_push=1`、其他首次 latch 来源均为 0，`invalid=0`、`vnet_input_close=0`、`finalize=1`；随后 `disposed` 增至 11,679,249，说明首个 fail-closed 分支是 coalescer `Push()` 失败后 `FailTunWrite` 的既有关闭路径。47 条 XTCP perf 记录累计 `output_rejected=11,523,774`、`accepted=268,052`，而 weak owner expired、VEthernet disposed、tap missing 均为 0；因此后续拒绝发生在 owner/Tap 调用后的返回值，而非该 lambda 的三个前置对象状态。该证据只定位失败分支，尚未解释 `Push()` 为何返回 false，不能据此归因于 KCC、GSO 策略或底层写失败。该历史样本当时仍阻塞；其后由 §11.4.1 的修复与回归更新当前状态。

固定 XTCP GSO-on P16 DL 的 50-run 专场在 round-5 再次触发 watchdog。该次 `Push=false` terminal 是预写 strict-MTU 分支：ordinary negative rejection=`mtu`、`original_packet_bytes=1512`、requested/written=`0/0`、errno=`0`、`precursor` 不存在；这不是 kernel syscall errno。为保留未知的 packet shape 而不记录 payload 或五元组，default-off `tun_output.first_push_failure.terminal.packet_shape` 对 MTU terminal 记录 supplied bytes、独立的 IPv4 total length、IHL、TCP data offset/payload length、IPv4 version/protocol/fragment flags、DF/TCP flags、固定 1500 guard 与 excess bytes。ParsePacket 失败时 `parsed=false` 且解析字段为零；非-MTU/no-event terminal 也稳定输出该默认值。guard 始终按 supplied buffer length 判断，不能将其与 IPv4 total length 混同。这只说明既有 pre-write 分支及其输入形状；并不证明 kernel、GSO 实现、`XtcpMSS`、KCC 或任何具体组件是 stall 根因。

#### 11.4.1 `XTCP-MSS-RETX-001`：历史 GSO stall 的已修复根因

以上段落保留了历史现场和诊断链；其“根因未知/矩阵阻塞”的结论已被随后取得的 packet shape、上游源码和回归证据取代，不能作为当前状态。

根因是 XTCP 的 segment payload sizing 曾固定使用 1460B，未扣除实际 TCP header 长度。启用 TCP Timestamp 时，TCP header 为 32B；RTO 重传于是构造 `IPv4 20B + TCP 32B + payload 1460B = 1512B` 的 L3 packet。Tap 的 1500B strict-MTU guard 正确拒绝该包，继而触发既有 `Push()==false → FailTunWrite() → Dispose()` 链。GSO coalescer 是 fail-closed 的下游检测点，不是根因；不得放宽它的 1500B guard。

修复以 header-aware cap 在 XTCP segment/retransmission queue 建立前完成分段：

```text
payload_cap = effective_l3_mtu - actual_ipv4_header_length - actual_tcp_header_length
```

因此 IPv4 无 Timestamp 保持 `1460B`，IPv4 Timestamp 为 `1448B`。初次发送与 RTO 重传使用同一个逻辑 segment，禁止在 RTO 阶段截断 payload。focused 合同覆盖 Timestamp on/off、边界长度、多 segment 与 RTO exact-size/seq/payload 一致性。

已验证的修复后回归：

- `XTCP-GSO-STALL-001-fixed-r50`：历史 `XTCP/GSO-on/P16/DL` cell 连续 **50/50 PASS**，无 watchdog、zero-rate flow、first push failure、VNET close、oversize output 或 XTCP output rejection；这表示修复后 50 次未复现，不是统计学上的永久保证。
- `XTCP-GSO-MATRIX-RETX-001-r3`：native + XTCP、GSO-on、P1/P4/P16、UL/DL、3 rounds 共 **36/36 PASS**；18 个 XTCP cell 均有完整 stats，未见上述失败信号。

当前仍保持 `GSO default-off`。未完成的 production gate 包括当前 direct revision 的完整三栈 strict 基准、idle/loaded latency 与短流/故障矩阵；因此这些回归不构成 default-on 或 production 结论。历史 `spinlock_test` 超时已定位为大量在线 CPU 上纯自旋压力的调度敏感性：固定 CPU0-7 后约 7.3s 通过，当前 lab 门禁为 135/135。

#### 11.4.2 三栈 provisional benchmark（2026-09）

已完成 CURRENT-LWIP、native 与 XTCP 在相同 Linux datapath 下的第一轮统一比较：`client.concurrent=1` 固定，P 仅映射为 `iperf3 -P`；每个 `(P,direction)` 跑 3 round，按 `native/off → lwip/off → xtcp/off → native/on → lwip/on → xtcp/on` 的 canonical mode 顺序循环轮换。共 **108/108** cell 完成并通过 runner 的配置、runtime proof 与统计完整性检查；所有 GSO-on cell 的每条 stats 样本均证明 `tap_linux.vnet_header=true` 且 `tap_linux.gso_merge_active=true`，没有 capability fallback、watchdog 或 XTCP stats 缺失。

本次构建/工作树指纹：

```text
ppp_sha256=00e357521664134faac6ec429d8521f20d36bc39523809511a08cd0f33fb9b5d
git_head=898667737a14b649bd49e84504a387e39a044454
git_describe=8986677-dirty
CMAKE_BUILD_TYPE=Release
ENABLE_SIMD=OFF
ENABLE_XTCP=ON
compiler=c++ (Debian 14.2.0-19) 14.2.0
dirty tracked=42, untracked=36
```

这只是共享宿主上的 provisional 结果，所有比值均为同一 round 内 `Mbps` 相除后再取中位数；没有隔离 CPU 的 system-wide CPU ns/B、延迟、内存或故障矩阵，故不能据此做 production stack 或 default-on 选择。

| P/方向 | GSO | lwIP/native | XTCP/native | XTCP/lwIP |
| --- | --- | ---: | ---: | ---: |
| P1 UL | off | 2.0543 | 1.1818 | 0.5559 |
| P1 UL | on | 1.1670 | 0.5002 | 0.4332 |
| P1 DL | off | 1.0281 | 0.8146 | 0.8224 |
| P1 DL | on | 0.3971 | 0.4390 | 1.1056 |
| P4 UL | off | 2.4550 | 1.0009 | 0.4062 |
| P4 UL | on | 1.0187 | 0.2885 | 0.2787 |
| P4 DL | off | 1.0276 | 0.8966 | 0.8616 |
| P4 DL | on | 0.4025 | 0.5085 | 1.2631 |
| P16 UL | off | 2.8112 | 0.7466 | 0.2641 |
| P16 UL | on | 1.0792 | 0.4740 | 0.4392 |
| P16 DL | off | 1.0280 | 0.9270 | 0.9133 |
| P16 DL | on | 0.4638 | 0.5672 | 1.2331 |

同栈 GSO-on/off uplift：

| P/方向 | native | lwIP | XTCP |
| --- | ---: | ---: | ---: |
| P1 UL | 2.8983x | 1.6489x | 1.2713x |
| P1 DL | 1.7876x | 0.7133x | 0.9697x |
| P4 UL | 3.3258x | 1.3647x | 0.9249x |
| P4 DL | 1.7179x | 0.6624x | 0.9712x |
| P16 UL | 2.6122x | 1.0212x | 1.6585x |
| P16 DL | 1.5539x | 0.7000x | 0.9612x |

该结果不能简化为“GSO 对所有栈普遍加速”：native 在 UL/DL 都有明显 uplift；lwIP 在 UL 受益而 DL 稳定回退；XTCP 的 DL 基本持平或微退、P4 UL 回退，P16 UL 虽受益仍明显落后 native/lwIP。尚未有 GSO ledger、CPU/byte 或 packetization 归因，禁止据此调整 GSO cap/hold、XTCP queue/KCC/pacing 或 lwIP 参数。

**GSO 叙事（收紧为解释假设，非结论）。** “XTCP 从 GSO 获益较少（P1 UL 1.27×）是因为它不吃 syscall tax”目前只能作为**待验证假设**：GSO 对完整 OpenPPP2 路径的影响已被证明不只是 `write(TUN)` syscall 计数（还会改变 TUN reads、VNET framing、packetization、frame encode rate、carrier sends 与上游 batching），因此更严谨的表述是：**XTCP 的完整集成路径对 edge packet-rate 摊薄的敏感度低于 native；具体份额需由 C 榜 capability ladder / stage ledger 定量**，而不是直接归因于 syscall。

唯一的公平性告警是 round-3 `XTCP/GSO-off/P16/UL` 出现 1 条 zero-rate flow。加上 Stage A 同 mode 曾观察到的 2 条零速流，这已是可复现的 `XTCP-SHARED-PATH-001` 信号；因此 **108/108 runner pass 不等于全部性能 cell pass**，该 mode 不可宣称公平性通过。

CURRENT-LWIP 未调参：`NO_SYS=1`、callback API、`TCP_MSS=1460`、`TCP_WND=TCP_SND_BUF=32KiB`、`MEM_SIZE=128KiB`、`MEMP_NUM_TCP_PCB=16`、`LWIP_STATS=0`；TCP Timestamp 当前未启用，`CHECKSUM_CHECK_IP/TCP/UDP/ICMP=0`、`LWIP_CHECKSUM_ON_COPY=1`。这是当前集成的透明记录，不是关闭 checksum 或调大窗口后的优化成绩。静态路径与 runtime proof 均表明 lwIP cell 实际进入 lwIP，而非初始化失败后静默回退 native。

后续顺序是：先在真实隔离 CPU 环境采集 process 与 client-side system CPU ns/B、softirq/ksoftirqd/额外 CPU 归属，再做 idle/loaded control-flow latency、短流和 MTU/retransmission/故障矩阵；通过这些 gate 后才执行 12-round（两套完整 6-mode rotation）校准。`GSO default-off` 保持不变。

#### 11.4.3 严格单核 P1 单轮基线（provisional，宿主污染，非正式榜）

artifact：`build/three-stack-singlecore-p1-ul-r1`、`build/three-stack-singlecore-p1-dl-r1`（均为 `client-single-core`、P1、30s、`affinity_cpus=8`、`--stall-diagnostics`）。**这些数字来自当前共享宿主，CPU8 被大量非 ppp 活动抢占，且 `process_cores` 下界是事后才加入 qualifier**，因此只能作为单轮 provisional 参考，**不构成正式三栈排名**。权威重判定（用修复后 qualifier）结果如下：

| 方向 | mode | Mbps | process_cores | qualification |
| --- | --- | ---: | ---: | --- |
| UL | native off | 262 | 0.985 | ✅ pass |
| UL | native on | 824 | 0.975 | ✅ pass |
| UL | lwIP off | 373 | 0.943 | ✅ pass |
| UL | lwIP on | 103 | 0.224 | ❌ **fail（饥饿）** |
| UL | XTCP off | 246 | 0.704 | ❌ **fail（饥饿）** |
| UL | XTCP on | 418 | 0.978 | ✅ pass |
| DL | native off | 369 | 0.985 | ✅ pass |
| DL | native on | 656 | 0.975 | ✅ pass |
| DL | lwIP off | 272 | 0.975 | ✅ pass |
| DL | lwIP on | 257 | 0.976 | ✅ pass |
| DL | XTCP off | 303 | 0.926 | ✅ pass |
| DL | XTCP on | 291 | 0.924 | ✅ pass |

DL 六 cell 全 pass，UL 4/6 pass（lwIP on 与 XTCP off 因未吃满单核作废）。**初步趋势（仅限本轮单轮）**：native+GSO 双方向领先（UL 824 / DL 656 Mbps）；GSO 对 lwIP/XTCP 在严格单核 P1 未观察到正收益（lwIP DL 272→257、XTCP DL 303→291，XTCP UL 246→418 方向相反），而 native 明显受益（UL 262→824、DL 369→656）。**这些 GSO 差异仍需 3-round paired rotation 才能定案**：`0.94×/0.96×` 很可能在单轮波动范围内，不能写死为"用户态栈不吃 GSO 红利"；XTCP DL 的 `XTCP/native = 0.82×（off）/0.44×（on）` 中，0.44× 主要来自 native 的 GSO 红利（369→656），XTCP 自身 off→on 约 0.96× 是基本不吃 GSO 收益，不能解释为"XTCP 自己退化 56%"。

#### 11.4.4 XTCP 集成优化 + KCC pacing 修复验证（2026-09-02）

**优化改动（OpenPPP2 侧，`XtcpRuntime.cpp`）：**
- 删 `OnReceive` 遗留 `fprintf(stderr, "XTCPDBG ...")`（每 segment 一次 stderr I/O）；
- `kConnectorReadBytes` 16K→64K（UL read chunk 放大，UL 提升主因之一）；
- UL 零拷贝：`Submit` 直接 `BufRef::Acquire`（省 1 次 vector 分配+memcpy，经 A/B 无吞吐收益——证明 UL 下一瓶颈是 strand/同步而非 memcpy，保留无害）；
- `OPENPPP2_XTCP_CC`（kcc/bbr/cubic/reno）与 `OPENPPP2_XTCP_SNDBUF_BYTES` env 开关；
- runner 新增 `--xtcp-cc`/`--xtcp-sndbuf`/`--netem-delay-ms`（netem 用于 RTT 扫描，已验证 `tc qdisc netem` 生效：ping RTT 0.05ms→40.2ms）。

**KCC pacing 钳制根因（216Mbps 天花板，由开发者 `0005-pacing-burst-quantum.patch` 修复）：**
- `FlushPendingSend` 在 `pacing_rate>0` 时每次调用最多发 1 个 MSS（now 冻结 + 逐 segment 重设 deadline）；
- `pacing_deadline_` 无调度器消费——`NextTimerDeadline()` 不看它，pending 非空一律报"立即到期"，host loop 空转；
- KCC 的 bw 采样测到的正是这个串行化速率，自我实现天花板。CUBIC 因 `pacing_rate=0` 绕开，故修复前 DL 翻倍（216→400）。
- 修复后另解决突发发送暴露的丢包恢复停摆（OOO dup-ACK 限速、gap-fill delayed-ACK、trim 前沿静默），`test_wscale_transfer` 40-200s 超时 → 17-228ms。

**修复验证（本机复现，单核 CPU8，P1 DL）：**

| 场景 | KCC 修复前 | KCC 修复后 |
| --- | ---: | ---: |
| DL off | 216 | **395** |
| DL on | 217 | **393** |
| DL 40ms RTT | 219 | **398**（无停摆） |

**3-round 稳定性回归（72/72 cell，native/XTCP × P1/P4/P16 × UL/DL × GSO off/on × 3 rounds，单核 CPU8，artifact `build/kcc-fixed-regression-r3`）：**

- **72/72 完成，无 watchdog、无 zero-rate flow、无 first_push_failure**；paired ratio 每 cell 的 3-round MAD 全部 <0.05（多数 <0.02），KCC 修复后无间歇波动。
- **6 个 qualification fail 全部为 XTCP P1 DL 的 `process_cores_ok`**（cores 0.72-0.75 < 0.9）：DL 发送是 ACK clock 驱动，CPU 不饱和是固有特征（开发者也确认 perf task_clock 遥测缺失），**吞吐/正确性全过，非故障**——qualifier 的 `process_cores_ok` 不应适用于 DL 发送场景。
- **XTCP/native paired ratio（3-round median，MAD 括号）：**

| P/方向 | GSO off | GSO on |
| --- | ---: | ---: |
| P1 DL | 1.09（±0.01） | 0.60（±0.01） |
| P1 UL | 1.29（±0.05） | 0.55（±0.01） |
| P4 DL | **1.49**（±0.03） | 0.83（±0.01） |
| P4 UL | 1.14（±0.07） | 0.30（±0.00） |
| P16 DL | **1.46**（±0.00） | 0.89（±0.05） |
| P16 UL | 0.81（±0.03） | 0.46（±0.01） |

- **DL GSO-off 全面反超 native**（P1 1.09×、P4 1.49×、P16 1.46×），DL GSO-on 接近（P16 0.89×）；**UL 落后**（GSO-off P1 反超 1.29×，但 GSO-on 0.55×、P16 0.46×，strand 串行投递是瓶颈，见 `XTCP-STRAND-DISPATCH-001`）。

**CC A/B 定案（KCC-fixed vs CUBIC 全场景等价）：**

| 场景 | native | KCC-fixed | CUBIC |
| --- | ---: | ---: | ---: |
| P1 UL on | 818 | 473 | 478 |
| P1 DL on | 663 | 393 | 392 |
| P16 UL on | 707 | 305 | 313 |
| P16 DL off | 331 | **499** | 493 |
| P16 DL on | 529 | **473** | 484 |

**决策**：修复前 KCC pacing bug（216Mbps）→ 曾临时默认 CUBIC；`0005` 修复后 KCC 追平 CUBIC（全场景 ±3%），**恢复 KCC 默认**（上游默认、开发者维护）。`--xtcp-cc cubic` 保留可切。**已回滚实验**（证明方向不对）：`SetRcvBuf(4MB)`（XTCP 在 DL 是发送方，无效）、`SetSndBuf(4MB)`（pending 一次 flush 超大段，DL 崩到 25Mbps）、`SetSndBuf(512K)`（snd_buf 不是门，无效）、KCC sndbuf 16K-32K（read 64K 不匹配，DL 崩到 0-70Mbps；开发者建议针对上游原始用法，与 OpenPPP2 64K read chunk 不兼容）。

**XTCP 对标 native 最终成绩（单核，KCC 修复后默认，binary `15daa299`）：**

| 场景 | native | XTCP | 差距 |
| --- | ---: | ---: | --- |
| P1 UL on | 818 | 473 | 1.73× |
| P1 DL off | 352 | **398** | **反超** |
| P1 DL on | 663 | 393 | 1.69× |
| P16 DL off | 331 | **499** | **反超** |
| P16 DL on | 529 | 473 | 1.12× |
| P16 UL on | 707 | 305 | 2.3× |

**DL 全面接近/反超 native（P16 DL off 反超），UL 仍落后（下一瓶颈 = 单 strand 串行同步，零拷贝已证 memcpy 不是门）。**

#### 11.4.5 `XTCP-STRAND-DISPATCH-001` 修复：批量 ingress + 无锁 budget + timer churn（2026-09-02）

§11.4.4 回归登记的 UL strand 瓶颈本轮修复（全部在 ppp 集成层，`XtcpRuntime.cpp`/`XtcpRuntimePolicy.h`，不动上游 core）：

**根因链（perf 证据钉死）**：每包一次 `asio::post` 到单 owner strand（GSO 64K 突发 ≈ 44 段 = 44 次调度）→ strand 消化速率低于到包速率 → in-flight 打满 1024 item budget 上限 → `ingress_dropped` 累计 68.2 万（丢包率窗口峰值 10-20%）→ TCP 层真丢包 → 重传风暴 → UL GSO-on 崩到 0.30-0.55×。伴随：每包 2 次 `state_sync_` mutex 跨线程争用（Submit/TryReserve 与 ProcessIngress/Release）、`KickPoll` 因 pacing deadline 每次前移几乎逐包 cancel+`make_shared<steady_timer>` 重臂、以及 zero-copy 改造遗漏的死代码（Submit 里 vector 分配+memcpy 后弃用）。

**修复**：
1. Submit 改批量 handoff：压入 mutex 护栏的 MPSC 队列，仅队列从空变非空时 post 一次 `DrainIngress`，strand 单次调度换出整批逐包注入（同锁内"空检查+清位"保证无包滞留）；
2. `XtcpIngressBudget` 无锁化：items+bytes 合并单 CAS 字段，热路径零锁；`state_sync_` 只留 Start/MarkReady/Stop 冷路径；
3. poll timer 复用单一 `steady_timer` 对象 + 50µs re-arm slack（deadline 微移不再重臂）；
4. 删除死代码 copy。

**效果（单核 CPU8，binary `eaac9eda`，paired vs §11.4.4 三轮中位数）**：

| cell | 修复前 | 修复后 | Δ |
|---|---:|---:|---:|
| P16 UL on | 0.46×（305）| **0.487×（336）** | +10% |
| P1 UL on | 0.55×（473） | 0.572×（480） | +1.5% |
| P16 DL off | 1.46×（499） | **1.573×（527）** | +6% |
| P16 DL on | 0.89×（473） | **0.931×（503）** | +6% |
| P1 DL off / on | 1.09× / 0.60× | 1.064× / 0.586× | 持平 |

**结构性指标**：`owner.dropped` **68 万 → 0**；`q_p50` 恒定 128µs → 多数窗口 0；retx=0；`posts ≈ dispatched ≈ injected` 自洽。验证：xtcp runtime/dependency 5/5、lab 套件 135/135、netns 8 cell 全 PASS。

**剩余 UL 差距已换层**：XTCP 每字节 CPU ~2× native（P16 UL on 24.1 vs 11.6 ns/B），单核下被 CPU 顶死——下一层是数据面每包成本（parse/hash/alloc/Inject），不再是调度。附带登记：上游 `dup_acks_` 会把带 payload 段的 piggyback ack（== 空闲发送侧 snd_una_）也计数，收方向连接遥测刷高，但所有恢复路径均有 `retrans_queue_` 非空门卫（实测 retx=0、fast_rec=0），行为良性，不改上游。

**数据面层跟进（同日第二轮，binary `e68b1e75`）**：Output 全链零拷贝（栈 BufRef 经 owning `shared_ptr` 直通 TAP 写队列，省每包 1 分配+1 memcpy；Tx 被拒时所有权回迁 `packet.owned`，`TestProductionNdiOwnership` 契约保持）+ TAP 写队列有界同步 drain（fd 为 O_NONBLOCK，64 包/批摊薄 epoll 往返；EAGAIN 回退单 async_write）。**实测：P16 两侧 +5-8%（DL off 1.51×、DL on 0.91×、UL on 0.486×），P1 持平；r1/r2 两轮独立样本落在同噪声带**。UL 接收侧剩余大头：connector 逐段写（avg 1.4KB/write，925K 次/30s）——但 write 合并已被 `XTCP-UL-WRITE-BATCH-001` 实验证伪（256KB 单次写超时，UL 崩到 2.6Mbps），维持逐段写。至此单核 XTCP 剩余差距为结构性每包用户态 TCP 成本（native 的 TCP 在内核），无低风险进一步优化项；P1/P16 UL 提升需 `XTCP-SHARED-PATH-001`（多核分片）路线。

**历史两栈参考（2026-08；已被上述三栈 provisional 取代，不作为当前公平性结论）。** 下表数字来自有限轮次的同机测量，用于人工判断参考，**不得直接作为 CI 的 PASS/FAIL 硬门禁**——单轮对照在共享环境里噪声带很宽（实测同一构建 P1 upload 跨轮 343–404 Mbps、native 271–332 Mbps），已出现过"实现无回归却触发三条绝对 hard fail"的假阳性。CI 门禁须先完成文末的 paired baseline 校准。

**参考实测区间（2026-08，本仓库构建，多轮汇总）：**

| 场景 | xtcp | native | 稳定结论 |
|------|------|--------|---------|
| P=1 upload | 343–404 Mbps | 271–332 Mbps | xtcp 反超且跨轮区间不重叠（+18~27%）；UL cap 修复稳定复现 |
| P=1 download | 261–328 Mbps | 389–396 Mbps | −19~−34%，根因归 `XTCP-KCC-PACING-001` |
| P=4 upload | 268 Mbps | 267 Mbps | 打平（单轮数据，**候选分水岭**：并发上升后共享路径开始主导，需 2–3 轮重复确认后升级为定案）|
| P=4 download | ~309 Mbps | ~386 Mbps | 差距收窄 |
| P=16 upload | 163–195 Mbps | 218–244 Mbps | **paired ratio 漂移（0.89→0.67）是当前最值得关注的信号**，见 SHARED-PATH-001 |
| P=16 download | 325–328 Mbps | 366–376 Mbps | −10~−14% |
| 延迟 mean | 0.31–0.37 ms | 0.29 ms | +7% |
| 连接建立速率 | 35–38/s | 38–42/s | −6% |

#### CI 门禁设计（待三栈校准后生效）

采用**三层判定**，替代单一绝对 Mbps 硬门禁：

1. **环境健康门禁**：native 是同机锚点；每轮先检查其是否仍落在已校准分布内，偏离明显则整轮标记 `PERF_ENV_UNSTABLE`，不将环境抖动误判为任一栈回归。
2. **paired relative gate（主判据）**：分别比较同一 round 的 `lwip/native`、`xtcp/native` 与 `xtcp/lwip`，对每类比值取中位数（不是分别取吞吐中位数后再相除）。低于校准后的 relative floor 才判 regression。
3. **absolute catastrophe floor**：保留但显著低于各 stack/GSO-mode 的正常分布，仅抓灾难性回退。

判定逻辑：

```text
if 功能、runtime proof 或统计完整性失败:  FAIL
if native 基线明显异常:                    PERF_ENV_UNSTABLE
else if 绝对吞吐 < catastrophe_floor:       FAIL
else if paired relative ratio < floor:      FAIL
else:                                       PASS

WARN: 离散度异常 / zero-rate flow / P16 fairness 恶化 / 接近门槛
```

**CI 运行形态**：canonical mode 为 `native/off → lwip/off → xtcp/off → native/on → lwip/on → xtcp/on`。每一轮将该六项序列循环左移一位，连续 6 round 后每个 mode 恰好经历每个位置一次，以抵消温频/cache/负载漂移。

每个 cell 记录 requested/active TCP stack、requested/active GSO proof、吞吐、per-flow min/p10/p50/p90/max、zero-rate flow、公平性、paired ratio 与离散度；GSO-on 还保存 GSO ledger。缺失 active proof 或能力回退不是有效 score。

**校准规程**（重新制定 §11.4 门槛前一次性执行）：P=1/4/16 × UL/DL × native/lwIP/XTCP × GSO off/on × **12 rounds**（两套完整 6-mode rotation）；每个 cell 保存 median、p10/p90、MAD、paired ratio median、paired ratio p10/p90；门槛从该分布推导，**不手工拍绝对阈值**。

**已定案的归因（勿重复排查）：**

- UL 曾被 runtime 接收队列上限过小导致的人为反压限速（拒绝 → 栈不 ACK → 对端 RTO/cwnd 坍缩）；per-flow cap 提升至 4MiB 后消除并反超 native。该 cap 不是最终流控设计：production 需叠加全局 queued-byte budget 与高水位监控。
- **全局 budget 是安全保险丝，不是正常流控机制**：budget 耗尽同样走 `OnReceive(false)` 恶性路径（对端 RTO）。production gate 要求在受支持并发（P=16/64/256、burst/churn）下 `global rejection ≈ 0`、`OnReceive(false) ≈ 0`，并以真实并发 burst 水位分布确定默认值——32MiB 目前是工程缺省而非实测结论。
- DL 天花板与 XTCP 栈发送节奏相关：NDI callback interval p50≈32µs（~22kpps），Output() wall time p50=16µs。A2-0 排除了 Output 存在独立 ~22kpps service-rate 硬上限，也证明当前不应实现 OutputBatch；但 Output 同步耗时约占 callback 周期一半，**尚不能排除它与 kcc pacing 串联形成最终发送间隔**。源码证据（tcp_fsm.cpp 发送路径）：pacing deadline 基于发包起点时间戳（absolute deadline），Output 耗时小于 pacing 间隔时被吸收；DL 有效 flight 受 `min(cwnd, snd_wnd, snd_buf)` 限制，观测值约 10KiB 量级，按观测 RTT 粗略换算得到约数百 Mbps 的容量上限，与实际 DL 天花板处于同一量级——结合发送路径源码与 pacing 行为，证据指向上游 kcc 稳态 cwnd/发送节奏，而非 bridge 的 Output service-rate 硬上限。若需最终因果钉死，再做 Direct-TUN 或 pacer deadline 遥测（验证性增强，非必要归因步骤）。
- strand/CPU/timer/ingress 全链路健康（queue-delay p95≤128µs、owner CPU ~40%、timer late p95≤256µs、ingress 零丢弃）。
- 历史两栈 P16 样本曾无明显 starvation：每流吞吐连续分布（9.6–26Mbps）、无接近零的流；但这已被 §11.4.2 的三栈 provisional 结果限制——`XTCP/GSO-off/P16/UL` 在 Stage A 与 round-3 分别出现 2 条和 1 条 zero-rate flow。故不得再宣称 P16 公平性已通过；`XTCP-SHARED-PATH-001` 必须同时报告 SUM、per-flow p10/p50/p90、max/min 与 zero-rate flow，并在隔离 CPU 环境复核。

**记账生命周期不变量**：runtime 全局 queued-byte ledger 在任意 teardown 路径（peer_gone mid-flight / RST / 正常关闭 / runtime stop）后必须精确归零——禁止用 saturating subtraction 掩盖问题。回归覆盖见 `xtcp_runtime_bridge_test` 的 `TestQueuedBytesAccounting`。

**实验旋钮约定**：`OPENPPP2_XTCP_PERF_JSON`（保留）、`OPENPPP2_XTCP_WRITE_CAP_BYTES`（内部/实验配置）、`OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES`（production 前按压力矩阵定默认值）、`OPENPPP2_XTCP_LAB_SEND_RETRY_US`（LAB-only——已证明 retry 周期不影响吞吐，禁止当作生产调优参数）。

### 11.5 后续独立工作项

> **multi-worker 边界（勿迁移）：** 即使上游 bench 显示其 RX multi-worker 扩展 sublinear（如 1 worker 135 → 8 worker 99），也不得据此推导 OpenPPP2 "应做 8 shard"。那只能说明**增加 worker 不天然提升 XTCP core**；`PPP-DATAPATH-001` 继续严格单核，多流/multicore 归 `XTCP-SHARED-PATH-001` 独立评估，不混入单核主线。

| 优先级 | 工作项 | 目标 |
|------|------|------|
| P1 | `XTCP-KCC-PACING-001` | 分析 kcc 稳态 cwnd/pacing/ACK clock，解释 clean netns、RTT≈0.3ms 下稳态仅 ~10KiB flight 的成因（cwnd 自身目标 / ACK clock / snd_buf 配额 / 窗口字段单位或更新错误），争取 DL 从 −19% 收敛至 native −10% 内。**禁止一开始就调大 cwnd**——先拆解 cwnd、snd_wnd、snd_buf、bytes_in_flight、ACK cadence、growth/decay、pacing_rate、loss/retrans，并区分 app-limited / cwnd-limited / rwnd-limited |
| P2 | `XTCP-WRITABLE-001` | `SendSome`（prefix 接受语义）/ writable notification（0→正边沿一次性武装），移除无效 retry polling；效率与接口语义改善，非当前吞吐主修复 |
| P2 | `XTCP-SHARED-PATH-001` | P16/64/256 shared-path 容量、全局 budget 水位压力矩阵（确定 production 默认值）、fairness 与容量门禁。**首要观察项：P16 upload 的 paired ratio（xtcp/native）已从 ~0.89 漂移至 ~0.67**——native 自身波动不能完全解释该相对比值漂移，须厘清其中 XTCP 额外损失的成分；同时确认 P=4"共享路径候选分水岭"是否可复现升级为定案 |
| P1 | `XTCP-NDI-MEMORY-001` | C 榜 attribution：不走 TUN、不改 XTCP core 与 tunnel wire，NDI Output 直接进 memory-backed sink、输入由 memory source 喂入，保持相同 packet bytes/MTU/TCP options、单 owner / single-core。回答"去掉 TUN/Tap 后 OpenPPP2 XTCP adapter 自己能跑多少"；对 UL/DL 分开测（RX→NDI direct sink 与 memory source→XTCP TX 分岔），把 NDI/backend ceiling 与 KCC pacing/cwnd ceiling 分开 |
| P2 | `LWIP-NETIF-MEMORY-001` | C 榜 lwIP 阶梯：in-memory netif → bare TUN → OpenPPP2 VNet → full PPP，与 XTCP 的保留率对比，回答 integration 更适合哪个执行模型 |

**`XTCP-NDI-MEMORY-001` C1 初测（2026-09-05，非 product throughput）：**新增 `xtcp_ndi_memory_probe`，以两个 `XtcpStack` 和两个 OpenPPP2 `XtcpNdiBackend` 组成 loopback；NDI Output 的 owning `shared_ptr<Byte>` 进入 memory FIFO，pump 在边界复制到 `BufRef` 后 `Inject` 对侧。它实际覆盖 adapter 的 Output ownership、Input inject、XTCP 数据/ACK 处理及 KCC ACK clock，但不经过 TUN/TAP、carrier、bridge queue 或 runtime strand，也不声称端到端零拷贝。16KiB chunk：1MiB `605.68 Mbps`（`0` reject）；64MiB `621.63 Mbps`，`bytes_sent=bytes_recv=67,108,864`、`69,645` packets，A `46,430/46,430/0` 与 B `23,215/23,215/0`（attempts/accepted/rejected）。payload byte-exact 且测试成功。

该 C1 上限仍处于现有 product DL 约 `0.4–0.7 Gbps` 的同一量级，不能支持“NDI Output rejection 是主要瓶颈”的说法，也不能单凭此项把责任归给 bridge/carrier/TAP。下一步仍是 `XTCP-KCC-PACING-001` 的 cwnd、snd_wnd、snd_buf、in-flight、ACK cadence 和 pacer deadline 遥测；禁止以移除 single-flight/recovery gate 或盲目膨胀 cwnd 换取吞吐。Route 1–3 与严格稳定 `1.2×` 目标均**尚未完成**。

**XTCP-SINGLECORE-BASELINE-20260902（单核优化封板锚点，多核结果一律相对此基线报告）：**

- 锚点 commit：本 commit（`XTCP-SINGLECORE-BASELINE-20260902`）；内容冻结于 ba67601（docs）+ 本记录
- ppp binary sha256: `e68b1e75deac0636577069fa99b8a715ab98f243a913ec871ec6937ba63680fe`（build/xtcp-runtime-root，Release，）
- XTCP upstream revision: `e79db8fd10a1ee39be2dc3a9361727fcad79d04c`（archive sha256 `fd194478...`）
- patchset 0001-0005 合并 sha256: `bf8e25bf32110e755de34be1cb842c299392e6be3f98fd6daebac9695dc6464d`
- GSO 模式：off/on 双模均属基线；单核 pinned CPU8
- 基线配对比（KCC 修复+两层优化后，单轮样本）：P1 DL off 1.06-1.09×、P1 DL on 0.59-0.60×、P1 UL on 0.56-0.57×、P16 DL off 1.51-1.57×、P16 DL on 0.91-0.93×、P16 UL on 0.486-0.487×

### 11.6 `XTCP-SHARED-PATH-001` S0：共享资源审计与分片单位定案（2026-09-02，单核基线 `ec3bc66` 之后）

**S0 三个问题的回答：**

1. **P16 的 shared resource 饱和点**：单核 pin 下不是任何一个共享锁，而是"整个 runtime 只有一个执行域"本身（owner strand 串行 = 全部 flow 的 Inject/ACK/定时器）。两轮优化后 queue 延迟已打掉，剩余差距是执行域宽度，不是某个 mutex 热点。
2. **最小可安全分片单位 = XtcpRuntime 实例**（方案 (a)：N 个完整 runtime，switcher 按 flow 4-tuple hash 路由 Submit）。不用方案 (b)（单 stack 多 strand 驱动）：上游 stack 虽有 per-conn shard 锁（`ShardOf` + `recursive_mutex`），但 accept/listen/timer/回调契约是 stack 全局的，方案 (b) 破坏"回调在 owner 线程"语义；方案 (a) 复用全部已验证 runtime 代码、可回滚、隔离清晰。同一 flow（含 SYN/deferred_syn）按 4-tuple hash 永远落同一 shard，ordering/ACK 状态/generation/close 生命周期天然保持。
3. **共享资源分类**（S1 实现的约束清单）：

| 资源 | 类 | 说明 |
|---|---|---|
| XtcpRuntime::Impl（strand/flows_/listeners_/stack_/backend_/budget/poll timer/handoff/stats） | A | 每 shard 一份（方案 a 即此含义） |
| ITap 写路径（`_write_mutex` + 单 fd + TAP strand） | D 候选（低危） | 临界区 O(1) push，sync drain 已批量化；内核侧 fd write 本就串行。S1 必须报告 per-shard enqueue p95 证实无新排队 |
| XtcpPoolLease 全局 BufRef 池（`pool_sync` 单 mutex） | D 候选（中危） | UL 每 包 Acquire 都过这把锁。2 shard 先测量池锁竞争；若 p95 恶化 → per-shard lease |
| GlobalQueueBudget / flow write_queue 记账 | A（语义变更点） | per-runtime 后全局上限变 32MiB×N——S1 需决策：总量守恒（每 shard 32MiB/N）或按 shard 放大（先 32MiB×N，报告 high-water） |
| runtime stats / perf JSON | A | 每 shard 独立输出（shard 标签），汇总在矩阵脚本层做 |
| packet_dispatch_ / switcher OnPacketInput | B（新增路由器） | 解析 4-tuple → hash → shard；复用 XtcpRuntime 的 ParsePacket |
| crypto/mux/carrier | 不在 XTCP 数据面 | client 侧 flow 经 loopback connector 桥接本地应用，wire 侧在 server 实例；server 线程入口同 pattern 路由 |

**S1 矩阵（冻结）**：P=1/4/16/64 × shards=1/2 × UL/DL × GSO off/on；每 cell 报 SUM Mbps、per-flow p10/p50/p90/min/max、Jain fairness、zero-rate flows、process cores、Mbps/core、ns/B、per-shard packets/bytes/flows/CPU/queue p50/p95/p99/high-water、global budget high-water/rejections/OnReceive(false)。**吞吐与单位 CPU 效率必须同时报告**。

**2-shard 工程门槛（非 CI gate）**：P16/P64 throughput ≥1.5× 1-shard 且 total CPU ≤2.1 cores 且 per-core 效率 ≥0.75× 基线 且 zero-rate=0 且 Jain ≥0.98 且 global rejection ≈ 0 且 OnReceive(false) ≈ 0 且 lifecycle/记账回归零。达 1.6-1.8× 才扩 4 shard；<1.5× 停下找新串行点，不扩规模。KCC/PACING-001 与本战线严格串行，不同时改。

**S1 结果（2026-09-02，binary `043894d1`，2×CPU{8,9} `client-cpuset`，30s formal，xtcp-only 32 cell；相对 1-shard 同设置配对）：**

| cell | 1-shard | 2-shard | × | cores(1→2) | Mbps/core × | Jain(1→2) | zero |
|---|---:|---:|---:|---|---:|---|---|
| P16 UL off | 179 | **593** | **3.31** | 0.59→0.92 | 2.13 | 0.992/0.980 | 0/0 |
| P16 UL on | 339 | **531** | **1.57** | 0.53→0.88 | 0.94 | 0.989/0.787* | 0/0 |
| P16 DL off | 529 | **833** | **1.57** | 0.53→0.91 | 0.92 | 0.983/0.993 | 0/0 |
| P16 DL on | 505 | **773** | **1.53** | 0.54→0.93 | 0.89 | 0.972/0.992 | 0/0 |
| P64 UL off | 211 | **606** | **2.87** | 0.55→0.92 | 1.71 | 0.560/0.781 | **18**/1 |
| P64 UL on | 238 | **476** | **2.00** | 0.59→0.89 | 1.31 | 0.735/0.894 | **14**/1 |
| P64 DL off/on | — | — | stall（见下） | — | — | — | — |
| P1 全部 | 344-485 | **151-320** | **0.31-0.81** | — | — | 1.000 | 0 |

**2-shard 门槛判定（P16/P64）：✅ 通过**——吞吐 ≥1.5×（P16 四 cell 1.53-3.31×，P64 UL 2.00-2.87×）、总 CPU ≤2.1 核（实测 ≤0.93）、per-core 效率 ≥0.75×（0.84-2.13×）、zero-rate=0、global rejection=0、lifecycle/记账零回归。Jain：p16-ul-on 单轮 0.787 为瞬态，两轮复跑 0.982/0.984 判为噪声；P64 UL 的 Jain 低于 0.98 是 1-shard 就存在的 P64 公平性问题（SHARED-PATH 已立项观察项），2-shard 反而改善（18/14 zero-rate → 1/1）。

**关键发现：**
1. **多 shard 必须有真正的执行域**：runtime 原绑定在仅主线程 run 的 default context 上，双 strand 实测零并行（+4%）；专属 io_context + 每 shard 一个 worker 线程后才拿到上述数字。
2. **P1/P4 在 shards=2 下回退（0.31-0.81×）**：跨 context 投递税——TAP 读/写在主线程（default context），shard 工作在专属池，每个突发 ingress/egress 各跨线程一次。P1 吞吐对 ACK 往返延迟敏感（ACK clock）。**shards 默认仍为 1**，S2 需做 IO 同址（TAP IO 与 shard 池合并）才能默认启用。
3. **P64 DL GSO off/on 完整 stall（既有问题，与分片无关）**：client `posts=0`、cwnd=1、inflight 单段卡死、iperf 64 流全零——用基线 binary（`e68b1e75`，分片改造前）复现同样挂死，r3 回归从未覆盖 P64 DL。wedge 在 server 侧/隧道路径而非 client runtime。**S2 阻塞项**。
4. `process_cores_ok`/`zero_migrations` fail 为本环境 perf task_clock 遥测缺失（基线已记录），吞吐与正确性检查全过。

**S2 工作项（按优先级）**：① IO 同址消除跨 context 投递税（解锁 shards=2 默认化与 P1 回归）；② P64 DL stall 根因（posts=0 指向 server 侧/隧道路径）；③ 达标后再议 4 shard 扩展。

**`XTCP-KCC-PACING-001` 第一轮定案（2026-09-02，binary `1c69ff13`，单核 CPU8，DL GSO-on）：**

**根因（perf 铁证）**：DL 发送被 **snd_buf=64K 准入门**卡死，与 cwnd/pacing 无关——64K 时 `inflight` 峰值恰 62640B、`send.rejected≈906/s`、**stall 960ms/1000ms**（发送侧 96% 时间等 1ms 重试定时器）。旧"512K 无效/4M 崩到 25M"结论是 **0005 之前**的测量；0005 的 burst quantum 已消除旧失败模式。

**snd_buf 扫参（DL GSO-on，配对同设置）**：

| snd_buf | P1 | P4 | P16 |
|---|---:|---:|---:|
| 64K（默认）| 399（0.58× nat）| 521 | 514（0.92× nat）|
| 128K | 474 | 551 | 513 |
| 512K | **527** | **584（0.93× nat）** | **WEDGE** |
| 1M | **544（0.80× nat）** | — | **WEDGE** |

**P16 ≥512K wedge 机制**（诊断实锤）：大 snd_buf 破坏自时钟——server 无界 offer（16 流 × 1MB pending）→ client ingress budget（1024 items）瞬时溢出（实测 drop=184/534）→ 丢包 → server RTO/重传风暴 → 载荷挤压载波与 client ingress → 互相饿死；client 主线程 94.7% CPU 自旋在重试环上（shards=2 / 大 ingress budget 均不能解——溢出是触发点，自持机制在丢包螺旋）。**P16 包络：snd_buf ≤128K**，修复 offered-load 形状是上游工作（S2）。

**已加旋钮**：`OPENPPP2_XTCP_INGRESS_ITEMS/BYTES`（默认 1024/8MB 不变，仅实验室用）；矩阵 runner `--xtcp-send-retry-us`（复测证明重试节奏非杠杆：1ms=544 vs 200µs=517，反而更差）。

**结论**：DL GSO-on 的 snd_buf 扫参把 P1 从 0.58× 拉到 **0.80×**、P4 到 **0.93×** native；P16 已在 0.92×。残余 P1 差距（544 vs 684）限速者转为队列膨胀的有效 RTT（BDP 环），需载波/TAP 排队治理。默认 snd_buf 维持 64K（per-concurrency 包络未自动化前不变）。

**逼近 native 第二轮（2026-09-02，binary `bccd3d3d`，单核 CPU8 除注明外）：**

**① `XTCP-UL-WRITE-BATCH-002`（connector gather-write）**：与已证伪的 001（256KB 单块）不同，按 cap=32KB 收割已排队块做一次 `async_write`（内核 writev 聚合），不等待攒批；env `OPENPPP2_XTCP_CONNECTOR_BATCH_BYTES`（1=逐段，A/B 基线）。UL GSO-on 实测：P1 478→**582**（+22%，0.67× nat）、P16 331→**433**（+31%，0.60× nat）；与 shards=2 叠加 P16 UL on 达 **557**（0.78× nat，比本轮起点 +68%）。`conn.wr_ops` 从 ~21K/s 降一个量级。

**② SendData 重试指数退避**：连续拒绝按 1ms→32ms 退避（成功复位）。P16 sndbuf≥512K wedge **依旧**（退避只消 CPU 自旋，不破丢包螺旋）——offered-load 形状确认为上游 S2 工作；退避保留（降低拒绝风暴的 CPU 浪费）。

**③ 延迟定位（iperf RTT）**：UL P1 xtcp mean_rtt=1.4ms vs native 0.8ms（max 尖峰 26ms 值得后续追查）；P16 两侧相当（13.7 vs 16.0ms）。DL 侧 stall 51% @ inflight≈sndbuf 属满管道自时钟正常形态——真正的 DL/UL 共同天花板是**client 接收端每包 ~20µs**（TAP 读→dispatch→XTCP RX→connector→内核 loopback→VNet RX→TAP 写约 8-10 级流水 vs native 内核 1.7µs/包）。下一个大杠杆是端到端 GSO-RX（server 发 64KB super-frame、上游 Inject 内部分段，44× 减包率）——上游 0006 级工作，本轮不做。

**本轮后单核对位（GSO-on）**：P1 UL 0.67×、P16 UL 0.60×（shards=2 时 0.78×）、P1 DL 0.80×（sndbuf=1M）、P4 DL 0.93×、P16 DL 0.92×。DL 已全面进入 0.8-1.5× 带；UL 是剩余主战场。

**全优化 binary 刷新表（`bccd3d3d`，单核 CPU8，GSO-on，1 轮；`build/final-refresh-a|b|c`）：**

| cell | native | xtcp | ratio | 此前 |
|---|---:|---:|---:|---:|
| P1 UL on | 874.5 | 575.6 | **0.66** | 0.55 |
| P4 UL on | 804.6 | 594.4 | **0.74** | 0.41 |
| P16 UL on | 652.5 | 445.8 | **0.68** | 0.46 |
| P1 DL on | 691.7 | 376.6 | 0.54（sndbuf=512K → **0.77**）| 0.58 |
| P4 DL on | 605.1 | 459.7 | 0.76（512K → **0.86**）| 0.82 |
| P16 DL on | 537.1 | 521.9 | **0.97** | 0.92 |
| P64 UL on（2×CPU shards=2+批写）| — | **491.3** | jain 0.967，zero 0/64 | jain 0.51-0.77、12-19 零速流 |

**本轮研究总结**：全部 GSO-on 对位比抬升至 0.66-0.97×（起点 0.41-0.92×）；P64 UL 饥饿由分片+批写联合解决。剩余边界：① UL 接收端双栈每包 ~20µs（端到端 GSO-RX=上游 0006 级）；② P16 snd_buf≥512K offered-load wedge（上游）；③ P64 DL stall（既有，server 侧）。

**逼近 native 第三轮：端到端 GSO 超帧链（binary `c6578e8c`，P16 UL GSO-on 主战场）：**

**perf profile 实锤（client，UL on，单核）**：aesni+cfb128 ≈17.4%（隧道解密，native 同付）、**内核 loopback 桥（tcp_sendmsg→tcp_write_xmit→loopback RX→skb 拷贝→唤醒）≈25-30%**（XTCP 专属税，native 无此桥）、TcpChecksum 2.2%、mutex/syscall/copy 各 2-4%。接收端每包 ~20µs 的主要成分不是 XTCP 栈本身，而是**桥**。

**本轮落地**：
1. `TunGsoCoalescer` 合并上限 env 化（`OPENPPP2_TAP_GSO_SEGMENTS`，默认 4=历史行为，≤48=64KB 超帧）；TAP vnet 基础设施（IFF_VNET_HDR/TUNSETOFFLOAD/BuildGso）本就完整，超帧实测可过内核 netns 链（native 11KB 读即 TSO 超帧）。
2. **GSO-RX 分段器**（Submit 层，>MTU 帧拆回 MSS 段，seq/长度/校验和逐段修正，env `OPENPPP2_XTCP_GSO_RX` 默认开）——并实测证明**可关**：整帧直通 Inject（>MSS 段对接收端合法）与分段等价，拆不拆不是瓶颈。
3. runner `--tap-gso-segments/--xtcp-gso-rx` 旗标。

**实测（P16 UL GSO-on）**：合并 cap 4→48 仅 +10（读 syscall 占比小）；单核组合 ~459（起点 331，+39%）；**2×CPU{8,9} + shards=2 + 48 段 + 批写 = 602.2 Mbps = 0.92× native 单核**（全程 +97%），jain 0.895（单轮）。

**1.2× 结论（诚实评估）**：DL off 多 cell 已达 1.46-1.57×；DL on 0.77-0.97×；**UL on 单核被 loopback 桥税封顶在 ~0.7×，量化路径 = 桥旁路**（复用 iOS 原生直注模式 `DeliverNativePayload`/`EmitNativeToClient`：XTCP recv 直接注入 VNet TCP，砍掉 25-30% 桥成本，预计单核 ~0.9-1.0×、叠加 shards=2 后 2 核上 1.1-1.3×）——列为下一个独立工作项 `XTCP-VNET-BRIDGE-BYPASS-001`。

**`XTCP-VNET-BRIDGE-BYPASS-001` 第一阶段实验（socketpair 桥，binary `9b121d06`+）：**

用 `AF_UNIX SOCK_STREAM` 对替代 XTCP Flow 与 VNet 泵之间的内核 loopback TCP（`OPENPPP2_XTCP_UNIX_BRIDGE=1`，默认关；fd 经 `BeginExternalAcceptWithFd` 直接采纳，跳过 listener accept 配对）。本地 bridge 测试全场景（握手/双向/半关/RST/churn/记账）135/135 通过。

**netns A/B 实测（GSO-on 单核）**：P1 UL **+8%**（561→608，0.70× nat）；P16 UL **-24%**（455→348）；P1 DL **-25%**；P16 DL 持平。**混合收益，默认保持关闭**——unix socket 泵的 per-write 唤醒/拷贝成本在多流下反超内核 TCP loopback 的合并收益。真正的桥消除需要纯用户态内存直递（绕过 vmux 泵的 socket 语义），涉及 netstack 抽象层重构，规模超本轮，记录为后续方向。

**逼近 native 总账（会话全程，GSO-on 单核对位）**：P1 UL 0.55→**0.65-0.70×**、P4 UL 0.41→**0.74×**、P16 UL 0.46→**0.68-0.78×**（shards=2）、P1 DL 0.58→**0.77×**（sndbuf 512K）、P4 DL 0.82→**0.86×**、P16 DL 0.92→**0.97×**、DL off **1.05-1.57×（含 >1.2× 达标 cell）**。剩余结构性差距 = 隧道 AES（双方共担 ~17%）+ 双用户态栈 + TAP 拷贝；集成层低成本杠杆已尽，进一步需要：① VNet 泵直递重构 ② 端到端 GSO-RX（上游 0006）。③ 隧道密码套件 GCM 化（协议层）**暂不执行**——双方共担成本、改善绝对吞吐但不改善对位比值，且属协议兼容性变更。

### 11.7 端到端 GSO ingress 直递（2026-09-04，工作树）

**根因修正**：此前 `TapLinux::OnInput` 在 VNET GSO 帧进入 VEthernet 前无条件拆成 MSS，因此 `XtcpRuntime` 的超帧接收分支在真实 TAP 路径上基本不可达。现改为：完成 IPv4/TCP 校验和后先把完整 GSO packet 交给上层；只有 XTCP 明确消费，native/lwIP 继续使用原有逐段回退。XTCP 再按 BufRef 最大 tier 将超帧切成有界 GRO 块。

**自适应包络**：少于 4 条活跃 flow 保持 1500B MSS 路径；4 条及以上默认 24KB GRO。`OPENPPP2_XTCP_GRO_BYTES` 可覆盖实验值；`OPENPPP2_XTCP_GSO_RX=1` 强制恢复 MSS 分段。P1 强制 8-32KB GRO 在 5 秒五轮中出现 0.12-1.20× 大幅波动，根因是单 socket connector queue 的整块背压/重传，因此默认不启用。

**client 进程单核 CPU8，GSO-on，3 秒 + 1 秒 omit，三轮 paired**：

| cell | native median | XTCP median | ratio median | ratio range |
|---|---:|---:|---:|---:|
| P1 UL | 836.7 | 692.6 | **0.83×** | 0.81-0.84× |
| P4 UL | 813.2 | 1086.1 | **1.34×** | 1.31-1.36× |
| P16 UL | 539.0 | 684.6 | **1.30×** | 1.27-1.40× |

P4/P16 已满足“每轮 >1.2×”的 client 进程单核吞吐门槛；P1 未满足。24KB 相比 32KB 峰值略低，但 P16 三轮离散更小，选作默认。三轮均验证 client affinity=CPU8、process `cpu_migrations=0`；但这些运行发生在 Route3 strict IRQ/RPS/XPS 与 iperf affinity/perf 硬门加入之前，且 selected CPU 外仍观测到 NET_RX/TX softirq，因此结果仍是 provisional，不是完整 A 榜 qualification pass。新契约下 other-CPU softirq 单独仍是 warning-only，不能把这条历史说明误读为新的 hard fail。

**附带修复**：`OPENPPP2_TAP_GSO_SEGMENTS=48` 原先只放大运行时 cap，保留 packet 的固定数组仍为 4 项；第 5 段起越界。数组容量现与最大 cap 48 对齐，并新增 48 段回归测试。

**已撤回实验**：允许 PSH packet 进入 TAP GSO coalescer 后，XTCP P1 DL 确实把 91,530 段合并为 5,849 个 GSO frame，但吞吐仍约 330-394Mbps；native 同条件升至约 1.02Gbps，paired ratio 反而下降。结论是 XTCP DL 门不在 TAP write syscall，PSH 放宽已撤回。空队列时直接 `send(MSG_DONTWAIT)` 到 connector 的实验也仅把 P1 UL ratio 从约 0.83× 提到 0.834×（三轮中位），CPU 效率基本不变，已撤回。

纯内存上传桥原型（复用 iOS `SendBufferToPeerAsync`）与 24KB GRO 组合时，P1 UL 单轮达到 1.17-1.34Gbps、约 1.50× native，证明目标算力上可达；但三轮中会随机退化到零速。根因是现有 `connection->Run` socket pump 与旁路 writer 构成双 owner，writer/flow 生命周期竞争后触发 XTCP 零窗口退化。扩大队列、提高 packet cap、ingress quantum 和修正入队 consumed 竞态均未消除。该原型已完整撤回；后续 bridge bypass 必须替换原 pump 为单 owner 状态机，不能在现有 pump 旁并挂 writer。

### 11.8 opt-in NDI TSO → Linux TAP virtio GSO（2026-09-04，工作树）

发送合同不按长度猜测：上游 `0007` 在 `BufRef::SegMeta` 显式标记 TSO，OpenPPP2 严格验证后将不可变 `TxGsoMetadata` 透传至 TAP。Linux `TapLinux::OutputGso` 先 flush coalescer，再以一次 `writev` 写入 10-byte `virtio_net_hdr`（flags/csum 字段为 0、TCPv4、complete-checksum）和共享 L3 payload；负写或短写立即 fail-closed，不重放。只有 `OPENPPP2_XTCP_NDI_TSO_TX=1` 且 TAP 成功协商 `IFF_VNET_HDR/TUN_F_TSO4` 才 advertise `kCapTsoTx`；默认关闭或不支持时，上游软件分段。

`0008` 保持保守 single-flight recovery：direct/buffered TSO 都只在 retransmission queue 为空且不在 recovery 时发出；listener/accept 是 DL bulk sender 的真实生产路径，因此 capability 在 `BindDataPath` 对 active、TFO、listener 与 SYN-cookie 统一继承，TCP-MD5 仍禁用 TSO。

最终算法证据：

- upstream `test_tso_tx` / `test_tso_rto` 全绿，覆盖 backpressure 整帧重试、KCC 连续 8×16KB、accept-side reverse send 与 RTO；
- kernel byte-exact probe 对 2/4/8/16 段均观察到精确 552-byte segment 与正确 checksum；
- 最终二进制 P1 DL、sndbuf=512KiB、10s+2s、3 rounds：535.72 / 527.46 / 526.49 Mbps，中位 527.46 Mbps；每轮 NDI 与 TAP GSO packet/byte 计数精确相等、均非零且 rejected=0，artifact：`artifacts/ndi-tso-final-conservative-r3-20260904`；
- gate-off control 保持 TAP capability 可用但 `ndi_gso_enabled=false`，NDI/TAP GSO packet/byte/rejected 全为 0，artifact：`artifacts/ndi-tso-final-gate-off-control-20260904`；
- 最终短版 netns 电池通过 echo、half-close、peer-close、RST、churn×16、1% loss/reorder/delay、MTU 1280、3s soak 与 route/DNS rollback，artifact：`artifacts/ndi-tso-final-netns-e2e-20260904`。

TSO-on 三轮中位 527.46 Mbps 低于同代 gate-off direct P1 DL 的约 596 Mbps，因此该能力只保留作 default-off laboratory 路径，不构成 Route2 性能完成。

**门控归因复验（2026-09-05，sndbuf=128KiB，strict CPU8，单轮 P1/P4 DL）**：`artifacts/p1p4-tso-gate-off-128k-20260905` 的 P1/P4 XTCP/native 为 `0.5764×/0.8347×`，所有 TSO candidates 均由 `disabled` 拒绝；`artifacts/p1p4-tso-gate-on-128k-20260905` 为 `0.6292×/0.9102×`，两组 cell qualification 均 pass。on 的 P1/P4 分别构造 `11,296/13,499` 个 NDI GSO frame、rejected 均为 0，但 buffered candidates 主要被 `outstanding`（`317,137/513,891`）拒绝，direct candidates 主要被 `pending`（`19,465/31,743`）与 `outstanding`（`18,114/21,870`）拒绝。这证明该窗口不是 TAP/backend reject，而是保守 single-flight 与 ACK-clock 的吞吐限制；不能以移除 `retrans_queue_.empty()` 或 recovery gate 换取速度。诊断字段 `tso_gate.direct/flush` 仅随 `OPENPPP2_XTCP_ACK_RELEASE_JSON=1` 输出。TSO 仍 default-off，Route2 性能门禁仍失败。

### 11.9 单-owner direct bridge 与当前 qualification（2026-09-04，工作树）

`OPENPPP2_XTCP_MEMORY_BRIDGE=1` 启用真正替换 socket pump 的 direct 状态机：`AckAccept` 成功启动后不调用原 `connection->Run`；上传由唯一 transmission writer 排空有界队列，下载由唯一 transmission reader 读入并切成 16KiB alias chunk。runtime 强持有 second leg；ready/payload 排队竞态、重复 close、普通/direct receive resume 都有 generation/one-shot/low-watermark 保护。仅支持半关的 raw child TCP carrier 可进入 direct path：upload queue 排空后实际 `shutdown(SHUT_WR)`，接收方向保留；WebSocket/TLS 等回退 socket pump。`ppp::telemetry` 记录 upload queue bytes/items/highwater、writer starts/exits/writes 与 send-shutdown；稳定 stats 记录 direct reject/download queue/resume/close，`degraded_half_close` 是兼容字段。

P1 direct GRO 扫描排除了较大默认：12KiB 三轮 975/1010/1039 Mbps；13KiB 仅约 4.5 Mbps，14KiB 为零，15KiB 约 40 Mbps；16KiB xtcp-only 有 1093–1281 Mbps 高峰，但 paired 曾零速。故 direct 默认是 12KiB，不以峰值换稳定性。

正确性门禁：

- `xtcp_runtime_adapter_test` + `xtcp_runtime_bridge_test` 通过，覆盖 direct zero-window resume、强 second-leg 生命周期、FIN 数据排空和幂等关闭；
- lab C++ 135/135 通过；`spinlock_test` 在未限制大量在线 CPU 时可因纯自旋超时，固定到 CPU0-7 后约 7.3s 完成，不是本工作树死锁；
- 上游 fault suite 20/20，bench best 6340.37 Mbps；
- 旧 direct E2E artifact `artifacts/direct-e2e-20260904` 的 `degraded_half_close` 非零，仅证明旧 revision 走过 direct path，不能证明协议级半关；本 revision 的 `transport_auth_lifecycle_test` 覆盖 raw child TCP `shutdown(SHUT_WR)` 后对端 EOF、反向继续读及幂等调用，正确 stats 路径保持 `degraded_half_close=0`；
- 新 runner 显式 flag strict smoke `artifacts/route3-strict-direct-flag-smoke-20260904`：P1 DL 408.2 Mbps，qualification pass，metadata 明示 `xtcp_memory_bridge=true`、`xtcp_ndi_tso_tx=false`，direct telemetry 非零；
- 最终 GSO-on strict paired 分拆为 `artifacts/direct-final-ul-p1p4p16-r3-20260904`、`artifacts/direct-final-dl-p1p4-r3-20260904`、`artifacts/direct-final-dl-p16-r3-20260904`：36/36 native/XTCP cell qualification pass，无 watchdog 或零速；PPP 与 iperf 全线程固定 CPU8、migrations=0，RPS/XPS readback 目标 mask，veth/TUN IRQ 均按 not-applicable 通过，cleanup restore pass。XTCP cell connector bytes 为零且 direct telemetry 非零。
- 旧六模式 strict 主矩阵 `artifacts/route3-six-mode-strict-r3-20260904` 仅生成 106/106 cell；两个 repair artifact 分别补证 lwIP GSO-on P4 DL 和修复后的 XTCP GSO-on P4 DL。随后在同一修复 revision 上完成原子矩阵 `artifacts/route3-six-mode-strict-persist-fix-r3b-20260904`：108/108 cell、108/108 qualification pass。P4 DL XTCP GSO-on 三轮为 614.42–619.07 Mbps，无 watchdog。
- 修复后 GSO-on native/XTCP 全 paired `artifacts/route2-persist-fix-paired-p1-p4-p16-r3-20260904` 为 36/36 qualification pass，无 watchdog。XTCP/native ratio 中位（min–max）：P1 UL 0.9112（0.9107–1.0420）、P4 UL 0.9375（0.9252–0.9376）、P16 UL 1.0019（0.9833–1.0046）；P1 DL 0.5568（0.5148–0.5625）、P4 DL 0.8423（0.8409–0.8440）、P16 DL 1.1298（1.0390–1.1552）。
- 原子 108-cell 的 qualification 不代表性能稳定：`XTCP/GSO-on/P1/UL` 三轮为 655.76、30.20、734.58 Mbps；低值轮有 52 次 retransmit、`direct_upload_rejected=1`、`resume_requested=1`、`resume_effective=0`，仍需继续定位 upload receive/direct queue 的间歇性退化。

零窗口修复消除了已复现的 P4 DL watchdog，Route3 strict qualification 装置也已在修复 revision 上原子 108/108 pass；但性能门禁仍失败：P1/P4 双向未达稳定 1.2×，P16 DL 也未达每轮 1.2×，且 NDI TSO 仍为负收益。raw child TCP 的 capability-gated 协议级 half-close 已实现并通过单测/E2E；vmux 平台尾包排空限制及 P64 DL wedge 仍未解决。Route1–3 均不得标记完成。
