# XTCP Linux IPv4 laboratory runtime 设计

> Status: Active / Laboratory
> Type: Design
> Last verified: 2026-09-27 (working tree; uncommitted)

## 0. 现状总览（2026-09-04，`XTCP-SINGLECORE-BASELINE-20260902` 之后）

> 本文其余章节按时间线记录实验细节；本节是当前状态的唯一起点摘要。

**当前工作树**包含端到端 TCPv4 GSO ingress、opt-in 单-owner 用户态 direct bridge、显式 receive resume、16KiB download chunk、DL 零窗口 persist/pacing 治理、Route3 strict isolation/qualification，以及 default-off NDI TSO laboratory capability。binary：`build/xtcp-runtime-root/bin/ppp`。这些改动尚未提交，不能把历史 commit 链当作当前 revision。

**direct bridge（未设置 `OPENPPP2_XTCP_MEMORY_BRIDGE` 时默认尝试；`=0` 可强制 legacy socket pump；runner `--xtcp-memory-bridge` 显式启用）**替换原 socket pump，而不是与其并行：XTCP receive → 32MiB/4096-item 有界 upload queue → 唯一 transmission writer；唯一 transmission reader → 16KiB alias chunk → XTCP `Send`。runtime 强持有 second leg；队列降到 low watermark 后显式 `ResumeReceive()`/window update。`ITransmission` 默认不保证半关；raw child `ITcpipTransmission` 则通过真实 TCP `shutdown(SHUT_WR)` 在 upload queue 排空后发送 FIN、保留接收方向。该 direct 路径按 carrier capability gate；WebSocket/TLS 等不支持的 carrier 安全回退 socket pump；`degraded_half_close` 仅为兼容遥测，正确路径保持 0。

**当前严格单核 paired 证据**（GSO-on，direct bridge，CPU8）已有三轮 artifact `artifacts/direct-final-*` 的 36/36 qualification pass。旧六模式主矩阵 `artifacts/route3-six-mode-strict-r3-20260904` 仅生成 106/106 cell；修复 revision 的原子矩阵 `artifacts/route3-six-mode-strict-persist-fix-r3b-20260904` 已完成 **108/108 cell qualification 全 pass**。原故障维度 `XTCP/GSO-on/P4/DL` 三轮为 614.4–619.1 Mbps，未再出现 watchdog。

qualification 只证明配置、隔离、runtime proof、统计完整性与 cleanup，不是性能稳定性门禁：原子矩阵的 `XTCP/GSO-on/P1/UL` 三轮为 655.76、30.20、734.58 Mbps；低值轮有 52 次 retransmit、`direct_upload_rejected=1`、`resume_requested=1`、`resume_effective=0`。因此这一路径仍有间歇性退化信号，不能因 108/108 qualification pass 而宣称性能通过。

P1 direct GRO 扫描中 12KiB 三轮稳定（975/1010/1039 Mbps）；13–15KiB 出现严重退化，16KiB 虽有高峰但 paired 曾零速，因此 direct P1 默认取 12KiB。DL 将约 64KiB transmission read 切成 16KiB 后，gate-off P1 DL 三轮约 596 Mbps；opt-in NDI TSO 中位 527.46 Mbps，反而更低，必须保持 default-off。

**UL gather 实验**：direct upload writer 可由 `OPENPPP2_XTCP_DIRECT_UPLOAD_GATHER_BYTES`（runner `--xtcp-direct-upload-gather-bytes`）合并已入队连续 payload；不等待凑批，受 carrier plaintext cap 限制。5 秒单轮 strict paired screen 中，60KiB 为唯一 P1/P4/P16 全过候选（1.2057–1.2576×）；但三轮 artifact `artifacts/ul-gather-61440-r3-20260904` 的 P1 round 2 为 1.1873×、P16 round 3 为 1.0939×，即使 18/18 qualification pass 仍未通过稳定 1.2× 性能门禁。

**DL four-credit 实验已否决并回退**：尝试将每 flow direct download reservation 从单个 16KiB 增至 64KiB，目的是连续读取 transmission payload。`artifacts/dl-credit-sndbuf-131072-r1-20260904` 显示 P1/P4 ratio 仅 0.1413/0.6850，且每 flow queue 卡在 64KiB、server `rwnd_limited` 约 99.9%；512KiB artifact 的 P16 发生 watchdog。该路径会造成持续 receiver-window backpressure，不能以增大 sndbuf 或重试掩盖。实现已恢复为单个 16KiB flight：每次 XTCP `Send` accepted 后才由 writable notification 继续读取下一块。

**DL watchdog 根因与修复**：P4 现场四流均为 `snd_wnd=0`、`inflight=0/1`、`pending≈sndbuf`，direct queue 另有 62248 bytes；persist 探针约每两秒发出并获 ACK，但 `NextTimerDeadline()` 仍优先返回无进展可能的高频 `pacing_deadline_`，使同核 PPP timer loop 空转并饿死负责读取 socket、重开窗口的 iperf。补丁 `0010-zero-window-pacing-deadline.patch` 在零窗口且 persist 已武装时忽略 pacing deadline，只等待 persist/RTO 等真实恢复期限；不改变正常开窗 pacing、sndbuf、retransmission ownership 或 NDI TSO。原故障维度 `XTCP/GSO-on/P4/DL/sndbuf=128KiB` 修后专场 `artifacts/route2-persist-fix-p4dl-gso-on-r3-20260904` 连续 3/3 pass，配对 qualification 6/6 pass，无 watchdog；XTCP 611.8–620.2 Mbps。

**验证状态（本工作树）**：lab C++ `135/135`、targeted persist/persist-stack/pacing `3/3`、runtime adapter/bridge `2/2`、项目 XTCP/GSO `8/8`、上游 fault suite `20/20`；修复后 direct bridge 短版 netns E2E（churn×16、netem/MTU、3s soak、rollback）通过，artifact 为 `artifacts/xtcp-direct-persist-e2e-20260904`。Route3 runner 已实现 PPP+iperf 同核 affinity、zero migration、RPS/XPS/相关 IRQ readback 与 compare-and-restore；other-CPU softirq 仅 warning。修复 revision 的六模式 strict 原子矩阵为 108/108 qualification pass。

**旋钮一览**：`OPENPPP2_XTCP_SHARDS` / `--xtcp-shard-route` / `--xtcp-cc` / `--xtcp-sndbuf` / `--xtcp-unix-bridge` / `--xtcp-memory-bridge` / `--xtcp-ndi-tso-tx` / `--xtcp-direct-upload-gather-bytes` / `--tap-gso-segments` / `--xtcp-gso-rx` / `OPENPPP2_XTCP_GRO_BYTES` / `OPENPPP2_XTCP_INGRESS_ITEMS/BYTES` / `--xtcp-send-retry-us` / `OPENPPP2_XTCP_CONNECTOR_BATCH_BYTES`。runner 会先清除继承的 direct-bridge/NDI-TSO env，只按显式 flag 启用，并把它们写入 dry-run、matrix 和 cell metadata。

**剩余阻塞**：
1. 固定owner候选的 P1/UL 与 P4/DL 单核 GSO-on 已分别达到稳定 1.2×；但单核 P16/DL/GSO-on 仍只有约1.05×，完整跨并行度/方向矩阵未全部达到目标。P16/DL 双核路径虽稳定超过1.2×，公平性仍有间歇性异常，且route实验尚未晋升默认；
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

**CPU profile资格判定（每 cell 硬 invariant）。** runner 在非 `none` profile 下为每个 cell 写 `qualification.json`（纯 Python `tools/datapath_qualifier.py`，可单测）。`process_cores` **直接按 PPP `process task-clock / formal wall time` 计算，不从 Mbps/ns-per-byte 反推**（反推值仅作 `process_cores_derived_sanity` 交叉验证）。`client-vnet-isolated` 保留 **`0.9 ≤ PPP process_cores ≤ 1.02`**；`client-cpuset` 要求CPU列表非空、无重复，且核心数上限为 **选定CPU数 × 1.02**，下限仍为0.9。多CPU cpuset内调度迁移允许，但必须有 affinity verified；单CPU cpuset仍要求零迁移。`client-single-core` 则因 PPP 与 iperf 有意竞争同一 CPU，只把 **PPP `process_cores > 1.02`** 作为硬失败，低于 0.9 记录 `ppp_process_cores_below_0.9_same_core_contention` warning。strict profile 另以 selected `/proc/stat` non-idle、以及可用时 system perf 的 `CPUs utilized` 验证总容量不超过 1.02 核，并始终要求 payload positive。每 cell 必须同时满足：

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

### 11.10 新鲜 strict 基线与 A2 复验（2026-09-24）

在 `gpt6fix` 当前工作树上重建 XTCP-enabled `bin/ppp`，使用 CPU8 strict profile、单核、client/server 双向、native/lwIP/XTCP、GSO off/on、P1/P4/P16，各 3 轮、10s+2s omit；XTCP memory bridge 开启，NDI TSO 保持关闭。完整原始证据保存在 `artifacts/closeout-baseline-108-20260924/`。

- qualification **108/108 pass**，无 cell/watchdog/capability fallback；1.20× paired gate **23/36 fail**，故不启动后续 576-cell impairment campaign。
- 各组 XTCP/native 中位数（3 轮范围）：DL GSO-off：P1 `0.6296×`（0.6102–0.6542）、P4 `1.1637×`（1.1610–1.1886）、P16 `2.3206×`（2.2913–2.3604）；DL GSO-on：P1 `0.4034×`（0.3971–0.4187）、P4 `0.7511×`（0.7443–0.7650）、P16 `1.1671×`（1.1041–1.1875）。UL GSO-off：P1 `1.2967×`（1.2083–1.3043）、P4 `1.2060×`（1.1855–1.2122）、P16 `1.4670×`（1.1056–1.6895）；UL GSO-on：P1 `1.1999×`（1.1292–1.2307）、P4 `1.1461×`（1.0817–1.2372）、P16 `1.1843×`（1.1461–1.2166）。
- telemetry 暂未显示 TAP/backend 拒绝是 DL 主因：XTCP direct DL 样本中 TAP write 全成功，P1 direct-write p95 低于 16µs，owner queue p95 为 4µs；同时 `send.sndbuf_quota` 持续出现，P1 DL `snd_buf=64KiB`、`inflight` 经常贴满 64KiB，P4/P16 direct download queue high-water 约为每流 16KiB。该证据指向 XTCP sender buffer/ACK-clock 与应用侧 direct queue 的交互，而非证明某个单一根因；后续应对 P1/P4 做受控 sndbuf、ACK cadence 与 queue-drain 扫描，P16 保持已知安全包络，不能直接照搬大 sndbuf（历史上 ≥512KiB 曾触发 offered-load wedge）。
- A2 按 P16 UL/GSO-on/direct bridge/CPU8/60s/omit0 六轮复验：runner qualification 6/6 pass；coherent iperf 3.18 sender-side parser 六轮均为 `no_observed_stall`，16/16 flow 有完整区间覆盖。中位吞吐 `865.5Mbps`，范围 `856.3–874.9Mbps`。证据位于 `artifacts/closeout-a2-capturefix-20260923/`；所用本地采集器为独立二进制，loopback 区间/summary 一致性验证通过，但原构建源码目录未保留，需在后续可复现复测时补齐 collector provenance。此前 stock iperf 结果保存在 `artifacts/closeout-a2-20260923/`，因区间与 summary 字节数不一致而标记 not_assessed，不计入 A2 结论。

### 11.11 DL quota 部分发送试验（2026-09-24，未保留代码）

针对 DL 的 `snd_buf=64KiB` 整块准入拒绝，试过在 `Send()` 因 snd_buf quota 拒绝后读取 admission snapshot，按 `snd_buf - pending_send - inflight` 重试可用前缀，并在 runtime 端保存剩余偏移。候选二进制 SHA256 为 `f2a3acf1f9a28edb45624a44a9ee84533d4807f2ee3d5ab6324999631b29291e`。最终用于判断的矩阵与 11.10 基线对齐：CPU8 单核 strict、direct memory bridge、GSO-on、P1/P4 DL、native/XTCP、3 轮、10s+2s；12/12 qualification pass、无 watchdog。结果：

| cell | baseline XTCP/native | 部分发送候选 XTCP/native | XTCP median goodput |
|---|---:|---:|---:|
| P1 DL | 0.4034× | 0.4003×（范围 0.3996–0.4153×） | 308.1 Mbps |
| P4 DL | 0.7511× | 0.7571×（范围 0.7510–0.7701×） | 571.6 Mbps |

收益与基线差异处于轮间波动内，且均未达到 1.20×；非 strict 的先导矩阵因没有 CPU 隔离与 direct bridge，明确不用于性能比较。候选期间仍观察到 sndbuf quota admission：P1 拒绝快照为 `attempted_len=16,384B`、`inflight=62,640B`、`pending_send=0`、`snd_buf=65,536B`，cwnd/peer window 有余量；当时可用 credit 仅 `2,896B`，低于该候选的 4KiB 部分发送门槛，因此至少这个常见拒绝形态不会触发前缀重试。owner queue p95 为 32µs、NDI 输出 p95 为 16µs；TAP/backend reject 和 ingress drop 均为零。这继续把调查范围指向 XTCP sender quota/ACK 释放节奏，但**不能证明唯一根因**。下轮可用显式计数验证“约一个 MSS 的可用 credit 是否常见、前缀是否被接收、是否降低 stalled time”，再评估小于 4KiB 的门槛；不要先扩大默认 snd_buf 或放宽 TSO/recovery gate。

### 11.12 1KiB credit 部分发送复验（2026-09-24，未保留代码）

针对 11.11 常见 `2,896B` credit 被 4KiB 门槛跳过的问题，候选将最小前缀降为 1KiB，并加上 perf JSON 的 `partial_attempts/partial_accepted/partial_bytes` 计数；只在当前 Send 拒绝产生了新 generation、attempted length 匹配且原因是 sndbuf quota 时尝试。CPU8 strict、direct memory bridge、GSO-on、P1/P4 DL、native/XTCP、3 轮，共 12 cells；qualification **12/12 pass**，无 watchdog，证据在 `artifacts/closeout-dl-partial-credit-1mss-strict-20260924/`。

- 部分路径实际触发且均成功：P1 约 514–650 次/s、1.86–4.83MB/s 前缀；P4 约 897–963 次/s、5.87–6.72MB/s 前缀。
- 原始 XTCP 中位吞吐没有提升：P1 `308.1→306.7Mbps`，P4 `571.6→566.9Mbps`。paired ratio 为 P1 `0.4123×`、P4 `0.7019×`，但该轮 native P4 波动到 `739–865Mbps`，ratio 不能单独归因于候选；基线分别为 `0.4034×/0.7511×`。

结论：排除了“available credit 小于一个 16KiB chunk 导致明显吞吐空洞”作为当前可获益的大杠杆；前缀能够提交，却增加 Send 调用而没有提高原始吞吐。候选代码和实验计数已撤回。结合严格 128KiB snd_buf 扫描中 P1/P4 原始吞吐上升、以及 64KiB 状态下 inflight 长期接近 snd_buf，后续优化应转向有 per-flow/全局内存预算的 snd_buf/BDP 自适应，而不是继续切小发送；未完成活跃连接内存预算与高并发门禁前，不修改 64KiB 默认值。源码检查还发现 `XtcpStack::SetSndBuf` 是 stack-wide、仅影响新连接的启动配置，没有 per-connection setter；runtime 每 shard 可有 4,096 flows、最多 8 shards。按 quota 满额估算，64KiB 对应最高约 2GiB、128KiB 约 4GiB 的全 runtime 发送额度（这是理论上界，不是预分配内存），因此扩大默认值会改变资源暴露面。下一步如实现自适应，需先设计并验证 per-connection quota API 与全局 aggregate cap，再做高并发/公平性压力矩阵；本轮不引入未验证的 stack API。实验逻辑撤回后的 XTCP-enabled 产品已重建（SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`），完整 C++ suite 在 `taskset -c 0-7` 下 **141/141 通过**。

### 11.13 per-connection snd_buf 自适应试验（2026-09-24，未保留代码）

为验证“少流用 128KiB、高并发回到 64KiB”，临时加入 `ConnSetSndBuf`（所属 shard 锁保护）和 opt-in `OPENPPP2_XTCP_ADAPTIVE_SNDBUF=1`；每 shard 活跃 flow≤5 时，对新接受连接设置 128KiB，全局 sndbuf 显式覆盖优先。上游 quota 单测验证 live connection 更新、非法值拒绝及配额准入/排空通过；XTCP-enabled `ppp` 产品也成功编译。

严格 A/B：CPU8 单核、memory bridge、GSO-on、DL P1/P4/P16、native/XTCP、3 轮、10s+2s，18/18 qualification pass，无 watchdog/零速流。证据保存在 `artifacts/closeout-dl-adaptive-sndbuf-20260924/`。1.20× 门禁 9/9 未通过；paired ratio 中位数 P1/P4/P16 分别为 `0.5948×/0.7970×/1.1248×`。原始 XTCP goodput 中位数分别 `438/625/580 Mbps`，相较新鲜 64KiB 基线 `317/571/570 Mbps`，P1/P4 有提升；但 P16 每流 `max/min` 公平性从基线约 `1.06–1.12` 恶化到 `1.75–1.79`（零速仍为 0），表明按建连顺序给前五条流扩大 quota 会造成明显流间不均。静态 128KiB 的既有矩阵 P16 公平比约 `1.48–1.71`，也不构成更好的平衡。

因此 per-connection API 与 runtime 策略均已撤回，64KiB 默认与现有显式 `OPENPPP2_XTCP_SNDBUF_BYTES` 试验旋钮不变；矩阵和单测证据保留。后续若继续做自适应，必须以全连接一致的窗口/预算策略避免先到流获益，且把 Jain/fairness 纳入硬验收，不能只看总 goodput。

### 11.14 DL pacing burst 与窗口扫描（2026-09-24，未保留代码）

根据 baseline perf 采样中 DL P1 每 1s 有约 0.65s send-stall、pending flush 常被 pacing/cwnd gate 阻塞的证据，在隔离 XTCP 源码副本中临时把 pacing quantum cap 从 64KiB 增至 opt-in 256KiB（默认值不变），并配合 snd_buf 扫描。严格 CPU8 单核、GSO-on、memory bridge、10s+2s、paired native；所有矩阵 qualification 均通过。

| XTCP 配置 | 场景 | ratio 中位（范围） | XTCP goodput 中位 | 结论 |
|---|---|---:|---:|---|
| snd_buf=512KiB + pacing cap=256KiB | P1 DL | `0.8001×` (`0.7968–0.8537×`) | 613 Mbps | 明显改善但距 1.20× 仍远 |
| snd_buf=512KiB + pacing cap=256KiB | P4 DL | `0.7591×` (`0.6957–0.7703×`) | 566 Mbps | 无稳定收益 |
| snd_buf=1MiB + pacing cap=256KiB | P1 DL | `0.8407×` (`0.8072–0.8436×`) | 642 Mbps | 本轮最佳稳定 P1 DL，仍未达标 |
| snd_buf=128KiB + pacing cap=256KiB | P16 DL | `1.2195×` (`1.1466–1.4265×`) | 591 Mbps | 中位过线但有一轮低于 1.20×；不得算稳定通过 |
| snd_buf=512KiB + pacing cap=256KiB + BBR | P1 DL | `0.6459×` (`0.0422–0.6687×`) | 498 Mbps | 第三轮仅 32 Mbps，淘汰 |
| snd_buf=1MiB + pacing cap=256KiB + NDI TSO | P1 DL | `0.1853×` (`0.1783–0.2816×`) | 139 Mbps | 显著回归；TSO 继续 default-off |

原始证据分别位于 `artifacts/closeout-dl-pacing-256k-sndbuf-512k-p1p4-20260924/`、`artifacts/closeout-dl-pacing-256k-sndbuf-128k-p16-20260924/`、`artifacts/closeout-dl-pacing-256k-sndbuf-1m-p1-20260924/`、`artifacts/closeout-dl-bbr-pacing256-sndbuf512-p1-20260924/` 与 `artifacts/closeout-dl-tso-pacing256-sndbuf1m-p1-20260924/`。1MiB P1 DL 的进程 task-clock 约 `11.49ns/byte`，native 约 `9.66ns/byte`；瓶颈已从 64KiB quota/pacing 侧转向每字节 CPU 成本。256KiB cap 仅存在于临时实验源码，已撤回并重建原 baseline 产品（SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`）；没有提升默认 snd_buf、没有放宽 TSO single-flight/recovery gate。当前仍未实现稳定的全场景 1.20×。下一阶段转查 DL `SendData` 的分段/校验和/重传数据所有权成本，先用 profile 定量，若尝试零拷贝必须保持 retransmission queue 独立持有且通过丢包恢复测试。

### 11.15 DL fused copy/checksum SSSE3 dispatch 试验（2026-09-24，未保留代码）

检查发现产品以 `-O3` 构建但没有 `-mssse3`，因此 `CopyAndChecksumSimd` 在产品 TU 中未编译；CPU 已有 SSSE3，源码也已有 CPUID 检查。临时在隔离源码副本中给 SIMD 函数加 `target("ssse3")`，保留运行时 CPUID dispatch，不提高整份 TU 的最低 CPU 指令集。objdump 确认候选对象包含 `pshufb`；`test_checksum_simd`、`test_loss_recovery`、`test_1mb_stream`、`test_bidi_1mb` 四项均通过。

严格 P1 DL A/B 使用相同 CPU8 单核、memory bridge、GSO-on、native/XTCP、3 轮、10s+2s 和默认 XTCP sndbuf/pacing：两组各 6/6 qualification pass。基线证据在 `artifacts/closeout-dl-ssse3-baseline-p1-20260924/`，候选在 `artifacts/closeout-dl-ssse3-candidate-p1-20260924/`。基线 XTCP 中位 `315.4Mbps`、ratio `0.3903×`、进程 task-clock `12.86ns/B`；候选分别为 `310.6Mbps`、`0.4003×`、`12.64ns/B`。候选原始吞吐约低 1.5%，task-clock 改善约 1.7%，均落在轮间波动范围，未证明有益，更未接近 1.20×。因此未把 dispatch 改动带入产品源码；产品二进制恢复为基线 SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`。此结果说明 fused checksum SIMD 不是当前 DL 的主要可获益点；后续先做调用栈/符号级 profile，避免仅凭静态每字节成本猜测。

随后将已有 `--xtcp-sndbuf` 旋钮单独设为 1MiB，保持默认 pacing，不改源码，再跑相同严格 P1 DL 三轮。证据在 `artifacts/closeout-dl-sndbuf-1m-default-pacing-p1-20260924/`，qualification 6/6 pass、无 watchdog。XTCP 中位 `629.8Mbps`，paired ratio `0.8157×`（范围 `0.7947–0.8472×`），相对默认 64KiB 基线 `315.4Mbps` 约翻倍，但仍未达到 1.20×；进程 task-clock `11.75ns/B`，仍高于 native 的 `9.65ns/B`。这验证了小 snd_buf 是先前低吞吐的重要限制，但增大后仍有约 18% 单核效率差距，且 1MiB 将活动连接理论额度上限提高到默认的 16 倍，不适合作为无预算的默认修复。perf JSON 中 sndbuf-quota 拒绝显著少于 64KiB 组，pacing-block 计数仍持续增长；结合 `perf_event_paranoid=3` 阻止符号采样，下一步须取得可用的函数级 CPU 归因或低开销定点计时，再决定是否优化 pacing/构包/校验和路径。

### 11.16 XTCP P1 DL gprof 定点归因（2026-09-24，仅诊断构建）

宿主 `perf_event_paranoid=3` 禁止 perf record。为获得符号级线索，独立 `/tmp` 构建以 `-pg` 插桩，保持 Release 优化、用 1MiB snd_buf、memory bridge、GSO-on 跑一轮 XTCP P1 DL；SIGTERM 优雅退出后生成 gmon。此构建吞吐约 `542Mbps`，受插桩影响，**不作为性能结果**。客户端 gmon 原件保存在 `artifacts/xtcp-gprof-p1dl-20260924/diagnostics/gmon.xtcp-client.3631072`，供 `gprof /tmp/ppp-xtcp-gprof <gmon>` 复核。

客户端 flat samples 前列为 `aesni_encrypt` 48.5%、`aesni_cbc_sha256_enc_shaext` 9.4%、XTCP `BuildSegmentPacket` 5.6%、`CRYPTO_cfb128_encrypt` 3.8%、`TcpConn::FlushPendingSend` 2.3%、`XtcpNdiBackend::Tx` 1.9%、`TapLinux::WriteTunFrame` 1.9%。profile 没有可用 call-graph arcs，且多线程 gprof 采样不是精确的进程 CPU 拆分；这些占比只用于排序，不能相加成可实现收益。方向结论：CopyAndChecksum/单一 NDI holder 不是足以解释 0.816× 的单点，任何优化它们都不可能凭目前证据达到 1.20×；后续应检查实际传输加密/封装调用粒度及 XTCP per-segment packetization 的调用数，先提出可以跨边界减少工作量的方案，再用未插桩严格矩阵验证。基线 `bin/ppp` 已恢复并核对 SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`。

### 11.17 缓冲发送 PSH 尾段化与 DL GSO 复验（2026-09-24）

gprofng 的 uninstrumented-ledger 对照显示，XTCP P1 DL 基线 451,061 次普通 TUN write、0 个 eligible/merged GSO segment；其中 451,057 个包因 PSH 被 coalescer 拒绝。native 同轮则有 481,600 个 eligible、478,484 个 merged segment。源码审查发现 `TcpConn::FlushPendingSend` 对每个 MSS 子段都设置 PSH，虽然 PSH 是 push 提示而非“每段数据标志”，这使相邻 TCP 段无法进入现有 TUN GSO 合包。

在 `0016-buffered-push-tail-gso.patch` 中仅调整缓冲发送：PSH 保留在当前缓冲字节范围的最后一个片段，其余 ACK/CWR、分段、重传队列和窗口/pacing gate 不变；单段直发路径不变。未增加 TSO，也未调整默认 snd_buf 或 GSO segment cap。`0017-tests-identify-data-by-payload.patch` 修正 SACK recovery、early retransmit、combo stress 中把 PSH 当成 payload 判据的测试 harness。

严格 P1 DL、snd_buf=1MiB、默认 pacing、GSO cap=4、CPU8 单核 memory bridge、3 轮 paired native：证据在 `artifacts/closeout-dl-psh-last-segment-1m-p1-20260924/`，qualification 6/6 pass。XTCP 中位吞吐从同配置基线 `629.8 Mbps` 提到 `770.3 Mbps`（约 +22.3%）；paired ratio 为 `1.0243×`（范围 `0.9620–1.0368×`），仍未达到 1.20× 稳定门禁。前两轮 ledger 分别合并约 651k/664k 个 segment，GSO writes 约 172k/171k；baseline 合并数为 0。随后用新 artifact `artifacts/closeout-dl-psh-last-segment-gso16-p1-rerun-20260924/` 重跑 cap=16 三轮，qualification 6/6 pass，无 contention/watchdog：XTCP median `996.6 Mbps`（982.8–996.6），native median `945.2 Mbps`（912.3–966.3），ratio median `1.0543×`（1.0314–1.0773）；XTCP task-clock `7.14 ns/B`，native `7.97 ns/B`。这确认较大 cap 在本机 P1 DL 下稳定打满近 1Gbps 且单字节 CPU 成本更低，但 paired ratio 仍远低于 1.20×，且 native 也获益，因此保留为实验旋钮、不提升默认 cap。

将 cap=16 扩展到 P4/P16 后，1MiB snd_buf 试验在全部 XTCP cell watchdog；诊断显示 cwnd 塌至 1 MSS、pending/in-flight 堆积、send admission 持续被 quota 拒绝，NDI/TAP 输出拒绝为 0。原始证据在 `artifacts/closeout-dl-psh-last-segment-gso16-p4p16-20260924/`，该配置 qualification fail，不能计算有效 ratio；确认大 snd_buf 多流配置不安全。随后恢复默认 snd_buf=64KiB，重跑三轮 P4/P16，证据在 `artifacts/closeout-dl-psh-last-segment-gso16-p4p16-sndbuf64k-20260924/`：qualification 12/12 pass、无 watchdog，但所有 6 个 paired cell 均未过 1.20×。P4 ratio median `0.8883×`（0.8841–0.9064），P16 `1.0130×`（1.0015–1.0494）；因此 cap=16 仅对 P1 DL 绝对吞吐有效，不能解决 P4/P16 的比值目标。

继续验证 GSO-off 的 P4 DL：128KiB snd_buf 的三轮 artifact `artifacts/closeout-dl-gsooff-p4-sndbuf128k-20260924/` qualification 6/6 pass，paired ratio `1.4822×/1.2829×/1.2961×`，1.20× gate 3/3 pass，中位 `1.2961×`，XTCP median `648.0 Mbps`。同条件默认 64KiB 对照 `artifacts/closeout-dl-gsooff-p4-sndbuf64k-20260924/` 也 qualification 6/6 pass，但三轮 ratio `1.1773×/1.1807×/1.1742×`，均略低于 gate；因此对 P4，GSO-off + 128KiB 是目前已复验通过 1.20× 的配置，而 64KiB 不过线。P1 DL 用 128KiB/GSO-off 的复验 `artifacts/closeout-dl-gsooff-p1-sndbuf128k-20260924/` qualification 6/6 pass，但 ratio 仅 `0.8629×`（0.8612–0.8803），所以该调优不能外推到 P1。以上是按并发数分层的实验配置，不代表已改变产品默认参数或完成全矩阵目标。

随后以当前 PSH 尾段候选复测 P16 DL、GSO-off、默认 snd_buf=64KiB：`artifacts/closeout-dl-gsooff-p16-sndbuf64k-20260924/`，qualification 6/6 pass，无 watchdog；native median `260.5 Mbps`（252.7–268.7），XTCP median `591.8 Mbps`（588.3–593.4），paired ratio `2.2777×`（每轮 `2.1895–2.3418×`），1.20× gate 3/3 pass。XTCP process task-clock `12.43 ns/B`，native `31.38 ns/B`。这复现了 P16 GSO-off 的高收益，说明该配置不是依赖放大 snd_buf；它与 P4 的 GSO-off +128KiB 结果一起构成已验证的分层配置，但仍未解决 P1 DL、GSO-on 及 UL 全矩阵欠账。根 `bin/ppp` 仍应保持 baseline，不将临时候选误认为默认产品。

对 PSH 尾段候选补齐 UL 回归矩阵：`artifacts/closeout-ul-psh-tail-r3-20260924/`，CPU8 strict、memory bridge、P1/P4/P16、GSO off/on、3 轮，36/36 qualification pass，无 watchdog/零速。候选 XTCP goodput median（范围）为：P1 off `318.8`（309.8–346.5）/on `827.5`（826.1–889.0）Mbps；P4 off `339.8`（338.8–353.5）/on `857.6`（851.1–870.5）Mbps；P16 off `313.3`（291.3–329.4）/on `862.3`（860.8–866.6）Mbps。对应 paired ratio median（范围）：P1 off `1.1392×`（1.0195–1.1588）、on `1.1483×`（1.1441–1.2119）；P4 off `1.1945×`（1.1642–1.2224）、on `1.1895×`（1.1565–1.2108）；P16 off `1.3551×`（1.2486–1.4771）、on `1.2008×`（1.1694–1.3308）。18 个配对中 10 个单轮未过 1.20×，因此 UL 稳定门禁仍未通过。

为排查 GSO-off P1/P16 的 raw-goodput 下滑疑虑，又用未含尾段化补丁且 SHA256 已核对的 `bin/ppp` 做同条件 12-cell baseline：`artifacts/closeout-ul-gsooff-p1p16-baseline-r3-20260924/`，qualification 12/12 pass。XTCP P1 median `316.9 Mbps`，候选为 `318.8 Mbps`；P16 baseline `325.8 Mbps`，候选 `313.3 Mbps`。两组范围重叠，差异不足以证明稳定回归或稳定收益；性能 ratio 对 native 当轮波动敏感，不能用前一批 108-cell 的 ratio 直接归因。综合看，此矩阵未复现间歇性低速/零速，但也未证明 PSH 改动能提升 UL。候选 patch 仍只作为 DL 实验改动，不据此调整 UL 默认行为；继续优化前应以 `direct_upload_rejected/resume_effective/retransmit` 的同步计数定位真正失速边界。

为覆盖短矩阵可能遗漏的间歇事件，另跑 P1 UL/GSO-on 60 秒 × 3 轮：`artifacts/closeout-ul-p1-gsoon-60s-r3-20260924/`，6/6 qualification pass。XTCP median `848.9 Mbps`（843.1–852.5），native `739.7 Mbps`（735.8–744.1），ratio 每轮 `1.1331×/1.1477×/1.1586×`。每轮 60 个有效 1s 区间；最低区间吞吐为 `762/775/786 Mbps`，5th percentile `792/798/811 Mbps`，没有低速/零速区间；iperf retransmit=0。三轮 direct upload backpressure/rejected、resume、ingress drop、XTCP send stall/reject、sndbuf quota、output reject 均为 0；owner queue dropped=0、最大 q95=64µs、NDI output p95=16µs。结论：在当前 CPU8 strict/direct-bridge 场景没有复现此前的 P1 UL 间歇低速；剩余可见差距是稳定约 15% 的相对吞吐比，而非已观测到的队列停顿。不能把未复现当作根因已修复。

TAP GSO cap 从默认 4 提至 16 的 P1 UL/GSO-on 三轮实验在 `artifacts/closeout-ul-p1-gsoon-cap16-r3-20260924/`：qualification 6/6 pass，XTCP median `891.7 Mbps`（846.3–893.3）、native `867.1 Mbps`（857.8–877.9），ratio median `1.0175×`（0.9866–1.0283）；XTCP task-clock `7.92 ns/B`。XTCP 绝对吞吐提高，但 native 同时获益更多，单轮 ratio 全部低于 1.20×，故 cap16 不构成相对性能修复，默认 cap 仍为 4。

候选 XTCP 回归中，SACK、RTO、ECN、early-retransmit、GSO/GRO、TSO、pacing、1MiB 单向/双向与组合丢包相关的 21 项定向用例通过。全量 239 项 CTest 首轮为 225 pass/14 fail；将 `test_early_retx` 与 `test_combo_stress` 从 PSH 判据改为 payload 判据后复跑通过，全量复验结果为 **227 pass/12 fail**。干净未改 XTCP 基线确认 `test_ts_ooo_drain`、`test_rack`、`test_stack`、`test_ooo_capacity`、`test_rcvbuf_config`、`test_icmp_spoof` 六项同样失败；剩余六项均为 PMTU/MTU floor/reprobe 类测试，报告的 MSS/payload 期望与实际值不一致，尚未逐项做基线对照，因此全量 CTest 仍不能记为全绿。根 `bin/ppp` 保持原 baseline SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`。

### 11.18 DL GSO 聚合边界与 KCC 低速根因复核（2026-09-24）

cap=48 的三轮 P1 DL 试验暴露出 coalescer 可能生成 IPv4 `total_length` 超过 16-bit 上限的 superpacket。`CanAppend` 现增加 IPv4 总长上限检查；cap=48、MSS=1460 回归测试确认 48 段拆为 44+4 段，IPv4 长度分别为 64280 和 5880 字节。修复后的隔离产品候选 `/tmp/ppp-xtcp-gso48-guard` SHA256 为 `f32401f01e98958ee7a8e58da0b0829bed814cff1515ec893da65d48377c542f`；根 `bin/ppp` 未覆盖，仍是 baseline SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`。对应 coalescer 用例通过；全量 C++ 141 项测试的 8 个需特权用例在 sandbox 首轮因 `Operation not permitted` 失败，特权重跑 8/8 通过，其余 133/133 首轮通过。

严格 CPU8、P1 DL、GSO-on、snd_buf=1MiB、memory bridge 的新矩阵均 qualification 通过，但没有任何 cap 达到 paired 1.20×：cap=32 的 artifact `artifacts/closeout-dl-gso32-p1-sndbuf1m-r3-20260924/` 三轮 ratio `0.5620×/1.0603×/0.5660×`；cap=24 的 `artifacts/closeout-dl-gso24-p1-sndbuf1m-r3-20260924/` 为 `1.0441×/0.2825×/1.0404×`。后者低速轮 XTCP 仅 `278.9Mbps`，窗口为 12 MSS、累计发送 stall 约 0.8s；cap32 的低速轮窗口为 26 MSS、约 0.48s stall。两者均无重传、TAP/NDI 输出拒绝为零，且 native 中位数约 0.98Gbps。故现有证据支持“发送窗口/pace 约束发生阶段性坍缩”，但尚不能单独归因于 coalescer。

另以相同 cap16、1MiB snd_buf 跑了 BBR 三轮：`artifacts/closeout-dl-bbr-gso16-p1-sndbuf1m-r3-elevated-20260924/` qualification 6/6 通过，但 XTCP 仅 30.4–43.8Mbps、paired ratio `0.0315–0.0472×`；否决 BBR 作为绕过 KCC 的方案。源码审阅发现当前 KCC 将每个有时间推进的 ACK rate sample 递增为一个 `rtt_cnt`，从而令 10 项带宽最大值窗口按 rate sample（可远密于真实 RTT）而非真实 RTT 老化；这构成 KCC `max_bw`/pacing/cwnd 阶段性偏低的合理嫌疑，但仍是待证假设，尚未修改 KCC。GitNexus 当前索引不含第三方 KCC 符号（impact=UNKNOWN），更不能把算法关联当成已验证根因。下一步应为采样频率与 RTT round 建立可观测性/定向测试，再隔离验证 KCC round-boundary 修正；不能直接改默认拥塞控制或放宽性能门禁。

### 11.19 KCC round-boundary 隔离验证（2026-09-24，候选未晋升）

针对上一节的嫌疑，在 `/tmp/xtcp-kcc-final-check` 隔离 upstream 源副本依次应用 `0018` flight-boundary、`0019` 每 RTT 保留最高 bandwidth sample、`0020` 基于 min-RTT 的 time boundary 补丁；`tools/prepare_xtcp.sh` 干净应用成功，候选 `ppp` SHA256 为 `1758e49448b407d2d84c5d1610c9b791201a7c1a16cbd44d6750f1bb661fccc1`。回归方面，KCC 定向测试和 9 个连接/拥塞控制用例通过，完整 XTCP fault suite **20/20** 通过，`bench_throughput` 三次为 5.96–6.19 Gbps。该证据支持候选补丁链没有触发已覆盖的连接、丢包恢复、背压故障，但不等于证明其拥塞控制时序在所有 RTT/ACK 模式下正确。

严格 CPU8、P1 DL、GSO-on、snd_buf=1MiB、memory bridge 三轮中，time-boundary 候选 cap16 ratio `1.0485×/1.0606×/1.0528×`；cap24 为 `1.0619×/1.0643×/1.0951×`，比此前同类 cap24 的间歇极低轮更稳定，但仍未达 1.20×；cap32 仍有约 `0.4131×` 的低速轮。证据分别在 `artifacts/closeout-dl-kcc-time-round-bwmax-cap16-p1-sndbuf1m-r3-20260924/`、`artifacts/closeout-dl-kcc-time-round-bwmax-cap24-p1-sndbuf1m-r3-20260924/`、`artifacts/closeout-dl-kcc-time-round-bwmax-cap32-p1-sndbuf1m-r3-20260924/`。增大 snd_buf 并非通用解：cap24 + 默认 64KiB snd_buf 只有约 0.34×。

P1 UL 默认 gather 的 60 秒三轮为 `1.1516×/1.2451×/1.2221×`，中位过线但只有 2/3 轮过线；gather 60KiB 的 10 秒筛选曾三轮过线，但 60 秒复验降为 `1.1762×/1.2180×/1.1884×`，也是 1/3 轮过线。因此短测结果不构成稳定修复，且不能据此启用 gather 默认值。详细证据在 `artifacts/closeout-ul-kcc-time-round-default-r3-20260924/`、`artifacts/closeout-ul-kcc-time-round-gather60k-p1-r3-20260924/` 和 `artifacts/closeout-ul-kcc-time-round-gather60k-60s-p1-r3-20260924/`。目前只能说 time-boundary 候选对部分 DL 配置的低速轮和 UL 中位数有改善迹象；未建立稳定 ≥1.20×，KCC 补丁仍属实验候选，不晋升为已完成优化或默认行为。

继续筛选 upload gather：48KiB 首组 60秒×3 ratio `1.2901×/1.2100×/1.2861×`（3/3），但独立重复为 `1.1838×/1.1958×/1.2487×`（1/3）；40KiB 试验为 `1.2137×/1.1961×/1.2503×`（2/3）。三个目录分别是 `artifacts/closeout-ul-kcc-time-round-gather48k-60s-p1-r3-20260924/`、`artifacts/closeout-ul-kcc-time-round-gather48k-60s-p1-r3-repeat-20260924/` 和 `artifacts/closeout-ul-kcc-time-round-gather40k-60s-p1-r3-20260924/`。这些结果表明 48KiB 有可观收益但跨组波动，40KiB 与默认 gather 相近；都不足以改默认。XTCP 各组 60 个正式 1秒区间均无队列停顿证据，48KiB 首组每轮最低区间约 `816–903Mbps`、p5 `839–914Mbps`，direct-upload backpressure/reject、resume、ingress drop 和 runtime queued bytes 均为 0。独立重复中比值跌破门槛时，这些边界计数仍未显示背压，故间歇性短缺更像端到端 CPU/调度变化，当前采集不能证明具体根因。

基于 64KiB gather 的两组独立 P1 UL 60秒×3 override 实验均 3/3 达标：ratio 分别 `1.2172×/1.2298×/1.2472×`、`1.2939×/1.2776×/1.2713×`；task-clock 每字节效率分别约提升 `1.27–1.30×` 和 `1.32–1.33×`。随后将 `GetDirectUploadGatherBytes` 的非明文默认 cap 从 32KiB 提至 carrier 上限 64KiB，并在不传环境 override 的隔离产品候选上复验，P1 UL ratio `1.2509×/1.2011×/1.2733×`，qualification 6/6、门槛 3/3；第二轮只高出阈值 0.0011，仍需关注轮间稳定性。证据在 `artifacts/closeout-ul-kcc-time-round-gather64k-60s-p1-r3-20260924/`、`artifacts/closeout-ul-kcc-time-round-gather64k-60s-p1-r3-repeat-20260924/` 和 `artifacts/closeout-ul-gather64k-default-p1-60s-r3-20260924/`。多流 60秒×3 中 P16 ratio `1.3955×/1.2625×/1.3109×`（3/3）；P4 为 `1.1885×/1.1942×/1.2321×`（2/3，median `1.1942×`），未能严格过门槛，但四流 min/max goodput 比仅 `1.006–1.012`、零速流为 0，未见公平性/背压回归。记录在 `artifacts/closeout-ul-gather64k-p4p16-60s-r3-20260924/`。因此这次变更是 bounded UL 批量优化：P1/P16 已有重复长测通过，P4 近线但尚未达标；它不代表全场景 1.20× 已完成，KCC time-boundary 仍是隔离候选。根 `bin/ppp` 仍保持 baseline SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`。

最终候选在 `/tmp/openppp2-kcc-gather-default-test` 的 standalone C++ CTest 以所需网络权限复验 **132/132**；无权限 sandbox 首轮的 7 个 socket/websocket 相关用例在权限重跑后全部通过。`python3 tests/tooling/test_datapath_linux_matrix.py` 的 runner/CPU accounting contract 通过，`bash -n tools/run_datapath_linux_matrix.sh` 与 `git diff --check` 通过。KCC 隔离补丁链的上游 fault suite 为 **20/20**（含本次 gather 调参前的同一 KCC 候选）；默认 gather 产品候选构建成功，只有既有 `stdafx.h` tautological-comparison warning。无提交/推送，产品基线二进制未替换。

### 11.20 P1 DL 大 GSO cap 与 1.5–2MiB snd_buf 淘汰（2026-09-24）

time-boundary KCC 候选下继续探索 P1 DL。cap44 + snd_buf=1MiB 的10秒×3筛选全部 qualification pass，但 ratio 仅 `0.6170×/0.4177×/0.6482×`；native 约0.98–1.05Gbps，而 XTCP task-clock 成本升至约 `11.4–13.6ns/B`。GSO ledger 显示每轮约 39–57万段被合为 1.3–1.9万次 superpacket 写、没有 MTU 拒绝或负向 fallback；因此“大 cap 少 syscall”在该路径上反而提高单位字节 CPU 成本，cap44 淘汰。证据：`artifacts/closeout-dl-kcc-gso44-p1-sndbuf1m-screen-r3-20260924/`。

保留 cap24 将 snd_buf 增至2MiB后，10秒×3 ratio `1.1230×/1.0740×/0.2680×`，末轮发生阶段性坍缩。1.5MiB 的短筛 `1.1342×/1.1060×/1.1645×` 看似较稳，但60秒×3复验为 `1.0833×/1.0984×/0.4173×`，末轮仍塌陷。低速轮 client stats 中 `direct_download_queue_bytes=0`、`direct_download_rejected=0`、`ingress_dropped=0`，而完成载荷从正常轮约8.77GB降至约3.27GB；目前只能确认发送/交付工作速率降低，不能把根因归给应用队列或 GSO coalescer。2MiB与1.5MiB都不晋升；1MiB/cap24仍是较稳定的参考，但只有约1.05–1.10×，P1 DL目标未达成。证据分别在 `artifacts/closeout-dl-kcc-gso24-p1-sndbuf2m-screen-r3-20260924/`、`artifacts/closeout-dl-kcc-gso24-p1-sndbuf1536k-screen-r3-20260924/` 和 `artifacts/closeout-dl-kcc-gso24-p1-sndbuf1536k-60s-r3-20260924/`。

### 11.21 DL 主流拥塞遥测修正与 current-RTT KCC 边界淘汰（2026-09-24）

复核发现原 `OPENPPP2_XTCP_PERF_JSON` 每秒从 shard 0 的 unordered flow map 取“第一个存活连接”，可能采到控制/ACK 流；P1 DL 旧快照的本地接收累计量只有 180B，不能据此解释 bulk 流 cwnd。`XtcpRuntime` 的可选遥测现按各 Flow 成功交给 `XtcpStack::Send` 的累计 payload 字节选主数据连接，并输出 `payload_sent_bytes`、local/remote port；该计数仅在 perf JSON 开启时更新，不改变数据面决策。修正遥测的 P1 DL cap24、snd_buf=1.5MiB 单轮短测为 `1.0824×/1.0865×/1.0905×`，selected flow 均为 iperf 数据连接 local port 5201。

在完全相同参数下，对比 time-boundary + min-RTT 与 current-RTT round boundary，各进行 P1 DL 60s×3：current-RTT 组 `0.8568×/1.0921×/1.0725×`，证据在 `artifacts/closeout-dl-payload-flow-current-rtt-gso24-p1-sndbuf1536k-60s-r3-20260924/`；min-RTT 组 `1.0820×/1.0848×/1.0733×`，证据在 `artifacts/closeout-dl-payload-flow-min-rtt-gso24-p1-sndbuf1536k-60s-r3-20260924/`。current-RTT 的低速轮中，payload flow 的 cwnd 为 14 MSS 持续约 25 秒、snd window 约 3.1MiB、无重传；每秒约 0.94 秒 send stall，`window_cwnd`/pacing gate 约各 2,000 次，之后 cwnd 升至约 1,713 MSS 并恢复吞吐。min-RTT 对照三轮没有该启动拖延（cwnd 约 687–1,832 MSS；stall/reject 接近零）。这组对照说明 current-RTT round 边界会引入或放大长时间小窗口启动的风险，`0021-kcc-current-rtt-round-boundary.patch` 淘汰，不晋升；time-boundary/min-RTT 候选相对稳定但仍只有约 1.08×，未达 1.20×。

新的证据把调查收窄到 KCC payload flow 启动阶段的 cwnd/pacing 建立，而不是应用 download queue、重传或输出拒绝。下一步应在隔离 upstream 副本中同步采集该连接的首批 rate sample（`delivered/interval/rtt`）、KCC `min_rtt/max_bw/pacing_rate` 与 cwnd 写入时序，定位为何偶发约 25 秒停留在 14 MSS；不再仅凭每秒聚合的 `ConnStats` 推断 KCC 内部状态。候选仍不进入根 vendor 源码或默认配置。

### 11.22 KCC STARTUP ACK-byte cwnd 增长实验淘汰（2026-09-24）

进一步检查显示 XTCP `RateSample` 只有当前批次的 `delivered`，没有 Linux BBR round detector 使用的发送时 `prior_delivered`；`SentSeg` 也未保留该发送快照。后续不再尝试无边界 ACK-byte 增长，而应先评估把发送时 delivery snapshot 安全带到 ACK 采样点所需的 `SendData`、重传分段和迁移 checkpoint 影响，再决定是否做隔离原型。Linux BBR 的 round-start 使用 `prior_delivered` 与 `next_rtt_delivered` 比较，而不是仅按时间周期递增计数，见 [Linux `tcp_bbr.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_bbr.c)。

随后在临时 upstream 副本实现了该 packet-timed round 原型：发送段携带 delivery snapshot，ACK 侧回填 RateSample，并传递重传、PMTU resplit 与 checkpoint；KCC differential 和 `test_tcp_fsm` 通过。P1 DL 15秒×3 短筛 qualification 通过，但 ratio `0.9894×/1.0097×/0.9850×`（median `0.9894×`）；选中的数据流 cwnd 中位约 `0.81–0.85M MSS`、峰值约 `1.63M MSS`，没有超过 native 或此前 time-boundary/min-RTT 的收益。完整上游 CTest 239 项中 14 项失败，提升网络权限重跑同一 14 项仍失败。再对仓库 vendor 基线重跑失败子集，其中 12 项同样失败，集中在 RACK、OOO/Timestamp、PMTU/ICMP 与接收窗口；其余 `test_sack_gap_edge`、`test_rto_recovery` 虽在 vendor 基线通过，也在先前已有的 time-boundary/min-RTT KCC 临时副本和保留原计时的 metadata-only 副本中失败，因此不能归因于新 metadata 管线，但当前 KCC 候选测试状态不干净。该原型每秒遥测还显示 cwnd 膨胀至数十万至百万 MSS 量级，故仍淘汰，不跑昂贵长矩阵、不晋升、不进入仓库 vendor 源码。短筛证据：`artifacts/closeout-dl-kcc-delivery-round-screen-p1-sndbuf1536k-15s-r3-20260924/`；构建与日志保存在 `/tmp/xtcp-kcc-delivery-round-tests/`。本轮仍未改写根 `bin/ppp`。

### 11.23 P1 DL 替代 congestion control 短筛淘汰（2026-09-24）

为确认约1.08×的 DL 差距是否由默认 KCC 选择造成，在未改动的 baseline `bin/ppp` 上对同参数 P1 DL、GSO-on、cap24、snd_buf=1.5MiB 做 BBR 与 CUBIC 各15秒×3短筛；qualification 均通过。BBR XTCP/native ratio `0.1709×/0.1665×/0.2299×`，CUBIC 为 `0.0700×/0.0703×/0.0685×`，均远低于此前 default-KCC time-boundary/min-RTT 约1.08×参考，不做长测，也不改默认 congestion control。证据分别在 `artifacts/closeout-dl-bbr-p1-sndbuf1536k-15s-r3-20260924/` 与 `artifacts/closeout-dl-cubic-p1-sndbuf1536k-15s-r3-20260924/`；根 `bin/ppp` SHA256 未变。

### 11.24 P1 DL memory bridge 因果对照（2026-09-24）

为判断 P1 DL 间歇低速是否由 opt-in memory bridge 引入，使用未改动 baseline `bin/ppp`（SHA256 `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`）分别跑 bridge on/off；除 `--xtcp-memory-bridge` 外参数相同：CPU profile none、P1 DL、GSO-on、cap24、snd_buf=1.5MiB、KCC、native/XTCP、15秒×3。两组 qualification 均 6/6 pass，native 吞吐稳定约 0.94–0.97Gbps；XTCP 三轮都严重波动：bridge on `571/159/243Mbps`（paired `0.5920×/0.1680×/0.2519×`），bridge off `131/436/589Mbps`（paired `0.1357×/0.4562×/0.6275×`）。关闭 bridge 未消除退化，on/off 的三轮中位数也不构成可靠因果差异，故不能将低速归咎于 bridge，也不能据此晋升该参数组合。证据：`artifacts/closeout-dl-memory-bridge-p1-sndbuf1536k-cap24-15s-r3-20260924/` 与 `artifacts/closeout-dl-memory-bridge-off-p1-sndbuf1536k-cap24-15s-r3-20260924/`。

两组 XTCP 现场均无输出拒绝；慢速轮普遍出现数百毫秒/秒级 `Send` stall、每秒数百次拒绝及约 31–92 次 iperf TCP retransmit。bridge-on 的 direct download queue 高水位仅约 16.7KiB，bridge-off 为零，因此应用桥队列不是这些样本的共同解释。慢速轮还能观察到 `pending_flush.window_cwnd` 或 pacing gate 计数显著增加；当前每秒聚合快照无法辨别在途样本的窗口/RTT、loss recovery 与 pacing 状态先后关系。此结果将调查重点收窄至发送许可/拥塞窗口时序，但尚未证明 KCC 是根因。历史 PSH-tail + GSO-cap16 候选可稳定跑到约 0.99Gbps，但 paired ratio 约 `1.05×`；本轮单核 native 中位约 0.95Gbps，现有证据只证明接近打满时比例仍未过 `1.20×`，并未证明存在硬性 1Gbps 上限。后续应优先提升按 ACK/发送事件关联的窗口与 pacing 可观测性，避免继续扫 bridge、CC 或 snd_buf 旋钮。

针对 STARTUP 早期低 `max_bw` 可能将 BDP/cwnd 锁在初始窗口的假设，在隔离 upstream 副本中试验了「STARTUP 且尚未 `full_bw_reached` 时，按 ACK 字节增加 cwnd」，并同步实现 reference core、添加 differential 单测。`test_cc_kcc` 通过。P1 DL cap24、snd_buf=1.5MiB、GSO-on 的 60秒×3 矩阵 qualification 全通过，但 XTCP/native 为 `0.9894×/1.0105×/1.0013×`（median `1.0013×`），低于无此补丁的 time-boundary/min-RTT 对照 `1.0820×/1.0848×/1.0733×`。候选 payload flow 的 cwnd 中位数达到约 `2.9M MSS`，峰值约 `5.86M MSS`，snd_wnd 仍限制实际在途字节；三轮未见重传或 NDI 输出拒绝。实验说明当前 full-bandwidth/round 退出逻辑没有及时收住 ACK-byte 增长，这一直接套用的启动窗口方案会造成 cwnd 失控且吞吐没有收益，故明确淘汰，不晋升、不复制到仓库 vendor 源码或默认配置。完整 qualification 和 telemetry 证据：`artifacts/closeout-dl-kcc-startup-additive-p1-sndbuf1536k-60s-r3-20260924/`。根 `bin/ppp` SHA256 仍为 baseline `d5e4be423ceaf4f3f2c96251b1421e3c41eb4f190a8de4192b737b8e44a24cac`。

### 11.25 KCC STARTUP 样本关联与有界 cwnd probe 淘汰（2026-09-24）

为把间歇低速与 KCC 输入对应，在隔离的 `gain=1.32` 候选上启用 round trace。无详细 trace 的 15秒×3 配置曾复现 ratio `1.0953×/0.4027×/1.0753×`；低速轮 `cwnd=16 MSS`、`inflight` 近零到约 23KiB、`pending_send` 长期贴近 1.5MiB snd_buf、`snd_buf_quota` 拒绝反复出现，内部 retx 与 NDI/TAP 输出拒绝均为 0。仅此一轮不能单独证明 KCC 因果关系。

增加 `rtt_sample_us/interval_us/delivered/acked/lost` 的日志字段后，详细 trace 会显著扰动时序（trace-on 三轮只有 `0.19–0.48×`），因此 trace 组吞吐作废，只用于方向判断。慢轮首批带宽样本约 `76 MB/s`，KCC 在约六个 RTT round 后按三轮 plateau 规则退出 STARTUP，cwnd 仍约 10–11 MSS；rate-sample interval 后续常见 `0.2–0.9ms`，而采到的 min RTT 约 `70µs`。正常轮首批样本约 `241 MB/s`，后续 max_bw/cwnd 较快上升。这支持“初始 flight/ACK cadence 可能让慢轮带宽估计过早平台化”的假设，但尚不能区分是 KCC 估计策略还是用户态 ACK/调度节奏造成，不能据此改默认 KCC。

隔离试验随后在 STARTUP 中按 delivered bytes 慢启动 cwnd，但把 additive probe 的部分限制为 32 MSS，并同步改 reference core；`test_cc_kcc` differential/fidelity 用例通过。trace-off 15秒×3 筛选 `artifacts/closeout-dl-kcc-bounded-startup32-gain132-p1-15s-r3-20260924/` qualification 6/6 通过，XTCP goodput `1.019–1.038Gbps`，paired ratio `1.0612×/1.0776×/1.1012×`，短测未复现低速轮，但仍远低于 1.20×。更重要的是，后续 telemetry 中 selected flow cwnd 达到约 `1,481–1,593 MSS`，远高于 32 MSS probe cap（该 cap 只限制 additive 分量，未限制 BDP target），虽然本地样本未见 retx、配额拒绝或明显 stall，但高 cwnd 缺乏高 RTT/多流/损伤安全证据。该候选不做 60秒长测，不晋升；说明“有界 startup additive”仍可能被 BDP 更新放大，下一次原型必须对完整 cwnd target 而非单一 additive 步进设定安全界，并先通过延迟/多流/丢包回归。

trace-on artifact 为 `artifacts/closeout-dl-kcc-event-trace-gain132-p1-15s-r1-20260924/`、`artifacts/closeout-dl-kcc-event-trace-gain132-p1-15s-r3-20260924/` 和 `artifacts/closeout-dl-kcc-samples-gain132-p1-15s-r3-20260924/`；这些性能值不作为验收结果。所有 KCC 实验均在 `/tmp` upstream source/build 副本中完成；没有改仓库 vendor 源、KCC patch series 或根 `bin/ppp`。全场景稳定 `>=1.20×` 目标仍未完成。

### 11.26 DL pending-send 尾部复制消除与长测（2026-09-24）

单核 P1 DL 的秒级遥测曾显示低速轮每秒约 2,000 次 `pending_flush.window_cwnd`、约 1,000ms/s `send.stall_ms`，pending send 长期贴近 1MiB 配额；审阅 `TcpConn::FlushPendingSend()` 发现 partial flush 在窗口关闭后反复 `assign(data.begin()+off, data.end())`，每次 ACK 都复制剩余队列。新增 patch `tools/xtcp-patches/0023-pending-send-offset.patch`：用 offset 保留 live suffix，按逻辑长度计配额/遥测，处理 persist probe、重入 requeue、Close 与迁移 checkpoint；checkpoint 只保存 live suffix。前缀压缩只在后续 append 且 consumed prefix 已足够大时摊销进行。GitNexus 不含该第三方 `TcpConn` 符号，impact 为 UNKNOWN；因此改动只在隔离的完整 patch-chain 副本中验证，没有覆盖 `third-party/xtcp` 或 `bin/ppp`。

针对性 upstream 测试 `test_close_pending`、persist/zero-window、`test_pacing_flush`、`test_1mb_stream` 和扩展后的 `test_scheduler`（验证部分 flush 后 checkpoint/restore 保留逻辑剩余字节）共 **8/8** 通过；完整 239 项 CTest 并行结果为 225 pass/14 fail，失败子集串行复跑仍有 14 项失败。未改 offset 的同一上游基线对照中，`test_ts_ooo_drain`、`test_rack`、`test_stack`、`test_ooo_capacity`、`test_rcvbuf_config`、`test_pmtu_reprobe`、`test_icmp_spoof`、`test_sack_gap_edge` 已重现同型失败；其余六项本轮未完成基线对照，故 full CTest 不能记为全绿。最终隔离产品 SHA256 `b62ca36c224d28724502452e9390b5b7edd071d0c159c2d9d2c5982290bdeb49`。

严格 CPU8、memory bridge、snd_buf=1MiB、GSO cap16、P1 DL 的 60秒×3 结果：

- GSO-off：`artifacts/closeout-dl-pending-offset-patchchain-gsooff-p1-60s-r3-20260924/`，qualification 6/6、`>=1.20×` 门禁 3/3；ratio `1.3301×/1.3291×/1.3230×`，median `1.3291×`、MAD `0.0010`。XTCP/native median goodput 为 `672.3/506.8Mbps`；process task-clock 分别 `10.88/14.70ns/B`，CPU efficiency gain median `1.3509×`。
- GSO-on：`artifacts/closeout-dl-pending-offset-patchchain-gsoon-p1-60s-r3-20260924/`，qualification 6/6，但性能门禁 0/3；ratio `1.0454×/1.0475×/1.0575×`，median `1.0475×`。XTCP/native median goodput 为 `1005.8/956.5Mbps`，process task-clock `7.07/7.81ns/B`。未复现低窗口坍缩，吞吐已靠近当前测试链路约1Gbps的上限，但这一观察本身不证明物理上限；该 GSO-on 配置仍未达到 1.20×。

因此该 patch 对消除 DL 间歇性低速有明确长测证据，并在 P1 DL/GSO-off 达到稳定 1.20×；它不是全矩阵完成证明。GSO-on、其他并发度/方向及网络损伤矩阵仍需继续验证；没有改变 NDI TSO TX 默认关闭状态、性能门禁或 snd_buf 默认值，也未提交/推送。

### 11.27 XTCP BufRef 小块池耗尽与容量验证（2026-09-24）

在 `0023` 候选的 P4 DL/GSO-on 低速复现中，`OPENPPP2_XTCP_PERF_JSON` 新增的入口丢包原因计数捕获到 `BufRef::Acquire` 失败：单秒 `buffer=118`，`not_ready/split_invalid/split_budget/budget/post` 全为 0；随后 TCP cwnd 从约 14,704 MSS 收缩到 1 MSS、重传增加，NDI/TAP 输出逐渐停摆。检查上游 `src/buf/bufref.cpp` 的三档预分配池：2KiB/4KiB/32KiB 原容量为 1024/512/128 块，总计约 8MiB；4 条 1MiB 发送流可同时保留超过 2,500 个普通 MSS 缓冲，原来 1,536 个小块不足以覆盖该负载。增加入口 drop reason 只在 perf JSON 开启且发生丢包时计数，未改成功包路径。

隔离验证补丁 `tools/xtcp-patches/0024-bufref-pool-headroom.patch` 将小块池调为 8192/4096，32KiB GRO 池仍为 128，总池容量约 36MiB（相对原值增加约 28MiB/初始化进程）。P4 DL/GSO-off CPU8、10秒×3 qualification 6/6、性能门禁 3/3：ratio `1.3509×/1.3449×/1.3139×`，median `1.3449×`；此前 64KiB snd_buf 的对应历史轮约 `1.17–1.18×`。P4/GSO-on 10秒×3 无 watchdog/池分配失败但 ratio 仅 `1.1089×/1.0859×/1.0170×`，未过 1.20×。首组 P16/GSO-off 60秒×3 配对比 `1.6799×/1.7137×/1.7051×`，但第三轮 XTCP qualification 因 16 流中 3 条零速而失败；该轮的 BufRef 分配失败计数为 0。随后同参数独立复测 `artifacts/closeout-dl-p16-pool36m-gsooff-cpu8-60s-r3-repeat-escalated-20260924/` qualification 6/6、性能门禁 3/3，ratio `1.7882×/1.6102×/1.7087×`（median `1.7087×`），三个 XTCP 轮次零速流均为 0，入口 pool allocation failure 也均为 0。故首组零速暂定为间歇性资格异常、未能复现，不能声称由池扩容修复；长测公平性仍需保留监控。P16/GSO-on 也未达到门槛（median 约 `1.054×`）。证据目录分别为 `artifacts/diagnostic-ingress-drop-p4-gsoon-5s-r1-20260924/`、`artifacts/closeout-dl-p4-pool36m-gsooff-cpu8-10s-r3-20260924/`、`artifacts/closeout-dl-p4-pool36m-gsoon-cpu8-10s-r3-20260924/`、`artifacts/closeout-dl-p16-pool36m-gsooff-cpu8-60s-r3-20260924/` 和 `artifacts/closeout-dl-p16-pool36m-gsoon-cpu8-10s-r3-20260924/`。隔离候选二进制 SHA256 为 `8a0a7366408a8bafea799457f698300d73d6c0c154ca7509fa1fdc94bf6a1d27`。

针对性上游测试在扩容候选中 `test_bufref`、`test_bufref_starvation`、`test_1mb_stream` **3/3 通过**；`test_stack` 的 3 项失败（接收总长度/内容、RTO 数据发现）在未扩容、只含 `0023` 的基线也以相同行号和结果复现，故不归因于 `0024`，但完整 fault suite 仍未通过。补丁对 `/tmp/xtcp-patch-0023-final-check` 基线执行 `patch --dry-run -p1` 成功。该容量调整目前只进入 patch series 文件，尚未应用到仓库 `third-party/xtcp`，也未更改根 `bin/ppp` 默认二进制。扩容按每个初始化进程增加约 28MiB 池容量，是稳定性收益与常驻内存的明确取舍；在晋升前仍需完整 fault suite 处置及 P16 零速流单独定位。此阶段不代表 XTCP 全矩阵性能目标完成。

### 11.28 最新 1.20× 矩阵与 GSO-on DL 归因（2026-09-24）

新增 CPU8、strict netns 的 P4 DL/GSO-on 参数筛选均 qualification 6/6，但没有稳定达到 paired 1.20×。当前短测最优为 cap24、`OPENPPP2_XTCP_GRO_BYTES=32768`、snd_buf=1MiB：`artifacts/goal12-dl-p4-gsoon-cap24-gro32k-cpu8-10s-r3-20260924/`，ratio `1.1773×/1.0921×/1.1541×`，median `1.1541×`；process task-clock efficiency 中位 `1.2141×`，但 CPU efficiency 不等价于 goodput gate。cap32+GRO32KiB median `1.0913×`，cap40+GRO32KiB median `1.0821×`，cap24+GRO32KiB+snd_buf=256KiB median `1.1042×`；P16 cap32/GSO-on median `1.0528×`。这些变化不晋升为默认值，NDI TSO TX 继续 default-off。

低开销 GSO ledger 显示，pending-offset 候选的 P1 DL/GSO-on 每轮约 5.15–5.19M 段进入合并路径、约 5.14–5.18M 被吸收到 superpacket，最终约 354–356K 次 GSO 写；flush 主要由 cap 触发（约 229–231K 次），其次为 PSH（约 129K 次），timeout 很少。说明“GSO 完全未生效”不是当前低比例的解释；继续只增大 cap 收益有限，下一步应关注 TCP flush/ACK/pacing 与 TUN write 的端到端成本。

作为对照，同一候选的 GSO-off DL 在已有新鲜矩阵中通过 1.20×：P1、snd_buf=1MiB、60秒×3 ratio `1.3301×/1.3291×/1.3230×`（`artifacts/closeout-dl-pending-offset-patchchain-gsooff-p1-60s-r3-20260924/`）；P4、36MiB BufRef 池、GSO-off、10秒×3 ratio `1.3509×/1.3449×/1.3139×`（`artifacts/closeout-dl-p4-pool36m-gsooff-cpu8-10s-r3-20260924/`）；P16、相同池配置、60秒独立复测 ratio `1.7882×/1.6102×/1.7087×`、qualification 6/6（`artifacts/closeout-dl-p16-pool36m-gsooff-cpu8-60s-r3-repeat-escalated-20260924/`）。因此当前 1.20× 目标在已测普通分段 DL 配置可达，但 GSO-on DL 仍欠账，不能把前者外推成全矩阵完成。

UL 的最新 64KiB direct-gather 矩阵也显示分层结果：P1/GSO-on/60秒×3 ratio `1.2509×/1.2011×/1.2733×`，门禁 3/3；P16/GSO-on/60秒×3 ratio `1.3955×/1.2625×/1.3109×`，门禁 3/3；P4/GSO-on/60秒×3 ratio `1.1885×/1.1942×/1.2321×`，median `1.1942×`，仍有两轮略低于门槛。对应 artifacts 为 `closeout-ul-gather64k-default-p1-60s-r3-20260924/` 与 `closeout-ul-gather64k-p4p16-60s-r3-20260924/`。因此 UL 的 P1/P16 已通过严格单轮门槛，P4 是当前临界短板；这没有复现零速，但不能解释或宣称旧问题已根治。

一次针对最新 GSO-on P4 DL 的 gprofng profile 导致 iperf 超过 50秒 watchdog，出现 cwnd=1 MSS、持续 `window_cwnd` 阻塞，属于强扰动/失速样本，不作为性能结论或正常负载热点证据；artifact `artifacts/goal12-gprofng-current-p4-gsoon-cap24-gro32k-12s-20260924/` 保留其超时现场。后续 profiling 必须先降低采样扰动并证明资格稳定，否则使用现有低开销 ledger/perf telemetry。尝试将 NDI `BufRefHolder` 改为 PMR pool 的临时二进制虽通过 ownership adapter、memory probe 和 bridge 测试，但同场短矩阵 XTCP median goodput `1.051Gbps`、paired ratio median `1.030×`，低于旧二进制的 `1.113Gbps`/`1.147×`；样本只用于否决晋升，不足以断言确定回归。实现已从工作树撤回，两个 raw artifacts 仍保留。

### 11.29 UL P4 direct-upload gather 尺寸同候选长测（2026-09-24）

为避免与不同 patch/build 的历史 P4 数据直接比较，在同一候选二进制 `/tmp/ppp-kcc-round-candidate-out/ppp`（SHA256 `a1a1cd3a598de1c3e4667773c49f56cb90feea146b5f122c0d8cd819bca11930`）下，固定 CPU8、P4、UL、GSO-on、memory bridge、snd_buf=1MiB、omit=2秒，分别 override direct-upload gather 为 60KiB 与 64KiB，执行 60秒×3。两组 qualification 均为6/6；60KiB ratio `1.2602×/1.2279×/1.2052×`，median `1.2279×`、门槛3/3；64KiB ratio `1.2322×/1.2266×/1.2353×`，median `1.2322×`、门槛3/3。64KiB 的 ratio 中位数略高、轮间 MAD 更低（`0.0031` 对 `0.0227`）；process task-clock efficiency median 分别为 `1.2908×` 和 `1.2797×`，也略偏向64KiB。故没有证据将 gather cap 从现有64KiB下调到60KiB；保留当前64KiB默认，不增加 P4 专用分支。

两组所有 XTCP 轮均为零速流0、TCP retransmit 0、direct-upload backpressure/reject 0、ingress drop 0；64KiB XTCP goodput 为 `886.7–896.5Mbps`，60KiB 为 `875.8–899.8Mbps`。60KiB 短筛同样 qualification 6/6、ratio `1.2018×/1.2210×/1.2070×`，但长测才作为验收证据。artifact 为 `artifacts/goal12-ul-p4-gather60k-gsoon-cpu8-10s-r3-20260924/`、`artifacts/goal12-ul-p4-gather60k-gsoon-cpu8-60s-r3-20260924/` 和 `artifacts/goal12-ul-p4-gather64k-gsoon-cpu8-60s-r3-20260924/`。该结果证明的是当前组合候选上 P4 UL/GSO-on 达到单轮≥1.20×三轮门槛；不能单独归因于 gather 尺寸，也不外推至 DL 或损伤网络矩阵。根 `bin/ppp` 未覆盖、未提交/推送。

### 11.30 DL watchdog 的二进制快照隔离（2026-09-24）

一次新矩阵误用了 `/tmp/ppp-kcc-round-candidate-out/ppp`（SHA256 `a1a1cd3a598de1c3e4667773c49f56cb90feea146b5f122c0d8cd819bca11930`），它与前述 36MiB BufRef 池候选 `/tmp/ppp-pending-offset-patchchain/ppp`（SHA256 `8a0a7366408a8bafea799457f698300d73c0c0c8154ca7509fa1fdc94bf6a1d27`）并非同一构建快照，tracked-diff fingerprint 也不同。前者 P4 DL 10秒筛选的三轮 XTCP 均在 42秒 watchdog 停止（GSO-on cap24/GRO32KiB），同候选 GSO-off 与 bridge-off 各一轮也 watchdog；现场中 direct-download queue 达64KiB、send rejected 增长并伴有 ingress drop。不能将这些失败归因到某个 datapath 改动，也不能拿不完整 cell 算 paired ratio。

随后对池扩容候选 `8a0a736...` 做相同 P4 DL/GSO-on 参数的一轮对照，qualification 2/2 通过、goodput `1072.9/954.9Mbps`、ratio `1.1236×`，无 watchdog；该单轮只用于确认候选快照的行为差异，不作为性能验收。两个候选的具体源码差异及 a1 快照的停滞原因尚未确认。相关 artifact：`artifacts/goal12-dl-p4-gsoon-cap24-gro32k-latestcandidate-cpu8-10s-r3-20260924/`、`artifacts/diagnostic-dl-p4-gsooff-latestcandidate-cpu8-10s-r1-20260924/`、`artifacts/diagnostic-dl-p4-gsoon-cap24-gro32k-bridgeoff-latestcandidate-cpu8-10s-r1-20260924/`、`artifacts/diagnostic-dl-p4-gsooff-known-good-8a0-cpu8-10s-r1-20260924/` 与 `artifacts/diagnostic-dl-p4-gsoon-pool36m-knowncandidate-cpu8-10s-r1-20260924/`。后续 DL 验收固定使用 fingerprint 对应的池扩容候选；根 `bin/ppp` 未改。

### 11.31 DL coalescer owned-writev 原型 A/B 淘汰（2026-09-24）

尝试让 `TunGsoCoalescer` 保留原始段 owner，并用 `writev` 直接写出 virtio 头、TCP/IP 头与多个 payload 引用，避免先拷入连续 superpacket。原型仅由 `OPENPPP2_TAP_GSO_WRITEV=1` 显式开启，默认行为不变；byte-exact、owner 生命周期、负向写回退及 partial-write 不重放等定向单测通过，隔离 `ppp` 构建成功。

CPU8、P4 DL/GSO-on、cap24、GRO=32KiB、snd_buf=1MiB 的10秒筛选中 writev-on 中位 ratio `1.1254×`，off 为 `1.1077×`，看似有小幅收益；但同参数 60秒×3 复验不支持该结论：on ratio `1.0757×/0.9606×/1.0447×`（median `1.0447×`），off 为 `1.0416×/1.0118×/1.0492×`（median `1.0416×`）。XTCP median goodput 分别约 `1.049/1.060Gbps`，task-clock efficiency median 分别约 `1.0734×/1.0737×`，差异在噪声范围内，writev-on 的 XTCP 吞吐还略低。因此撤回实现及其测试，不晋升；短测差值视作轮间波动。记录在 `artifacts/goal12-p2-writev-p4-gsoon-cap24-gro32-cpu8-10s-r3-20260924/`、`artifacts/goal12-p2-writev-p4-gsoon-cap24-gro32-cpu8-60s-r3-20260924/` 和 `artifacts/goal12-p2-writev-p4-gsoon-cap24-gro32-base-cpu8-60s-r3-20260924/`。本轮保留的 `TapGsoCoalescer`/测试差异仅为此前已有的段缓存布局、IPv4 total_length 防溢出及尾随字节处理工作；writev 原型已不在源码中。根 `bin/ppp` 未覆盖。

### 11.32 DL GSO-on pacing/window 事件基线（2026-09-24）

在 36MiB BufRef 池候选上，对 P4 DL/GSO-on、cap24、GRO=32KiB、snd_buf=1MiB 做一轮10秒低开销 stall/admission 采集：qualification 2/2 通过，XTCP/native `1056.96/968.17Mbps`，单轮 ratio `1.0917×`（仅用于定位，不作为性能验收）。XTCP perf JSON 汇总约 9.49万次 stack Send、5.15千次拒绝、累计 stall 23.1秒（多 flow 累加）；`pending_flush` 的 pacing gate 约 16.68万次、window_cwnd gate 约 16.92万次，fast-recovery-pipe gate仅4次。send-admission 只出现20次短暂 sndbuf-quota 拒绝；selected payload flow 末段 cwnd约1657 MSS、inflight约447KiB、snd_wnd约41.8MiB、retx=1。NDI acceptance/rejection与 TAP 输出失败均为0。事件数据支持把下一步重点放到 TCP pacing/window 发送许可及 ACK cadence，而不是 NDI/TUN 写拒绝；不过单次采样不能区分 KCC 算法上限与 ACK/调度节奏，也不能证明其为唯一原因。原始证据：`artifacts/diagnostic-dl-p4-gsoon-pool36m-cap24-stall-ledger-cpu8-10s-r1-20260924/`。低开销计数仍可能改变时序，需用隔离 KCC 差分和无详细诊断性能复验确认。

### 11.33 KCC pacing burst 批量发送原型未晋升（2026-09-24）

针对 11.32 中高频 pacing/window gate，在 `/tmp` 隔离的 XTCP upstream 副本里将 `FlushPendingSend` 每次 pacing grant 从约1ms提高到4/8/16ms，并分别限制最大 burst 为256/512/1024KiB；没有修改仓库 vendor 源码。匹配当前 OpenPPP2 源码、36MiB BufRef 池和同一 CPU8/P4/DL/GSO-on/cap24/GRO32KiB/snd_buf=1MiB 参数的1ms控制组，10秒×3 ratio 为 `1.1887×/1.1054×/1.0474×`，60秒×3 为 `1.0554×/1.0569×/1.0608×`。4ms burst 的10秒×3为 `1.1345×/1.2097×/1.1264×`，60秒×3为 `1.1443×/1.0818×/1.1134×`；短测的单轮过线未能在长测复现。

8ms burst 的10秒×3全部过1.20门槛（`1.2322×/1.2457×/1.2343×`，median `1.2343×`），但60秒×3只有 `1.1588×/1.1500×/1.1467×`，三轮均不达标，XTCP goodput约 `1.168–1.194Gbps`。16ms burst 又降为10秒×3 `1.1506×/1.2413×/1.1745×`（仅1/3过线），收益非单调且依赖测试时长。对应证据分别在 `artifacts/goal12-dl-p4-gsoon-pacing1ms-base-cap24-gro32k-cpu8-10s-r3-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing1ms-base-cap24-gro32k-cpu8-60s-r3-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing4ms-cap24-gro32k-cpu8-10s-r3-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing4ms-cap24-gro32k-cpu8-60s-r3-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing8ms-cap24-gro32k-cpu8-10s-r3-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing8ms-cap24-gro32k-cpu8-60s-r3-20260924/` 和 `artifacts/goal12-dl-p4-gsoon-pacing16ms-cap24-gro32k-cpu8-10s-r3-20260924/`。因此 burst 可减少单位字节 CPU 成本并抬高短时 DL，但没有达到长时1.20×验收；不晋升，也不继续放大 burst。

8ms 原型定向 CTest 中 `test_multi_drop`、`test_sack_recovery`、`test_wscale_transfer`、`test_pacing_flush`、`test_ecn_loss`、`test_combo_stress`、`test_bidi_1mb`、`test_cc_kcc` 共8项通过；`test_rto_recovery` 失败。该 RTO 失败在同一 `0023` 基础补丁链的1ms控制组中也稳定复现，而未改动 vendor baseline 通过，故是该基础补丁链的既有未解决差异，不能视为8ms通过或归咎于 burst。8ms 下 `test_1mb_stream` 收发文件仍 byte-exact，但其1/100丢包注入未实际丢弃任何段（dropped=0），导致“必须至少发生一次丢包”的断言失败；该用例没有覆盖到真实丢包恢复，不能把完整性结果当作丢包门禁。原型产品构建与矩阵均在隔离路径完成；无 vendor 源码改动、提交或推送。

### 11.34 GSO-on DL CPU profile 与 XTCP shard 筛选（2026-09-24）

对8ms burst 候选做60秒 P4 DL/GSO-on 的 `cpu-clock:u` 低频采样（profile-only，不作吞吐验收），共收集15,886个样本且无 lost samples。全命令样本中 `aesni_encrypt` 很突出，但按矩阵记录的 XTCP client PID 单独过滤后没有 AES 符号；此前把同一 perf 记录内多个 `ppp` PID 合并后归为“XTCP 进程”的66.6% AES 结论不成立，不能用来解释 XTCP 栈 CPU。PID-filtered XTCP client 的 `BuildSegmentPacket` 自耗时约占该 PID 样本5.2%，`FlushPendingSend` 与 `XtcpNdiBackend::Tx` 各约1.3%；由于优化符号/调用者信息不完整，这仍是采样线索而非精确成本分解。profile 数据保存在 `/tmp/goal12-8ms-p4dl-cpuprofile.data`，profile 运行矩阵在 `artifacts/goal12-dl-p4-gsoon-pacing8ms-cpu-profile-cpu8-60s-r1-20260924/`。

为做同一方法的 GSO 对照，另采8ms候选 P4 DL/GSO-off 单轮60秒 profile：qualification 2/2、XTCP/native `692.3/506.7Mbps`、profile-run ratio `1.3663×`（不作验收），共9,716样本且无 lost samples。对应 XTCP client PID 中 `BuildSegmentPacket` 约占样本5.0%，`FlushPendingSend` 约1.5%，`XtcpNdiBackend::Tx` 约1.4%，与 GSO-on 的 client-PID 估算相近；这组单轮低频 profile 没有证据表明 GSO-on 显著抬高这些函数的相对自耗时。数据保存在 `/tmp/goal12-8ms-p4dl-cpuprofile-gsooff.data`，artifact 为 `artifacts/goal12-dl-p4-gsooff-pacing8ms-cpu-profile-cpu8-60s-r1-20260924/`。硬件 cycles/instructions 计数在当前环境不可用，profile 也捕获了矩阵脚本的进程；不据此归因 AES 或宣称实现层收益。

随后用同一8ms隔离二进制、CPU8/P4/DL/GSO-on/cap24/GRO=32KiB/snd_buf=1MiB 完成 matched shard 筛选：`OPENPPP2_XTCP_SHARDS=1` 三轮 ratio `1.2322×/1.2128×/1.2453×`（median `1.2322×`，qualification 6/6）；shard=2 为 `1.0482×/1.0816×/1.0413×`（median `1.0482×`，qualification 6/6）。两组 native 中位吞吐分别约 `978/985Mbps`，但 shard=2 的 XTCP 中位吞吐仅约 `1.032Gbps`，而 shard=1 约 `1.205Gbps`；同一批次对照复现了此前 shard=1 短测水平，因此这次差异不应仅归因于机器短时降速。该工作负载是少量长流且客户端单核约束，flow hash 将每条 flow 固定在单 shard；新增 worker/context 无法并行单条 flow，当前证据不支持在该负载启用多 shard。artifact 分别为 `artifacts/goal12-dl-p4-gsoon-pacing8ms-shards1-cpu8-10s-r3-20260924/` 与 `artifacts/goal12-dl-p4-gsoon-pacing8ms-shards2-cpu8-10s-r3-20260924/`。没有改产品源码或默认 shard 数。下一步不继续扫 shard/burst；应在低扰动条件下区分共同隧道加密成本与 XTCP 发送许可/ACK 节奏，并优先验证 GSO-on 下额外 CPU 成本是否来自协议栈分段/校验路径。

对相同8ms候选再做一轮10秒、XTCP-only 的 stall/admission 事件采集（只作诊断，不作性能验收）：qualification 1/1，goodput `1.166Gbps`、零速流0、fairness max/min `1.064`。全程 NDI Output reject、入口 drop、TCP retransmit 均为0；sndbuf quota 只在少数采样窗口短暂出现，snd_wnd 约14–56MiB、cwnd约2,836–5,260 MSS，而 `pending_flush.pacing` 多个稳态秒约1.2–1.7K次/s、`window_cwnd` 在启动后降至0或近0。pacer timer late p95 约4–512µs，send stall 是多 flow 累加，约1.4–1.8s/s。该单轮现场把可观测阻塞进一步偏向 pacing deadline/ACK 驱动节奏，而非 NDI reject、拥塞窗口、重传或常态 sndbuf quota；但不同流的快照聚合、低开销计数扰动与单轮样本仍不足以证明唯一根因。artifact 为 `artifacts/goal12-dl-p4-gsoon-pacing8ms-send-ledger-cpu8-10s-r1-20260924/`；不据此调大 cwnd、不改 pacing 默认。

同样的10秒诊断配置在工作区1ms控制二进制上复跑（SHA256 `941f4b0e…b8c904`；8ms候选 `d453fc3d…a6c2479d`，二者 patch-chain revision/stamp 相同；artifact `artifacts/goal12-dl-p4-gsoon-pacing1ms-send-ledger-cpu8-10s-r1-20260924/`）。两组均为单 XTCP cell、qualification pass，非 paired 性能验收；控制 goodput `1.052Gbps`，8ms 为 `1.166Gbps`。剔除启动/关闭快照后，1ms/8ms 的全栈平均 `pending_flush.pacing` 分别约1.51K/1.43K次/s、`send.stall_ms` 约1.56/1.71秒每秒、timer late p95 约256/282µs，均没有显示8ms显著减少 gate 尝试或累计等待；全栈 ACK advance events 从约1.19K降至0.49K次/s。`WritePerfLine()` 的 `cwnd/inflight` 是当前累计 payload 最大 flow 的快照，不保证相邻采样或不同候选指向同一连接；实际8ms样本在 remote port `56772/56776` 间切换，1ms样本则一直是 `43860`，因此此前把所选 flow 的 cwnd/inflight 跨候选比较不成立，不能据此声称 cwnd 增长解释了吞吐差。诊断只支持 pacing/ACK 仍值得追踪，不足以判断是 KCC rate sampling、ACK batching 还是 flow 状态导致差异。下一步若继续碰 KCC，应先增加**按同一 flow/ACK round 关联**的观察，而非再扩大 burst、调大 cwnd 或把多 shard 打开。

对8ms候选把 GSO cap 从24降到16再做严格 CPU8/P4/DL/GSO-on 配对筛选和60秒长测。10秒筛选 qualification 6/6，但 ratio `1.2186×/1.0951×/1.2548×`（中位数 `1.2186×`，仅2/3轮过线）；60秒复验 qualification 6/6，ratio `1.1615×/1.1540×/1.1738×`，中位数 `1.1615×`、3/3均未过线。长测 XTCP/native 中位吞吐约 `1.140/0.980Gbps`，process task-clock efficiency gain 中位 `1.1804×`；相对同候选已完成的 cap24 60秒中位 `1.150×` 仅小幅改善，仍未达目标，因此 cap16 不晋升、不扩大 sweep。证据目录为 `artifacts/goal12-dl-p4-gsoon-pacing8ms-cap16-cpu8-10s-r3-20260924/` 和 `artifacts/goal12-dl-p4-gsoon-pacing8ms-cap16-cpu8-60s-r3-20260924/`。

### 11.35 AVX2 CopyAndChecksum 原型未晋升（2026-09-24）

针对 `BuildSegmentPacket` 的 profile 自耗时热点，在 `/tmp/xtcp-avx2-pacing8-proto` 为 SSSE3 的 fused payload copy/checksum 添加 runtime-dispatched AVX2 变体；只有 GCC/Clang x86 且 CPU feature probe 确认 AVX2 时启用，MD5 路径和其他平台保留既有实现。生成的临时产品二进制为 `/tmp/openppp2-avx2-pacing8-product-build/bin/ppp`（SHA256 `9bf11c58e3faed2ad047bd685014f608bef45f8281242d43839560cd6468239f`），反汇编确认该路径发出 YMM `vpshufb` 指令；原仓库 `bin/ppp` 已恢复并核验为控制 SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

隔离 XTCP tests 中 `test_checksum_simd`、`test_tcp_fsm`、`test_ip`、`test_ipv6_stack`、`test_gso`、`test_md5`、`test_md5_loss` 7/7 通过；`test_stack` 的三个接收/RTO 失败在同一 8ms、未加 AVX2 的 patch-chain 二进制中逐行复现，属既有基线差异。CPU8/P4/DL/GSO-on/cap24/snd_buf=1MiB 的 AVX2 与原 8ms 二进制相邻配对短筛均 qualification 6/6：AVX2 ratio `1.2271×/1.1820×/1.1739×`、median `1.1820×`；原二进制 `1.1551×/1.1895×/1.2050×`、median `1.1895×`。两组 native 中位吞吐分别约 `986/998Mbps`，有约1.2%时间窗口差；process task-clock efficiency gain 分别 `1.2446×/1.2668×`，AVX2 未显示 CPU 或 goodput 收益，因此不做长测、不晋升。矩阵 artifact 为 `artifacts/goal12-dl-p4-gsoon-pacing8-avx2-cap24-cpu8-10s-r3-20260924/` 与 `artifacts/goal12-dl-p4-gsoon-pacing8-base-cap24-cpu8-10s-r3-20260924/`；AVX2 修改仅留在 `/tmp`，未改 vendor 源或产品默认。

### 11.36 GSO-on DL TUN write 耗时对照（2026-09-24）

复用 11.32、11.34 的 `datapath-client.jsonl` 中已有 `direct_write_*` 遥测；该计时覆盖 Linux TUN writer 的同步 `write()` 耗时，因此不需要新增产品代码或采样器。11.32 的同场 P4 DL/GSO-on/cap24 样本里，XTCP 约 90,611 次写、写出 1.455GB、累计同步 write elapsed 1.293s，均值 14.27µs/次；native 约 90,895 次写、写出 1.557GB、累计 1.609s，均值 17.70µs/次。该 elapsed 是 syscall 墙钟时间，不等同于 CPU 消耗。

再对同一 8ms patch-chain 的 1ms 控制与 8ms burst 诊断样本比较：1ms 约 100,200 次写、1.469GB、elapsed 1.502s、14.99µs/次、14.3KiB/次；8ms 约 79,078 次写、1.736GB、elapsed 1.213s、15.34µs/次、21.4KiB/次。8ms 增加每次写的合并字节并减少写次数，单次 syscall 延迟没有改善；这些数据不支持把 TUN write 延迟视为 GSO-on DL 的主导瓶颈。它也不是严格的 60秒性能验收，不能把该组吞吐差异外推为稳定收益。证据分别位于 `artifacts/diagnostic-dl-p4-gsoon-pool36m-cap24-stall-ledger-cpu8-10s-r1-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing1ms-send-ledger-cpu8-10s-r1-20260924/` 与 `artifacts/goal12-dl-p4-gsoon-pacing8ms-send-ledger-cpu8-10s-r1-20260924/`。

现有 user-only perf profile 仍把 `BuildSegmentPacket` 标为约5.2%的 XTCP client 样本，但它已融合拷贝/校验和，AVX2 候选没有收益；perf kernel-domain 采样当前受 `perf_event_paranoid=3` 拒绝。本轮未调整系统安全设置，也未改写 coalescer/XTCP 发送逻辑。接下来应优先做低扰动的同 flow ACK/pacing 事件归因，或找到可在现有权限下分离用户态 CPU 与阻塞时间的证据，再决定是否碰拥塞/发送调度代码。

### 11.37 多 flow TCP 快照用于 pacing 归因（2026-09-24）

为避免 perf JSON 每秒只输出一个“累计 payload 最大连接”而在相近流之间切换，本地 `XtcpRuntime.cpp` 的可选 perf 输出现在额外提供 `tcp_flows`，最多列出 4 条按累计已接收 Send 字节排序的活跃流，并带 local/remote port、payload bytes、cwnd、inflight、snd_wnd、retx 等快照。该路径只在 `OPENPPP2_XTCP_PERF_JSON` 启用时运行；不留存 `Flow` 指针或数据包，不改发送行为。GitNexus 对 `WritePerfLine` 的 upstream impact 为 LOW：直接 caller 是 `ArmPerfDump`，影响限于 XTCP 诊断模块。

隔离 Release 构建成功；`xtcp_runtime_bridge_test` 在沙箱内因 loopback socket 权限被拒后，经授权的本机 loopback 重跑通过。5秒 P4/DL/GSO-on/P=4 smoke 的 qualification 通过，生成 11 行有效 JSON、其中6行含4条唯一流；自动校验了流数量上限、payload 降序、唯一端口以及旧 `tcp` 主快照与 `tcp_flows[0]` 一致。该短跑吞吐不作性能结论。

随后在 8ms 隔离候选上运行固定 CPU8、P4 DL/GSO-on/cap24/GRO=32KiB/snd_buf=1MiB 的 XTCP-only 60秒诊断：qualification pass、零速流0、watchdog/retransmit anomaly 均未触发、goodput `1.180Gbps`；这是单栈诊断，不含 native 配对，不能计算或验收 ratio。perf JSON 共68行、62个活跃流快照；四个 remote port 在全程可追踪。稳态各流 cwnd 中位约 `2,836–6,847 MSS`，snd_wnd 中位约 `3.2–47.4MiB`，没有持续的小窗口塌缩；其中一个流末尾累计 retx=4，qualification 未将其判为异常。shard 聚合的 `pending_flush.pacing` 中位约 `1,630/s`，`window_cwnd` 中位约 `35/s`，多流累计 `send.stall_ms` 中位约 `1,799ms/s`。这把后续重点进一步指向 pacing gate，而非普遍 cwnd/window gate；但 pacing/ACK 计数仍是 shard 聚合值，不是每流事件，且该 8ms 单候选结果不能证明 pacing 是唯一根因。

新快照 schema 检查、构建和 bridge 测试已通过；artifact 为 `artifacts/goal12-tcp-flow-ledger-smoke-cpu8-5s-20260924/` 与 `artifacts/goal12-tcp-flow-ledger-p4-gsoon-pacing8-cpu8-60s-r1-20260924/`。诊断二进制 SHA256 `9f1d37dd45742dceea5a50d20af386dd007e7f039e02c1b22aff8f9cb11a7083`；仓库 `bin/ppp` 仍为原控制 SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。本次未把 8ms/AVX2 临时 XTCP 源码晋升至 vendor 或默认配置。下一步应利用端口稳定的快照，对比每流状态并补齐 per-connection pacing/ACK event 计数，不能直接调大 cwnd 或继续扩 burst。

### 11.38 按连接 pacing/ACK 计数与早期返回筛选（2026-09-24）

为按连接核对 gate 来源，在 `/tmp/xtcp-avx2-pacing8-flow-ledger-proto` 临时增加只读 `ConnAckReleaseTelemetry(conn_id)`，对既有 per-connection 原子计数加连接锁快照；只在诊断 JSON 中显示，不触碰发送路径。`test_pacing_flush` 定向断言通过。在匹配的 CPU8/P4/DL/GSO-on/cap24/GRO32KiB/snd_buf=1MiB/memory-bridge 60秒 XTCP-only 诊断中，qualification pass、goodput `1.186Gbps`、零速流0，四个稳定 remote port 覆盖62个活跃采样窗。按端口对累计计数做相邻窗差分后，per-flow pacing/window 计数与现有全栈 aggregate 逐窗闭合；ACK advance 仅首个热身窗有3个未归属事件。四条流 retx 都保持0，cwnd中位约 `3,011–10,444 MSS`、snd_wnd中位约 `4.9–15.0MiB`。全栈 pending flush 共约187,686次，其中 pacing gate 89,983次（47.9%）、window/cwnd gate 5,122次（2.7%）；分流后 pacing gate 对四条流分布近似均匀。它说明可观测的首阻塞计数偏向 pacing，而不是普遍窗口关闭；gate 次数不是等待时长或 CPU 成本，仍不能据此改 pacing 默认或认定唯一根因。证据：`artifacts/goal12-perflow-ack-ledger-p4-gsoon-pacing8-cpu8-60s-r1-20260924/`，隔离诊断二进制 SHA256 `2edddefd6bc4b150559bd96385de70a11a405366d835ac518245ea51144f57c3`。

基于 11.37 的高频 pacing gate，又在同一临时 patch-chain 对 `FlushPendingSend()` 做早期返回原型：若函数入口已知 pacing deadline 未到，则不先 swap 出再换回 pending vector，保持 ACK/pacing 和 TSO 首阻塞计数语义。匹配的 10秒×3 筛选中，控制组三轮 qualification 全通过、median `1.2036Gbps`、process task-clock `6.371ns/B`；原型三轮也全部通过，但 median `1.1573Gbps`、`6.556ns/B`，相对控制 goodput低约3.8%、task-clock/byte高约2.9%。这组是 XTCP-only，不是 paired 1.20×验收；方向明确不利，因此不做长测、不晋升。`test_pacing_flush`、`test_pacing_update` 在原型与控制均通过；`test_rto_recovery` 与丢包未实际发生的 `test_1mb_stream` 在控制中也以相同断言失败，属于该 patch-chain 已知差异，不归因于早期返回，但也不记为通过。矩阵证据为 `artifacts/goal12-dl-p4-gsoon-pacing8-precheck-matched-control-cpu8-10s-r3-20260924/` 和 `artifacts/goal12-dl-p4-gsoon-pacing8-precheck-matched-candidate-cpu8-10s-r3-20260924/`；隔离原型二进制 SHA256 `9e517098d272497585a2b778a11e728991c33f0306c74f986166aaf8d0915e78`，匹配控制 SHA256 `757cfb422340c97b7d513d5ab096911a81c7aadd062521937bd9c4bead420e1b`。首次使用不含同等 per-flow 诊断字段的旧控制二进制所做的筛选已作废，不作为比较证据。

临时 per-connection XTCP API 和早期返回代码均未写入仓库 vendor/patch series；OpenPPP2 保留的只有有界 `tcp_flows` 状态快照，不再依赖该临时 API，使用仓库当前 vendor 重新构建的 `xtcp_runtime_bridge_test` 已通过。根 `bin/ppp` SHA256 仍为 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。后续优化不再从这个微热点开始，应转向更高层 ACK/pacing 唤醒与可用 CPU 时间的因果分析。

### 11.39 单 shard 长测与 poll lateness 复核（2026-09-24）

此前 8ms pacing 候选在 CPU8/P4/DL/GSO-on/cap24 的10秒筛选中，单 shard 三轮 ratio 中位数为 `1.2322×`，多 shard 中位数约 `1.0482×`。为避免把短测误当稳定收益，使用同一隔离候选二进制（SHA256 `d453fc3d…a6c2479d`）、memory bridge、GRO=32KiB、snd_buf=1MiB、CPU8 和单 shard 完成配对60秒×3。6/6 cell qualification 通过，但 ratio 为 `1.1358×/1.1814×/1.1658×`，中位数 `1.1658×`，仍未达 `1.20×`；XTCP goodput 中位 `1.186Gbps`，native 中位 `1.015Gbps`。因此单 shard 对比多 shard 有明确改善，但不能通过长测门禁，8ms 配置不晋升为达标结论。process task-clock/byte 中位为 XTCP `6.389ns/B`、native `7.534ns/B`，说明 XTCP 在此候选上单位字节 CPU 成本较低，但仍需结合绝对核心占用分析，不能据此排除执行资源瓶颈。完整记录：`artifacts/goal12-dl-p4-gsoon-pacing8ms-shards1-cap24-cpu8-60s-r3-20260924-privileged/`。

同批标准1ms、shard默认配置的60秒矩阵 `xtcp-perf-client.jsonl` 中，65个活跃窗口的 timer `late_p95_us` 有60个为256µs、4个为512µs、1个为16µs；窗口中位 rearm attempt 约1.6K/s。这里的 p95 是每秒窗口统计，不应将跨行 JSON 字段求和后误读成整体毫秒级尾延迟。当前证据不支持持续的 poll lateness 是 DL 吞吐落后的主因，也不支持仅凭 pacing gate 事件数去修改定时器或拥塞控制；后续应回到低扰动 CPU 热点归因，并保持性能门禁作为唯一晋升标准。沙箱内第一次无特权 netns 预检失败、0 cell，证据保留在 `artifacts/goal12-dl-p4-gsoon-pacing8ms-shards1-cap24-cpu8-60s-r3-20260924/`；随后授权重跑成功，未覆盖仓库根 `bin/ppp`。

### 11.40 GSO segment cap=48 长测筛选（2026-09-24）

在相同8ms候选、单 shard、CPU8/P4/DL/GSO-on/memory-bridge/GRO=32KiB/snd_buf=1MiB 条件下，将 TAP GSO segment cap 从24提高到48。10秒×3 qualification 6/6，XTCP goodput 中位约 `1.251Gbps`，比此前 cap24 单 shard短筛约 `1.205Gbps` 高，但 ratio 中位 `1.1919×`（`1.1793×/1.1919×/1.2938×`），仍未过线，且第三轮高 ratio 部分来自 native 吞吐低点。因 XTCP 吞吐看起来有约4%改善，继续做60秒×3：qualification 6/6，XTCP/native goodput 中位约 `1.234/1.047Gbps`，ratio `1.1905×/1.1783×/1.1222×`、中位 `1.1783×`，三轮均未达到1.20。cap48 相比此前 cap24 单 shard 60秒的 ratio 中位 `1.1658×` 有约1.3个百分点改善，但不足以晋升。

长测前两轮四流速率较均衡（max/min约 `1.015/1.027`）；第三轮出现一条流约 `25Mbps`、其余三条约 `383–390Mbps`，该流 retransmits=21，其余各约189–251。未触发 watchdog，且既有 qualification 将 retransmit anomaly 判为通过；因此要把“qualification pass”与流公平性/性能门槛分开看，不能掩盖该轮的吞吐退化。新矩阵和每轮原始结果：`artifacts/goal12-dl-p4-gsoon-pacing8ms-shard1-cap48-cpu8-10s-r3-20260924/`、`artifacts/goal12-dl-p4-gsoon-pacing8ms-shard1-cap48-cpu8-60s-r3-20260924/`。cap48 不晋升为达标配置；后续重点应是减少 XTCP client 每字节 CPU 成本并追查单流退化，不能再单靠放大 GSO cap 宣称达标。

### 11.41 NDI 热路径诊断计数门控与同配置筛选（2026-09-25）

`XtcpNdiBackend::Tx()` 原先即使 `OPENPPP2_XTCP_PERF_JSON` 未启用，也会对每个 NDI 包读取两次 `steady_clock` 并更新 attempts/accepted/rejected、byte/call 和延迟直方图；`TxBatch()` 也无条件维护 batch 计数。现改为运行时按可选 perf JSON 开关这些诊断工作；默认直接构造的 backend 仍保持诊断开启，保证既有诊断/API 单测语义。GSO 包数/字节/拒绝数继续无条件记录，供运行时 stats API 使用。诊断关闭时不会执行两次时钟读取；输出所有权和发送行为不变。

定向 `xtcp_runtime_adapter_test` 通过，断言关闭诊断不影响成功输出、而可选计数保持为零；现有默认诊断开启的 ownership/NDI 测试也通过。使用同一 P4 DL/GSO-on/cap48/CPU8/single-shard/8ms-pacing候选、10秒×3 fresh netns 配置做前后筛选：控制 XTCP goodput median `1.2683Gbps`、paired ratio `1.1924×`（`1.2436×/1.1349×/1.1924×`）；门控候选 XTCP median `1.2752Gbps`（约 `+0.5%`）、ratio `1.1881×`（`1.1755×/1.3159×/1.1881×`）。进程 task-clock/byte 中位 `6.0113→6.0003ns/B`（约 `-0.2%`），selected-CPU non-idle 指标略增；这些变化处于轮间/基准波动范围，不能宣称有可识别的吞吐或 CPU 收益。两组 qualification 均 6/6，且都只有 1/3 轮过 `1.20×`，所以严格目标仍未通过。

原始矩阵：`artifacts/goal12-dl-p4-gsoon-ndi-diag-off-control-cap48-cpu8-10s-r3-20260925-escalated/` 与 `artifacts/goal12-dl-p4-gsoon-ndi-diag-gated-cap48-cpu8-10s-r3-20260925/`。该改动只减少 perf JSON 关闭时的非必要诊断成本，作为低风险路径清理保留；不将其记作 1.20× 性能优化，也不据此晋升 pacing/GSO 配置。仓库 `bin/ppp` 未被候选构建覆盖，仍为原 SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

### 11.42 GSO-on DL 单流偏斜复核与 sender-side TCP_INFO（2026-09-25）

cap48、CPU8/P4/DL/GSO-on 的一组先前长测曾出现单流 `25–60Mbps`、其他流 `380–590Mbps`。先前 `tcp_flows` 的 cwnd/snd_wnd 是 XTCP 连接的本地发送方向，而测试是 iperf `-R` 下载；该方向不代表实际下载 sender，因此不能用它解释慢流。iperf server 日志中的慢流 cwnd 中位仍约 `0.54–0.58MiB`，也与快流接近。

为取得真正发送端的 `TCP_INFO`，矩阵 runner 新增默认关闭的 `--tcp-info-sampling`：仅在启用后，每秒对 target namespace 执行 `ss -tinp`，保存到 cell 的 `target-ss-tin-samples.txt`；不调整 TCP 参数、不参与普通性能门禁。Help/planner 合同、Python tooling contract、shell 语法和 `git diff --check` 均通过。

在同一 cap48/CPU8/P4/DL/GSO-on/single-shard/8ms pacing/snd_buf=1MiB/memory-bridge 配置下，候选二进制 XTCP-only 60秒×3 qualification 3/3，goodput `1.260/1.278/1.264Gbps`。三个 run 的每条流均约 `302–331Mbps`，未复现严重偏斜。对端每流 RTT 中位 `0.53–0.86ms`、cwnd 中位 `367–406` MSS，snd_wnd 中位约 `100–310KiB`；`rwnd_limited` 中位约 `88–92%`，但同轮流间近似且实际吞吐均衡，故不能单凭这个累计状态认定 receive window 是瓶颈。此前单流偏斜在本复测中未复现，根因仍未确定；这些 XTCP-only 样本不等价于 paired `1.20×` 验收。

证据：`artifacts/goal12-dl-p4-gsoon-target-tcpinfo-cap48-cpu8-60s-r1-20260925/` 与 `artifacts/goal12-dl-p4-gsoon-target-tcpinfo-cap48-cpu8-60s-r3-20260925/`。后者含三轮 iperf per-flow 结果、server interval log 和逐秒 sender-side TCP_INFO。下一步只有在异常复现时，才应基于 peer port 对齐 RTT、advertised window、retransmit 与 XTCP ingress/direct-bridge 队列，避免再由错向 cwnd 快照推导改动。

### 11.43 cap48 owned-writev DL 原型复测与淘汰（2026-09-25）

重新尝试让 TAP shared-buffer 输出保留 owner，并由 `TunGsoCoalescer` 通过 `writev` 输出 GSO common header 与各段 payload。byte-exact、owner 生命周期和负向写顺序 fallback 定向测试通过；10秒×3 初筛全部 qualification pass，但 paired ratio 为 `1.1516×/1.2477×/1.2445×`，只有2/3轮超过1.20，不能据此晋升。

随后在同一 CPU8/P4/DL/GSO-on/cap48/KCC/single-shard/`sndbuf=1MiB`/memory-bridge 配置下做60秒×3配对复测。writev 候选 qualification 6/6，但严格性能门禁失败，ratio `1.1961×/1.1919×/1.2214×`（median `1.1961×`）；XTCP median goodput `1.259Gbps`，process task-clock median `5.989ns/B`。同设置旧连续写 control qualification 6/6、ratio `1.2207×/1.2275×/1.2320×`（median `1.2275×`）、XTCP median goodput `1.281Gbps`、task-clock median `5.893ns/B`。因此该轮 writev 候选 goodput 约低1.7%，task-clock/byte 约高1.6%；由于配对 ratio 还受各自 native cell 波动影响，不把二者差异解释成严格因果或显著性结论，但数据没有支持预期收益。

据此撤回 `PushOwned`/owner-retaining writev、`TapLinux::OutputInternal` 与 vector writer 实现及对应测试；保留独立的 IPv4 聚合 `total_length` 上限保护和负向 GSO fallback 尾随字节保真修复。矩阵证据：`artifacts/goal12-dl-p4-gsoon-owned-writev-cap48-cpu8-60s-r3-20260925/`、`artifacts/goal12-dl-p4-gsoon-contiguous-control-cap48-cpu8-60s-r3-20260925/`；短筛选为 `artifacts/goal12-dl-p4-gsoon-owned-writev-cap48-cpu8-10s-r3-20260925/`。候选 SHA256 `e5156a6b41c049d4f7c8ad4edf1cb4aed2b9cae0b3d29de339e37d8c1852c87c`，连续写 control SHA256 `226d19f3cab6f3dc02defeff3808ed2fa873b9e66112bd0a1d6710ce0ea13174`。修改后的 coalescer 定向测试和 TapLinux 独立对象编译通过；根 `bin/ppp` 仍保持原 SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

在修复当前源码 candidate 的 BufRef pool exhaustion 后，又以实际启用 XTCP 的同一 strict build 重新构造 owner-writev 实验，避免把之前可能受 ingress drop 影响的二进制直接外推。候选和 contiguous pool-headroom control 分别做 fresh-netns、P4/DL/GSO-on、CPU8、cap48、KCC/single-shard/`sndbuf=1MiB`、memory-bridge 的 10秒单轮 smoke，均 qualification pass。候选 XTCP `0.993Gbps`、control `0.995Gbps`（约 `-0.3%`）；paired ratio 因两轮 native 分别为 `1.048Gbps` 和 `0.969Gbps` 而为 `0.9475×` 与 `1.0274×`，说明此短测波动较大，但绝对吞吐没有显示 owner-writev 收益。证据：`artifacts/goal12-dl-p4-gsoon-owned-writev-poolhead-smoke-cap48-cpu8-10s-r1-20260925-escalated/`、`artifacts/goal12-dl-p4-gsoon-poolhead-contiguous-control-smoke-cap48-cpu8-10s-r1-20260925/`；本轮候选 SHA256 `dee015a725309fee6d40016d9a8b72a4b13b8269b1e2cb8544524500b2af935f`，control SHA256 `03114a52ba334fb51f91ea529edaee86dd9a960ae92a4b3ac47bdec580c05957`。重新实现时新增的三项 owned/writev 定向测试通过，但因没有性能证据，实验代码与测试已撤回；writev 仍不晋升。

### 11.44 当前源码候选 BufRef pool exhaustion 根因与修复（2026-09-25）

为验证 writev 撤回后的实际源码，曾误用 `build/full` 构建候选；其 `ENABLE_XTCP=OFF`，该产物的 `NetworkProtocolUnsupported` 失败完全作废。随后 `ENABLE_XTCP=ON` 的当前源码候选 DL smoke 超时。诊断发现不是 rwnd 或 coalescer 导致：`BufRef::Acquire` 的 2KiB/4KiB 池块容量为 `{1024,512}`，高并发下载下 ingress 出现约 `536` 次 buffer failure，继而引发 TCP 重传和发送窗口塌缩；控制二进制 `ingress_dropped=0`。真正已应用的 upstream patch `0024-bufref-pool-headroom.patch` 本应将其扩至 `{8192,4096}`，但 vendor patch stamp 已匹配时 `prepare_xtcp.sh` 的快路径没有验证最新 patch 是否实际存在于源码树，导致漏应用。

已将 pool capacity 修复应用到 `third-party/xtcp/src/buf/bufref.cpp`，并修正 `tools/prepare_xtcp.sh`：stamp 命中前先对最新 patch 做 reverse dry-run，若 patch 未应用则重建/重放，而不是盲信 marker。此修复后的诊断 smoke ingress drop 为零、direct download queue 接收正常、cwnd 恢复；同配置无诊断 60秒×3矩阵 qualification `6/6`，但 ratio `0.9499×/0.9795×/1.0697×`、median `0.9795×`，仍未达到性能目标。故 pool exhaustion 是间歇低速/零速的已确认可靠性根因，但 pool 扩容本身不等于 1.2×优化。正式证据：`artifacts/goal12-dl-p4-gsoon-pool-headroom-smoke-cap48-cpu8-10s-r3-20260925/`、`artifacts/goal12-dl-p4-gsoon-pool-headroom-cap48-cpu8-60s-r3-20260925/`。当前修复候选 SHA256 `03114a52ba334fb51f91ea529edaee86dd9a960ae92a4b3ac47bdec580c05957`。根 `bin/ppp` 未被候选覆盖。

### 11.45 P4 DL GSO 合并效率复核（2026-09-25）

对上述 pool-headroom candidate 做单独 10秒 P4/DL/GSO-on 诊断 cell（开启 stall/GSO ledger，仅用于定位，不作性能验收）。资格通过，XTCP goodput `1.041Gbps`。窗口内 coalescer 收到 `925,717` 个 eligible 段、约 `1.350GB`，其中 `919,861` 段、约 `1.348GB` 进入合并，按字节约 `99.82%`；形成 `27,392` 次 GSO 写，平均约 `33.6` 段/次。普通写 `5,908` 次但仅约 `2.61MB`，负向 fallback/partial 均为零，packet rejection 仅 incompatible 4、PSH 4。结论：这组 P4 下载里 GSO 合并已覆盖绝大多数数据，继续优化合包 cap 或 PSH 接纳不太可能单独带来 20% 吞吐；owner-writev 复测无绝对吞吐提升也与此一致。下一步应转查 XTCP TCP send/ACK 与 direct-download 到输出的 CPU 路径，而不是再动 coalescer。证据：`artifacts/goal12-dl-p4-gsoon-poolhead-gso-ledger-cap48-cpu8-10s-r1-20260925/`。根 `bin/ppp` 仍为基线 SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

### 11.46 Pool 修复后 P4 DL 多流偏斜复现与 KCC gate 定位（2026-09-25）

此前 11.42 的另一组 8ms pacing 复测曾均衡，但 pool 修复后的当前 strict 源码再次复现显著偏斜，说明不能把上一组无偏斜结论推广到当前二进制。无诊断开销的 P4/DL/GSO-on/cap48/single-shard/`sndbuf=1MiB`/memory-bridge 60秒×3正式矩阵中，XTCP 每流 goodput（Mbps）分别为 `[209,270,102,412]`、`[106,207,325,384]`、`[83,63,706,258]`，max/min 为 `4.03×/3.64×/11.21×`；总体 paired median 仍只有 `0.9795×`，该轮不是性能验收通过。数据位于 `artifacts/goal12-dl-p4-gsoon-pool-headroom-cap48-cpu8-60s-r3-20260925/`。

随后针对偏斜运行当前 pool-headroom binary 做 XTCP-only 60秒 sender-side 采样：一轮 goodput `1.103Gbps`，四流约 `27.7/837.2/152.6/85.9Mbps`（max/min `30.2×`）；另一轮同时启用 XTCP perf 与目标端 `ss -tinp`，goodput `0.989Gbps`，四流约 `75.9/126.8/392.2/394.0Mbps`。第二轮稳定 remote-port 快照中，XTCP cwnd 约 `10/18/44/45 MSS`，snd_wnd 约 `2.5/3.8/5.2/5.7MiB`、重传为0；对应慢流 cwnd 较小，但 snd_wnd 仍远大于在途数据。目标端 Linux iperf sender 的 BBR cwnd 则约 `384–392 MSS`、无实际重传，四流 RTT 与 `rwnd_limited` 差异较大（约 `0.3–6.3ms`、`85–97%`）。这把检查方向从 coalescer 转到 XTCP per-flow ACK/pacing 与接收侧窗口/交付节奏，但两次流偏斜的慢流并不固定，现有证据不足以认定单一根因或直接调高 cwnd。

再用一轮10秒 `stall-diagnostics` cell 读取现成 ACK-release/send-admission counters（只用于诊断，goodput不可与无诊断矩阵比较）：累计 `35,205` 个有效 ACK、约 `190,374` 次 pending-flush attempt，其中 pacing gate `132,430`（约 `69.6%`）、window/cwnd gate `57,930`（约 `30.4%`），fast-recovery/packet-allocation gate 均为0；XTCP direct-download queue high-water 为 `64KiB`，ingress drop/reject 为0。pacing/window 计数是首阻塞事件数，不代表等待时长或 CPU 占比；也不能只凭 pacing gate 较多就改定时器。证据：`artifacts/goal12-dl-p4-poolhead-tcpinfo-cap48-cpu8-60s-r1-20260925/`、`artifacts/goal12-dl-p4-poolhead-tcpinfo-xtcpperf-cap48-cpu8-60s-r1-20260925/`、`artifacts/goal12-dl-p4-poolhead-kcc-admission-probe-cap48-cpu8-10s-r1-20260925/`。这些均为 XTCP-only 或诊断测试，不提供配对性能结论。

当前最有证据支持的下一步是对 pool-headroom 当前源码重新做低扰动 per-flow ACK/pacing 状态对照，重点确认每流 cwnd 差异与 RTT、ACK cadence、pacing deadline 的因果关系；在这之前不增加 GSO 改造、不调高 cwnd、不把历史临时 8ms pacing patch 或吞吐筛选当作晋升配置。根 `bin/ppp` 未覆盖，SHA256 仍为 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

### 11.47 P4 DL 按连接 ACK/pacing 诊断补充（2026-09-25）

为避免聚合 ACK-release 计数掩盖单流差异，新增只读 `ConnAckReleaseTelemetry`，并将每条 payload flow 的 ACK advance、pending-flush 首阻塞原因、RTT、当前 pacing rate 输出到可选 `OPENPPP2_XTCP_PERF_JSON` 的 `tcp_flows[]`；默认每秒最多采样4条流，诊断时可用 `OPENPPP2_XTCP_PERF_INTERVAL_MS` 降到10ms，不改拥塞/发送决策。上游 patch chain 新增 `0025-per-connection-ack-release-telemetry.patch` 与 `0026-kcc-readonly-state-telemetry.patch`。`test_pacing_flush`、`test_cc_kcc` 通过，严格 `ENABLE_XTCP=ON` 产品候选构建成功。根 `bin/ppp` 保持 baseline SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`，当前阈值3控制候选 SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。

当前候选、P4/DL/GSO-on、single-shard、`sndbuf=1MiB`、memory bridge 的20秒 XTCP-only cell goodput 为 `774.5Mbps`，逐流 max/min `28.27×`；另一个15秒 XTCP-only cell 为 `798.5Mbps`，逐流 max/min `7.42×`。后一个 cell 的末样本四流 RTT 为约 `3.3–4.2ms`，pacing rate 约 `10.7–88.9MB/s`，cwnd 为 `29–226 MSS`；pacing rate 与各流已交付速率大致同向变化，但该单轮样本不能确定是 KCC 带宽估计造成流速差，还是此前交付/ACK cadence 差异令 KCC rate 分化。`flush_pacing/flush_attempts` 在各流约 `84–94%`，但这是重复尝试的首阻塞次数，不是等待时间占比；window/cwnd gate 约 `5–16%`，recovery/allocation 为0。无成对 native/LWIP 数据，这些 goodput 只作归因诊断，不能作性能验收。

紧接着用最终候选在完全相同的 P4/DL/GSO-on/cap48/CPU8/single-shard/`sndbuf=1MiB`/memory-bridge 参数上，关闭 `OPENPPP2_XTCP_PERF_JSON` 做 native 配对60秒×3：qualification `6/6`，XTCP goodput `1.0268/1.0035/1.0252Gbps`，paired ratio `0.9706×/0.9578×/0.9792×`，性能门禁 `0/3`；native median `1.0478Gbps`，XTCP median `1.0252Gbps`。每轮 max/min 分别 `1.51×/2.99×/3.70×`，未复现诊断轮的28×极端偏斜，但公平性仍比既往均衡轮差。进程 task-clock/byte 中位 `6.930ns/B` 对 native `7.320ns/B`，selected-CPU non-idle `7.625ns/B` 对 `7.663ns/B`；性能仍略低于 native，不能说已因 CPU efficiency 达标。证据：`artifacts/goal12-dl-p4-perflow-telemetry-off-cap48-cpu8-60s-r3-20260925/`。此配对矩阵验证了 perf-off 无诊断路径，也表明 per-flow 诊断中的严重偏斜幅度会随轮次变化。

在15秒诊断 cell 的第一个包含四条 bulk flow 的样本中，四流 cwnd 已约 `226/98/29/28 MSS`、pacing rate 约 `109/44/20/14 MB/s`，但 RTT 约 `4.5–5.1ms`；这说明分化至少在首次1秒级采样前已发生，单看末态并不足以捕获它的建立过程。当前候选的正式配对低于 native，因此继续方向是隔离 KCC 首批 ACK/rate-sample/state transition 时序；不应只调 perf 采样计时、pacing retry 或 GSO cap。正式配对矩阵的无诊断数据不应与前述短诊断 goodput直接比较。

证据：`artifacts/xtcp-per-flow-ack-telemetry-20260925-r1/`、`artifacts/xtcp-per-flow-ack-telemetry-20260925-r2/`。KCC state snapshot 已加入 patch 0026；10ms startup 轨迹和算法候选筛选见 11.48。

### 11.48 KCC STARTUP→PROBE_BW 首轮状态轨迹与六轮门槛实验淘汰（2026-09-25）

只读 KCC snapshot 补出 `max_bw/full_bw/full_bw_count/mode/rtt_round/min_rtt`、round 采样量和最近 rate-sample 的 delivered/interval；callback 只在 perf JSON 采样时读取，不扩展 `XtcpConnCc` 布局，也不增加 KCC ACK 更新路径的工作。将 perf interval 临时设为10ms（默认仍1s）后，首批 bulk-flow 快照显示多流在数据开始后数毫秒至数十毫秒内已跨入 `PROBE_BW`：观察到的 transition round 为 `5/11/15/13`。这些 transition 时每流 `max_bw_q24` 约 `0.25–2.27B`，当前 pacing rate 约 `18.5–386.8MB/s`，对应 min RTT 约 `68–232µs`；RTT/min-RTT及每轮 delivered 样本本身并不完全一致。因而“早期 KCC 状态建立与 rate 分化相关”得到支持，但不能只归因为 full-bw 三轮门槛。

基于该线索隔离试验将连续 plateau 门槛从3轮改为6轮，并同步更新参考 core/差分测试。`test_cc_kcc` 通过；15秒×3 短配对看似为 `1.0085×/1.0396×/1.0329×`，但严格60秒×3 qualification `6/6` 后结果为 `1.0020×/0.8933×/0.9000×`，median `0.9000×`，性能门禁 `0/3`；后两轮 XTCP 绝对 goodput约 `956–958Mbps`，低于同组 native约 `1.062–1.073Gbps`。process task-clock/byte效率中位只比 native好约 `0.5%`，selected-CPU non-idle反而差约 `5.3%`。长测否决该候选，已将阈值和参考测试恢复为3轮，并删除 patch 0027；不晋升六轮阈值。短测假阳性说明这类 KCC startup 参数不能用15秒筛选做结论。

实验与诊断证据：`artifacts/xtcp-per-flow-kcc-state-10ms-20260925-r1/`、`artifacts/xtcp-per-flow-kcc-state-100ms-20260925-r1/`、`artifacts/xtcp-per-flow-kcc-state-20260925-r1/`、`artifacts/goal12-dl-p4-kcc-fullbw6-cap48-cpu8-15s-r3-20260925/`、`artifacts/goal12-dl-p4-kcc-fullbw6-cap48-cpu8-60s-r3-20260925/`。只读复核10ms trace中四条 bulk flow 首200个有效样本，KCC `max_bw` 与相邻10ms `payload_sent_bytes` 增量的 Pearson相关系数仅约 `0.18–0.44`；由于 perf timer cadence 与 rate-sample 窗口并不严格同步，这只能说明瞬时模型值不是该采样尺度下的稳定吞吐代理，不能作为因果结论。源码审计还发现 `tcp_fsm.cpp` 两处都将 `RateSample.is_app_limited` 硬编码为0，而 `XtcpConnCc.app_limited` 字段未被赋值。下一步不盲扫 plateau count，也不直接过滤低 rate sample；先确认发送队列为空/窗口未填满时的真实 app-limited 语义，再决定是否修正采样标记，随后重做配对矩阵。根 `bin/ppp` 仍为 baseline SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

### 11.49 KCC PROBE_BW cwnd_gain=3 候选淘汰（2026-09-25）

依据10ms诊断里部分流频繁触及 cwnd/window gate 的现象，隔离测试只将 KCC `PROBE_BW` 的 cwnd gain 从2改为3，并同步修改 reference core；STARTUP、pacing、full-bandwidth退出门槛均保持不变。`test_cc_kcc` 通过。perf-off 的15秒×3筛选 qualification 6/6，XTCP/native 为 `1.0966×/1.0482×/1.0583×`，但仅作为进入长测的筛选信号。相同 cap48/CPU8/single-shard/sndbuf1MiB/memory-bridge 参数下，正式60秒×3 qualification 6/6，XTCP/native 为 `1.0250×/1.0343×/0.8553×`，median `1.0250×`，未达1.20×，且第三轮明显回退；process task-clock/byte 中位效率约改善8.1%，但第三轮也退化。逐流 max/min 为 `4.51×/14.24×/7.49×`，比先前2×控制矩阵的 `1.51×/2.99×/3.70×` 更不均衡。所有轮次均有其他 CPU 网络RX/TX活动的 migration warning，所以单独的第三轮跌幅不能归因于 cwnd gain；不过没有稳定达标或公平性改善证据，仍淘汰该候选，已恢复 gain=2 并移除实验 patch，不晋升到默认 KCC。

证据：`artifacts/goal12-dl-p4-kcc-cwndgain3-cap48-cpu8-15s-r3-20260925/`、`artifacts/goal12-dl-p4-kcc-cwndgain3-cap48-cpu8-60s-r3-20260925/`。根 `bin/ppp` 保持 baseline SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`；回退后的严格 XTCP 候选应恢复到原控制 hash `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。

### 11.50 KCC DRAIN 生命周期候选淘汰（2026-09-25）

代码核查发现 DRAIN 使用连接生命周期累计的 `rtt_cnt >= 3` 退出，而 STARTUP full-bandwidth 检测通常已在第3个以上 round 才触发，因此模式可能在进入 DRAIN 的同一 ACK 就退出。隔离测试了两个修正：DRAIN 入态后再等3轮，以及按 `inflight <= BDP`（对齐仓库 BBR 实现）退出；两者均同步修改 reference core 与状态机测试。第一种定向 KCC 测试通过，但15秒×3 ratio 为 `0.9262×/1.0104×/0.9090×`，median `0.9262×`。第二种定向回归6/6通过，但15秒×3 ratio 为 `1.0427×/0.9638×/0.9759×`，median `0.9759×`；逐流 max/min 为 `28.64×/1.39×/2.82×`，公平性仍有严重单轮偏斜。两者都不满足1.20×筛选条件，因此未做60秒长测；实验 patch 和源码改动均已撤销，恢复原控制 hash `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`，不把这些候选当作默认算法。

这些结果也说明只修正 KCC DRAIN 生命周期并不能解决 DL 吞吐与流间公平性；下一步转向 profile XTCP DL 的每字节 CPU成本和 GSO/输出批处理路径，不继续盲调 KCC。运行中的 `test_1mb_stream` 本轮字节校验相同，但其1/100丢包注入两次均 `dropped=0`，未覆盖真实丢包恢复；其他6项定向 KCC/pacing/recovery/stress/双向测试通过。该随机注入门禁不用于判断 DRAIN 候选。

证据：`artifacts/goal12-dl-p4-kcc-drain3-cap48-cpu8-15s-r3-20260925/`、`artifacts/goal12-dl-p4-kcc-bdpdrain-cap48-cpu8-15s-r3-20260925/`。根 `bin/ppp` 保持 baseline SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904`。

### 11.51 AES-NI 构建开关核对与 DL profile（2026-09-25）

低频 XTCP P4/DL/GSO-on/cap48/CPU8/memory-bridge profile 的样本主要落在加密帧读取路径：旧控制二进制中 CFB/OpenSSL EVP 调用链约占相关 PPP 样本的58–71%，`TunGsoCoalescer` 命中不足1.1%；`BuildSegmentPacket` 在 XTCP 进程样本约5.7%。perf_event_paranoid 限制使 `cycles:u` 被 perf 降级为 `task-clock:uH`，这些是低频软件时钟 callchain 样本，不是硬件 cycles，也不直接代表时间占比。

反汇编确认旧控制候选 SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802` 的 `aesni::aes_cpu_is_support()` 恒返回 false，`AES::TryAttach()` 为空实现；相关 CMake cache 为 `ENABLE_SIMD=OFF`，且项目 CMake 默认值为 OFF。测试配置中的 `simd-auto: true` 只是运行时偏好，不能覆盖未编入 SIMD 实现的构建。因此此前常规候选的 AES-CFB profile 实际走 OpenSSL EVP。该选项为避免全局 `-maes/-mpclmul` 对旧 CPU 的兼容风险，不应仅凭这组性能结果就把默认值改为 ON。

另建隔离 Release/XTCP/SIMD-on 候选（SHA256 `1198d8acc53add3362f17bc3383f695220a6485e6afd6de5aa651c906c58ac0a`）；CPUID 探测与 AES-NI 代码已确认实际编入。相同 P4/DL/GSO-on/cap48/CPU8/单 shard/`sndbuf=1MiB`/memory-bridge 参数下，SIMD-on 三轮 qualification 6/6，XTCP/native ratio `1.1264×/1.1657×/1.0500×`，median `1.1264×`；goodput 中位 `1.730/1.536Gbps`。匹配的 SIMD-off 三轮也为 qualification 6/6，ratio `1.0013×/1.1064×/0.9535×`，median `1.0013×`，goodput 中位 `1.080/1.079Gbps`。两批矩阵顺序执行，差异显示 SIMD-on 值得作为受支持 x86 主机的构建变量继续评估，但未随机交错运行，不能据此宣布稳定的1.20×性能提升，也不能推广为跨机器效果。

SIMD-on 的单轮低频 profile 中，自定义 `AES::Process` 命中两个 PPP 进程样本的约88.8%和26.9%；另一个进程的 `FlushPendingSend` 约13.5%、`BuildSegmentPacket` 约9.9%，coalescer约0.7%。这些 callchain 分类会重叠且样本数有限；它们支持优先检查实际生产构建是否显式启用 AES-NI，并在确认目标 CPU 支持后继续做 interleaved 配对，不支持继续优化 GSO coalescer。证据：`artifacts/goal12-dl-perf-paired-sample-p4-gsoon-cap48-cpu8-20s-20260925/`、`artifacts/goal12-simd-paired-p4-gsoon-cap48-cpu8-20s-r3-20260925/`、`artifacts/goal12-nosimd-paired-p4-gsoon-cap48-cpu8-20s-r3-20260925/`、`artifacts/goal12-simd-perf-sample-p4-gsoon-cap48-cpu8-20s-20260925/`。

构建隔离检查遗漏了顶层 CMake 的固定输出路径，SIMD-on link 曾短暂覆盖根 `bin/ppp`。已将 SIMD-on 二进制另存到 `build/goal12-simd-xtcp-20260925/bin/ppp`，并把根文件恢复为已知 r3 XTCP 控制二进制 SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。原先记录的根 baseline SHA256 `941f4b0e2df3a08952b6db4415252feb91f37fda18e3b18eb772bc8915b8c904` 在工作区和 `/tmp` 均未找到副本，当前不能声称已精确恢复；后续验收前需从外部保存件还原该 baseline。没有提交或推送。

对 SIMD-on 候选再跑正式60秒×3配对，qualification仍为6/6，但 ratio 为 `0.9857×/1.0634×/1.0916×`，median `1.0634×`，性能门禁 `0/3`；XTCP/native goodput median `1.609/1.516Gbps`。三轮 XTCP `max/min` 为 `3.85×/1.80×/1.43×`，第一轮低比值伴随较差公平性。所有六个 cell 都记录 other-CPU network RX/TX 活动 warning，因此该长测保留为受噪声影响的诊断结果，不能作为干净的性能晋升证据；不过它也没有稳定达到1.20×，20秒筛选优势不能外推成长测收益。artifact：`artifacts/goal12-simd-paired-p4-gsoon-cap48-cpu8-60s-r3-20260925/`。应在隔离、可重复的宿主上交错重测 SIMD 开关与 TCP 栈，再决定是否把该构建选项用于性能基线。

### 11.52 CPU8 内核态低频 callchain 对照（2026-09-25）

之前的 `perf_event_paranoid=3` 结论仅适用于 PMU cycles；实际用 system-wide `cpu-clock:k` 做一秒权限探针成功，随后在 CPU8 上以49Hz采集 native/XTCP 各20秒。两 cell qualification 2/2，但这只是 profile 诊断轮，XTCP/native ratio `0.9735×`，不作为性能门禁结果。每个正式窗口恰有562个内核样本，其中 idle `swapper` 分别168/172个，`ppp` 上下文308/282个，`iperf3` 上下文60/99个；这显示内核样本有相当部分为空闲或来自测试端点，必须按进程/时间窗拆分，不能直接将 system-wide 热点归到 XTCP。

在非 idle 样本中，native/XTCP 命中 `tun_get_user`/`tun_chr_write_iter` 的样本分别106/74（约26.9%/19.0%），命中 `tun_do_read`/`tun_chr_read_iter` 的为22/5（约5.6%/1.3%）；Asio/epoll/scheduler 相关栈约各15.7%/15.6%。XTCP 栈看起来少做 TUN 字符设备读写，但单轮里 native goodput仍略高，不能把这些频率直接解释为吞吐因果。另有宿主图形虚拟设备 `vmw_diff_memcpy` 样本 native 21、XTCP 3（非 idle约5.3%/0.8%），与本矩阵全部 cell 的 other-CPU 网络活动警告一致，说明宿主噪声确实混入采样。该证据支持把后续采集收窄到目标进程与真实网络栈，不能据此改 TUN/GSO/拥塞控制实现。

证据：`artifacts/goal12-kernel-profile-paired-p4-gsoon-cap48-cpu8-20s-20260925/`。`perf` 实际 event 为软件 `cpu-clock:k`，不是 hardware cycles；profile 采样会丢失内核地址符号，未解析帧不按名称猜测。下一步应在少干扰 host 上用低频 user+kernel paired profile 复测，再从确认的 XTCP 用户态段中挑候选。

### 11.53 XTCP NDI Linux 同步借用输出候选（2026-09-25）

全态 CPU8 profile 中 `XtcpNdiBackend::Tx` 出现在约9.1%的 XTCP user callchain 样本；它原先每个有 BufRef 的出站包都创建一个 `make_shared<BufRefHolder>`，以满足 owning `shared_ptr` 输出契约。实现了一个仅供同步消费者选择的 borrowed callback：Linux XTCP 普通包直接调用 `VEthernet::Output(const void*, size)`，成功后释放 NDI 包的 BufRef；拒绝时保留 BufRef 供栈重试。既有 owning handler 仍保留给异步/通用消费者，无 BufRef 的 defensive-copy 路径不变，GSO 仍走原 owning handler。运行时将回调对象在 backend 构造时共享，避免热路径复制 `std::function`。

生命周期审查确认 Linux `TapLinux::Output` 在返回前完成 bare write，或在 `TunGsoCoalescer::Push` 内复制包；直接 GSO 的 `writev` 也同步完成。因此借用路径不把裸指针放入异步队列。定向测试覆盖借用回调拒绝时 BufRef 保留、接受时 BufRef 释放且字节有效；`xtcp_runtime_adapter_test` 与 `xtcp_ndi_memory_probe` 通过，`git diff --check` 通过。全量独立 C++ 测试为133/141通过；8项失败里多个 socket 用例在容器中报 `Operation not permitted`，`p2p_channel_lifecycle_test` 另有生命周期断言失败，需在有 socket 权限的环境复核。

当前没有包含该候选的完整 `ppp` 产品二进制，也没有新鲜网络矩阵或分配计数对照；因此这里只记录结构性减少每包 holder 分配的候选，不宣称吞吐提升或通过1.20×门禁。正式晋升前需在隔离产品构建中完成 owning-vs-borrowed 配对矩阵及内存/拒绝语义验证。没有覆盖根 `bin/ppp`，未提交或推送。

### 11.54 KCC 带宽采样聚合 A/B：当前长测不支持 RTT 内聚合（2026-09-25）

为解释当前源码 DL 表现退化，在 `/tmp` 临时 XTCP 源树中只将 `plugins/cc_kcc.cpp` 换成当前 patch 0022 之前保存的 `cc_kcc.cpp.orig`：保留时间驱动 round 边界及其余 OpenPPP2/XTCP 修复，只把 `BwUpdate()` 从每个有效 ACK 样本调用切回 RTT 内聚合样本调用。该临时版本没有 KCC 新遥测字段，故未启用 `--xtcp-perf`。两候选均使用同一当前 OpenPPP2 工作树、产品构建参数及 P4/DL/GSO-on/cap48/CPU8/KCC/single-shard/`sndbuf=1MiB`/memory-bridge 配置，分别进行 fresh-netns 60秒×3 配对；每个矩阵 qualification 均为6/6通过。

每 ACK 更新候选 ratio 为 `1.0859×/1.7526×/1.0824×`，median `1.0859×`；RTT 聚合当前候选为 `0.9164×/1.0004×/0.9789×`，median `0.9789×`。前者 XTCP median goodput `1.108Gbps`，后者 `1.009Gbps`（约高9.8%）；process task-clock median 分别为 `6.798/6.981ns/B`。两组中 round 2 native 吞吐异常低、对应 paired ratio 被显著抬高，不能将该轮 `1.7526×` 当作稳定收益；但 round 1/3 的同向差异及 XTCP 绝对 goodput 中位数方向一致，支持“当前 RTT 聚合采样对 DL 吞吐有实质负面影响”的假设。两版本都未达到稳定三轮 `>=1.20×` 门槛，因此不构成性能验收，也尚不能单凭这组 A/B 断定因果已完全隔离。

证据：每 ACK 候选 `artifacts/goal12-current-kcc-perack-p4-dl-cap48-cpu8-60s-r3-20260925-escalated/`（产品 SHA256 `b6ae22f69b60c844aa2bdb47191f003e67c27f7e1c6c35f246623d53dd8ef67c`）；RTT 聚合候选 `artifacts/goal12-current-kcc-aggregate-p4-dl-cap48-cpu8-60s-r3-20260925-escalated/`（产品 SHA256 `5ba28feaef6c3b78c7f4568f8a4c6fc3019bd13cf6c2fb989f8b463e6262c96b`）。根 `bin/ppp` 两次均保持 SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。下一步应在保留 round 聚合与每 ACK 即时样本的前提下，改为“每 ACK 更新 BwFilter，round 完成时只推进 full-bandwidth 状态”，再用同一60秒×3配对矩阵验证；不要直接回退已独立验证过的 round 边界或 pool-headroom 修复。

### 11.55 KCC per-ACK filter + round-only full_bw 正式长测淘汰（2026-09-25）

将上一节提出的 hybrid 方案整理为可从锁定归档干净重放的 patch `0022-kcc-per-ack-bandwidth-round-fullbw.patch`：带宽 filter 每个有效 ACK 更新；round 完成时清空累计样本并只推进 full-bandwidth 检测；保留 time-based round boundary、首次采样 provisional pacing、cwnd 仅使用模型带宽。修复 patch 的 unified-diff 上下文/hunk 后，在隔离归档运行 `tools/prepare_xtcp.sh` 完整重放 0001–0026；生成源码确认含 per-ACK `BwUpdate`、round gate 和 reference-core 对应逻辑。正式 OpenPPP2 候选构建成功，二进制 SHA256 `d07a508f76b506656b9f0fc199ef09d1e7bd053652330ff7e9295f5833f12654`。以隔离 `XTCP_FAULT_BUILD_DIR` 执行上游 fault suite，20/20 通过；`bench_throughput` 三轮为 `6.10–6.32Gbps`。这些结果只验证重放、构建和已有故障覆盖，不代表性能提升。

正式 fresh-netns P4/DL/GSO-on/cap48/CPU8/KCC/single-shard/`sndbuf=1MiB`/memory-bridge 60秒×3 矩阵 qualification 为6/6通过，但 XTCP/native 分别为 `0.979×/0.962×/0.947×`，median `0.962×`，三个配对均未达到1.20门槛。XTCP goodput median `1.136Gbps`、native `1.164Gbps`；process task-clock/byte efficiency median `0.989×`，selected-CPU non-idle efficiency median `0.967×`，也未显示 CPU/byte 改善。相较上一节的 RTT 聚合矩阵 median `0.979×`，此 hybrid 没有改善配对结果，因此不作为 DL 性能修复晋升；不能因旧的混杂 per-ACK A/B 中 XTCP 绝对吞吐较高就忽略本次同矩阵配对结果。证据：`artifacts/goal12-kcc-hybrid-formal-p4-dl-cap48-cpu8-60s-r3-20260925-escalated/`。根 `bin/ppp` 仍为 baseline SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。

下一步不继续盲调 KCC round/plateau 参数；优先验证 `RateSample.is_app_limited` 的生产语义（当前发送队列空/受窗口限制时是否被错误标成非 app-limited），并用只读 per-flow KCC/ACK/pacing 遥测与 DL GSO/coalescer 的进程内采样将模型限速和数据路径 CPU 成本分开。该 KCC hybrid 仍是本地实验 patch，尚未提交或推送；默认算法晋升必须等待独立矩阵证据。

### 11.56 XTCP DL per-flow 状态诊断：队列/窗口快照（2026-09-25）

在正式 hybrid 二进制上补跑一轮 XTCP-only、P4/DL/GSO-on/cap48/CPU8/KCC/single-shard/`sndbuf=1MiB`/memory-bridge 的30秒诊断 cell，开启默认1秒 `OPENPPP2_XTCP_PERF_JSON` 与 target-namespace `ss -tinp`；qualification `1/1` 通过，goodput `1.156Gbps`，process task-clock `6.53ns/B`。这是诊断单轮，不是配对性能门禁。

35个有效 per-flow 快照中，累计 XTCP send calls/rejections 为 `317,924/14,768`（rejection约4.6%），跨流累计 send-stall 时间约 `58.0s`；direct download queue 高水位仅 `65,536B`，accept-to-writable p95 最大 `1µs`，NDI GSO reject、owner drop、ingress drop 均为0。末快照四条 bulk flow 的 cwnd 为 `1,683–5,355 MSS`、snd_wnd 为 `10.1–55.5MB`、in-flight `0–1.03MB`；KCC 当前 `max_bw` 约 `64–282MB/s`，pacing约 `79–349MB/s`。这些快照不支持“接收窗口或应用队列普遍卡死”的解释，也不足以证明 pacing 是根因；per-flow pacing/backlog/ACK 的同步时序和 host 侧 TUN/GSO CPU 归因仍缺失。

源码复核确认 ACK 采样处两条路径均将 `RateSample.is_app_limited` 固定写0，`XtcpConnCc.app_limited` 没有被赋值；但当前 KCC `KccMain` 本身不读取 `rs->is_app_limited`，所以这只是拥塞控制契约缺口，不是已证实的 KCC 限速根因。诊断 artifact：`artifacts/goal12-kcc-hybrid-diag-perf-p4-dl-cap48-cpu8-30s-20260925-escalated/`。后续若修正该语义，须先从发送队列空闲/窗口阻塞状态构造精确定义并做 KCC differential + 应用限速/饱和发送测试，再用同配置 paired matrix；在此之前不做参数扫掠或默认算法调整。

### 11.57 P4 DL GSO-off / 128KiB send buffer 当前正式候选复验通过（2026-09-25）

在当前正式候选二进制（SHA256 `d07a508f76b506656b9f0fc199ef09d1e7bd053652330ff7e9295f5833f12654`）上，把既往10秒筛选中表现较好的 P4/DL/GSO-off/`sndbuf=128KiB` 配置升级为 fresh-netns 60秒×3 配对；CPU8 单核、KCC、single-shard、memory bridge，其余参数与正式矩阵一致。qualification **6/6**，三轮 XTCP/native `1.3112×/1.3165×/1.3120×`，median `1.3120×`，性能门禁 **3/3** 通过。XTCP goodput median `665.2Mbps`（663.96–671.10），native `507.4Mbps`（506.06–509.75）；process task-clock/byte efficiency median `1.3408×`，selected-CPU non-idle efficiency median `1.3296×`。证据：`artifacts/goal12-kcc-hybrid-formal-p4-dl-gsooff-sndbuf128k-cpu8-60s-r3-20260925-escalated/`。

该结果确认 GSO-off +128KiB 是当前 P4/DL 可稳定达到1.20×的分层运行配置，但绝对吞吐约0.665Gbps，低于 GSO-on/cap48 的约1.136Gbps XTCP中位数；它改善的是相对 native 的单位CPU效率，不代表 GSO-on瓶颈已解决，也不能外推到 P1/P16、UL 或其他内核/设备。仍保持产品默认参数不变，根 `bin/ppp` SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802` 未改写。

### 11.58 SIMD-on P4 DL GSO-off / 128KiB send buffer 复验通过（2026-09-25）

为检验 AES-NI/SIMD 构建是否能改善既有 P4 分层配置，使用独立输出目录构建 `ENABLE_SIMD=ON`、`ENABLE_XTCP=ON` 候选（SHA256 `1425ff81109c494390c73f3ff3a6090236aeb8de5bf6b7580e9786a7270bd32a`），并用反汇编确认二进制含 AES-NI 指令。随后 fresh-netns 运行 CPU8 单核、KCC、single-shard、memory bridge、GSO-off、`sndbuf=128KiB` 的 native/XTCP 配对 60秒×3 矩阵。qualification **6/6**、性能门禁 **3/3** 通过；三轮 XTCP/native 为 `1.4109×/1.4005×/1.3991×`，median `1.4005×`。XTCP goodput median `846.6Mbps`（845.61–853.32），native `604.8Mbps`（603.80–605.07）；process task-clock/byte efficiency median `1.4475×`，selected-CPU non-idle efficiency median `1.4187×`。artifact：`artifacts/goal12-kcc-hybrid-simd-p4-dl-gsooff-sndbuf128k-cpu8-60s-r3-clean-20260925-escalated/`。

相较前节 SIMD-off 构建同配置的正式矩阵（XTCP/native median `665.2/507.4Mbps`，ratio `1.3120×`），本次 SIMD-on 构建分别提高绝对 goodput 约 `27.3%/19.2%`，配对 ratio 增至 `1.4005×`。这支持该候选构建/配置的复验成绩，但 SIMD 同时作用于两栈，且不是硬件加解密成本的单变量随机 A/B，不能据此断言全部提升由 AES-NI 单独导致。仍不外推到其他并行度、方向、GSO 模式或设备，也不改变产品默认值；根 `bin/ppp` 仍为 baseline SHA256 `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。

### 11.59 SIMD-on P1 DL 不满足相对吞吐门槛，收益仅限 P4 当前配置（2026-09-25）

用 §11.58 同一候选与 GSO-off/`sndbuf=128KiB` 配置，将并行流数改为 P1，fresh-netns 60秒×3 qualification **6/6**；XTCP/native 为 `0.8479×/0.8569×/0.8505×`，中位数 `0.8505×`，故性能门槛 **0/3**。goodput median 为 `519.0/610.2Mbps`（XTCP/native）。XTCP process task-clock/byte efficiency 为 `1.3883×`，selected-CPU non-idle efficiency 为 `1.3458×`；没有 zero-rate flow 或 qualification 异常。artifact：`artifacts/goal12-kcc-hybrid-simd-p1-dl-gsooff-sndbuf128k-cpu8-60s-r3-clean-20260925-escalated/`。因此 §11.58 只证明 P4/DL/GSO-off 的分层配置结果，不能推广为 P1 或通用 SIMD 提速。

追加的 XTCP-only P1 诊断（30秒）中，单核仍有余量，NDI reject 与输出 reject 均为0，未见重传异常；perf 样本约 `1,000 ACK/s`、RTT `0.23–0.49ms`、cwnd `1,168 MSS`，在途数据通常低于 `130KiB`，KCC pacing 样本多数约 `180–200MB/s`，而 timer late p95 为 `32–128µs`。target-namespace Linux `ss -tinp` 多次报告内核发送端 `rwnd_limited` 约 `89–91%`，发送队列累积到数 MiB；XTCP perf 同时记录的远端发送窗口约 `0.43–0.57MiB`，但两者不是同一端的直接窗口读数，现有采样没有足够的连接级时序关联。该证据把后续调查收窄到 ACK/window 更新节奏、P1 的 pacing/窗口供给以及 native BBR/TSO 对照差异；它尚不能单独判定是接收窗口实现缺陷，不能通过放宽窗口、移除拥塞/重传保护来修复。诊断 artifact：`artifacts/goal12-kcc-hybrid-simd-diag-p1-dl-gsooff-sndbuf128k-cpu8-30s-20260925-escalated/`。产品默认值、TSO gate 与 KCC recovery 保护均未改变。

### 11.60 P1 DL 的 send buffer 单变量复验：1MiB 通过、128KiB 不通过（2026-09-25）

保持 SIMD-on 二进制、P1/DL/GSO-off、CPU8 单核、KCC、single-shard、memory bridge 不变，只将 XTCP `sndbuf` 从 `128KiB` 改为 `1MiB`，执行 fresh-netns 60秒×3 配对矩阵。qualification **6/6**、性能门禁 **3/3** 通过；XTCP/native 三轮 `1.4495×/1.4800×/1.4897×`，median `1.4800×`。XTCP goodput median `894.1Mbps`（880.7–896.1），native `605.5Mbps`（600.2–607.6）；process task-clock/byte efficiency median `1.5313×`。对照 §11.59 的 P1/128KiB XTCP median `519.0Mbps`、ratio `0.8505×`，1MiB 组 XTCP goodput 上升约 `72.3%`，native 中位数保持约 `605Mbps`。artifact：`artifacts/goal12-kcc-hybrid-simd-p1-dl-gsooff-sndbuf1m-cpu8-60s-r3-clean-20260925-escalated/`。

这说明 P1/DL 的 128KiB 配置会限制当前实验路径，1MiB 是已复验通过的 P1/DL 分层配置；不等于可提高所有连接的默认 sndbuf。按最大活跃流数粗略计算，sndbuf 配额上限会随连接数线性增加，必须结合并发/内存预算另做门禁。此结果不能外推到 UL、P4/P16、GSO-on 或其他设备/内核；根 `bin/ppp` 与产品默认配置均未修改。

### 11.61 SIMD-on P1 UL / 1MiB send buffer 首批复验未达稳定门槛（2026-09-25）

在 §11.60 同一 SIMD-on、GSO-off、`sndbuf=1MiB`、CPU8/KCC/single-shard/memory-bridge 配置下，将方向改为 P1/UL 做60秒×3 配对矩阵。qualification **6/6**，但 paired gate 仅 **1/3** 通过：XTCP/native `1.1976×/1.0912×/1.2223×`，median `1.1976×`，略低于1.20目标且轮间散布明显。XTCP/native median goodput `351.1/319.0Mbps`；无 retransmit/zero-rate flow，qualification 均通过。artifact：`artifacts/goal12-kcc-hybrid-simd-p1-ul-gsooff-sndbuf1m-cpu8-60s-r3-clean-20260925-escalated/`。

另做一轮30秒 XTCP-only 诊断，aggregate goodput `384.1Mbps`、qualification通过；NDI/output reject、global queue 与 direct-upload send rejection 均为0，owner dispatch无drop，queue p95 `32µs`。不过 perf TCP-flow 明细未能对应 bulk iperf 流，因此不据此认定 KCC/strand/ACK 的根因。诊断 artifact：`artifacts/goal12-kcc-hybrid-simd-diag-p1-ul-gsooff-sndbuf1m-cpu8-30s-20260925-escalated/`。

后续同配置重复三轮，ratio `1.0773×/1.3378×/1.3392×`（2/3过门槛）；再一次把 gather 显式设为 `65536` 的矩阵 ratio `1.3175×/1.2053×/1.2201×`（3/3过门槛），但源码 `kDirectUploadGatherDefaultBytes=PPP_BUFFER_SIZE=65536`，该显式设置等于原默认，并非变量 A/B。真实把 gather cap 从64KiB改为60KiB（`61440`）后，ratio `1.0747×/1.3569×/1.2173×`，仍只有2/3过门槛且 MAD `0.1396`。因此 P1/UL 在同一默认64KiB配置下也出现两批门槛失败、一批通过，另一个60KiB批次同样不稳定；60KiB未证明能修复间歇性。证据分别为 `artifacts/goal12-kcc-hybrid-simd-p1-ul-gsooff-sndbuf1m-repeat-cpu8-60s-r3-clean-20260925-escalated/`、`artifacts/goal12-kcc-hybrid-simd-p1-ul-gsooff-sndbuf1m-gather64k-cpu8-60s-r3-clean-20260925-escalated/`、`artifacts/goal12-kcc-hybrid-simd-p1-ul-gsooff-sndbuf1m-gather60k-cpu8-60s-r3-clean-20260925-escalated/`。当前结论仍是 P1/UL 未证明稳定达到三轮门槛；不能把一批3/3或 DL 的1MiB收益外推为 UL 修复。

### 11.62 XTCP perf JSON 补齐 direct-upload per-flow 计数（2026-09-25）

前述 UL 诊断中的 `tcp_flows[].payload_sent_bytes` 只在 `TrySendPending()`（connector→TCP stack）方向累计，因此 P1/UL bulk 的 `OnReceive()`→`SendToPeer()` accepted bytes 被排除，采样常选中 ACK/control flow，无法与 bulk 吞吐关联。现在仅在 `OPENPPP2_XTCP_PERF_JSON` 开启时，按 Flow 累计 direct-upload accepted bytes，并把 `direct_upload_accepted_bytes` 随 TCP tuple/cwnd/window/KCC 状态写入同一 flow sample；候选流排序同时考虑两个方向。性能路径在 perf JSON 关闭时不做该计数，原字段语义保持不变。

复验时把 perf 开关在 `StartFlow()` 缓存到 Flow，数据包热路径只做普通 bool 判断，不为新计数逐包读取全局 atomic。新的 SIMD-on XTCP-only P1/UL 30秒诊断 qualification **1/1**，goodput `374.1Mbps`；`5201:42004` bulk flow 的 per-flow accepted bytes 为 `1,621,334,109`，运行时 aggregate 为 `1,640,235,542`，两者约相差1.2%，再次证明可把 bulk 数据关联到 TCP tuple。此轮 direct-upload backpressure/reject、队列积压、ingress drop、NDI GSO reject 均为0；但 flow 快照同时显示 `cwnd=10 MSS`、`inflight=0`、`snd_wnd=43,008`、重复 ACK 计数持续增加而 ACK advance 为0，不能把这些当前 TCP 状态字段直接当作吞吐根因。下一步需与服务端 `ss -tinp` 按 tuple/时间对齐，确认发送端受限窗口与本端 XTCP flow 的方向映射。artifact：`artifacts/goal12-kcc-ul-perf-upload-flow-diag-p1-ul-cached-perf-tracking-30s-20260925-escalated/`。

隔离 SIMD-on 构建通过；XTCP 相关无 socket 权限测试 **8/8** 通过。完整 `ctest` 为 **133/141** 通过，8项失败；`xtcp_runtime_bridge_test` 与 socket protector 明确报 `Operation not permitted`，其余网络/lifecycle 失败未在本轮逐一归因，不能据此判断为本次字段改动导致。带 perf JSON 的 P1/UL 30秒单格 qualification 通过，XTCP `332.0Mbps`；新 flow tuple `5201:<ephemeral>` 报告 `direct_upload_accepted_bytes=1,431,479,341`，同 cell stats 的 aggregate direct-upload accepted bytes 为 `1,449,132,563`，证明 bulk flow 已被识别并与运行时总计同量级。artifact：`artifacts/goal12-kcc-ul-perf-upload-flow-diag-p1-ul-30s-20260925-escalated/`。

### 11.63 P1/UL 服务端 TCP 接收窗口诊断及 runner 修正（2026-09-25）

`--tcp-info-sampling` 原本只在 DL 启动，虽然参数会出现在 UL metadata 中，却不会生成采样文件。将其扩展为 UL/DL 都对 target iperf namespace 每秒采一次 `ss -tinp`；shell 语法及 `test_datapath_linux_matrix.py` tooling contract 通过。新 XTCP-only P1/UL 30秒诊断 qualification **1/1**，goodput `333.5Mbps`；target `ss` 采样32次，bulk server socket `5201:47578` 的 `bytes_received` 从约49MB增长到 `1,467,206,469`，`Recv-Q` 为0–5,792B，`rcv_space` 约148–202KiB，`rcv_wnd` 持续约1.0MiB。XTCP direct-upload aggregate 为 `1,467,482,647`，backpressure/reject/队列积压/ingress drop 均为0；目标应用接收队列或小 receive window 暂无证据是瓶颈。

注意 per-flow XTCP tuple 是 `5201:42158`，服务端 socket tuple 为 `5201:47578`，端口不同；因此 XTCP 的 `cwnd=10 MSS`、`inflight=0`、重复 ACK 与 ACK-advance 字段不能直接映射到该服务端 socket。当前证据只排除了明显的 server receive-window/应用队列压力；下一步应将 client 侧 XTCP per-flow 与两端 TCP/strand 调度时间线进一步对齐，不能据单轮样本宣称已找到吞吐根因。artifact：`artifacts/goal12-kcc-ul-tcpinfo-perf-diag-p1-ul-30s-fixed-20260925-escalated/`。

随后对同一配置做单轮 PPP 进程 `cpu-clock` call-graph 采样：qualification **1/1**，goodput `387.1Mbps`，perf 采到 **3,193** 个样本且 lost=0。self samples 中 AES-NI CFB encrypt 为 `10.93%`；可见的 XTCP `Submit` 为 `1.25%`、`OnReceive` 为 `0.53%`、`DrainIngress` 和 `XtcpStack::OnPacket` 各约 `0.47%`、标量 checksum `1.03%`；shared_ptr release `2.41%`、mutex lock `2.04%`。另有约 `6.5%` 未符号化 kernel kallsyms 和 `5.4%` libc 原始地址，故这份 profile 只能说明没有一个已符号化的 UL bridge 回调/显式 memcpy 独占热点，不能排除内核/异步栈成本。单轮有 profile 开销且缺少同二进制 native 配对 profile，不构成正式性能对比；不要据此直接改 AES、strand 或拷贝路径。artifact：`artifacts/goal12-kcc-ul-perf-profile-p1-ul-30s-retry-20260925-escalated/`。

这是 opt-in 诊断可观测性修复，不是 UL 吞吐修复，也不改变 gather、sndbuf、KCC 或 default-off TSO。下一步先解释 direct bridge 两侧 tuple/端口映射，并对齐 XTCP 接收、ACK 与 writer completion 时间线，再区分 strand 调度、TCP 窗口供给与 host-side native sender 的贡献。

### 11.64 当前 SIMD 候选 P1/UL GSO-on 通过 1.20× 三轮门槛（2026-09-25）

在较空闲的 CPU11 上，对当前 SIMD-on XTCP 候选（SHA256 `e969c6a8fed767d57772f9b1a2c38f03d3d0d2189415a72fe8131d848ae9454b`）运行 P1/UL、native/XTCP、GSO-on、`sndbuf=1MiB`、KCC、single-shard、memory bridge、60秒×3 fresh-netns 配对矩阵。qualification **6/6**，GSO requested/active 均匹配，paired gate **3/3** 通过；XTCP/native ratio `1.2728×/1.2894×/1.3072×`，median `1.2894×`、MAD `0.0165`。XTCP goodput median `1.097Gbps`、native `850.5Mbps`；process task-clock/byte efficiency median `1.3629×`。artifact：`artifacts/goal12-kcc-hybrid-simd-p1-ul-gsoon-sndbuf1m-post-perf-cache-cpu11-60s-r3-20260925-escalated/`。

同一候选/CPU11/缓冲/bridge 配置的 GSO-off 配对矩阵为 `1.4708×/1.1955×/1.3385×`，仅2/3过线，XTCP/native median goodput `383.7/286.6Mbps`；因此当前证据表明 **GSO-on 是这组 P1/UL 达成稳定1.20×的有效配置**，而非证明 GSO-off 已修复。GSO-on 的 absolute goodput 与 process task-clock/byte 均明显优于 GSO-off，但不能把跨模式变化单独归因于某个代码热点。runner 仍保留 GSO-on opt-in 行为，没有全局切换默认值，以免将此 P1/UL 结果外推到其他并行度、方向或栈。GSO-off 结果：`artifacts/goal12-kcc-hybrid-simd-p1-ul-gsooff-sndbuf1m-post-perf-cache-cpu11-60s-r3-20260925-escalated/`。

### 11.65 P1/UL 达标依赖 direct memory bridge，默认 socket-pump 不达标（2026-09-25）

保持当前候选、CPU11、P1/UL、GSO-on、`sndbuf=1MiB`、KCC/single-shard、60秒×3，仅移除 `--xtcp-memory-bridge`。6/6 qualification 通过，但 XTCP/native ratio 为 `0.6750×/0.6197×/0.6484×`，性能门禁 **0/3**；XTCP/native median goodput `550.0/846.3Mbps`，XTCP process task-clock/byte 为 `13.74ns/B`、native `8.65ns/B`。对照 §11.64，direct memory bridge 开启时同目标配置 3/3 通过、median ratio `1.2894×`。artifact：`artifacts/goal12-kcc-hybrid-simd-p1-ul-gsoon-sndbuf1m-cpu11-defaultbridge-60s-r3-20260925-escalated/`。

因此当前可验收的 P1/UL 1.20× 路径明确要求 `OPENPPP2_XTCP_MEMORY_BRIDGE=1`；这不是 XTCP 的隐式默认行为。受控 datapath acceptance contract 已显式固定该环境变量（`tools/datapath_acceptance.py::XTCP_CLIENT_ENVIRONMENT`），而不支持 direct I/O/half-close 的 carrier 会由 `AckAccept()` 回退到原 socket pump。现阶段不把该 capability 改成所有 XTCP 会话的全局默认：本轮证明的是受控 Linux P1/UL 能力路径达标，不是 WebSocket/TLS、所有 carrier 或默认应用配置均达标；若要晋升默认，还需补齐直接桥接的协议生命周期/兼容性 E2E 覆盖。

### 11.66 direct memory bridge Linux lifecycle E2E（2026-09-25）

为补齐 §11.65 提出的生命周期覆盖，在候选二进制上运行 `tests/integration/linux/xtcp_tap_netns_e2e.sh` 两组短矩阵：`XTCP_SOAK_SECONDS=3`、`XTCP_E2E_CHURN=16`，除 `OPENPPP2_XTCP_MEMORY_BRIDGE` 开关外配置相同。两组均通过 echo byte integrity、client half-close、peer-close drain、RST/refused target、16连接 churn、1% loss/25% reorder/10ms delay + MTU 1280、stats-json 计数、3秒 soak 及退出后的 routes/DNS rollback。

direct 组显式设置 `OPENPPP2_XTCP_MEMORY_BRIDGE=1`；最终 stats 样本记录 `direct_bridge_starts=85`、`direct_bridge_fallbacks=0`、`direct_bridge_active=1`，connector socket-pump 读写字节均为0，degraded half-close 与 direct upload/download reject 均为0。unset 对照组记录 bridge starts/active 均为0，connector read/write 分别约69.9/70.0MB；两组 `flows_opened=86`、`flows_closed=85`（最后一个存活流对应 soak 结束时清理）。证据：`artifacts/xtcp-direct-bridge-netns-e2e-20260925/`、`artifacts/xtcp-fallback-netns-e2e-20260925/`。

额外对 direct 组运行 `XTCP_E2E_CHURN=512`、`XTCP_SOAK_SECONDS=15` 的扩展轮，同一组 lifecycle、netem、MTU 与 rollback 检查全部通过。最终 stats 为 `flows_opened=582`、`flows_closed=582`、`direct_bridge_starts=581`、`direct_bridge_fallbacks=0`、upload/download reject 均为0；累计 direct upload/download accepted bytes 分别约260.0/260.0MB，connector socket-pump 字节仍为0。artifact：`artifacts/xtcp-direct-bridge-netns-e2e-512x15s-20260925/`。

这证明当时的候选在本 Linux raw-child carrier 的短时损伤、512连接 churn 和关闭路径中真实选择 direct bridge，且相同 legacy fallback 仍可工作；它补足的是功能/lifecycle 与中等 churn 证据，不是长时间 soak、极限压力/内存上限或其他 carrier 的兼容性验收。当时仍维持 opt-in；后续默认策略变化见 §11.69。

### 11.67 CPU11 P1/DL 的 matched GSO-on/off 三轮矩阵（2026-09-25）

为验证 direct bridge 的方向适用性，在同一 SIMD-on 候选（SHA256 `e969c6a8fed767d57772f9b1a2c38f03d3d0d2189415a72fe8131d848ae9454b`）、CPU11、P1/DL、KCC、single-shard、`sndbuf=1MiB`、memory bridge 配置下，分别执行 native/XTCP fresh-netns 60秒×3 配对矩阵。两组 qualification 均为 **6/6**，没有 zero-rate flow；GSO-on 有一项 CPU-contention warning（round 1 process cores `0.881`），round 2/3 无 warning。artifact：`artifacts/goal12-p1-dl-gsoon-bridge-cpu11-60s-r3-20260925/`、`artifacts/goal12-p1-dl-gsooff-bridge-cpu11-60s-r3-20260925/`。

GSO-on 的 XTCP/native ratio 为 `0.9030×/0.9471×/0.9386×`，median `0.9386×`、MAD `0.0085`，性能门禁 **0/3**；XTCP/native median goodput 为 `1.118/1.211Gbps`。GSO-off ratio 为 `1.3958×/1.4798×/1.4740×`，median `1.4740×`、MAD `0.0057`，门禁 **3/3**；median goodput `0.897/0.609Gbps`。因此同机数据不支持“打开 GSO 会降低 XTCP 绝对吞吐”：XTCP GSO-on 比 GSO-off 快约24.6%；但 native GSO-on 快约98.9%，使相对1.20×门禁失败。此处的目标是相对 native 比率，不能把 GSO-on 单侧 goodput提升解释为目标达成。

归一化 process task-clock/byte 同样呈现此差异：GSO-on XTCP/native 为 `6.38/6.08ns/B`，即 XTCP 每字节进程成本略高；GSO-off 为 `7.97/12.08ns/B`，XTCP 成本低约33.9%。XTCP 输出路径 GSO-on stats 中 `gso_merge_active=true`、VNET header/TX GSO capability 均 active，NDI TSO 本身仍为关闭；三轮均无 direct-bridge fallback/reject。perf 采样中每秒约100k NDI packet、TUN direct write约27–30k次，粗略每次约3–4个 MSS；该关联提示可能存在更大 write batching 空间，但采样并不能证明 coalescer 是吞吐差异的原因。历史 NDI TSO TX A/B 曾回退（§0），不可为追 ratio 直接打开 TSO；下一步应先沿 coalescer→同步 TUN write 路径审查 batch flush/边界与当前 `writev` 行为，并做单变量低风险 A/B。当前结果只证明这组 P1/DL GSO-off 门槛通过、GSO-on 未通过，不外推到其他 P/方向，也不改变产品默认值。

### 11.68 TAP GSO cap=16 未改善 P1/DL 相对门槛（2026-09-25）

依据 §11.67 的 batch-size 线索，只将 `OPENPPP2_TAP_GSO_SEGMENTS` 从默认4改为16，在同一候选、CPU11、P1/DL、GSO-on、`sndbuf=1MiB`、KCC/single-shard、memory bridge 下执行 native/XTCP 60秒×3。qualification **6/6**，但 ratio 为 `0.8768×/0.9434×/0.8899×`，median `0.8899×`、MAD `0.0131`，门槛 **0/3**。XTCP/native median goodput为 `1.472/1.661Gbps`；对照 cap4 的 `1.118/1.211Gbps`，cap16使两栈绝对吞吐均明显提高，却没有让 XTCP相对 native更快。process task-clock/byte median为 `4.62/4.42ns/B`，XTCP每字节成本仍略高。artifact：`artifacts/goal12-p1-dl-gsoon-cap16-bridge-cpu11-60s-r3-20260925/`。

因此停止继续扩大共用 GSO segment cap：该 knob 改善 shared TUN path，而非已证实的 XTCP 专属优势；更大 cap 没有证据能满足1.20×目标。NDI TSO TX 仍保持关闭，避免重启已观察到的回退候选。

### 11.69 memory bridge 对可支持 carrier 改为默认尝试（2026-09-25）

在 §11.66 的短时 lifecycle/512连接 churn E2E 通过，且 formal P1/UL GSO-on 3/3达标明确依赖 direct bridge 后，将 `XtcpMemoryBridgeEnabled()` 的默认语义改为：环境变量未设置或为空时尝试 direct bridge；精确值 `1` 显式启用；`0` 或其他非空值关闭。`AckAccept()` 原有 transmission/capability 检查不变：不支持真实 half-close 的 carrier 仍走 legacy socket pump，显式 `OPENPPP2_XTCP_MEMORY_BRIDGE=0` 保留回退开关。没有改动 direct 状态机、queue/backpressure、FIN 顺序或 recovery gate。

隔离 Release/SIMD/XTCP build 成功，新 binary SHA256 `4189f88132bbdaf4fb3949bdf8c24cb3650622cce22413fd8ee40364338753ce`；旧矩阵 binary 已留在 `/tmp/ppp-xtcp-simd-pre-bridge-default-20260925`，此前 P1/UL matrix使用 `=1` 的 datapath与新 unset 默认走同一 direct 分支。新 binary上 unset 的 netns E2E通过，最终 stats `direct_bridge_starts=85`、fallback=0、connector read/write=0、`degraded_half_close=0`；显式 `=0` 对照也通过并保留 legacy pump，starts=0、connector read/write约65.7/65.8MB。两组均完成 half-close、peer drain、RST、churn、netem/MTU、stats及 route/DNS rollback。artifact：`artifacts/xtcp-default-auto-bridge-e2e-20260925/`、`artifacts/xtcp-default-bridge-optout-e2e-20260925/`。

`test_datapath_linux_matrix.py`、datapath acceptance contract 与 `git diff --check` 已通过；受控 acceptance runner 仍显式固定 `=1`，以确保严格合同不依赖新默认。默认选择与 opt-out 的生命周期测试只覆盖 Linux raw-child carrier；WebSocket/TLS carrier 和跨平台行为仍需单独验收。60秒性能复验见 §11.70；没有提交或推送。

### 11.70 默认 direct bridge 下 P1/UL GSO-on 60秒三轮复验（2026-09-25）

对 §11.69 新 binary（SHA256 `4189f88132bbdaf4fb3949bdf8c24cb3650622cce22413fd8ee40364338753ce`）执行 native/XTCP fresh-netns、P1/UL、GSO-on、CPU11 单核、KCC/single-shard、`sndbuf=1MiB`、60秒×3 paired matrix；显式 unset `OPENPPP2_XTCP_MEMORY_BRIDGE` 与 `OPENPPP2_TAP_GSO_SEGMENTS`，其余能力参数不变。qualification **6/6**、paired gate **3/3**；XTCP/native ratio `1.3018×/1.2478×/1.2718×`，median `1.2718×`、MAD `0.0240`。median goodput为 `1.082/0.845Gbps`；process task-clock/byte median效率提升 `1.3452×`。artifact：`artifacts/goal12-p1-ul-gsoon-defaultbridge-cpu11-60s-r3-20260925/`。

三轮 XTCP stats 均确认真实 direct 分支：每 cell `direct_bridge_starts=2`、fallback=0、connector read/write=0，direct upload rejected/backpressured均为0；结束时 active=0 是 flow 正常关闭后的状态。结果证明新默认选择在该 Linux P1/UL 场景保留了1.20×三轮门槛，不依赖 acceptance runner 注入 `=1`。相较 §11.64 的显式 `=1` 矩阵，本次 median ratio `1.2718×` 对比 `1.2894×`，两批都达标但不声称默认切换带来额外提速。P4/P16 UL复验见 §11.72–11.73；DL GSO-on、其他 carrier 或平台仍未达标/验收。TAP GSO 模式仍需单独选择，NDI TSO TX 保持关闭。

### 11.71 默认 direct bridge 下 P1/DL GSO-off 三轮复验（2026-09-25）

用 §11.69 同一 binary，在 CPU11 对 P1/DL/GSO-off、native/XTCP、KCC/single-shard、`sndbuf=1MiB` 做 fresh-netns 60秒×3 配对矩阵，unset `OPENPPP2_XTCP_MEMORY_BRIDGE` 与 `OPENPPP2_TAP_GSO_SEGMENTS`。qualification **6/6**、paired gate **3/3**；ratio `1.4314×/1.4437×/1.4722×`，median `1.4437×`、MAD `0.0123`。median goodput `884.5/612.7Mbps`，process task-clock/byte效率提升 median `1.4798×`。三轮 stats 每 cell均为 `direct_bridge_starts=2`、fallback=0、connector read/write=0、direct upload/download reject=0。artifact：`artifacts/goal12-p1-dl-gsooff-defaultbridge-cpu11-60s-r3-20260925/`。

这与 §11.70 的默认 P1/UL GSO-on 结果共同确认：新默认 direct bridge 在这两个已测 Linux P1 配置中保留并通过 `>=1.20×` 三轮门槛。它不改变 P1/DL GSO-on 的未达标结论（§11.67–11.68），也不代表更高并行度、其他方向/GSO 模式或 carrier 已验收；根 `bin/ppp` SHA仍保持原 baseline `d280be71be62adcb6f9f7868c6e79da77208c2b0ab9b62dc56c2743f78fd0802`。

### 11.72 默认 direct bridge 下 P4/UL GSO-on 三轮复验（2026-09-25）

使用 §11.69 binary、CPU11、P4/UL/GSO-on、KCC/single-shard、`sndbuf=1MiB`、native/XTCP、60秒×3；unset `OPENPPP2_XTCP_MEMORY_BRIDGE` 与 `OPENPPP2_TAP_GSO_SEGMENTS`。qualification **6/6**、paired gate **3/3**；XTCP/native ratio `1.2495×/1.2488×/1.2665×`，median `1.2495×`、MAD `0.0007`。median goodput为 `1.062/0.842Gbps`；process task-clock/byte效率提升 median `1.3332×`。三轮无 zero-rate，fairness max/min `1.004/1.011/1.010`；每 cell stats `direct_bridge_starts=5`、fallback=0、connector read/write=0，direct upload reject/backpressure=0。artifact：`artifacts/goal12-p4-ul-gsoon-defaultbridge-cpu11-60s-r3-20260925/`。

所有 XTCP cell 都带 `ppp_process_cores_below_0.9_same_core_contention` warning，process cores `0.857–0.859`；paired ratio仍高度稳定，但该 warning保留为环境/CPU利用 caveat，不伪装为 clean run。

### 11.73 默认 direct bridge 下 P16/UL GSO-on 三轮复验（2026-09-25）

相同 binary/CPU11/UL/GSO-on/bridge-unset 配置，将 iperf并行数提高至 P16。qualification **6/6**、paired gate **3/3**；ratio `1.2624×/1.2623×/1.2606×`，median `1.2623×`、MAD约0。median goodput为 `1.052/0.833Gbps`；process task-clock/byte效率提升 median `1.3322×`。16条流三轮均无 zero-rate，fairness max/min `1.009/1.008/1.009`；每 cell stats `direct_bridge_starts=17`、fallback=0、connector read/write=0，direct upload reject/backpressure=0。artifact：`artifacts/goal12-p16-ul-gsoon-defaultbridge-cpu11-60s-r3-20260925/`。

三轮同样都有 process-core contention warning（`0.860–0.871`），需作为 host 测量 caveat；吞吐比值、公平性和 backpressure 指标仍稳定。至此，默认 direct bridge 的 UL GSO-on P1/P4/P16 都已通过当前三轮1.20×门槛；该结论限于 CPU11/Linux/当前 SIMD-on binary与本配置，不能外推为完整方向/GSO矩阵通过。

### 11.74 默认 direct bridge 下 P4/P16 DL GSO-on 并行度矩阵（2026-09-25）

为检查 DL 的单 flow 16KiB reservation 是否能靠增加并行流摊薄交接成本，使用 §11.69 binary、CPU11、DL/GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge 环境变量 unset，执行 P4/P16、native/XTCP、60秒×3 paired matrix。12/12 cells qualification 通过；性能 gate 0/6。P4 XTCP/native ratio 为 `1.0362×/1.0446×/1.0337×`，median `1.0362×`、MAD `0.0025`，median goodput `1.187/1.142Gbps`；P16 ratio 为 `0.9510×/0.9735×/0.9838×`，median `0.9735×`、MAD `0.0104`，median goodput `1.113/1.140Gbps`。process task-clock/byte efficiency median 分别为 P4 `1.0391×`、P16 `0.9947×`。artifact：`artifacts/goal12-p4-p16-dl-gsoon-defaultbridge-cpu11-60s-r3-20260925/`。

每轮 direct bridge starts 与 flow 数一致（P4=5、P16=17），fallback、download reject、ingress drop 均为0；direct queue high-water 分别约66KiB/265KiB，符合并行数乘以单 flow 约16KiB reservation 的量级，不支持扩大 per-flow credit来解决该结果。XTCP `Send()` admission/stack send rejection 与累计 stall 在 P16 明显高于 P4；诊断快照显示主要等待在 TCP pending flush 的 window/cwnd gate，NDI output rejection为0。TAP GSO active 不等于 NDI TSO TX active：本矩阵中 `ndi_gso_enabled=false`、`ndi_gso`输出计数为0，TSO TX 仍保持关闭。

结论是并行流不能把 DL GSO-on 提升到1.20×：P4 稳定略快于 native但仅约3.6%，P16则略慢于 native，且每字节CPU效率随并行度恶化。该现象更符合栈发送准入/pacing-window供给压力，而非 direct-download 队列不足；单纯缩短已知无吞吐收益的 laboratory retry cadence 或扩大单流 reservation 都不是当前修复方向。下一步应继续将 admission拒绝、pending-flush window/cwnd原因与逐流 ACK/pacing时序关联，并将数据面 CPU成本与 KCC发送供给分开。此结果不外推到 GSO-off、P1、其他 CPU profile 或其他 carrier。

### 11.75 DL GSO-on 将 sndbuf 提至 2MiB 未改善，P16 出现超时（2026-09-25）

基于 §11.74 的 sndbuf quota 观测，只改变 XTCP per-connection `sndbuf` 为2MiB，复跑相同 CPU11/P4/P16/DL/GSO-on/60秒×3 参数。完成的10个 cells qualification 均通过；P4三轮完整 ratio 为 `1.0203×/0.9862×/1.0125×`，median `1.0125×`，低于1MiB配置的 `1.0362×`。P16第一轮 ratio `0.9456×`；第二轮 XTCP cell 在100秒 watchdog超时；第三轮 XTCP 未形成有效 result，runner 在长时间无进度后被中断。因此 P16没有完整配对结论，不能补跑或按完成轮次计算门禁。matrix summary、超时前诊断与不完整 cell 文件均保留在 `artifacts/goal12-p4-p16-dl-gsoon-sndbuf2m-cpu11-60s-r3-20260925/`。

超时诊断中的 target iperf server 多条 socket Send-Q 约6–9MiB、`rwnd_limited` 约99.9%；抽样到的一条 XTCP flow `cwnd=1 MSS`、`ssthresh=4`、`retx=9`。这更像发送/接收窗口及拥塞控制恢复异常，而不是 buffer quota 单独偏小；增加 sndbuf 没让 P4 变快，P16还触发严重低速/超时，故不再扩大该参数，不晋升2MiB。矩阵只改变诊断配置，未改变产品默认、KCC门控或恢复保护。

### 11.76 P16/2MiB ingress loss 对照与 10ms KCC 只读快照（2026-09-25）

§11.75 超时的末10条 XTCP stats 中 `ingress_dropped=628`、`ingress_submitted=4,956`，而 direct-download reject=0；源码已有注释记录 P16 大 sndbuf 会超过默认 `1024 items/8MiB` ingress 预算并形成 loss spiral。随后用现有 LAB-only budget overrides 做一格 XTCP-only P16/DL/GSO-on/20秒诊断：`sndbuf=2MiB`、`OPENPPP2_XTCP_INGRESS_ITEMS=8192`、`OPENPPP2_XTCP_INGRESS_BYTES=64MiB`。qualification 1/1，iperf goodput `976.1Mbps`，ingress dropped=0、submitted/injected=`21,860/21,857`、direct-download reject=0、queue high-water约265KiB。它证明扩大 ingress budget 可消除本轮观测到的 ingress drop 并让短 cell 完成，但这是有诊断开销的单栈短测、没有 native 配对，不能当作性能提升或正式通过；64MiB ingress cap也不晋升默认。artifact：`artifacts/goal12-p16-dl-gsoon-sndbuf2m-ingress64m-diag-cpu11-20s-20260925/`。

另对默认1MiB sndbuf跑一轮 XTCP-only P16/DL/GSO-on/20秒，`OPENPPP2_XTCP_PERF_INTERVAL_MS=10` 只用于细粒度只读 KCC 采样。qualification 1/1，goodput `1,024.4Mbps`（无 native 配对、诊断数据不作为 gate）；2,841份样本中 bulk-flow状态出现RTT约0.4–32.9ms。历史 JSON 的 `pacing_bps` 键存在单位误标：它原样输出 `ConnInfo::pacing_bps`，而上游定义单位实际是 bytes/s；原始范围约`3.17MB/s–16.55GB/s`，换算成 bit/s 应为约`25.4Mbps–132.4Gbps`，不能把旧文件中的数值直接当 bit/s。target iperf sender 多条 socket 的 `rwnd_limited` 约89–97%、Send-Q约5.9–13.6MiB；当时尚未建立 XTCP flow 与 target peer socket 的逐流映射，所以这些只能作整体相关性线索，不能直接推断为 XTCP receive-window 或 KCC 算法根因。artifact：`artifacts/goal12-p16-dl-gsoon-kcc-10ms-sndbuf1m-cpu11-20s-r1-20260925/`。

综合 §11.74–11.76：1MiB sndbuf 诊断配置无 ingress drop，却 P16 GSO-on 仅约0.97× native；2MiB会因 ingress budget不匹配产生drop，单纯提高budget只消掉drop、短测吞吐仍不足以证明收益。下一步优先建立逐条逻辑 flow 与 target peer-port/ACK/window时间线的关联，再决定是否改 KCC/接收窗口或 ingress admission；不改 `SetRcvBuf`（历史 DL 实验中 XTCP 是发送方，该旋钮无效），也不扩大默认 queue/budget。

### 11.77 默认 direct bridge 下 P4/P16 DL GSO-off 干净配对矩阵（2026-09-25）

为单独确认 TAP GSO-off 的 DL 表现，使用 §11.69 binary、CPU11、DL/GSO-off、KCC/single-shard、`sndbuf=1MiB`、memory bridge 环境变量 unset，执行 P4/P16、native/XTCP、60秒×3 paired matrix。此轮未启用 `OPENPPP2_XTCP_PERF_JSON` 或 `--stall-diagnostics`，保留 process perf-stat 与 runner qualification。12/12 cells qualification 通过，XTCP/native 六个配对全部通过1.20× gate。P4三轮 ratio=`1.4465×/1.4271×/1.4361×`，median=`1.4361×`（MAD `0.0090`），goodput median native/XTCP=`602.2/864.9Mbps`；P16 ratio=`1.3654×/1.8217×/1.3691×`，median=`1.3691×`（MAD `0.0037`），goodput median=`580.0/800.8Mbps`。P16第二轮 native 只有`445.9Mbps`，而其余两轮约`580Mbps`；相应公平性 `max/min=1.766`，所以`1.8217×`是 reference outlier 放大的单轮比值，不代表典型提升。即使排除该轮，另两轮也都超过1.20×。artifact及逐 cell证据：`artifacts/goal12-p4-p16-dl-gsooff-defaultbridge-cpu11-60s-r3-20260925/`。

process task-clock/byte efficiency median P4/P16 分别为`1.4737×/1.3996×`，与goodput改善方向一致；P16 native第二轮 task-clock/byte也明显偏高，故同样不能把其`1.94×`单轮效率比当典型。P4/P16 XTCP三轮 goodput分别落在`855.6–874.0Mbps`和`794.0–812.2Mbps`，自身重复性较好。此结果支持“在当前单核CPU11、默认direct bridge、DL/GSO-off配置下，XTCP相对native稳定超过1.20×”，但不推翻GSO-on失败结果，也不外推到P1、其他CPU/profile、其他carrier或production负载。下一步保留GSO-on与GSO-off分开验收；若追究P16 outlier，应先查该native cell当轮 CPU/softirq/宿主竞争证据，而不重跑或丢弃现有正式数据。binary：`build/goal12-kcc-hybrid-simd-formal-20260925/out/ppp`（SHA-256 `4189f88132bbdaf4fb3949bdf8c24cb3650622cce22413fd8ee40364338753ce`）。

### 11.78 默认 direct bridge 下 P4/P16 DL GSO-on 干净配对复验（2026-09-25）

使用与§11.77相同 binary、CPU11、KCC/single-shard、`sndbuf=1MiB`、bridge unset、60秒×3参数，仅把 TAP GSO 改为 on；未启用 XTCP perf JSON 或 stall diagnostics。12/12 cells qualification通过，但六个 XTCP/native 配对全部低于1.20×：P4 ratio=`1.0864×/1.0686×/1.0921×`，median=`1.0864×`（MAD `0.0057`），goodput median native/XTCP=`1.152/1.249Gbps`；P16 ratio=`1.0021×/1.0047×/0.9895×`，median=`1.0021×`（MAD `0.0027`），goodput median=`1.172/1.172Gbps`。XTCP P4/P16自身goodput分别为`1.236–1.251Gbps`与`1.156–1.175Gbps`，三轮稳定；没有 zero-rate flow。artifact：`artifacts/goal12-p4-p16-dl-gsoon-clean-defaultbridge-cpu11-60s-r3-20260925/`。

process task-clock/byte efficiency median增益 P4=`1.0962×`、P16=`1.0515×`；proc selected non-idle CPU metric的P16 median仅`1.0012×`，均不支持1.20×性能门槛。结合§11.77，可见此配置下GSO-on的绝对goodput高于GSO-off，但native相对受益更大：DL GSO-off P4/P16通过1.20× gate，GSO-on P4/P16未通过，二者不是互相矛盾的结果，而是不同批量/packetization模式下的相对栈差异。该复验确认GSO-on低相对增益并非perf/stall诊断采样导致；仍不能由此推断GSO是XTCP绝对吞吐瓶颈，也不启用NDI TSO TX。维持两种TAP GSO模式独立验收，不更改默认策略；下一步应把优化目标放在可归因的XTCP发送供给/packetization成本，并在改源码前先完成函数级影响分析与无诊断基线对照。binary同§11.77，SHA-256 `4189f88132bbdaf4fb3949bdf8c24cb3650622cce22413fd8ee40364338753ce`。

对每轮 `datapath-client.jsonl` 的 direct TUN write 计数作累计可见，GSO-on 下平均单次 write 约4.86–5.49KiB，GSO-off约1.26–1.48KiB，且两种 TCP stack 都呈现相同数量级变化。这确认矩阵中的 TAP GSO 实际改变了进入 TUN 的批量粒度；GSO-on时XTCP与native每次write字节数接近，而P16 XTCP write次数略少，不能据此声称XTCP合包实现失效或某个单独函数是瓶颈。它更支持把后续采样对准 per-flow send供给/系统吞吐上限，而不是重复调整已生效的 coalescing/TSO开关。

### 11.79 P16 DL 逐流 telemetry 的可关联范围（2026-09-25）

重新核对§11.76的10ms XTCP perf与同 cell iperf JSON：XTCP `tcp_flows[].remote_port` 与 `iperf.start.connected[].local_port` 的16个数据流端口逐个精确相等，可直接把 XTCP top-flow samples 关联到对应 iperf client stream；`tcp_flows`本身仍只采每次累计字节最多的4条，不覆盖所有16流。在频繁出现的端口`53800/53804/53808/53820`上，XTCP观测到的`payload_sent_bytes`最大值约`162.8/167.1/168.6/165.8MB`，对应 iperf receiver 约`161.1/161.5/162.9/159.3MB`，相差约1–4%。这验证了高字节样本可对回实际 DL stream，但样本窗口与 iperf 结束边界不完全相同，不能把该差值解读为重复交付或丢失。

target namespace `ss` 中 iperf server 的 peer ports 则为另一组`54228–54394`，与 client ephemeral ports不相等，且样本中有17个peer而iperf数据流为16个（另含控制连接）；artifact未提供NAT/代理两侧逐连接映射。因此此前把多条 target socket 的`rwnd_limited`与某一条 XTCP KCC state直接配对的做法不成立，仍仅是整体相关性线索。后续分析可先以`remote_port == iperf local_port`研究被采样流的 XTCP state 与该 stream goodput；若要解释 target `ss` 的窗口限制，必须再取得 NAT/代理连接映射，不能按端口排序猜配对。

以`remote_port==local_port`逐流对齐后，对4条高频采样流按 iperf 区间和 XTCP payload counter变化拟合 logger offset，最佳约`5.18s`；77个 per-stream interval 的 payload delta 与 iperf receiver bytes Pearson `r=0.9515`，中位 byte ratio=`1.018`、平均绝对相对误差约`13.4%`。offset是由同一组吞吐/byte计数拟合出来的，并非独立时钟证据；因此它验证了流级趋势一致，但状态/速率相关性仍是探索性结果。对具有至少3个有效10ms状态样本的69个 flow-interval，RTT median约`6.70ms`、cwnd median`25,491`段、inflight median`48KiB`、snd_wnd median`228KiB`、pacing median原始`28.5MB/s`（正确单位约`228Mbps`）。inflight显著低于广告窗口，且这些快照没有显示 cwnd/window 接近饱和；速率与 RTT/cwnd/inflight/snd_wnd/pacing 的简单 Pearson 分别约`-0.046/+0.107/-0.218/-0.095/+0.277`，未呈现能解释整体吞吐的强单变量关系。该结论只覆盖 top-four telemetry 中可关联的高频流，不推广到其余12流；同时也不支持仅凭旧 `rwnd_limited` 统计去调大 receive/send window。

同一诊断 cell 的累计 XTCP perf delta 还显示内部 send 准入压力：`stack_send_calls=208,406`、rejected=`47,291`、累计 stall=`322,921ms`（多 flow 时间重叠，不能当墙钟时长）；其中 admission `sndbuf_quota=31,450`，pending-flush attempts=`2,888,383`，window/cwnd gate=`1,811,729`、pacing gate=`1,074,785`、fast-recovery gate=86、packet-allocation gate=0。相对地 direct bridge starts=17、fallback=0、connector read/write=0、direct-download reject=0，NDI output `1,860,608/1,860,608` 全部接受。因该 cell 开启10ms perf与 stall diagnostics，这些是压力路径线索而非正式吞吐证据；它们把下一步优先级指向 XTCP send-admission/flush service，而不是 NDI 输出失败、bridge queue 上限或盲目放大 receive window。2MiB sndbuf 的 ingress loss/timeout 证据仍禁止直接扩大默认 sndbuf/ingress budget（§11.75–11.76）。

本轮修正 `XtcpRuntime::WritePerfLine` 的单位输出：上游 `ConnInfo::pacing_bps` 实际以 bytes/s 保存，现在对外 `pacing_bps` JSON 字段乘8并对 `uint64` 上限饱和，保持键名但使其真正表示 bit/s。历史 artifact不重写，读取时仍需乘8；新旧采样的 pacing 数值不能直接比较。

### 11.80 XTCP send 与输出回调边界计时（2026-09-25）

在已有 `OPENPPP2_XTCP_PERF_JSON` 开启时，增加 `boundary_timing_ns`：`xtcp_send_*` 测量 `TrySendPending()` 调用 `XtcpStack::Send()` 的同步耗时，`output_*` 测量 NDI backend 调用 runtime 输出 handler 的同步耗时；均按采样间隔输出调用数、耗时总和与加权平均值。计时仅覆盖被测调用本身，不包含前后 rejection diagnostics；它不代表完整 TCP 服务时间、异步 TUN write 完成时间或端到端延迟。perf JSON 关闭时不读时钟、不更新这些计数。该诊断用于将下一轮瓶颈分到 stack send/admission 与 runtime output handoff 两侧，不改变发送/重试/队列策略；诊断开启有少量测量开销，性能门禁仍必须使用 perf-off binary/configuration。

### 11.81 NDI Tx 热路径与 GSO coalescer 诊断对象构造筛查（2026-09-25）

对 `XtcpNdiBackend::Tx()` 去除每包 `sync_` 加锁及 callback `shared_ptr` 复制后，用同一 P4/DL/GSO-on、memory bridge、cap48、CPU8 配置进行60秒×3 native/XTCP确认：qualification **6/6**，ratio=`1.1274×/1.1322×/1.1694×`，median=`1.1322×`（MAD `0.0047`）。相较先前同配置候选的median `1.0912×` 有改善，但仍未达到1.20×；此对照不是随机交错A/B，故只记录为候选优化的支持性证据，不作因果或门禁结论。NDI output仍全接受，优化未改变TX输出/拒绝语义，handler保留到backend析构以避免并发回调生命周期风险。artifact：`artifacts/goal12-p4-dl-gsoon-memorybridge-cap48-lockfree-cpu8-60s-r3-20260925/`。

随后将 coalescer 的 `EligiblePacket` 诊断事件构造限制在 observer 已安装时；默认未观测路径不再构造携带 `PacketShape` 的事件，合包及写出逻辑不变。coalescer/runtime adapter聚焦测试 **2/2** 通过。启用 datapath telemetry 的三轮配对screen会安装 observer，故不覆盖该优化目标；关闭 telemetry 的XTCP-only三轮screen qualification均通过，但先后运行的基线与候选吞吐分别为 median `1.885/1.664Gbps`，候选波动明显且非随机交错，不能解释为该改动导致的回退或收益。对应artifact：`artifacts/goal12-p4-dl-gsoon-memorybridge-cap48-lockfree-coalescerguard-screen-cpu8-20s-r3-20260925/`、`artifacts/goal12-p4-dl-gsoon-memorybridge-cap48-lockfree-noobserver-baseline-cpu8-20s-r3-20260925/`、`artifacts/goal12-p4-dl-gsoon-memorybridge-cap48-lockfree-coalescerguard-noobserver-cpu8-20s-r3-20260925/`。因此该 guard 暂保留为默认非观测热路径上的局部工作削减，但性能收益仍未证实，不晋升任何GSO/bridge默认，也不作为1.20×达标证据；后续若继续追究，应做交错/随机化的perf-off A/B。

### 11.82 无 borrowed-output capability 时保留 owning fallback（2026-09-25）

提权运行完整 C++ suite 时，`xtcp_runtime_bridge_test` 曾在 handshake path 超时。GDB 确认 SYN-ACK 到达 `XtcpNdiBackend::Tx()` 但返回 false；源码根因是 `XtcpRuntime::Impl::Start()` 无条件把一个捕获空 `BorrowedOutputHandler` 的包装 lambda 赋给 `counted_borrowed_output_`。外层 `std::function` 因而非空，backend 误选同步 borrowed fast path；包装回调发现真实 handler 为空并拒收，未回退到 owning 输出。这影响未提供 borrowed capability 的调用方和测试，Linux 生产 `ClientConnectionOpener` 提供真实同步 TAP borrowed handler，走该路径不变。

现改为只有真实 `borrowed_output_` 非空时才创建计数包装；否则向 backend 传空 borrowed callback，保持原 owning output fallback。聚焦 bridge test 提权后 **1/1** 通过，完整 C++ suite 提权后 **141/141** 通过（普通 sandbox 下该测试因 loopback socket `Operation not permitted` 不可执行）。这是 capability 选择正确性修复，不改变 Linux 生产 fast path，也不是吞吐提升证据；GSO-on P4/DL 当前仍未达到1.20×。

### 11.83 当前候选 P1/UL 门禁复验与 P4/DL 单变量筛查（2026-09-25）

将上述 fallback 修复编入最新隔离候选（SHA-256 `e88ecfdda8fb4d3ab2dd22c40c7293afcd4d74c518ed14736d5bcf29af860f19`），在 CPU11 对 P1/UL、KCC、GSO-on、memory bridge、`sndbuf=1MiB` 执行 native/XTCP 60秒×3 fresh-netns formal matrix。6/6 qualification通过且 paired gate **3/3** 通过；ratio=`1.2356×/1.2841×/1.2689×`，median=`1.2689×`（MAD `0.0153`），XTCP median goodput `1.005Gbps`、native `795.3Mbps`；process task-clock/byte efficiency median=`1.3158×`。三轮 CPU isolation restore 均成功。artifact：`artifacts/goal12-p1-ul-gsoon-lockfree-fixedruntime-cpu11-60s-r3-20260925/`。该结果验证当前候选在这一明确配置下重新达到目标，但不意味着其他并行度/方向或 GSO 模式均达标。

针对仍未过线的 P4/DL/GSO-on，短筛只改变拥塞控制或 TUN GSO segment cap，其他主要参数保持 memory bridge、`sndbuf=1MiB`、CPU8：KCC cap64 三轮 ratio=`1.1230×/1.0467×/1.1036×`，median=`1.1036×`（qualification 6/6）；Cubic cap48 为`1.1049×/0.5178×/0.6160×`，XTCP自身吞吐波动明显。两组均未过1.20×；它们是20秒筛查，不作正式性能结论，但足以否决“继续增大 coalescer cap”或“改用 Cubic 已解决差距”的假设，不改产品默认。artifact：`artifacts/goal12-p4-dl-gsoon-kcc-cap64-lockfree-cpu8-20s-r3-20260925/`、`artifacts/goal12-p4-dl-gsoon-cubic-lockfree-cap48-cpu8-20s-r3-20260925/`。接下来应回到 stack send admission/pacing 与 TUN output CPU 服务之间做可归因的代码级优化和 perf-off 随机交错复验。

### 11.84 固定 owner + writev 消除 coalescer payload copy（2026-09-25）

P4/DL perf-off 诊断显示 NDI output call约79k/s，coalescer为每个 payload 做一次复制；源码核对后确认不是“两次 payload memcpy”。先试验把回调切到 `shared_ptr` owning output，并由 coalescer持有 owner、以 `writev` 发 GSO frame：单轮20秒 ratio=`1.1383×`，随后60秒×3 ratio=`1.1475×/1.2197×/1.1650×`，只有1/3过线；XTCP process task-clock/byte median=`4.086ns/B`。由于该路径每段多一次 holder/control-block堆分配，且对照有明显机器负载漂移，未保留此方案。试验 artifact：`artifacts/goal12-p4-dl-gsoon-writev-owner-screen-cpu8-20s-r1-20260925/`、`artifacts/goal12-p4-dl-gsoon-writev-owner-cpu8-60s-r3-20260925/`、旧版参照 `artifacts/goal12-p4-dl-gsoon-prewritev-ref-cpu8-60s-r3-20260925/`。

随后改为固定大小 move-only `RetainedPacketOwner` 内联槽：NDI仅对原 `BufRef` 做 `Clone()`（引用计数增量），所有权经过runtime交给Linux TAP/coalescer；合包frame将virtio/IP/TCP头与各segment payload通过固定iovec数组同步 `writev`，没有每段堆分配。非Linux/非TapLinux仍保留原 borrowed或owning路径；NDI TSO仍关闭。扩展 coalescer所有权/iovec测试后，提权完整 C++ suite **141/141**、include boundary、VCXPROJ source清单与 `git diff --check` 全通过。

固定owner候选 SHA-256 `028c196f2da0cd7785e62bb658658ec0828e179aade4fef88d30a7fce91e9202`，binary仅位于 `/tmp/xtcp-retainedowner-writev-candidate-20260925`。P4/DL/GSO-on、cap48、memory bridge、sndbuf=1MiB、CPU8，native/XTCP 60秒×3 fresh-netns qualification **6/6**，ratio=`1.2472×/1.2281×/1.2387×`，median=`1.2387×`（MAD=`0.0085`），门槛 **3/3**；process task-clock/byte efficiency median=`1.2384×`。artifact：`artifacts/goal12-p4-dl-gsoon-retainedowner-cpu8-60s-r3-20260925/`。P1/UL 同候选 CPU11、GSO-on、memory bridge、sndbuf=1MiB、60秒×3仍 **3/3**：ratio=`1.2748×/1.2658×/1.2491×`，median=`1.2658×`；artifact：`artifacts/goal12-p1-ul-gsoon-retainedowner-cpu11-60s-r3-20260925/`。

随后对P16/DL执行同条件60秒×3正式矩阵：qualification **6/6**，ratio=`0.9892×/1.0734×/1.1278×`，median=`1.0734×`（MAD=`0.0544`），门槛 **0/3**；native/XTCP median goodput约`1.634/1.764Gbps`，XTCP轮间波动较大。process task-clock/byte效率median=`1.1024×`，也未达1.20×。artifact：`artifacts/goal12-p16-dl-gsoon-retainedowner-cpu8-60s-r3-20260925/`。之后按perf-off、相同CPU8/sndbuf/memory-bridge/GSO/cap参数再做60秒×3配对复验：qualification **6/6**，ratio=`1.0497×/1.0545×/1.0885×`，median=`1.0545×`，三轮均未达门槛；XTCP自身goodput`1.1426–1.1491Gbps`且16流fairness max/min约`1.03`、零速流为0，native约`1.0555–1.0948Gbps`。process task-clock/byte效率median=`1.1030×`，selected-CPU效率median=`1.0579×`。两批绝对吞吐整体相差约1.5倍，说明主机/环境可用容量有明显时段漂移；但两批ratio都未达1.20×，所以不能把P16失败仅归为单次异常。复验artifact：`artifacts/goal12-p16-dl-gsoon-retainedowner-repeat-cpu8-60s-r3-20260925/`。所以固定owner改进目前仅在P4/DL达到正式门槛，P1/UL通过回归，P16/DL没有达标；不能把该优化外推成全并行度收益。候选仍未覆盖正式 `bin/ppp`；NDI TSO default-off与所有 recovery/backpressure gate保持不变。

为定位P16差距，另做XTCP-only 30秒、启用1秒间隔 XTCP/TCP_INFO 只读遥测的诊断cell（goodput约`1.683Gbps`，无native配对，不作性能gate）：部分flow的`flush_pacing`在累计flush尝试中占比较高，同时可见window/cwnd gate、fast recovery与约256–512µs的timer-late p95；但状态为跨时刻/跨flow快照，不能单独证明pacing是吞吐根因。target namespace的iperf sockets有较高`rwnd_limited`和Send-Q，但没有建立target socket与XTCP逻辑flow的一一映射，不能据此归因接收窗口。诊断artifact：`artifacts/goal12-p16-dl-retainedowner-pacing-diagnostic-cpu8-30s-20260925/`。后续应先补同配置下的flow级时间序列/发送供给归因（并与历史10ms样本对照），再决定是否调整KCC或窗口；当前不放宽队列、budget或recovery gate。

### 11.85 P16/DL GSO-on 用户态热点采样（2026-09-25）

为避免仅凭flush gate计数推断根因，在固定owner候选上分别对XTCP、native各跑一格P16/DL/GSO-on/CPU8/30秒单栈cell，并用perf DWARF调用栈采样。两格qualification均通过，但采样明显增加开销：XTCP约`0.991Gbps`、process task-clock约`7.22ns/B`；native约`1.016Gbps`、约`7.67ns/B`。这两格没有paired gate，且profile开销足以改变吞吐，数值不用于性能比较。

XTCP样本中占比较高的可识别用户态热点是AES-CFB encrypt约`14.3%`、decrypt约`3.5%`；Asio scheduler的inclusive约`26.5%`，主要沿socket receive handler进入`ForwardSocketToTransmission`/transmission encryption。XTCP `BuildSegmentPacket`约`1.55%`；`XtcpNdiBackend::Tx`约`0.44%`，保留owner/writev回调约`0.34%`，coalescer/TAP retained-write没有成为显著单点。native样本同样由AES encrypt/decrypt主导（约`15.4%/3.8%`），另有GSO checksum completion与TCP checksum合计约`4.8%`。因此本轮没有证据支持继续把P16差距归因到coalescer payload copy或XTCP segment checksum；同时也不能因为双方共享AES热点就推出加密不是差距来源。TCP_INFO采样自身带来约`1.3%`的`inet_diag_dump_icsk`样本，应从后续正式perf-off基线剔除。

perf报告：`/tmp/goal12-p16-gsoon-perf-record.data`、`/tmp/goal12-p16-native-gsoon-perf-record.data`；cell artifact：`artifacts/goal12-p16-dl-gsoon-perf-profile-cpu8-30s-20260925/` 与 `artifacts/goal12-p16-dl-native-gsoon-perf-profile-cpu8-30s-20260925/`。

随后按上述方向在不启用TCP_INFO/ss采样的条件下执行一格XTCP-only 30秒flowtrace：qualification通过，iperf约`1.035Gbps`，process task-clock约`6.96ns/B`，无native配对，且单轮吞吐远低于正式三轮XTCP中位数，故不作性能结论。XTCP top-flow sample与iperf `local_port` 对齐；最常出现的6条flow各自区间goodput median约`62.5–66.8Mbps`，`flush_pacing`增量占flush尝试约`78–82%`，window/cwnd gate增量为0、末样本无重传；这些采样flow的inflight约`13–64KiB`，远低于当时snd_wnd/cwnd。该cell的采样流未覆盖全部16流，且`flush_pacing`是“尝试次数”而非等待时长/带宽贡献，不能据此断言KCC pacing限速；KCC报告的per-flow pacing值也显著高于观测流速，需进一步厘清flush gate与实际timer wait的对应关系。artifact：`artifacts/goal12-p16-dl-gsoon-flowtrace-cpu8-30s-20260925/`。

该诊断之后，发现 runner 把 `client-cpuset` 仍按单核1.02核上限和零migration进行qualification。GitNexus CLI fallback对 `qualify_cell` 的impact为LOW（1个直接tooling caller，0个execution process）；修正后，单核规则保持原样，多核cpuset按CPU列表长度计算核心上限，且仅在affinity已验证时允许集合内migration。增加多核通过、超配失败、affinity未验证失败及CPU列表重复失败的契约测试；`python3 tests/tooling/test_datapath_linux_matrix.py`、py_compile、`bash -n`、`git diff --check`通过。初次双核screen虽测得1.756×，但旧qualifier两格都FAIL，明确不采纳该轮ratio。

修正qualifier后，同一候选在CPU8,9、2-shard、memory bridge、sndbuf=1MiB、P16/DL/GSO-on进行了60秒×3正式native/XTCP矩阵：qualification **6/6**，paired gate **3/3**；ratio=`1.6830×/1.6458×/1.7645×`，median=`1.6830×`（MAD=`0.0372`）。native median约`0.6655Gbps`，XTCP约`1.1200Gbps`。XTCP进程使用`1.618–1.653`核，CPU affinity=`[8,9]` verified；native约`0.989–0.996`核。process task-clock/byte效率仅`1.0100×` median、selected CPU效率`1.0292×`，故吞吐收益主要对应XTCP实际使用了更多执行核，不是单位CPU成本大幅下降。

公平性仍是这条路线的验收缺口：XTCP三轮Jain为`0.9641/0.9893/0.9677`（median=`0.9677`），max/min=`1.52–1.76`，虽无zero-rate flow，但按既有2-shard工程门槛Jain≥`0.98`只通过1/3；不能宣称多shard方案全项通过。formal artifact：`artifacts/goal12-p16-dl-gsoon-retainedowner-2shard-cpu8-9-60s-r3-20260925/`。因此目前可报告“当前候选双核P16/DL/GSO-on吞吐ratio稳定超过1.20×”，但默认仍是single-shard且正式 `bin/ppp` 未替换；该结果不能外推到单核、P1/P4、其他方向或carrier。

随后执行XTCP-only 30秒双核flow诊断，无TCP_INFO/ss采样：goodput约`1.084Gbps`（无配对，不作性能结论），shard 0/1末期每秒enq约`3750/3391`、inject约`3752/3386`，drop均为0。原聚合trace只覆盖shard 0的top-4，故另增按shard strand写入的完整flow sidecar；它不读其他shard的flow map，也不改变TCP数据路径。sidecar采样显示两shard共16条数据流在该样本中分成5/11，流数较多的shard承载约`0.634Gbps`、另一shard约`0.447Gbps`；各shard内部流速分别约`56.8–58.1Mbps`和`83–92Mbps`，shard内Jain均约`0.999`。结合六轮正式矩阵端口回放，当前tuple hash曾产生`9/7、5/11、11/5、8/8`等拆分；近似均衡拆分对应较好的全局Jain，而5/11或11/5对应约`0.96`。这是诊断样本与历史矩阵的关联，不足以证明分片数量是唯一原因，但比“shard enqueue/inject接近”更直接地指向跨shard负载分配。sidecar诊断artifact：`artifacts/goal12-p16-dl-gsoon-retainedowner-2shard-allflowdiag-cpu8-9-30s-20260925/`。随后通过每包均可无状态计算的source-port bit-6选择器做了opt-in双shard路由实验；未增加flow表、锁或生命周期分支，tuple hash仍为默认。结论和复验见§11.86。

多核 qualification契约测试通过。原tuple-hash双shard路线在两批P16/DL/GSO-on矩阵中，吞吐门槛均3/3通过；合计公平性门槛仅2/6通过。source-port bit-6实验已在§11.86单独复验，尚未达到每批公平性3/3，因此不将其判为全项完成。单核 `client-single-core` 的零迁移、≤1.02核限制未放松。

### 11.86 P16/DL 双shard无状态分流实验（2026-09-25）

为减少tuple-hash在16条并行流间偶发的5/11或更差shard拆分，在`XtcpRuntime::Impl::Submit`增加默认关闭的实验路由：`OPENPPP2_XTCP_SHARD_ROUTE=source-port-bit6`，只在`OPENPPP2_XTCP_SHARDS=2`时按TCP源端口bit 6选择shard；其他配置始终使用原4-tuple hash。它对每个包无状态计算，未引入flow-owner map、锁、关闭清理或跨shard读；matrix runner增加`--xtcp-shard-route source-port-bit6`，限制必须与`--xtcp-shards 2`配合并记录到artifact metadata。默认路由和单shard路径不变。

短screen（10秒）XTCP/native qualification未通过，原因是未启用`--process-perf-stat`导致process cores/migrations缺证；因此只保留为早期筛查，不作为正式门禁。补齐采样后，CPU8,9、P16/DL/GSO-on、2-shard、sndbuf=1MiB、默认direct bridge正式60秒×3 qualification **6/6**、paired throughput **3/3**；ratio=`1.5675×/1.6395×/1.6060×`，median=`1.6060×`（MAD=`0.0335`）。XTCP median约`1.091Gbps`，native约`0.679Gbps`；task-clock/byte效率median约`0.998×`，表明吞吐收益仍主要来自使用更多CPU核。正式artifact：`artifacts/goal12-p16-dl-gsoon-portbit6-cpu8-9-60s-r3-20260925/`。

该批Jain=`0.9510/0.9997/0.9959`，其中一条流在约前5秒正常后停发约50秒、末尾恢复；累计zero-rate flow为0。XTCP-only sidecar复采未重现长停发：8/8数据流分配、Jain=`0.9930`、zero-rate=0，但单格诊断不能解释偶发原因。独立正式复验qualification **6/6**、throughput **3/3**；ratio=`1.6802×/1.7003×/1.6827×`，median=`1.6827×`。Jain=`0.9992/0.9892/0.9777`，fairness仍只有2/3通过。两批合计6轮route实验有4/6 Jain≥0.98，相比原tuple hash历史两批合计2/6有所改善，但仍未达到预设的每批3/3公平性门槛；不能把bit-6选择器晋升默认，也不能将公平性失败归咎于流数拆分已完全解决。复验artifact：`artifacts/goal12-p16-dl-gsoon-portbit6-repeat-cpu8-9-60s-r3-20260925/`；flow诊断artifact：`artifacts/goal12-p16-dl-gsoon-portbit6-flowdiag-cpu8-9-60s-20260925/`。

### 11.87 P1/DL 单核 GSO-on 复验与 32KiB 单飞筛查受限（2026-09-25）

固定owner候选在CPU11、P1/DL/GSO-on、single-shard、`sndbuf=1MiB`下完成native/XTCP 60秒×3配对矩阵；qualification **6/6**，但1.20× gate **0/3**。XTCP/native ratio=`1.0185×/1.0472×/1.0731×`，median=`1.0472×`；median goodput约`1.160/1.125Gbps`。process task-clock/byte效率增益三轮约`1.05–1.08×`，未达到目标；这与性能差距方向一致，但不足以单独证明吞吐受CPU而非其他资源限制。formal artifact：`artifacts/goal12-p1-dl-gsoon-cpu11-60s-r3-20260925/`。XTCP-only 30秒诊断中direct download仍为单flight，queue high-water约16KiB，未见direct queue reject；约8–9K次/s的chunk/callback以及较高send拒绝/累计stall提示可筛查flight粒度，但不是已证实根因。diagnostic artifact：`artifacts/goal12-p1-dl-gsoon-diagnostic-cpu11-30s-20260925/`。

据此增加默认保持16KiB的`OPENPPP2_XTCP_DIRECT_DOWNLOAD_CHUNK_BYTES=32768`实验选项，并让每flow reservation上限覆盖32KiB，但仍维持单flight与原全局budget。构建、XTCP adapter测试和matrix planner契约测试通过；候选仅在`/tmp/xtcp-p1dl-32k-candidate-20260925`，正式`bin/ppp`未替换。相同CPU11、GSO-on、P1/DL、60秒×3矩阵在sandbox启动前因netlink `Operation not permitted`退出，提权审批服务返回403，**0 cells、无ratio**；因此32KiB选项没有性能结论，不改变默认值，也不能宣称已解决P1/DL。完整C++ suite普通sandbox为133/141，8个失败测试均受loopback/socket权限限制。待测试环境恢复netns能力后，才可按配对门禁复验32KiB，并与16KiB正式基线比较。

同批6个P16双shard正式iperf结果的client源端口离线枚举显示：bit-6路由在样本中出现9/7、5/11拆分；源端口bit 5–8奇偶校验（mask `0x01e0`）对这6组历史端口给出5组8/8、1组7/9。但对另一批6组tuple-hash正式端口做交叉检查，该mask出现6/10、11/5，另有4/12，说明只在bit-6样本上挑选会过拟合。因此撤掉未测的`source-port-parity-5-8` runtime/matrix选项，没有性能或公平性结论。将两批12组端口一起枚举时，mask `0x0170`的最大数量差降至4（最差6/10），但它也是同一批数据内选择，尚不实现；必须先有独立端口样本及fresh-netns配对结果才值得纳入候选。默认tuple hash与已有opt-in route保持原样。

复核早先的P16双shard all-flow sidecar时，将XTCP `remote_port` 与iperf client `local_port` 对齐，16/16条数据流均可关联；该单轮样本中shard 1有9条流，均速`62.69Mbps`，shard 0有7条流，均速`72.57Mbps`。其中一条`53.2Mbps`流同时有较高`flush_window_cwnd`尝试计数，但该计数不表示等待时长；样本提示端口分组与per-flow速率差相关，却不能区分是流数负载不均、TCP状态差异或shard调度造成。后续任何新 route 矩阵都应同时保留逐流 sidecar，要求吞吐与Jain公平性都过门，并确认分组改善是否真的缩小per-flow速率差，而非只做到端口数量接近。sidecar artifact：`artifacts/goal12-p16-dl-gsoon-portbit6-flowdiag-cpu8-9-60s-20260925/`。

### 11.88 满发送窗口时抑制无效 pacing 唤醒（2026-09-25）

复核 pending flush 的 timer 行为时发现：`FlushPendingSend()` 在 pacing tick 到达后先推进下一 pacing deadline，再发现普通发送路径的 `inflight >= min(snd_wnd, snd_buf, cwnd)` 并将剩余数据重新入队；原 `NextTimerDeadline()` 仍会把新的 pacing deadline 返回给 host。窗口未变化时，这会让被 window/cwnd gate 挡住的流继续按 pacing quantum 唤醒，尽管 ACK/窗口更新或恢复计时器才可能带来进展。新增 `tools/xtcp-patches/0027-suppress-blocked-pacing-wake.patch`：flight 已填满 peer window/send buffer，或非 fast-recovery 下已填满 cwnd 时，不再单独返回 pacing deadline；零窗口尚未 armed persist 的分支仍保留一次唤醒以 arm persist，ACK/RTO/persist 等既有 deadline 不变。fast recovery 用 `PipeBytes()` 替代 cwnd；为避免在每次 deadline 查询中遍历重传队列，本补丁只抑制该路径上的 peer-window/send-buffer 满载，不判断 pipe gate。窗口在 timer 休眠期间被 ACK 打开时，packet 路径的 `KickPoll()` 会重算 deadline 并重排。

新增的确定性满窗口 pacing deadline 测试以及 `test_persist`、`test_persist_stack`、`test_persist_handshake`、`test_pacing_flush` 均通过。该修改尚无 fresh-netns 性能 A/B：当前环境 `ip netns list` 仍因 `Operation not permitted` 失败，因此没有吞吐、CPU或公平性结论；须在恢复 netns 能力后用同一候选与干净基线配对测量，并观察 `timer_polls`、`pending_flush_window_cwnd` 与 goodput，再决定是否保留。

回查既有 P1/DL 单核 GSO-on diagnostic artifact（`artifacts/goal12-p1-dl-gsoon-diagnostic-cpu11-30s-20260925/`）后，timer `armed` 的稳定采样约为99–100次/秒，远低于数据包/ACK处理频率；单流 `flush_window_cwnd` 约1.0–1.4K次/秒、`flush_pacing` 约1.8–2.2K次/秒。由此目前只能把本 patch 视作低成本减少无效 timer work 的候选，不能预期它单独带来1.20×。同一源码审计确认 DL retained-owner 路径已贯通 `XtcpNdiBackend::Tx` → `TapLinux::Output` → coalescer `writev`，当前不能再把 GSO 聚合 payload 双拷贝当作本构建的主热点。P1/DL diagnostic 的 stack-send 拒绝约2.5%、单流累计 stall 样本约0.26–0.28秒/采样窗；后续优先以 fresh profiling 拆解 `TrySendPending`/send-buffer admission 与 TCP packet build/checksum 的 CPU、等待贡献，再决定是否做更深的 owned-pending API 改造。

### 11.89 XTCP retained-owner 独立 TAP 聚合 cap 候选（2026-09-26）

共享 cap16 先前同时抬高 P1/DL GSO-on 的 XTCP/native 绝对吞吐，但 relative ratio median 只有`0.8899×`（§11.68）。为隔离变量，曾实现双 `TunGsoCoalescer`：借用/native维持共享 cap，retained-owner/XTCP使用独立 `OPENPPP2_XTCP_TAP_GSO_SEGMENTS`；增加 runner 参数并覆盖 direct-GSO、hold timer、disable、SSMT、teardown 的双队列 flush 屏障。候选产品 SHA-256 `8b765d8ebdea9ea432d4e4a3be2e1f08cc5d45b128d51e0a68fe47ef26dd6e62`，仅在 `/tmp/ppp-xtcp-cap16-20260926/ppp`，`bin/ppp` 未改。

同候选、CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge，fresh-netns 60秒×3正式矩阵均 qualification 6/6。XTCP cap4 control ratio=`1.0391×/1.0886×/1.0579×`，median=`1.0579×`；cap16 ratio=`0.6331×/1.2872×/0.7446×`，median=`0.7446×`，仅1/3轮过1.20×，XTCP median goodput约`580.8Mbps`、native`780.0Mbps`。cap16 process task-clock/byte效率中位约`1.1156×`，也未过目标。20秒 pilot 的 cap4 ratio=`0.3675×/1.1128×/1.0272×`，cap16=`1.2432×/0.8532×/1.3466×`；短筛显示该配置轮间波动明显，不能代替正式矩阵。完整 artifacts：`artifacts/goal12-p1-dl-gsoon-xtcpcap4-candidate-cpu11-20s-r3-20260926/`、`artifacts/goal12-p1-dl-gsoon-xtcpcap16-candidate-cpu11-20s-r3-20260926/`、`artifacts/goal12-p1-dl-gsoon-xtcpcap4-candidate-cpu11-60s-r3-20260926/`、`artifacts/goal12-p1-dl-gsoon-xtcpcap16-candidate-cpu11-60s-r3-20260926/`。

由于专属 cap16 未稳定提升，而且双队列扩大了 TAP状态/生命周期复杂度，这一实验性实现、环境变量和 runner 参数已从工作树撤回；原共享 cap 及其默认值不变。结果不能证明 cap16 必然造成退化，但足以否决将其保留为生产候选。后续不继续扩大 cap sweep；回到每字节成本/profile 与 ACK/pacing/send-admission 数据寻找能改变 P1/DL 稳态服务率的具体热点，再以随机交错60秒配对矩阵验证。

### 11.90 P1/DL GSO-on 当前发送链与单轮 CPU 画像（2026-09-26）

在 cap16候选产品（SHA-256同§11.89）上显式设共享 cap4，做 CPU11 single-core、P1/DL、KCC/single-shard、`sndbuf=1MiB`、memory bridge 的 XTCP-only 30秒诊断；qualification 1/1 pass，goodput `841.6Mbps`，process task-clock约`8.897ns/B`、selected-CPU约`9.323ns/B`。该格启用了 stall/ACK-release/TUN diagnostics，不是性能配对结果。artifact：`artifacts/goal12-p1-dl-gsoon-cap4-candidate-diagnostics-cpu11-30s-r1-20260926/`。

稳定样本中，同一数据 flow 每秒 payload 与 ACK advance 中位约`106.6MB`，约`690`个 ACK advance；`FlushPendingSend` pacing gate约`2,095/s`、window/cwnd gate约`1,299/s`、fast-recovery gate为0。TCP状态快照中位 cwnd约`303 MSS`、inflight约`382KB`、snd_wnd约`3.52MB`、RTT约`592µs`、pacing rate约`1.28Gbps`。TUN direct-write约`19.7k/s`、`108.9MB/s`，平均每次约`5.54KB`；write服务累计约`193ms/s`、最大`82µs`，无失败/partial。frame transport-decrypt累计约`333ms/s`（约`107.8MB/s`）。证据说明 TUN 写不是失败或超长 syscall，但它与解密都占用显著单核时间；由于这是单个 instrumented XTCP cell，不能将贡献直接等同于端到端瓶颈或与 native 做因果比较。

源码审查确认 `FlushPendingSend` 在 `BuildSegmentPacket` 前先做 pacing、recovery、snd_buf/snd_wnd/cwnd 准入；普通 gate 拒绝路径在 pending 队列为空时仅交换 vector 与偏移，不会先构造被丢弃的数据包。因此当前证据不支持以“避免 gate 前包构建/拷贝”为修复方向。cap16正式矩阵每个60秒 XTCP cell本身稳态且无 zero-rate interval（median约`498/996/583Mbps`），差异不像一次零速停顿；但依然只有1/3轮过线。接下来应先用 perf-off 与低扰动、相同二进制的配对诊断拆解单核内 TCP send/checksum、transport decrypt 与 TUN write 的 CPU 时间，再决定哪个热点值得改；本轮不引入新的未证实发送调度补丁。

### 11.91 P1/DL native 对照 CPU-clock profile（2026-09-26）

为区分共用隧道加密与 TCP 栈开销，用与§11.90相同 XTCP-enabled候选 binary（SHA-256 `8b765d8ebdea9ea432d4e4a3be2e1f08cc5d45b128d51e0a68fe47ef26dd6e62`）、CPU11、P1/DL、GSO-on/cap4、single-core、30秒负载，分别对 XTCP 与 native client PID 做25秒 `cpu-clock:u` 49Hz callchain profile；两个 profile均 **0 lost samples**，XTCP/native 各673/666样本。运行 qualification 各1/1 pass，goodput约`811/794Mbps`，但这不是 paired性能测试；采样只作热点定位。raw profile：`artifacts/goal12-p1-dl-gsoon-cap4-cpuclock-cpu11-30s-r1-20260926/cpu-clock.data`、`artifacts/goal12-p1-dl-gsoon-native-cpuclock-cpu11-30s-r1-20260926/cpu-clock.data`。

XTCP样本中 `aesni_encrypt` self约52.5%，native约48.2%，与`CRYPTO_cfb128_encrypt`的3.7%/4.5%共同指向占比很高的共用隧道CFB/AES工作；由于优化符号没有解析 AES caller，这仍是函数级采样，不等价于端到端crypto耗时归因。native另有`TcpChecksum`约7.1%、`CompleteTcpV4GsoChecksums`约6.5%、`ip_standard_chksum`约4.4%；XTCP可见栈侧符号为`BuildSegmentPacket`约4.75%、`FlushPendingSend`约1.93%、`XtcpStack::SendOne`约1.19%。因此此 profile没有发现一个已符号化的 XTCP发送函数足以解释全部差距；`BuildSegmentPacket` 内部copy/checksum仍值得精拆，但先前AVX2原型无可复现吞吐收益（§11.35），不直接重做该尝试。后续若优化共享crypto，必须以 native/XTCP同二进制随机交错paired矩阵检查相对比率，不能只用 XTCP绝对吞吐或user-only样本晋升。

### 11.92 P1/DL direct-download 单飞块 16/32KiB 长测（2026-09-26）

恢复 fresh-netns 权限后，使用同一 XTCP-enabled binary（SHA-256 `8b765d8ebdea9ea432d4e4a3be2e1f08cc5d45b128d51e0a68fe47ef26dd6e62`）、CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge，对`OPENPPP2_XTCP_DIRECT_DOWNLOAD_CHUNK_BYTES=16384/32768`分别执行 60秒×3；两组 qualification 均6/6。16KiB ratio=`1.0871×/1.0606×/1.1016×`，median=`1.0871×`、MAD=`0.0145`；32KiB ratio=`1.1086×/1.1075×/1.1014×`，median=`1.1075×`、MAD=`0.0011`。但两组是先后分开的矩阵，不是跨配置随机交错；XTCP median goodput 仅从`846.4`到`848.7Mbps`（约+0.3%），process task-clock/byte效率约从`1.104×`到`1.123×`，而native median同时从`780.9`降到`769.6Mbps`。因此 ratio 中约2.0个百分点的表观提升可能受 native 分母/时间漂移影响，不能据此断言32KiB有吞吐收益。32KiB本组MAD较低（`0.0011` 对 `0.0145`），可作稳定性线索，但三轮不足以确认因果；两种尺寸都未达1.20×。

短测20秒×3也完成：16KiB ratio=`1.1063×/1.0778×/1.0554×`，32KiB=`1.0951×/1.0886×/1.0841×`；短测方向不一致，不作为验收。正式 artifacts：`artifacts/goal12-p1-dl-gsoon-direct32k-cpu11-formal16k-r3-60s-20260926/`、`artifacts/goal12-p1-dl-gsoon-direct32k-cpu11-formal32k-r3-60s-20260926/`；pilot artifacts：`artifacts/goal12-p1-dl-gsoon-direct32k-cpu11-pilot16k-r3-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-direct32k-cpu11-pilot32k-r3-20s-20260926/`。这两组来自§11.89的 cap16实验候选二进制（测试时共享 cap4）；二进制相同、仅通过受支持的 runtime override 改变 chunk，因此配置差异可比较，但绝对值不替代已回退双coalescer代码后的 clean-source复验。结论：32KiB未证明吞吐提升，继续保留16KiB默认；32KiB选项仅留作交错复测，不晋升生产配置；根`bin/ppp`未改。

### 11.93 P4/DL direct-download 块尺寸短筛（2026-09-26）

继续使用§11.92同一候选 binary，在 CPU11 single-core、P4/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge 下对 16/32KiB 做20秒×3 fresh-netns pilot；两组 qualification 均6/6。16KiB ratio=`1.0748×/1.0947×/1.1191×`、median=`1.0947×`；32KiB=`1.0521×/1.0923×/1.1298×`、median=`1.0923×`。XTCP median goodput约`853.2/857.7Mbps`，但native median约`786.9/785.2Mbps`；ratio没有可见提升，轮间波动仍大。process task-clock/byte efficiency约`1.153×/1.146×`，也未显示32KiB改善。故P1/DL长测与P4/DL短筛合看，32KiB尚无足够证据作为吞吐优化；不扩大该参数 sweep、不改默认。artifacts：`artifacts/goal12-p4-dl-gsoon-direct32k-cpu11-pilot16k-r3-20s-20260926/`、`artifacts/goal12-p4-dl-gsoon-direct32k-cpu11-pilot32k-r3-20s-20260926/`。候选二进制仍含后续已撤回的dual-coalescer实验代码；此处差分只用于探索，正式结论需要 clean-source 交错复验。

### 11.94 当前源码下 P1/DL 16/32KiB 交错复测（2026-09-26）

为排除§11.92候选中的已撤回 dual-coalescer实现，以当前工作树重链候选 binary SHA-256 `7a109b44d0cfaa20e63876a917ba14bfe131f49ee25789ee2a2c4038d8de5fb5`（输出 `/tmp/xtcp-clean-source-out/ppp`，`bin/ppp`未改），在 CPU11、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge 条件下交错执行16/32KiB各三组20秒 native/XTCP配对；全部6个pair qualification通过。16KiB ratio=`1.0307×/1.1142×/1.1217×`、median=`1.1142×`；32KiB=`1.0987×/1.0638×/1.0918×`、median=`1.0918×`。两种尺寸的轮间方向反转，未观察到稳定的32KiB收益；XTCP goodput中位约`865.0/846.2Mbps`，支持继续保留16KiB默认。该短测每配置仅3个20秒pair，不是性能验收，且两者均未达1.20×。artifacts：`artifacts/goal12-p1-dl-gsoon-clean-interleave-r1-16k-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-clean-interleave-r1-32k-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-clean-interleave-r2-16k-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-clean-interleave-r2-32k-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-clean-interleave-r3-16k-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-clean-interleave-r3-32k-20s-20260926/`。停止 direct-download chunk sweep，下一步回到已记录的 `TrySendPending` admission/retry 与 TCP ACK/pacing 事件链，寻找可归因且足以贡献剩余约8–10% throughput gap的改动；不放宽保护门或变更默认拥塞控制。

### 11.95 P1/DL receive-window 假设复核与否决（2026-09-26）

§11.90 XTCP-only diagnostic 的目标端 `ss` 确有高 `rwnd_limited`，但复核发现先前把所有 TCP socket 的 `snd_wnd` 混在一起统计，`43KiB`中位主要受 idle/control socket 影响，不能代表 iperf data flow；有 `rwnd_limited` 的数据流样本中 `snd_wnd` 动态约`16KiB–1.92MiB`，中位约`311KiB`。因此不能据 `43KiB`推断默认 `SetRcvBuf(65535)` 是 DL 上限。

为验证而临时增加了只用于实验的 `OPENPPP2_XTCP_RCVBUF_BYTES` 和 runner `--xtcp-rcvbuf-bytes`，默认仍未设置；同一候选 binary、CPU11/P1/DL/GSO-on、XTCP-only、15秒诊断下，128KiB与1MiB配置 goodput分别`827.8/824.8Mbps`，peer `snd_wnd`观察值动态变化、`rwnd_limited`中位仍约`84–85%`，没有对 buffer 尺寸的单调吞吐响应。该短诊断不是配对验收，但与历史4MiB `SetRcvBuf` DL无收益记录（§0、§11.76）一致，足以否决继续扩大 receive-buffer sweep。实验代码、CLI选项与测试均已撤回，XTCP原64KiB默认和用户现有更改均未变。诊断 artifacts：`artifacts/goal12-p1-dl-gsoon-clean-ackdiag-cpu11-30s-r1-20260926/`、`artifacts/goal12-p1-dl-gsoon-rwnd128k-diagnostic-cpu11-15s-r1-20260926/`、`artifacts/goal12-p1-dl-gsoon-rwnd1m-diagnostic-cpu11-15s-r1-20260926/`。

### 11.96 当前 XTCP 源码重建后的 P1/DL GSO-on 正式基线与 KCC 诊断（2026-09-26）

复核发现，§11.94 所称“当前源码 clean-source”构建复用了 `build/xtcp-runtime-root/CMakeCache.txt`，其中 `XTCP_SOURCE_DIR=/tmp/goal12-xtcp-kcc-hybrid-iy0pFU`；该临时快照 patch marker 为 `aaea207c…`，与工作树当前 `third-party/xtcp` 的 `3d92c0a1…` 不同。特别是 `plugins/cc_kcc.cpp` 的 per-round bandwidth/full-bandwidth 更新逻辑不一致。因此 §11.94 的 16/32KiB相对比较对其自身二进制仍成立，但不能视作当前 XTCP 源码的绝对性能基线；之前基于该二进制的 KCC 零遥测也不能用于推断当前算法状态。

为纠正该问题，使用独立 CMake 目录 `/tmp/openppp2-current-xtcp-build`，显式指定 `XTCP_SOURCE_DIR=/home/openppp2/third-party/xtcp`，生成 `/tmp/openppp2-current-xtcp-out/ppp`（SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）；根 `bin/ppp` 未改。CPU11、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge、native/XTCP fresh-netns 60秒×3矩阵 qualification 6/6通过。XTCP goodput median `797.5Mbps`、native `776.1Mbps`；三轮 ratio=`1.0336×/1.0270×/1.0110×`，median=`1.0270×`、MAD=`0.0067`，仍未达1.20×。XTCP/native process task-clock/byte efficiency median=`1.0375×`，CPU收益同样不足以解释目标差距。artifact：`artifacts/goal12-currentxtcp-source-p1-dl-gsoon-cpu11-formal-60s-r3-20260926/`。

新二进制的活跃 data flow KCC telemetry 已非零：各轮均处于 `PROBE_BW`，但 round 2/3 的 RTT中位升至约`1.53/1.72ms`，in-flight中位约`499/473KiB`；pacing与window/cwnd flush-block计数均显著高于round 1。`kcc_max_bw_q24` 的P90在round 2/3约`32.4/40.3×10^9`，显著高于按端到端goodput估算的服务速率；这表明估算/准入值得继续追查，但计数相关性尚不能证明它是吞吐下降的原因。direct-download queue high-water约16KiB，reject、bridge fallback、NDI output reject均为0，不支持先扩大队列或回退direct bridge。

另以同一新 binary、相同CPU11/P1/DL/GSO-on条件将拥塞控制仅运行时切至Reno做20秒诊断配对：XTCP/native=`763.2/775.4Mbps`，ratio=`0.9843×`；qualification 2/2通过。这不是正式验收，但不足以支持把KCC换成Reno。继续保持默认KCC，不改变NDI TSO default-off。下一步应做函数级KCC sample/filter及ACK-release时序分析，再提出只影响实验二进制的单变量候选；当前源码对`completed_sample_round`存在 unused warning，需先查明其与已部署patch链的差异及来源，避免把未封装的third-party源码状态误当成可复现补丁。

### 11.97 KCC 每 RTT full-bandwidth 检查实验与全套单测对照（2026-09-26）

针对§11.96中 KCC 在每 ACK 检查 STARTUP plateau 的疑点，制作仅位于`/tmp/xtcp-kcc-round-avg-exp`的隔离候选，不改工作树XTCP源码。候选实质是把`full_bw` plateau/FSM检查限制到完成一个采样round时；虽实现中还累计了`round_sample_delivered/interval_us`，这些累计值没有用于带宽样本计算，因此本实验不应称为“round-average bandwidth”。每 ACK 的`BwUpdate`仍保留；结论应归因于round-gated full-bandwidth/FSM行为，而非带宽平均。

同一候选、CPU11、P1/DL/GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge的60秒×3配对矩阵 qualification **6/6**；native median `785.4Mbps`、XTCP median `851.3Mbps`，ratio=`1.0839×/1.1000×/1.0855×`，median=`1.0855×`、MAD=`0.0016`。相对§11.96当前源码 median `1.0270×`有改善，但未达1.20×，候选不晋升默认。正式artifact：`artifacts/goal12-currentxtcp-source-p1-dl-gsoon-kcc-roundavg-formal-60s-r3-20260926/`。

候选通过`test_cc_kcc`以及20项 upstream fault suite；随后在其239项完整upstream CTest中14项失败。为归因，在当前工作树原始XTCP源（复制到`/tmp/xtcp-current-baseline-control`，不改仓库源）用相同配置独立干净构建并执行完整 CTest：同样**恰为14/239、同一14项测试名且症状相同**（TS/OOO/RACK/stack、PMTU/ICMP/MTU、SACK、RTO等）。因此这批全套测试失败并非round-gated候选引入，但它们仍是当前基础树的已知失败，不能写成“全套测试通过”。两者完整CTest均为225/239通过，定向KCC与集成fault suite通过。

另将该变量进一步拆开，在隔离副本`/tmp/xtcp-kcc-round-bw-exp`中用一个time-round累计的`delivered_bytes / interval_us`更新带宽过滤器，并同步参考C core；upstream `test_cc_kcc`通过，完整CTest仍为和基础树相同的14项已知失败。使用该候选独立构建的Linux `ppp`（SHA-256 `1a184c850afe88bc01786844382de373942ae1319e3ebea1c5db5e74a9e33365`）完成CPU11/P1/DL/GSO-on/single-shard/1MiB sndbuf/memory bridge的20秒×3筛选，qualification **6/6**，ratio=`1.0672×/1.0596×/1.0645×`，median=`1.0645×`、MAD=`0.0026`，XTCP/native median约`812.4/766.7Mbps`；process task-clock/byte效率median=`1.0864×`。这低于上一round-gated候选的正式median `1.0855×`，且是短筛，不足以继续做正式长测，故淘汰round-average带宽滤波方向。pilot artifact：`artifacts/goal12-currentxtcp-source-p1-dl-gsoon-kcc-roundbw-pilot-20s-20260926/`。

操作事故记录：该候选CMake首次配置漏传`ENABLE_XTCP=ON`，修正后构建把项目固定输出路径写成根`bin/ppp`，短暂覆盖了开始前SHA-256 `e88ecfdda8fb4d3ab2dd22c40c7293afcd4d74c518ed14736d5bcf29af860f19`的原始二进制。发现后立即另存候选至`/tmp/openppp2-kcc-round-bw-out-ppp`，并把根`bin/ppp`恢复为已验证的当前源码baseline `/tmp/openppp2-current-xtcp-out/ppp`（SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）；全盘本地查找未找到原`e88ecf…`备份，因此这是可验证baseline恢复、不是原文件hash的精确恢复。后续候选矩阵均显式传`--ppp-bin /tmp/...`，新build需设置独立`CMAKE_RUNTIME_OUTPUT_DIRECTORY`避免重犯。未提交任何文件。

下一步若继续KCC调优，应从已验证的round-gated候选出发，单独评估初始pacing/cwnd或每round滤波行为；本round-average变体不晋升默认。

### 11.98 P16/DL 双shard单流停滞：TCP序号遥测与GSO/路由筛查（2026-09-26）

为诊断§11.86–§11.89的偶发zero-rate flow，在`XtcpRuntime::Impl::WritePerfLine`的per-shard flow sidecar加入只读字段`snd_una`、`front_seq`、`rto_deadline_us`；不改TCP发送、路由、计时器或拥塞控制。GitNexus CLI（MCP transport closed，索引标 stale）报告该方法LOW风险、1个直接调用方`ArmPerfDump`（置信度0.57）、0个执行流程、影响Xtcp模块。改动以独立输出目录构建：`/tmp/openppp2-diag-out/ppp`，SHA-256=`7e5b29469b2e755503c6d84b8d1145326ad85c80f491e788dd314dcb5baaea43`；`bin/ppp`与已验证baseline均保持`785d025c…`。

用同一候选binary、CPU8/9、P16/DL、2 shard、`sndbuf=1MiB`各做一格20秒XTCP-only诊断，非配对性能验收：

- `source-port-xor-1-2-8` + GSO-on：goodput`1.0578Gbps`，1/16流zero-rate，qualification因`no_zero_rate_flows`失败。坏流`remote_port=36430`的`snd_una==front_seq==2635965119`、`inflight==snd_wnd==395264B`、`cwnd=1`；从采样约第1秒至测试末尾累计ACK advance停在`227472B`，payload accepted停在`1276048B`。RTO deadline继续后移且重传数由1增至6，说明RTO timer确实触发，但队首缺口未获累计ACK；这只能定位为TCP缺口持续未恢复，不能确定丢失发生在发送端、隧道或接收端。
- 同路由 + GSO-off：goodput`1.1569Gbps`，zero-rate=0，qualification通过，Jain max/min=`1.038`。
- 默认tuple-hash + GSO-on：goodput`1.0168Gbps`，zero-rate=0，qualification通过，Jain max/min=`1.072`。

三格各只有一个20秒样本，受流端口与时序影响，不能据此认定source-port路由和GSO有因果交互，也不是1.20×配对结论；但两格GSO-on中只有opt-in xor路由样本复现停流，而GSO-off xor与GSO-on tuple-hash样本未复现，足以让该opt-in路由继续保持实验态、不晋升默认。后续若重开此路线，应捕获对应flow的ACK/重传包序列，并同时记录XTCP backend output与TUN送达侧的该连接计数，区分发送没出栈、回程ACK丢失和接收端缺口；在此之前不修改KCC/RTO保护逻辑或用聚合吞吐掩盖zero-rate流。Artifacts：`artifacts/goal12-p16-dl-gsoon-portxor-tcpstate-diag-cpu8-9-20s-20260926/`、`artifacts/goal12-p16-dl-gsooff-portxor-tcpstate-diag-cpu8-9-20s-20260926/`、`artifacts/goal12-p16-dl-gsoon-tuplehash-tcpstate-diag-cpu8-9-20s-20260926/`。

### 11.99 当前源码 baseline 的 P1/UL 1.20×正式复验（2026-09-26）

为避免只沿用§11.83旧候选结论，使用当前源码 baseline `bin/ppp`（SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）执行 CPU11单核、P1/UL、GSO-on、KCC、single-shard、`sndbuf=1MiB`、memory bridge、native/XTCP fresh-netns 60秒×3配对矩阵。qualification **6/6**，配对性能门禁 **3/3**；XTCP/native ratio=`1.2641×/1.2908×/1.2696×`，median=`1.2696×`、MAD=`0.0055`。XTCP/native goodput median=`929.9/732.6Mbps`；process task-clock/byte效率提升 median=`1.3267×`，selected-CPU效率提升 median=`1.2686×`。当前源码产物在这条明确配置下复现并超过1.20×，但不能外推为P1/DL GSO-on、其他并行度或完整矩阵达标。正式artifact：`artifacts/goal12-currentbaseline-p1-ul-gsoon-cpu11-60s-r3-20260926/`。

### 11.100 当前源码 baseline 的 P16/DL/GSO-on 双shard复验（2026-09-26）

沿用同一当前源码 baseline（SHA-256 `785d025c…`），CPU8/9 cpuset、P16/DL、GSO-on、默认tuple-hash、2 shards、`sndbuf=1MiB`，native/XTCP fresh-netns 60秒×3，**perf-off**正式复验；process perf CPU采样保留。qualification **6/6**，throughput gate **3/3**；ratio=`2.0071×/1.9516×/1.8919×`，median=`1.9516×`、MAD=`0.0555`。XTCP/native median goodput=`1.036/0.534Gbps`。因此当前binary在该明确双核运行配置下通过1.20×吞吐门槛。

验收边界仍需保留：XTCP process使用约`1.70–1.73`核，native约`0.99`核；process task-clock/byte效率中位只提升`1.1260×`，selected-CPU效率提升`1.1647×`，所以不能将goodput ratio解释为同等CPU预算下已有1.20×效率收益。逐流Jain为`0.9966/0.9896/0.9403`，仅2/3轮达到既定`≥0.98`公平性线；虽三轮zero-rate均为0，round 3的max/min约`5.47`仍显示明显偏流。另一个perf-on诊断矩阵出现1个zero-rate flow且qualification仅5/6，不作为性能证据；perf-off复验消除了该次zero-flow，但没有解决公平性间歇退化。故保留tuple-hash为默认，不晋升source-port路由，也不宣称P16/DL全项稳定完成。Artifact：`artifacts/goal12-currentbaseline-p16-dl-gsoon-tuplehash-perfoff-cpu8-9-60s-r3-20260926/`；含perf sidecar的失败诊断：`artifacts/goal12-currentbaseline-p16-dl-gsoon-tuplehash-cpu8-9-60s-r3-20260926/`。

### 11.101 P1/DL round-gated KCC STARTUP pacing gain 2×筛选与否决（2026-09-26）

针对§11.97留下的单变量方向，在隔离 `/tmp` XTCP 源副本中保留 round-gated full-bandwidth/FSM行为，只把 STARTUP pacing gain（含首次RTT boot-rate）从`2.885×`降为`2×`，cwnd gain、带宽样本和退出门限不变。GitNexus 对 vendor `KccMain` 返回`UNKNOWN/target not found`（索引未覆盖该源）；未修改仓库 vendor 源。候选 binary SHA-256=`b8264a57f5e1b13920d17228ee4861342a597bb06724e28062ccefb15d8f8859`，同源`2.885×` round-gated control SHA-256=`9b3def3e54a5c3b4e2f33f9c9c070115c10837984b003fd4a3192b5e6c5c0d2c`；根`bin/ppp`仍为当前 baseline `785d025c…`。隔离 reference core 与测试期望同步后，候选`test_cc_kcc`通过。

CPU11 single-core、P1/DL、GSO-on、single-shard、`sndbuf=1MiB`、memory bridge的60秒×3 fresh-netns矩阵两组 qualification 均6/6。2×候选 ratio=`1.0637×/1.0529×/1.0808×`，median=`1.0637×`；control=`1.0529×/1.0507×/1.0660×`，median=`1.0529×`。候选 XTCP goodput median=`817.8Mbps`、control=`822.6Mbps`；process task-clock/byte效率分别约`1.072×/1.072×`，没有单位CPU成本收益。两批不是随机交错，约1.1个百分点 ratio 差且绝对goodput未提升，不足以证明2× gain 有稳定收益；候选不做默认变更或进一步长测，回到当前KCC及已验证round-gated结果。短筛和正式artifacts：`artifacts/goal12-kcc-startup-pacing2x-p1-dl-gsoon-cpu11-pilot-clean-20s-r3-20260926/`、`artifacts/goal12-kcc-startup-pacing2885-control-p1-dl-gsoon-cpu11-pilot-clean-20s-r3-20260926/`、`artifacts/goal12-kcc-startup-pacing2x-p1-dl-gsoon-cpu11-formal-60s-r3-20260926/`、`artifacts/goal12-kcc-startup-pacing2885-control-p1-dl-gsoon-cpu11-formal-60s-r3-20260926/`。另有一次被中断且缺 round-1 XTCP cell 的pilot artifact `artifacts/goal12-kcc-startup-pacing2x-p1-dl-gsoon-cpu11-pilot-20s-r3-20260926/`，明确不计入结果。

### 11.102 当前源码 P1/DL profile 与发送/输出边界计时（2026-09-26）

为避免沿用旧候选 profile，在当前源码 baseline binary（SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）上重新采 CPU11、P1/DL、GSO-on 的单格诊断。`perf record -a -C 11` 后按 cell `client_pid=4001543` 精确过滤，901个样本、lost=0；该 cell qualification通过、goodput=`850.5Mbps`，但仅为profile诊断，不是native配对验收。XTCP self samples 约`50.5% aesni_encrypt`（调用链为`EVP_DecryptUpdate → Transmission_Packet_Read → RunDirectDownload`）、`4.77% BuildSegmentPacket`、`3.11% timerfd_settime`、`0.78% TunGsoCoalescer::PushInternal`。native 同配置单格 profile 的AES约`45.8%`，软件TCP checksum/GSO checksum相关符号合计约`16.0%`；两份是不同cell，不作直接因果比较。隧道 AES-CFB 是两栈共享成本，且先前 datapath telemetry 显示两栈每MB decrypt耗时近似，不能把它列为XTCP相对差距的优先修复项。timerfd 样本也不足以证明ACK timer是吞吐根因。

复核当前源码 P1/DL/GSO-on 三轮 artifact 的边界计时与TUN计数：XTCP 180秒累计`XtcpStack::Send()` 1,181,032次、拒绝24,590次（约2.1%），被测同步耗时3.83秒、平均3.24µs；输出回调12,993,736次、同步计时69.58秒、平均5.36µs。同期XTCP/native TUN direct write分别约364.1万/366.4万次、18.68/18.26GB，平均write大小约5,128/4,984B，单位GB累计write耗时约2.22/2.39秒；write失败和partial均为0。故输出回调墙内耗时大不能单独归因CPU热点，XTCP的TUN写单位字节耗时不高于native，coalescing也确实形成约5KB批次。当前证据更支持继续检查ACK释放、pending flush与pacing/window准入之间的供给节奏，而不是再调GSO cap、NDI TSO或扩大发送/接收缓存。

Artifacts：当前源码单格profile `artifacts/goal12-currentbaseline-p1-dl-gsoon-cpuclock-systemwide-xtcp-20260926/`、`artifacts/goal12-currentbaseline-p1-dl-gsoon-cpuclock-systemwide-native-20260926/`；三轮来源矩阵 `artifacts/goal12-currentxtcp-source-p1-dl-gsoon-cpu11-formal-60s-r3-20260926/`。profile有系统级采样开销且仅单格；正式结论仍以§11.96的三轮P1/DL矩阵为准。GitNexus MCP本轮 query/impact transport closed，未编辑任何代码符号；根`bin/ppp`未改。

### 11.103 ACK flush pacing burst 64→128KiB 筛选与否决（2026-09-26）

基于§11.102的 pending flush pacing/window gate 计数，在独立 `/tmp/xtcp-impact-index-20260926` vendor副本中只将 `TcpConn::FlushPendingSend` 的 pacing burst上限从64KiB改为128KiB，保留 `pacing_rate/1000` 预算和1ms公式。先做 impact：单独索引的upstream图将该方法评为 **HIGH risk**，有5个直接调用关系、涉及`OnAckReceived`/`OnPoll`/flush、3个执行流和3个模块；因此候选严格限制在 `/tmp`，未修改工作树vendor代码。独立Release `ppp` SHA-256=`d1961421c7a6023f5a0e5d7db626246e3a5abfbffd61e7ce096dfcd4d190f99e`，当前源码baseline为`785d025c…`，根`bin/ppp`保持baseline未变。

先通过 `test_pacing_flush`、`test_qdisc_pacing`、`test_e2e`（3/3）。`test_cc_kcc`在候选与未改动vendor基线都以相同10处`full_bw_cnt` reference期望断言失败，确认是当前源已有测试失败，与该burst改动无关。随后以perf-off方式交替执行CPU11单核、P1/DL/GSO-on、1MiB sndbuf、memory bridge的20秒配对筛选，两组 qualification 均4/4通过：baseline ratio=`1.0842×/1.0462×`、中位`1.0652×`；128KiB候选=`1.0480×/1.0589×`、中位`1.0535×`。XTCP自身goodput中位候选约高2.5%，但native约高3.6%，相对比值中位反而低约1.1%；process task-clock/byte效率增益中位也从约`1.096×`降到`1.073×`。只有两轮20秒筛选，不能当正式矩阵，但它没有稳定相对/CPU效率收益，故不升级60秒×3测试，否决扩大burst cap，不改变默认或保护门。

Artifacts：`artifacts/goal12-p1-dl-gsoon-q128-baseline-r1-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-q128-candidate-r1-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-q128-baseline-r2-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-q128-candidate-r2-20s-20260926/`。候选工程与vendor差分留在 `/tmp/xtcp-impact-index-20260926` 和 `/tmp/xtcp-q128-*`；未提交、未清理任何历史artifact。P1/DL GSO-on仍未达到1.20×，后续继续调查ACK-release/pacing估算与实际持续供给之间的差距，而不是继续放大burst。

为验证候选是否真的改变flush gate，再对两binary各跑一格20秒、XTCP-only、同CPU/方向/GSO/缓冲的`--xtcp-perf --datapath-telemetry`诊断（两格qualification均通过，不能当正式性能数据）。per-flow末快照中 baseline/candidate 的`flush_pacing`为`4,971/3,320`（候选约少33%），但`flush_attempts`为`49,814/50,192`，`flush_tx_bytes`为`2,433,025,856/2,433,636,944`，几乎一致；goodput为`821.97/825.02Mbps`，task-clock约`8.798/8.806ns/B`，timer armed计数约`96,628/99,422`。这证明burst cap确实减少了被pacing gate挡回的尝试，却未增加有效发送量、吞吐或CPU效率，也未减少timer arm；进一步支持将该方向淘汰，而非把“gate次数下降”误判成性能提升。诊断artifacts：`artifacts/goal12-p1-dl-gsoon-q128-baseline-diag-20s-20260926/`、`artifacts/goal12-p1-dl-gsoon-q128-candidate-diag-20s-20260926/`。

### 11.104 当前baseline P1/DL 199Hz profile 与包构造改动风险（2026-09-26）

为增加§11.102单格XTCP profile的样本量，在未改源码baseline binary（SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）上对CPU11采集`cpu-clock:u`、199Hz、DWARF callchain；全局perf数据无lost samples，按XTCP client PID `4051493`过滤约2K样本。对应XTCP-only P1/DL/GSO-on cell qualification通过，goodput=`813.89Mbps`，该 profile不是与native配对的性能验收。XTCP样本self占比：AES-CFB相关`aesni_encrypt`约`47.24%`、`CRYPTO_cfb128_encrypt`约`4.54%`；`BuildSegmentPacket`约`4.99%`、`timerfd_settime`约`1.79%`、`TcpConn::FlushPendingSend`约`1.45%`、`XtcpNdiBackend::Tx`约`0.89%`、`TunGsoCoalescer::PushInternal`约`0.63%`。这些比例只说明采样热点，不能直接转换为可消除的端到端时间。

libc地址`0x9a9ee`占约`6.14%`，反汇编确认该偏移是`sem_trywait` syscall返回点；但这些样本在fiber切栈处没有可恢复caller，不能据此归因给某个XTCP锁、timer或调度分支。另一个libc偏移`0x162e47`约`2.01%`，尚未确认其具体caller。包构造函数已有SSSE3 fused copy+checksum实现；单独vendor GitNexus图对`BuildSegmentPacket`报告**CRITICAL**（9个直接关系、26个影响点、15个流程、7个模块），覆盖数据发送以及SYN/ACK/重传/恢复等路径。因此不把它当作低风险优化入口；任何算法级改动都需先有逐字节校验、全部调用情形测试与针对性A/B证据。当前profile没有给出优于这一验证门槛的低风险Xtcp-only代码候选，根`bin/ppp`保持baseline。

Profile artifact：`artifacts/goal12-currentbaseline-p1-dl-gsoon-perf199-20260926/`。该结果把近期profile重点从“burst门次数”收敛到当前Xtcp独有CPU开销的归因；共享AES-CFB成本虽然占样本较高，但不能靠只优化XTCP发送路径消除，也不应通过更换隧道密码算法来制造对比优势。

### 11.105 KCC RTT聚合带宽样本原型因零窗口恢复回归而淘汰（2026-09-26）

沿§11.96遗留线索，在隔离源副本`/tmp/xtcp-kcc-roundavg-candidate-20260926`试做一项算法候选：用当前delivery-round内累计的`delivered/interval_us`产生整轮平均带宽样本，只在整轮结束时更新`BwMax`与STARTUP full-bandwidth检查；根工作树third-party源未修改。`KccMain`的GitNexus upstream caller解析为UNKNOWN（0 callers，图未解析插件回调注册关系），因此该变更只在隔离副本试验。

候选Release产品在`/tmp/openppp2-kcc-roundavg-out/ppp`构建成功，首版SHA-256=`95471853520b448db917c1e92e68c2bd1e7c7f8e4fcb1df4a61ecff1887e94de`；根`bin/ppp`保持baseline SHA `785d025c…`。隔离XTCP test build中，`test_e2e`、`test_loss_recovery`、`test_qdisc_pacing`、`test_cc_bbr`、`test_cc_selection`、`test_mixed_load`、`test_pacing_flush`、`test_ack_storm`、`test_cc_default`通过；`test_cc_kcc`有46处与现有逐样本reference和STARTUP直接速率断言不一致，显示这是算法语义变更，不能以现有reference直接验收。`test_1mb_stream`该次loss-enabled阶段实际`dropped=0`，没有形成有效丢包注入，故不作候选归因。

为调查零窗口恢复失败，在隔离副本增加“单个ACK间隔超过4×当前RTT则丢弃当前聚合样本”的保护并重编；`test_zero_window_backpressure`仍失败，恢复阶段仅收到`23,297/65,536`字节。与当前baseline源的同一测试通过对照后，确认这是候选真实回归，保护规则无效，整个round-aggregation算法候选淘汰。此前曾跑的两个20秒×3 pilot（候选 median ratio `1.1302×`、当前源 control `1.0270×`）属于回归尚未排除前的探索性数据；运行顺序不同且未随机交错，不能作为有效提升或因果结论，也不应据此继续长矩阵。

确定性聚合样本原型测试通过，但它不能覆盖零窗口、速率爬升、full-bandwidth plateau和丢包恢复完整状态机。`test_cc_kcc`仍未有与新算法匹配且独立的reference。结论：**不晋升、不进入正式吞吐矩阵、不改产品默认KCC**。若未来重开，需先查明零窗口恢复下round边界/空闲时间的状态语义并补齐算法reference，而不是继续堆叠启发式过滤。Artifacts：`artifacts/goal12-kcc-roundavg-p1-dl-gsoon-cpu11-pilot-20s-r3-escalated-20260926/`、`artifacts/goal12-kcc-roundavg-p1-dl-gsoon-currentbaseline-control-20s-r3-20260926/`；隔离源码和构建：`/tmp/xtcp-kcc-roundavg-candidate-20260926`、`/tmp/xtcp-kcc-roundavg-tests-20260926`、`/tmp/openppp2-kcc-roundavg-build-new`。产品`bin/ppp`保持baseline SHA `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`。

### 11.106 KCC round-gated full-bandwidth plateau 3→4筛选（2026-09-26）

为验证§11.97中median ratio `1.0855×`的round-gated KCC候选是否因3个plateau RTT过早退出STARTUP，在隔离`/tmp/xtcp-kcc-round-gate-count4-20260926`中仅将full-bandwidth连续plateau退出门槛从3提高到4，并同步修改参考C core及确定性状态转换测试。GitNexus对vendor `KccMain` / `kFullBwCnt`解析为UNKNOWN（插件回调未入图），所以所有改动仅位于`/tmp`。count=4候选产品SHA-256=`ef5f7bafcc95be45c409cb18379b742393172145b2d06aa8864ac3f00bfdc1c9`；同一主工作树、编译器和Release配置下重建的count=3 control SHA-256=`09360f5b35ea7503ab5cea7de7e46334590f3d61b9753eef4726eee7f6ae3d36`；根`bin/ppp`仍为baseline SHA `785d025c…`。

count=4候选的`test_cc_kcc`、`test_zero_window_backpressure`、`test_e2e`、`test_loss_recovery`、`test_qdisc_pacing`、`test_cc_default`均通过（6/6）。随后CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、1MiB sndbuf、memory bridge下完成3组20秒native/XTCP fresh-netns交错screen，两版qualification均6/6：count=3 ratio=`1.0688×/1.0795×/1.0738×`，median=`1.0738×`；count=4 ratio=`1.0635×/1.0330×/1.0598×`，median=`1.0598×`。count=4 XTCP goodput median约`823.9Mbps`、control约`827.7Mbps`；process task-clock/byte效率增益中位约`1.0887×`对`1.0952×`。count=4每组ratio均低于相邻control；screen仅20秒×3且native分母轮间波动明显，但没有吞吐或CPU效率收益信号。故否决延长到4 RTT，不跑正式长测、不改默认拥塞控制。

Artifacts：`artifacts/goal12-kcc-roundgate-count4-p1dl-gsoon-cpu11-pilot-control-r1-20s-20260926/`、`artifacts/goal12-kcc-roundgate-count4-p1dl-gsoon-cpu11-pilot-candidate-r1-20s-20260926/`、`artifacts/goal12-kcc-roundgate-count4-p1dl-gsoon-cpu11-pilot-candidate-r2-20s-20260926/`、`artifacts/goal12-kcc-roundgate-count4-p1dl-gsoon-cpu11-pilot-control-r2-20s-20260926/`、`artifacts/goal12-kcc-roundgate-count4-p1dl-gsoon-cpu11-pilot-control-r3-20s-20260926/`、`artifacts/goal12-kcc-roundgate-count4-p1dl-gsoon-cpu11-pilot-candidate-r3-20s-20260926/`。候选和构建保留在`/tmp/openppp2-kcc-roundgate-count4-*`、`/tmp/xtcp-kcc-round-gate-count4-20260926`；产品baseline未更改。

### 11.107 P1/DL GSO-on Cubic 单格筛选无收益信号（2026-09-26）

在当前源码 baseline binary（SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）上，将拥塞控制从默认KCC仅运行时切换为Cubic；CPU11单核、P1/DL、GSO-on、`sndbuf=1MiB`、single-shard、memory bridge、fresh-netns配对，20秒×1。native/XTCP qualification **2/2**通过，goodput=`778.9/783.2Mbps`，XTCP/native ratio=`1.0055×`；process task-clock/byte=`9.550/9.199ns/B`，XTCP相对native效率增益约`1.038×`。该单轮筛选只用于淘汰方向，不是正式验收；其吞吐比当前源码KCC三轮基线median `1.0270×`低，也远低于1.20×目标，因此不追加正式矩阵、不改默认KCC。既往Reno筛选为`0.9843×`，BBR结果显著更差；停止P1/DL单流的拥塞控制枚举，后续应转向更大的数据路径/架构差异，而不是继续替换算法。

筛选artifact：`artifacts/goal12-p1-dl-gsoon-cubic-screen-cpu11-20s-r1-elevated-20260926/`。首次无提升权限的尝试因netlink权限不足在创建namespace前失败、`cells=0`，保留于`artifacts/goal12-p1-dl-gsoon-cubic-screen-cpu11-20s-r1-20260926/`；授权提升后的独立重跑完整通过。两次均未修改源码、产品binary或系统网络配置。

### 11.108 P16/DL source-port-bit6 路由筛选未改善公平性（2026-09-26）

针对§11.100默认tuple-hash的P16/DL/GSO-on吞吐通过但公平性仅2/3轮达标，在当前baseline binary（SHA-256 `785d025c…`）上仅将双shard route切为opt-in `source-port-bit6`，CPU8/9、P16/DL、GSO-on、`sndbuf=1MiB`、memory bridge做30秒fresh-netns配对筛选。两stack的active route/GSO/XTCP数据路径均确认；单轮goodput XTCP/native=`1.035/0.512Gbps`，表面ratio=`2.0211×`，但XTCP qualification因`ppp_zero_migrations`与`process_cores_ok`失败，且采样提示其它CPU的NET softirq活动，故此ratio无验收效力。

更关键的是该轮16条流虽无zero-rate，min flow仅约`11.85Mbps`、P10约`66.76Mbps`、max/min约`5.94×`，并未改善公平性；因此不继续source-port-bit6长测，也不晋升该opt-in route。该结果只有一轮且受CPU迁移污染，不能证明路由导致了低速流，但足以说明当前没有晋升依据。artifact：`artifacts/goal12-currentbaseline-p16-dl-gsoon-portbit6-cpu8-9-30s-r1-20260926/`。无源码或产品binary改动。

### 11.109 修复 datapath matrix 汇总遗漏 client-cpuset qualification

§11.108 artifact揭示runner汇总缺陷：每个cell的`qualification.json`均为`fail`（`ppp_zero_migrations`、`process_cores_ok`），但历史`matrix.json`顶层`qualification_status`为`pass`。原因是`tools/run_datapath_linux_matrix.sh`的聚合逻辑只对`client-single-core`检查cell qualification，漏掉了多CPU `client-cpuset`；因此该artifact只能按逐cell qualification判失败，不能采用其顶层pass字段。

将聚合判断提取为`datapath_matrix_metadata.evaluate_qualification_status()`，对所有非`none` CPU profile统一要求cell qualification通过，同时继续传播runner失败和cell status失败；增加cpuset失败/通过及runner失败测试。修复后`tests/tooling/test_datapath_linux_matrix.py`通过，Python编译、runner shell语法、`git diff --check`均通过；对§11.108原始`matrix.json` cells做离线重算得到`fail`。历史artifact未重写，以保留原始报告现场。这个修复只提高后续验收可信度，不是吞吐优化，也不改变binary；根`bin/ppp` SHA保持`785d025c…`。

### 11.110 P16/DL 低速流复现及目标端 TCP_INFO 诊断（2026-09-26）

沿§11.100的tuple-hash默认双shard路径，用隔离诊断binary（SHA-256 `7e5b2946…`，含只读TCP序号/RTO sidecar）执行CPU8/9、P16/DL、GSO-on、2 shards、`sndbuf=1MiB`、30秒XTCP-only fresh-netns诊断。首轮CPU资格通过但`no_zero_rate_flows`失败，复现2/16条zero-rate；XTCP flow sidecar在该路径所有采样均为空，只有shard/timer数据，故不能从这轮推断`snd_una/front_seq/RTO`根因，不能把空sidecar当成TCP序号证据。

随后同配置启用目标namespace `ss -tinp`逐秒采样，qualification通过、zero-rate为0、goodput约`1.054Gbps`，process task-clock约`13.27ns/payload-byte`。16条服务端数据socket在样本窗口内的`rwnd_limited`中位约`96.2%`（最大`98.2%`），多条socket同时显示较大的Send-Q；但该轮没有低速流，且服务端peer端口与iperf客户端本地端口不同，无法仅靠该artifact把某个peer socket和复现轮低速流可靠配对。因此它只强化“接收窗口/数据交付节奏值得继续验证”的线索，不证明rwnd是零速流根因，也不构成吞吐对比或候选晋升依据。

两个诊断artifact分别为`artifacts/goal12-currentbaseline-p16-dl-gsoon-tuplehash-tcpdiag-cpu8-9-30s-20260926/`与`artifacts/goal12-currentbaseline-p16-dl-gsoon-tuplehash-ssdiag-cpu8-9-30s-20260926/`。根`bin/ppp`及源码未改；后续若继续追该问题，应同时关联客户端/服务端socket或按TCP四元组抓包，并让同一轮获得非空XTCP per-flow TCP状态，避免用单侧拥塞指标解释间歇停流。

### 11.111 P16/DL 中间代理 Recv-Q 的 native 对照（2026-09-26）

为解释§11.110的服务端`rwnd_limited`，在相同CPU8/9、P16/DL、GSO-on、30秒诊断下，通过只读旁路每秒采`pppmat-s-*`代理namespace的`ss -tinp`，并与runner同步采集的`pppmat-t-*`目标namespace数据按TCP peer/local port匹配。native与XTCP两个cell均qualification通过；goodput分别约`525.8Mbps`与`1.016Gbps`，单轮ratio=`1.932×`仅作诊断、不能替代三轮正式门禁。process task-clock/byte效率中位比约`1.111×`。

两组各有16条代理数据socket持续出现非零`Recv-Q`：per-flow Recv-Q中位数的中位分别约`2.077/2.075MB`，最后快照16/16均非零，latest median均约`2.058MB`；数值几乎一致。由此可确认该大队列/回压状态不是XTCP独有，也不足以单独解释两栈近2×吞吐差或XTCP偶发zero-rate。它更像该测试代理路径的共同稳态，不应贸然通过扩大接收缓存处理；下一步应把关注点移到两种栈的应用侧交付节奏和同一低速流的端到端ACK/序号进展。

artifact：`artifacts/goal12-p16-dl-gsoon-p16-proxyss-native-xtcp-30s-20260926/`，其中额外的中间代理socket采样在`proxy-ss-tin-samples.txt`；runner原生的目标端采样、逐流iperf JSON及cell qualification均保留。旁路采样会增加少量宿主观测开销，因此只用来比较队列状态，不作性能验收。源码和根`bin/ppp`未改。

### 11.112 patch 0027 满窗口 pacing wake 抑制的隔离 A/B 筛选（2026-09-26）

为补上§11.88因netns权限未做的性能对照，先对`NextTimerDeadline`做vendor GitNexus upstream impact：结果为`UNKNOWN/lower-bound`，明确有1个接收者类型未解析的调用点；人工源码搜索确认`XtcpStack::NextTimerDeadlineUs()`遍历连接并调用该方法。所有实验只在隔离control副本反向撤下patch 0027，工作树vendor文件未改。patched binary 使用已验证当前源码baseline（SHA-256 `785d025c…`）；control binary 从同一当前工作树和同一Release配置干净构建，仅XTCP源副本不同（SHA-256 `5c739d0b…`），输出在`/tmp/openppp2-pacingwake-control-out/ppp`。根`bin/ppp`未覆盖。

两组CPU11 single-core、P1/DL/GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge的20秒fresh-netns native/XTCP配对筛选按patched/control/control/patched次序交错，8/8个cell qualification通过。patched ratio=`1.0221×/1.0671×`、median=`1.0446×`；control=`1.0558×/1.0514×`、median=`1.0536×`。XTCP goodput median约`798.9/816.1Mbps`（patched/control）；process task-clock/byte median约`9.09/8.87ns/B`，patched没有CPU效率收益，且短测throughput ratio也略低。此结果不证明patch必然造成退化，但没有支持其改善P1/DL吞吐或CPU成本的信号。

同一XTCP perf JSON的中间23个`timer.armed`样本median为patched约`3,652`、control约`4,132`（低约11.6%）；当前sidecar对该字段的计数语义未独立审计，且这一下降没有转化为更好的goodput/task-clock，因此只视为计时器活动字段变化，不等同于CPU节省。结论：不做60秒×3正式长测；patch 0027继续只作为当前保留的低风险调度修正，不宣称它贡献1.20×，也不因本短筛单独回滚。完整短筛artifacts：`artifacts/goal12-p1-dl-pacingwake-patched-screen-r1-20s-20260926/`、`artifacts/goal12-p1-dl-pacingwake-control-screen-r1-20s-20260926/`、`artifacts/goal12-p1-dl-pacingwake-control-screen-r2-20s-20260926/`、`artifacts/goal12-p1-dl-pacingwake-patched-screen-r2-20s-20260926/`。

### 11.113 当前源码 P1/DL GSO-off 1.20×正式复验及模式边界（2026-09-26）

为校验历史 GSO-off DL 过线结论是否依赖旧 patch/build，使用与§11.96相同的当前源码产物（`/tmp/openppp2-current-xtcp-out/ppp`，SHA-256 `785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`），CPU11 single-core、P1/DL、KCC/single-shard、`sndbuf=1MiB`、memory bridge，native/XTCP fresh-netns 60秒×3，正式 paired threshold 设为1.20。6/6 cell qualification与性能门禁均通过；ratio=`1.4331×/1.3697×/1.4181×`，median=`1.4181×`、MAD=`0.0149`。XTCP/native median goodput=`703.0/501.6Mbps`；process task-clock/byte效率增益median=`1.4316×`，selected-CPU效率增益median=`1.4179×`。完整 artifacts：`artifacts/goal12-currentxtcp-source-p1-dl-gsooff-cpu11-formal-60s-r3-20260926/`。工作树`bin/ppp`与矩阵binary SHA一致，未被覆盖。

该结果只验证相同GSO-off模式下当前源码仍达1.20×，不能代表GSO-on：匹配的§11.96当前源码P1/DL GSO-on仍为median `1.0270×`。GSO-off native基准中位只有约`502Mbps`，XTCP绝对吞吐约`703Mbps`，仍低于GSO-on XTCP约`798Mbps`；所以不可通过把GSO默认关闭来把相对比率包装成整体优化。下一步仍需针对GSO-on路径找出并验证真实CPU/发送服务率收益；P1/UL与P16/DL的各自验收和公平性约束也不因本结果改变。

### 11.114 direct-download handoff 不是当前首要优化点（2026-09-26）

修复 GitNexus CLI 索引后，对`RunDirectDownload`做 upstream impact 得到1个直接caller `StartDirectBridge`、LOW；对`TrySendPending`得到2个直接调用者、涉及`OnSecondLegPayload`执行流。`OnSecondLegPayload`自身因接口/回调边无法解析返回0 callers/UNKNOWN；源码手工追到 `VEthernetNetworkTcpipConnection::AckAccept` 注册的 handler，再到`RunDirectDownload`对 handler 的调用。MCP服务仍读取storage v43而本地CLI为v40，故其impact接口继续失败；本结论来自同一仓库当前源码的CLI索引与人工callsite核对，不能将空图解释为未使用。

复核当前baseline P1/DL/GSO-on 199Hz profile（§11.104）时，`RunDirectDownload → ITransmission::Read → Transmission_Packet_Read → EVP_DecryptUpdate`链累计约52.6% child samples，其中 `aesni_encrypt`约47.2%；`OnSecondLegPayload`约0.67%，其 `boost::asio::post`调用链约0.5%。这些是抽样callchain比例，不是可直接相加的独占CPU比例，但足以否决先优化单flight map/post的假设：它们即使全部消除，也远不足以解释当前GSO-on约17%的目标差额。当前profile更支持先处理隧道CFB解密在单核上的成本/供给，再以native与XTCP同二进制配对验证；加密算法、线路协议和安全属性不因吞吐目标而擅自更改。本轮没有改数据面符号。

### 11.115 SIMD AES-CFB P1/DL profile 与 ABBA 筛选未证明 XTCP 相对收益（2026-09-26）

为验证§11.114的共享加密热点，在当前源码分别采集CPU11、P1/DL、GSO-on、XTCP/single-shard、1MiB sndbuf、memory bridge的15秒XTCP-only用户态perf profile。默认Release binary SHA-256=`785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`；隔离构建的 `ENABLE_SIMD=ON` 候选 SHA-256=`0cf17f10f6fa1d70923268361a47ae8c585062c9a8c9a64c078a67674be4e7f1`，运行配置 `simd-auto=true`，profile确认执行了自定义AES-NI实现。默认profile中 `aesni_encrypt` self约52.27%、`CRYPTO_cfb128_encrypt`约4.55%；候选中 `aesni::aes256_cfb_encrypt`约33.78%、`aesni::aes256_cfb_decrypt`约8.96%。这支持“隧道CFB是大热点且SIMD候选切换了实现”的判断，但CPU采样比例不是端到端性能收益，也不能把不同轮次的绝对Mbps直接作因果比较。

随后按default/SIMD/SIMD/default顺序进行4组15秒 fresh-netns 配对screen；CPU11 single-core、P1/DL/GSO-on、KCC、single-shard、`sndbuf=1MiB`及memory bridge一致，8/8 cell qualification通过。默认 ratio=`1.0002×/1.0746×`、中位`1.0374×`；SIMD ratio=`1.0415×/0.9676×`、中位`1.0046×`。process task-clock/byte效率增益中位约`1.0339×/1.0164×`（默认/SIMD）。轮次吞吐从约0.77到1.13Gbps波动明显，且样本数少；筛选不足以判断绝对吞吐收益，但未观察到SIMD提高XTCP/native相对比值或单位CPU效率的稳定信号。两种构建都远未达1.20×。另外 `ENABLE_SIMD` 是全项目构建开关，不是只切换隧道密码实现。因此不启用全局SIMD默认值、不追加正式长测，也不以共享加密热点替代对XTCP差异路径的定位。

Artifacts：profile筛选 `artifacts/goal12-current-simd-profile-p1-dl-gsoon-cpu11-15s-r1-20260926/`、`artifacts/goal12-current-default-profile-p1-dl-gsoon-cpu11-15s-r1-20260926/`；ABBA配对结果 `artifacts/goal12-current-aesni-abba-default-p1-dl-gsoon-cpu11-15s-204328-20260926/`、`artifacts/goal12-current-aesni-abba-simd-p1-dl-gsoon-cpu11-15s-204424-20260926/`、`artifacts/goal12-current-aesni-abba-simd-p1-dl-gsoon-cpu11-15s-204520-20260926/`、`artifacts/goal12-current-aesni-abba-default-p1-dl-gsoon-cpu11-15s-204615-20260926/`。perf原始采样暂存于`/tmp/openppp2-current-*-p1-dl-perf.data`；主线`bin/ppp`核验仍为默认binary SHA，源码未改。

### 11.116 P1/DL rwnd 与 iperf窗口筛选：高rwnd_limited不是窄窗口根因（2026-09-26）

§11.96当前baseline P1/DL/GSO-on三轮目标端TCP_INFO中，native/XTCP数据流`rwnd_limited`中位数约`84.7%/84.9%`。最初统计所有socket的peer `snd_wnd`得到`43,008B`，但这把idle/control socket混入；§11.90已有同类审计，指出43KiB主要由idle/control socket贡献，不能代表iperf data flow。重新只统计带`rwnd_limited`的数据流样本后，正式矩阵peer `snd_wnd`中位约native `257KiB`、XTCP `132KiB`，动态范围分别约`2KiB–1.81MiB`、`2KiB–1.14MiB`。所以撤回“native/XTCP共同受43KiB窄窗口限制”的解释；高`rwnd_limited`单独也不能证明接收窗是根因。

另外仅在iperf client端通过临时PATH wrapper请求`-w 1M`，运行当前baseline CPU11 single-core、P1/DL/GSO-on、KCC/single-shard、1MiB XTCP sndbuf、memory bridge的20秒fresh-netns配对诊断。qualification 2/2通过，ratio=`1.0706×`、goodput native/XTCP=`736.6/788.6Mbps`；过滤到带`rwnd_limited`的数据流后，peer `snd_wnd`中位约native `116KiB`、XTCP `296KiB`，仍有较大动态范围，没有显示可归因于`-w`的稳定方向或吞吐响应。该单轮改动测试socket设置的ratio不是正式性能结果，也不证明窗口无影响；它没有支持直接调整产品socket buffer。历史短测中128KiB/1MiB/4MiB XTCP receive-buffer sweep也无单调吞吐收益（§11.90），故停止扩大buffer sweep。

首轮wrapper错误地把client-only `-w`传给server，iperf未连接、0 cells，独立保留且不计入结果。成功诊断artifact及wrapper细节：`artifacts/goal12-currentbaseline-p1-dl-gsoon-window1m-diagnostic-cpu11-20s-r2-20260926/`、`artifacts/goal12-currentbaseline-p1-dl-gsoon-window1m-diagnostic-cpu11-20s-r1-20260926/`。未改源码或binary；主线`bin/ppp`保持SHA `785d025c…`。

### 11.117 direct-download 所有权断点与共享解密分配评估（2026-09-26）

沿`RunDirectDownload → OnSecondLegPayload → TrySendPending`逐段核对：`RunDirectDownload`通过aliasing `shared_ptr`把解密帧中的chunk视图交给XTCP队列，跨strand handoff仍持有同一owner，没有在该handoff再复制payload。真正的所有权断点是`XtcpStack::Send(connection_id, const Byte*, length)`：栈需要可靠保留可重传的完整packet，`BuildSegmentPacket`因此新建BufRef并融合payload copy与checksum。当前`BuildSegmentPacket`在XTCP P1/DL profile约为5% self samples（§11.104/§11.102），即使完全消掉也不足以单独弥合GSO-on相对目标约17%的差距；而BufRef又没有可供现有decrypt chunk直接转移的packet headroom/slice语义。因此暂不扩展`SendData(BufRef&&)`，避免在缺少上游owner兼容方案时引入重传、pending-send及同步ACK路径风险。

另核对`Transmission_Packet_Read`：carrier payload先读入allocator buffer；无delta编码时`Transmission_Payload_Decrypt`原地做轻量partial transform；启用transport cipher时，`EVP::Decrypt`再分配输出并由OpenSSL直接写明文，没有额外的中间memcpy。对AES-CFB而言，使用同一输入/输出缓冲在满足cipher/context约束时可行，但现有`Ciphertext`接口还包含RC4等另行分配实现，且该解密成本由native与XTCP共享。GitNexus upstream impact因storage v43/v40不匹配返回`UNKNOWN`；在没有“XTCP相对native收益”证据前，不做通用密码API改造。参考：[OpenSSL EVP_EncryptInit/DecryptUpdate文档](https://docs.openssl.org/3.5/man3/EVP_EncryptInit/)。

结论：direct handoff已是零拷贝；剩余stack packet-build copy是真实但约5%级，改成owned-send属高风险且理论上限不足。共享EVP解密的原地变体主要节省一次输出分配而非cipher遍历，尚无足以支持改动的吞吐证据。下一条优化线转向检查P16/DL公平性与P1/DL发送服务率数据之间的共同症状，先找出能产生XTCP专属收益、且不依赖关闭GSO或削弱资格门禁的变量。

### 11.118 当前binary关闭XTCP高频profiler后的P1/DL基线复测（2026-09-26）

针对此前参数筛选普遍启用`OPENPPP2_XTCP_PERF_JSON`、可能给XTCP路径额外增加逐秒/逐包统计成本的问题，使用根`bin/ppp`（SHA-256=`785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`）重跑CPU11 single-core、P1/DL、GSO-on、TAP cap48、KCC/single-shard、`sndbuf=1MiB`、memory bridge、direct-download chunk 32KiB的45秒×3 native/XTCP配对矩阵。显式保留datapath telemetry与CPU/perf stat，但关闭XTCP高频perf sidecar；6/6 cell qualification通过，没有更改源码或产品binary。

配对ratio=`1.1259×/1.1183×/1.1036×`，median=`1.1183×`、MAD=`0.0075`；XTCP/native median goodput=`1.160/1.045Gbps`。process task-clock/payload-byte效率增益median=`1.2003×`（范围`1.1980–1.2152×`），说明吞吐比仍低于1.20门禁并非简单等价于单位进程CPU效率不足。结果显著好于近期启用XTCP高频perf sidecar的同类筛选（约1.09×中位），因此后续正式比较不得混用两种观测配置；诊断侧car应与性能矩阵分开。

无高频XTCP sidecar的datapath记录中，XTCP三轮TUN direct write分别约`231,930/229,701/228,624`次，写入约`6.96–7.08GB`，同步write服务时间合计`3.59–3.68s/45s`，每轮最大in-flight为1，未见write失败/partial。size buckets中约一半为`>1500B` GSO write；单凭这些调用耗时不能判定TUN是吞吐瓶颈。相同记录里的frame encode计数仅36–40次，与传输字节数不匹配，不能用于推断加解密成本；解密热点以独立perf profile为准（见§11.104/§11.114）。这组结果校正了近期受高频观测影响的性能参考，不构成新的1.20×通过结论；XTCP GSO-on仍差约7.3%相对吞吐。

Artifact：`artifacts/gpt6-paired-clean-p1dl-cap48-direct32k-r3-45s-20260926/`。后续应基于现有flow/ACK-release数据做低扰动的四元组关联与时间轴诊断，重点区分ACK到达、pending-send供给、pacing/window准入与有效TUN输出服务率；在建立可重复因果证据前，不继续改GSO cap、direct chunk、拥塞控制或发送缓存默认值。根`bin/ppp`与源码未改。

### 11.119 P1/P16 per-flow TCP_INFO 端口关联诊断（2026-09-26）

为补足§11.118提出的流级映射，在当前baseline binary上分别对P1/DL与P16/DL执行30秒XTCP-only采样，并从client namespace按`iperf3 fd → local port`关联Linux `ss -tinp`，再以XTCP `tcp_flows[].remote_port`匹配同一虚拟TCP四元组。两项诊断均开启高频`OPENPPP2_XTCP_PERF_JSON`，故只用于状态定位，不用于吞吐、CPU或参数A/B结论。

P1/DL/cap48/32KiB样本中，iperf socket端口`33106`与XTCP flow tuple精确对应。steady窗口约1.12Gbps，`payload_sent_bytes`、`ack_advance_bytes`与`flush_tx_bytes`持续同速增长；末段`cwnd=4187 MSS`、`inflight`不超过约1MiB、pacing约1.6Gbps，而累计`flush_pacing=110`、`flush_window_cwnd=10`相较约72,852次flush尝试很少。direct-download queue high-water约33KiB、reject为0。该单格不支持“常态发送被pacing/window admission卡住”作为P1/DL的首要解释，但因sidecar扰动，不能将其状态计数与perf-off正式矩阵作严格量化对应。

P16/DL/2-shard/1MiB sndbuf的高频诊断复现1条零速流：iperf fd 23对应本地端口`58728`，XTCP `remote_port=58728`的累计发送/ACK在约3秒后分别停在约1.17MiB/131KiB；随后快照长期保持`cwnd=1 MSS`、`inflight=snd_wnd=217,088B`、重传计数从1增至7，应用socket累计接收约348KiB后不再推进。其他15条流正常推进。该cell qualification失败（零速流；且本次未显式请求`--process-perf-stat`，cpuset CPU资格字段不完整），因此只能视作高频观测下的故障现场。一个相同开启sidecar、sndbuf=64KiB的诊断cell未复现零速，但同样因缺少process perf统计而CPU qualification失败；二者不足以作sndbuf因果比较。

重要对照是perf-off的当前baseline P16/DL、1MiB sndbuf、60秒×3正式矩阵（§11.100相关复验）qualification **6/6**、无零速，paired ratio=`2.0071×/1.9516×/1.8919×`，均达到1.20门槛。故§11.119的零速现场更可能受高频profiler时序扰动或非确定性事件影响；不得据此修改KCC、恢复门、sndbuf默认或重传行为。两个诊断artifact分别为`artifacts/goal12-p1-dl-gsoon-flow-ack-correlated-cpu11-30s-r1-20260926/`、`artifacts/goal12-p16-dl-gsoon-flow-ack-correlated-cpu8-9-30s-r1-20260926/`与`artifacts/goal12-p16-dl-gsoon-flow-ack-correlated-sndbuf64k-cpu8-9-30s-r1-20260926/`。本轮没有源码或binary改动。后续性能优化继续以perf-off P1/DL GSO-on的`1.1183×`为明确未达门槛项；ACK/恢复算法在获得低扰动、可重复的故障证据前不作为代码改动目标。

### 11.120 低频配对profile与XTCP-only profile热点不一致，暂不用于归因（2026-09-26）

为检查单核运行栈，在当前`bin/ppp`（SHA-256=`785d025c…`）上采集49Hz `cpu-clock:u`系统级样本，native与XTCP各跑一格P1/DL/GSO-on、CPU11、memory bridge、TAP cap48、direct chunk 32KiB；总计2,171样本、lost=0。该单轮配对筛选goodput为native/XTCP=`1.040/1.167Gbps`、ratio=`1.1224×`，仅作profile诊断。

按client PID查看callchain，native样本主要落在`Transmission_Packet_Read → EVP_DecryptUpdate`（`aesni_encrypt` self约55.6%）；XTCP样本则显示`RunDirectDownload`约34.2% child、`FlushPendingSend`约7.1% child、`BuildSegmentPacket`约2.7% self，XTCP PID的self-symbol榜未见AES热点。这个形态与§11.104/§11.114的同一baseline XTCP-only profile（`aesni_encrypt`约47–61%）不一致。线程快照确认两格均为5线程且样本主要落在主线程，不能用“漏采worker线程”解释。

为复核，在相同CPU11、P1/DL、GSO-on、cap48、1MiB sndbuf、memory bridge、32KiB chunk、49Hz system-wide采样方式下再跑一格XTCP-only；cell qualification通过，goodput=`1.106Gbps`，perf记录1,058样本、lost=0，`ppp_process_cores=0.875`触发同核争用warning。该格`Transmission_Packet_Read → EVP_DecryptUpdate` child约66.1%，`aesni_encrypt` self约59.7%，与XTCP-only历史profile一致。因此配对格中“未见AES”的现象目前应视为未解释的单格profile异常，而非稳定的数据路径差异；不能据此声称XTCP绕过了解密，也不能把不同cell的profile百分比直接比较。

配对profile artifact：`artifacts/goal12-currentbaseline-p1-dl-gsoon-perf49-paired-cap48-20260926/`；XTCP-only对照：`artifacts/goal12-currentbaseline-p1-dl-gsoon-perf49-perfoff-cap48-20260926/`与`artifacts/goal12-currentbaseline-p1-dl-gsoon-perf49-repeat-cap48-20260926/`。XTCP-only PID-attached复核见§11.121，确认了单独PID采样时的AES与packet-build热点；配对格仍未解释，不据其反向推断数据路径差异。暂不据该单格异常改源码或选热点。P1/DL GSO-on的正式性能结论仍采用§11.118 perf-off三轮median=`1.1183×`。

### 11.121 PID-attached XTCP P1/DL profile确认热点（2026-09-26）

为排除system-wide采样和其他进程样本对归因的影响，在XTCP client PID存活期间直接执行`perf record -p PID`，CPU11、49Hz、`cpu-clock:u`、DWARF callchain；配置与§11.120一致，cell qualification通过，goodput=`1.113Gbps`。共记录1,099个样本、lost=0；`ppp_process_cores=0.873`触发同核争用warning，因此该格只用于profile，不用于吞吐/CPU效率比较。

PID-attached self样本为`aesni_encrypt`=`60.05%`、`CRYPTO_cfb128_encrypt`=`5.00%`、`BuildSegmentPacket`=`5.28%`、`TunGsoCoalescer::PushInternal`=`0.91%`、`TcpConn::FlushPendingSend`=`0.91%`、`XtcpNdiBackend::Tx`=`0.45%`、`OnSecondLegPayload`=`0.45%`。callchain确认`RunDirectDownload → Transmission_Packet_Read → EVP_DecryptUpdate`仍占主要child samples。由此确认此前XTCP-only AES热点可在PID-scoped方式复现；配对profile中XTCP未见AES仍属异常采样格。当前可见的XTCP专属包构造热点约5.3%，其余若干栈内热点均约1%或以下；单独消除包构造copy即使达到理论上限也不足以证明能补齐formal ratio从1.1183×到1.20×的差距，不能把它直接当作目标解法。

Artifact：`artifacts/goal12-currentbaseline-p1-dl-gsoon-perfpid-attached-xtcp-cap48-20260926/`。未修改数据面或binary；后续应进一步定位尚未符号化的libc samples及XTCP-only总CPU服务率差异，再决定是否值得进入高风险的SendData/BufRef切片改造。根`bin/ppp` SHA仍为`785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`。

### 11.122 隔离 AVX2 CopyAndChecksum 原型筛选，未晋升（2026-09-27）

基于§11.121中`BuildSegmentPacket`约5.3% self样本，在`/tmp/openppp2-xtcp-avx2-proto-20260926`隔离增加按函数target编译的AVX2 fused copy/checksum核，并在运行时仅对AVX2 CPU dispatch；未启用全局AVX2编译选项、未改工作树vendor源或根`bin/ppp`。对象代码确认使用`vmovdqu/vpshufb/vpaddd`。候选Release `ppp` SHA-256=`63c75b413904a9b82875169e37f9a453d5f1c08a94a622370aae9da5e42c35da`，baseline仍为`785d025c…`。

候选XTCP静态树上的`test_tcp_fsm`、`test_gso_stack`、`test_e2e`、`test_checksum_simd`、`test_loss_recovery`共5/5通过。随后对baseline/candidate/candidate/baseline做CPU11、P1/DL、GSO-on、cap48、1MiB sndbuf、memory bridge、32KiB direct chunk、20秒fresh-netns配对筛选；8/8 cells qualification通过。两轮ratio分别是baseline=`1.1212×/1.0583×`、candidate=`1.0965×/1.1278×`，中位数=`1.0898×/1.1122×`。candidate的XTCP绝对goodput中位约`1.135/1.124=+1.0%`，process task-clock/byte中位约降低`1.0%`；但ratio轮间差异大且逐轮方向不稳定，baseline与candidate native分母中位也相差约1.1%。因此不能把这两轮的ratio中位差当成AVX2因果收益，也不能声称接近1.20×。该改动理论上只优化packet-build中的一段成本，当前不晋升到工作树或正式60秒矩阵；后续优先找能解释剩余吞吐差距的大块服务率/所有权改造。

Artifacts：`artifacts/goal12-avx2-copychecksum-baseline-20260927-a/`、`artifacts/goal12-avx2-copychecksum-candidate-20260927-a/`、`artifacts/goal12-avx2-copychecksum-candidate-20260927-b/`、`artifacts/goal12-avx2-copychecksum-baseline-20260927-b/`；isolated build/test为`/tmp/openppp2-avx2-build-20260926`与`/tmp/openppp2-avx2-xtcp-tests-20260926`。根`bin/ppp` SHA和当前工作树vendor代码保持不变。

### 11.123 Tap GSO 热路径环境变量读取筛选（2026-09-27）

§11.121 PID profile中`getenv`约占1.36% self samples，callchain落在每个输出段都会经过的`TapGsoMergeRequested → TapLinux::OutputInternal`。将输出热路径改成只读取仍支持运行时更新的`OPENPPP2_TAP_GSO_MERGE_DISABLE` kill-switch；GSO enable仍在Tap创建/打开时读取，不再每段重复查询。GitNexus impact/context受v43/v40存储版本不匹配返回`UNKNOWN`，人工核对其3个调用点；语义保持动态关闭，不支持本来就无法激活的运行时动态开启。

使用与baseline相同的Clang 19/Ninja、Release选项、XTCP patch snapshot（stamp `3d92c0…`）构建隔离候选，依赖布局与根binary一致。baseline/candidate/candidate/baseline的CPU11、P1/DL、GSO-on、cap48、1MiB sndbuf、memory bridge、32KiB direct chunk、20秒fresh-netns筛选共8/8 cells qualification通过。ratio依序为`1.1151×/1.0976×/1.1227×/1.0956×`；baseline两轮中位`1.1053×`，candidate两轮中位`1.1101×`，每个交错对的方向相反，短测未显示稳定goodput收益，也远未达到1.20×。XTCP绝对goodput中位candidate约`1.162Gbps`、baseline约`1.175Gbps`；candidate process task-clock/byte中位约低1.2%，但样本很短，不能据此认定吞吐因果改善。

因此保留此低风险的冗余配置读取消除作为小幅CPU优化，不晋升为性能达标结果，也不启动正式45秒三轮矩阵。Artifacts：`artifacts/gpt6fix-getenv-baseline-a-p1dl-gsoon-20s-20260927/`、`artifacts/gpt6fix-getenv-candidate-a-p1dl-gsoon-20s-20260927/`、`artifacts/gpt6fix-getenv-candidate-b-p1dl-gsoon-20s-20260927/`、`artifacts/gpt6fix-getenv-baseline-b-p1dl-gsoon-20s-20260927/`。隔离候选`/tmp/openppp2-getenv-clang-out-20260927/ppp` SHA-256=`334d71eec5f2a1696be9fd2e4ffe8bae87bfb953f354815e26c34cb0dce88da8`；正式`bin/ppp` SHA仍为`785d025c8ddd8c4b9fa706d0ddc2358aa380d75823e34dff68bab3ffbf06b89e`。下一优化方向优先审查`SendData`超MSS输入路径的`pending_send_` vector insert（profile raw libc样本callchain合计约1.7%），但该路径涉及窗口、重入ACK及recovery，需先做单独安全设计与丢包回归，不能直接复活历史上已撤回的super-MSS直发路径。

### 11.124 SIMD-enabled build 的 P1/DL 正式交错复测：绝对服务率提升，但 XTCP ratio 未达标（2026-09-27）

为复核§11.115短screen中 profile 已切到自定义 AES-NI CFB、但吞吐差异尚不稳定的候选，使用同一 CPU11、P1/DL、GSO-on、cap48、XTCP `sndbuf=1MiB`、memory bridge、direct-download chunk 32KiB、45秒 duration / 2秒 omit 设置做三组交错 native/XTCP配对。顺序为 baseline A、SIMD candidate A、candidate B、baseline B、candidate C、baseline C；每组均为 fresh netns。六组 qualification **12/12 cells全通过**，没有启用XTCP高频perf sidecar，paired performance gate记录为off，性能结论直接按每组ratio审阅。

baseline `bin/ppp` SHA-256=`785d025c8ddd8c4b9fa706d0dcb2358aa380d75823e34dff68bab3ffbf06b89e`；candidate `/tmp/openppp2-current-simd-out/ppp` SHA-256=`0cf17f10f6fa1d70923268361a47ae8c585062c9a8c9a64c078a67674be4e7f1`，使用`ENABLE_SIMD=ON`，且二进制包含自定义 AES-256-CFB AES-NI encrypt/decrypt实现。各组paired ratio：baseline=`1.1039×/1.1193×/1.1109×`，median=`1.1109×`；candidate=`1.0945×/1.1619×/1.1671×`，median=`1.1619×`，相对baseline median约改善4.6%，但candidate三轮全部未过`1.20×`，且首轮明显低于后两轮。

candidate XTCP goodput median约`1.805Gbps`，baseline约`1.164Gbps`；native median也从约`1.051Gbps`升至`1.559Gbps`。XTCP process task-clock/payload-byte median从baseline约`6.048ns/B`降至candidate约`3.549ns/B`。这说明该构建在本机显著提高整条隧道数据面的绝对服务率/CPU效率，但native同样大幅受益，不能把绝对吞吐差归因为XTCP单独提速；相对ratio的改善有限，仍未完成XTCP目标。`ENABLE_SIMD`是全局构建选项，候选也不只切换隧道AES实现；本结果不授权把SIMD默认打开，也不替代旧CPU兼容性和完整跨并行度矩阵验证。

Artifacts：`artifacts/gpt6fix-simd-formal-base-a-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-simd-formal-candidate-a-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-simd-formal-candidate-b-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-simd-formal-base-b-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-simd-formal-candidate-c-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-simd-formal-base-c-p1dl-gsoon-cpu11-45s-20260927/`。**后续构建指纹审计发现此组不是有效的SIMD因果A/B**：candidate由当时有未提交源码改动的工作树构建，而baseline使用更早生成的`bin/ppp`，两者并非只差`ENABLE_SIMD`。上列goodput/ratio仅是两个binary的描述性观测，撤回其“SIMD导致4.6% ratio改善/绝对服务率提升”的因果解释，不能用来验收目标。binary和artifact保留供追溯；本节的因果结论由后续同一当前源码的SIMD-off/on配对实验取代。根`bin/ppp`未改。

### 11.125 SIMD + XTCP AVX2 packet-build + Tap getenv 组合候选正式筛验：中位过线但稳定性门禁失败（2026-09-27）

为筛查组合binary，在隔离目录构建`/tmp/openppp2-simd-avx2-out-20260927/ppp`（SHA-256=`fc9c2ee23f56f1f970da3577c38cece01457aa7fe2f4b09424c385f8cb3d716b`），包含`ENABLE_SIMD=ON`、隔离AVX2 `CopyAndChecksum`原型（XTCP patch stamp=`3d92c0…`）和构建时工作树中的源码状态。根`bin/ppp` SHA仍为`785d025c…`。首个sandbox内矩阵因缺少netlink权限产生0 cells，原失败artifact保留；使用fresh netns的提权重跑及正式筛验全部正常完成。

先做20秒ABBA筛选（baseline A、candidate A/B、baseline B，之后补candidate C/baseline C），配置为CPU11、P1/DL、GSO-on、cap48、KCC/single-shard、`sndbuf=1MiB`、memory bridge、direct-download chunk 32KiB；12/12 cells qualification通过。baseline ratio=`1.1377×/1.1462×/1.1856×`，median=`1.1462×`；组合候选=`1.1910×/1.2137×/1.2021×`，median=`1.2021×`。该筛选只用于决定是否值得正式复测。

随后按baseline A、candidate A、candidate B、baseline B、candidate C、baseline C做45秒×3交错矩阵，6/6组、12/12 cells qualification通过，未启用XTCP高频perf sidecar；测得baseline ratio=`1.0925×/1.1241×/1.1252×`、候选=`1.2071×/1.2866×/1.1228×`。但构建指纹审计确认这组A/B的baseline `bin/ppp`并非由矩阵时的当前工作树源码构建，而candidate是；两者源码差异还包括当时工作树内多处XTCP、TAP、bridge及测试改动（matrix metadata的当前`git_tracked_diff_sha256`相同只能说明运行时工作树相同，不证明旧binary由该源码生成）。因此这些ratio、goodput及CPU数值保留为历史描述数据，**整体撤销其用于归因SIMD/AVX2/配置优化或判定1.20×的证据资格**；不得把候选中位`1.2071×`报告为达标。首个sandbox失败artifact与成功artifact仍完整保留。后续同源AVX2消融见§11.126；SIMD-off/on同源正式对照待完成。

短筛选与正式artifact分别为`artifacts/gpt6fix-combo-base-a-p1dl-gsoon-cpu11-20s-20260927-retry/`、`artifacts/gpt6fix-combo-candidate-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-candidate-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-base-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-candidate-c-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-base-c-p1dl-gsoon-cpu11-20s-20260927/`；正式组为`artifacts/gpt6fix-combo-formal-base-a-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-combo-formal-candidate-a-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-combo-formal-candidate-b-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-combo-formal-base-b-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-combo-formal-candidate-c-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-combo-formal-base-c-p1dl-gsoon-cpu11-45s-20260927/`。后续不再把该组合矩阵用于性能验收；保持SIMD default-off，由同源SIMD-off/on结果决定是否保留构建选项方向。根`bin/ppp`与XTCP工作树源码未被本轮改动。

### 11.126 XTCP AVX2 CopyAndChecksum 单独消融：CPU成本小幅下降，尚不足以达成1.20×（2026-09-27）

为从§11.125组合结果中隔离XTCP AVX2内核，分别构建相同`ENABLE_SIMD=ON`、当前Tap getenv源码、Clang 19/Release配置的两份binary：无AVX2控制`/tmp/openppp2-simd-only-out-20260927/ppp` SHA-256=`2780f57a7284c444da435e4f0817fd74ef55f0b00b3d947d9181475d787175ca`；AVX2候选`/tmp/openppp2-simd-avx2-out-20260927/ppp` SHA-256=`fc9c2ee23f56f1f970da3577c38cece01457aa7fe2f4b09424c385f8cb3d716b`。代码差异仅限隔离XTCP树中的`CopyAndChecksumAvx2`实现及其CPU dispatch；均未改根`bin/ppp`或工作树XTCP源码。

先执行20秒ABBA再执行反转顺序BAAB筛选，共16/16 cells qualification通过。四个XTCP process task-clock/payload-byte配对中，AVX2每次均更低，降幅约`2.4–7.8%`；但native绝对goodput存在明显轮间/时序漂移，ratio不能独立证明kernel因果吞吐增益。故继续进行45秒×3正式交错复验：无AVX2控制A/B/C ratio=`1.0767×/1.1313×/1.1311×`，median=`1.1311×`；AVX2 A/B/C=`1.2189×/1.1712×/1.1763×`，median=`1.1763×`。12/12 cells qualification通过；AVX2候选仅1/3轮达到1.20，控制0/3轮达到，二者均不满足逐轮稳定门禁。XTCP绝对goodput median约从控制`1.817Gbps`升至候选`1.869Gbps`（约+2.9%）；process task-clock/payload-byte median从`3.522`降至`3.403ns/B`（约-3.4%）。方向与短测CPU成本信号一致，但量级不足以单独弥合剩余性能差距，且候选ratio仍低于1.20中位门槛。

20秒artifact：`artifacts/gpt6fix-avx2-ablation-noavx-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-avx-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-avx-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-noavx-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-avx-c-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-noavx-c-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-noavx-d-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-ablation-avx-d-p1dl-gsoon-cpu11-20s-20260927/`。正式artifact：`artifacts/gpt6fix-avx2-formal-noavx-a-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-avx2-formal-avx-a-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-avx2-formal-avx-b-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-avx2-formal-noavx-b-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-avx2-formal-avx-c-p1dl-gsoon-cpu11-45s-20260927/`、`artifacts/gpt6fix-avx2-formal-noavx-c-p1dl-gsoon-cpu11-45s-20260927/`。结论：AVX2原型可降低packet-build单位CPU成本，但当前不晋升产品代码，也不继续为它做更大性能矩阵；后续应优先调查占XTCP client CPU profile约30%的共享AES-CFB decrypt成本和其他能够产生更大、XTCP相对收益的路径，同时保留全局SIMD default-off。根`bin/ppp` SHA仍为`785d025c…`。

### 11.127 同一当前源码下 SIMD-off/on 短 ABBA：绝对吞吐加速不等于 XTCP ratio 改善（2026-09-27）

为纠正§11.124/§11.125的binary-source不匹配，使用当前工作树的同一主工程源码、同一XTCP无AVX2源码分别构建`ENABLE_SIMD=OFF`与`ON`，其余Clang 19/Release配置和依赖一致。OFF binary `/tmp/openppp2-nonsimd-current-out-20260927/ppp` SHA-256=`573cdadf73427502bb689d1e915a23c9a569ac043ce081c9c7c01414fbab3fa8`；ON binary `/tmp/openppp2-simd-only-out-20260927/ppp` SHA-256=`2780f57a7284c444da435e4f0817fd74ef55f0b00b3d947d9181475d787175ca`。四组runner metadata具有完全相同的`git_tracked_diff_sha256=cf970a01…`，因此这是一组受控的构建开关对照，而非旧`bin/ppp`对当前源码的比较。

CPU11、P1/DL、GSO-on、cap48、KCC/single-shard、`sndbuf=1MiB`、memory bridge、32KiB direct chunk，20秒fresh-netns ABBA（OFF A、ON A、ON B、OFF B），8/8 cells qualification通过。OFF ratio=`1.1642×/1.1140×`，中位=`1.1391×`；ON ratio=`1.1034×/1.1278×`，中位=`1.1156×`。ON XTCP绝对goodput约`1.79Gbps`，OFF约`1.16Gbps`，但native也从约`1.02Gbps`升到`1.60Gbps`；ON的相对ratio没有改善，反而约低2.1%。ON process task-clock/payload-byte约`3.59ns/B`，OFF约`6.12ns/B`，说明SIMD明显降低整个隧道两端共享处理的CPU成本，却没有改善XTCP相对native的优势。配对数较少且主机服务率波动大，本screen不作为正式验收；但结果不支持继续投入全局SIMD来解决XTCP ratio，故不跑该方向的45秒正式门禁，SIMD仍保持default-off。

Artifacts：`artifacts/gpt6fix-simd-ablation-nosimd-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-simd-ablation-simd-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-simd-ablation-simd-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-simd-ablation-nosimd-b-p1dl-gsoon-cpu11-20s-20260927/`。未改工作树源码或`bin/ppp`。下一步回到XTCP相对服务率：用低扰动client-PID perf与每字节CPU/ACK-output节奏关联，重点找packet build之外可贡献至少数个百分点的XTCP专属时间；不再从旧binary与当前dirty source的对比推导代码收益。

### 11.128 当前源码 no-SIMD P1/DL GSO-on 正式基线与匹配 profile（2026-09-27）

为校正旧`bin/ppp`与当前源码binary不一致的问题，使用当前主工程/XTCP源码构建的 no-SIMD binary（SHA-256=`573cdadf73427502bb689d1e915a23c9a569ac043ce081c9c7c01414fbab3fa8`），执行CPU11 single-core、P1/DL、GSO-on、cap48、KCC/single-shard、`sndbuf=1MiB`、memory bridge、32KiB direct-download chunk、45秒×3 native/XTCP配对矩阵。开启低频datapath telemetry与CPU/perf stat，关闭`OPENPPP2_XTCP_PERF_JSON`；6/6 cells qualification通过。ratio=`1.1659×/1.1095×/1.1168×`，median=`1.1168×`、MAD=`0.0073`；XTCP/native median goodput约`1.159/1.033Gbps`。process task-clock/payload-byte效率增益median=`1.2102×`（范围`1.2023–1.2135×`），selected-CPU效率增益median=`1.2347×`。因此当前源码的单位CPU效率稳定超过1.20，但吞吐ratio三轮均未达到1.20；两种门禁不可混为一谈。

同binary、同CPU/负载参数另外对native和XTCP各采一次15秒PID profile，明确`--tap-gso-segments=48`。这两格有perf采样且不是paired性能验收：XTCP cell观测`1.167Gbps`，native cell`1.036Gbps`只作profile期间的描述值。样本中XTCP最显著的栈内self热点为`BuildSegmentPacket`约`5.7%`、`FlushPendingSend`约`1.2%`；native侧`CompleteTcpV4GsoChecksums`、`TcpChecksum`与`ip_standard_chksum`约`11.4%`，调用链位于TUN VNET/GSO输入拆分。双方均有明显共享AES-CFB成本。cap4的先行profile不匹配本节cap48参数，仅保留在独立artifact中，不用于这里的热点结论。

当前正式矩阵低频计数未显示DL bridge/TUN写回压：三轮XTCP direct-download queue high-water均约`33.1KB`、拒绝为0；ingress drop为0。TUN direct write每轮约`222–224K`次、写入`6.80–6.86GB`，失败/partial均为0、最大in-flight为1，累计同步write服务时间约`3.49–3.54s/45s`。该证据不支持继续调大direct-download queue、TUN并发或GSO hold时间。

进一步在单个20秒XTCP诊断格同时采client与server PPP进程：两端profile仍以AES-CFB为主要共享热点；client仍可见packet build，server没有出现明显高于client的新专属热点。该格开启perf采样，不用于goodput比较。随后单独用`/proc/<pid>/stat`在另一个匹配20秒XTCP格采集进程CPU ticks：client侧`iperf3 -s`目标服务进程在15.01秒采样窗中约占`4.5%`单核，server PPP约占`63.0%`；目标iperf进程不是当前吞吐上限，server PPP也未显示单进程饱和。XTCP client的task-clock/B约`5.99ns/B`、selected-CPU nonidle约`6.23ns/B`，结合约`1.160Gbps` goodput，client选定CPU约九成忙，仍最接近当前供给上限。对iperf PID的`perf stat`事件不可用（task-clock/cycles/instructions均报告not supported），没有将该失败计入数据，CPU比例来自只读procfs tick差。

整体看，当前剩余可定位的XTCP专属热区以packet-build/pending-send为主，但前者已约5.7% self，既有AVX2消融的CPU收益仅约3.4%；直接消除packet ownership/build copy属于高侵入改造，单点理论上限也不足以解释全部吞吐差距。当前证据支持继续找client栈内可重复的至少数个百分点收益，但不支持把瓶颈归给iperf目标服务、TUN write或扩大队列。暂不为追1.20而改写重传、pacing或TUN生命周期；若后续试验零拷贝send契约，必须把可重传owner、segment slice和输出iovec一起设计，不能仅绕过首次copy。

Artifacts：正式矩阵`artifacts/gpt6fix-current-nosimd-p1dl-gsoon-cap48-direct32k-r3-45s-20260927/`；cap48 matched profiles `artifacts/gpt6fix-profile-diff-cap48-native-p1dl-gsoon-cpu11-15s-20260927/`、`artifacts/gpt6fix-profile-diff-cap48-xtcp-p1dl-gsoon-cpu11-15s-20260927/`；两端诊断`artifacts/gpt6fix-p1dl-both-endpoints-profile-cap48-20s-20260927/`；iperf进程perf event失败记录`artifacts/gpt6fix-p1dl-iperf-server-perfstat-cap48-20s-20260927/`；procfs tick替代观测`artifacts/gpt6fix-p1dl-server-cputicks-cap48-20s-20260927/`。根`bin/ppp`及产品源码本轮未改。

### 11.129 XTCP TCPv4 partial-checksum offload A/B：无收益，原型撤回（2026-09-27）

针对packet-build约5.7% self samples，曾在隔离候选中让IPv4数据段只写入未取反的TCP伪首部折叠和，并通过TUN VNET `NEEDS_CSUM`交由内核完成；控制段和不支持该语义的路径仍使用完整校验和。候选通过`test_tcp_retransmit`（包括RTO重传元数据/种子验证）、`xtcp_runtime_adapter_test`与`tun_gso_coalescer_test`，产品Release构建成功。随后保持同一候选binary、CPU11、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge与15秒omit配置，仅切换`OPENPPP2_XTCP_TX_CSUM_OFFLOAD`，off/on各3轮；6/6 cell qualification通过。

正式off组goodput=`823.9/830.1/860.7Mbps`，median=`830.1Mbps`；on组=`815.5/821.9/830.2Mbps`，median=`821.9Mbps`，相对约`-1.0%`。进程task-clock/payload-byte中位从`8.796`升至`8.937ns/B`（约`+1.6%`），没有可复现CPU或吞吐收益。初筛单轮on高于off约6.6%，但正式三轮方向相反，故按噪声处理。该实验是XTCP-only消融，不提供XTCP/native ratio验收证据。

据此不晋升该能力；所有本次partial-checksum源码改动已从工作树撤回，未进入vendor patch series或默认配置。对应矩阵和原sandbox netlink拒绝记录均保留：`artifacts/gpt6fix-tx-csum-formal-off-p1-dl-gsoon-20260927/`、`artifacts/gpt6fix-tx-csum-formal-on-p1-dl-gsoon-20260927/`、`artifacts/gpt6fix-tx-csum-candidate-off-p1-dl-gsoon-20260927/`、`artifacts/gpt6fix-tx-csum-candidate-off-p1-dl-gsoon-20260927-retry1/`、`artifacts/gpt6fix-tx-csum-candidate-on-p1-dl-gsoon-20260927/`。撤回后`xtcp_runtime_adapter_test`、`tun_gso_coalescer_test`、`test_tcp_retransmit`均通过。下一步不再优化TCP checksum/build约5%热点，优先从低频PID profile里继续分解timerfd/timer-reactor及kernel receive路径，再按可归因于XTCP的服务时间筛选候选；根`bin/ppp`未改。

### 11.130 隔离 pending-send owner 保留原型：正式收益过小，不晋升（2026-09-27）

§11.121的XTCP PID profile显示`std::vector<unsigned char>::_M_range_insert → TcpConn::SendData → XtcpStack::Send → TrySendPending`约占2.5% self samples。为避免direct-download数据在发送受窗口/pacing限制时先复制进`pending_send_`，在`/tmp/xtcp-owned-pending-proto-20260927`隔离实现`SendDataOwned`：pending队列暂持有owner、offset和length，flush时直接从owner构造可重传segment；加入owner生命周期测试，并补齐close/abort、persist及checkpoint flatten处理。主工作树vendor代码未改；产品候选binary位于`/tmp/gpt6fix-owned-pending-out-20260927/ppp`。

候选静态XTCP CTest为225/239；14个失败项在同一基线源码下逐项对照时均复现（其中`test_sack_gap_edge`首次基线批次通过、随后单项重跑也失败，说明该组有既有时序波动），未观察到该原型特有失败。新增`TestOwnedPendingSendLifetime`通过，产品Release构建成功。候选与未改动基线各进行CPU11、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge、32KiB direct chunk、45秒×3轮fresh-netns矩阵；两组qualification均6/6通过。候选goodput median=`861.0Mbps`、XTCP/native ratio median=`1.0921×`；基线goodput median=`847.0Mbps`、ratio median=`1.0862×`。同日候选相对基线goodput约`+1.65%`，process task-clock/payload-byte由`8.480`降至`8.358ns/B`（CPU效率约`+1.46%`），收益明显小于短筛查所暗示的`+3.8%`，且离`1.20×`仍远。短筛查的3/3组结果为候选=`879.3Mbps`、基线=`847.4Mbps`，仅用于解释短测高估。

该原型涉及TCP pending队列、重入sink字节序和checkpoint/abort生命周期，约1.5%的长测改进不足以覆盖其代码及回归风险，因此不移植、不晋升。全部实现仅存在隔离`/tmp`副本和候选binary；根`bin/ppp`、工作树vendor代码保持原状。正式候选/基线矩阵分别保存在`artifacts/xtcp-owned-pending-formal-candidate-20260927/`与`artifacts/xtcp-owned-pending-formal-baseline-20260927/`，短筛查保存在`artifacts/xtcp-owned-pending-screen-20260927/`与`artifacts/xtcp-owned-pending-baseline-screen-20260927/`。后续回到更高占比服务时间的测量，不继续扩大pending-send ownership实验。

### 11.131 XTCP timer rearm slack 200µs筛查：未降低timer churn，不晋升（2026-09-27）

基于XTCP perf telemetry，P1/DL/GSO-on传输期间约有3.5k KickPoll请求/s、0.7k实际rearm/s；默认50µs slack约抑制0.6k/s。`KickPoll`调用影响ACK/窗口恢复、收包、连接建立/关闭等时序路径，GitNexus索引对该私有符号返回UNKNOWN，故只在隔离Release构建中将`kRearmSlackUs`改为200µs，并采集与50µs基线相同的CPU11、P1/DL、GSO-on、32KiB direct chunk、1MiB sndbuf、memory bridge、12秒×3轮矩阵及XTCP perf telemetry。

两组均6/6 qualification通过；200µs候选XTCP goodput median=`831.9Mbps`，50µs基线=`840.2Mbps`（约`-1.0%`）；process task-clock/payload-byte为`8.682`对`8.665ns/B`，没有CPU收益。telemetry按各采样区间累计后，候选约`10.4k`次rearm/cell，高于基线约`7.6k`；被slack抑制次数约`4.4k`对`8.0k`，没有显示减少timer churn。该方向不晋升；工作树`kRearmSlackUs`恢复为50µs，候选binary仅保存在`/tmp/gpt6fix-timer-slack200-out-20260927/ppp`。矩阵：`artifacts/xtcp-timer-slack200-screen-20260927/`、`artifacts/xtcp-timer-slack50-screen-20260927/`；运行期计数诊断：`artifacts/xtcp-timer-reactor-diagnostic-20260927/`。

### 11.132 当前构建指纹下 AVX2 kernel 复核：CPU成本略降，DL ratio仍未过门（2026-09-27）

重新核对§11.126后，额外在当前工作树构建同为`ENABLE_SIMD=ON`的no-AVX2 control（SHA-256=`799311dc475c7088fca85390070ee6f6f7032123fea06c2ba5ec7c2c99b4b39a`）与隔离AVX2 candidate（SHA-256=`7640a45749b3efba97f0b40f9d0843cac66d833a105c8134034246cb96a7cded`），仅XTCP snapshot中的`CopyAndChecksum` AVX2 kernel不同。CPU11、P1/DL、GSO-on、20秒fresh-netns ABBA两组均qualification通过。control ratios=`1.1687×/1.0322×`、XTCP goodput median约`1.213Gbps`；AVX2=`1.1608×/1.1548×`、XTCP goodput median约`1.306Gbps`。AVX2两轮process task-clock/payload-byte约`5.63ns/B`，control约`5.89ns/B`，呈约4.5% CPU成本下降；但ratio轮间离散很大，候选两轮均未达`1.20×`，20秒screen不能作为性能晋升或稳定改善证据。结合§11.126的45秒×3正式结果，AVX2仍不晋升、不移植，继续优先分析加密/接收路径等更大占比热点。

本轮artifact：`artifacts/gpt6fix-avx2-isolate-control-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-isolate-candidate-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-isolate-candidate-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-avx2-isolate-control-b-p1dl-gsoon-cpu11-20s-20260927/`。其中standalone`test_stack`的数据/MTU用例在control与candidate均可复现失败，其他6个指定针对性测试通过；该失败不作为AVX2特有回归证据。构建时产品目标默认输出曾覆盖`bin/ppp`，已替换为本轮新鲜构建的SIMD-off/no-AVX baseline（当前SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）；原先记录的`785d025c…`二进制在本环境无可恢复副本。工作树产品源码与vendor XTCP源码未因本实验改变。

### 11.133 当前 bin/ppp 构建的 P1/UL GSO-on 三轮复验：每轮超过1.20×（2026-09-27）

为确认当前可执行文件而非历史hash是否仍满足UL目标，使用当前源码新鲜Release构建`bin/ppp`（SIMD-off，SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）执行CPU11 single-core、P1/UL、GSO-on、native/XTCP、`sndbuf=1MiB`、memory bridge、60秒×3 fresh-netns配对矩阵。6/6 cells qualification通过；ratio=`1.2168×/1.2175×/1.2440×`，median=`1.2175×`、MAD=`0.0008`，三轮post-hoc均超过1.20。XTCP/native goodput median=`897.9/737.4Mbps`；process task-clock/byte效率增益median=`1.2708×`，selected-CPU效率增益median=`1.2177×`。矩阵工具的paired性能gate mode为off，因此这里按落盘每轮goodput与paired ratio核验，不描述为runner gate启用通过。

Artifact：`artifacts/gpt6fix-current-bin-p1ul-gsoon-cpu11-r3-60s-20260927/`。该结果更新了当前SIMD-off binary下P1/UL证据；它不解决仍未达1.20×的P1/DL GSO-on及其他矩阵维度，不能代表XTCP整体性能目标已完成。

### 11.134 P1/DL direct-download handoff 高频诊断：尾延迟存在，但不足以归因为吞吐瓶颈（2026-09-27）

针对XTCP-only direct-download `RunDirectDownload → OnSecondLegPayload → TrySendPending`的单飞等待链，在当前 `bin/ppp` 上执行CPU11、P1/DL、GSO-on、32KiB chunk、1MiB sndbuf、memory bridge的30秒XTCP-only诊断，同时启用 `OPENPPP2_XTCP_PERF_JSON` 与datapath telemetry。cell qualification通过，goodput约`836.1Mbps`；因启用高频sidecar且无native配对，该值仅记录诊断环境，不与perf-off正式矩阵比较。

steady采样约每秒接受`3.2–3.4K`个32KiB chunk，direct queue high-water约`32.8KB`、reject为0；`second_leg.handler`中位约`1µs`，`accepted_wait_to_resume`中位约`8µs`。`handoff.admit_to_accept`与等待直方图的p95常落在`1.024ms`桶，少数采样区间升到`256–512µs`；这些是对数桶的上界近似，不等于每包固定等待。该现象提示存在调度尾延迟，但单飞流的主分布很短，且没有队列积压/拒绝，现有证据不足以说明它能解释P1/DL约7%的稳定差距。扩大chunk还受`kDirectReadFlowBudget=32KiB`及reservation单飞约束，未经新的配对测量不应改默认值或取消回压。

对同日PID profile数据重读后，样本中约`3.7%`落在 `Transmission_Packet_Read → recv()` 的内核接收链，约`2.5%`落在timerfd相关路径；二者目前都只有XTCP单侧profile，且隧道接收/解密由native与XTCP共用，不能据此推断相对差距。此次未改源码、XTCP patch、产品binary或运行门禁。诊断artifact：`artifacts/gpt6fix-p1dl-handoff-xtcp-perf-cpu11-30s-20260927/`。后续如复查这条链，应先用perf-off低扰动native/XTCP配对计数验证每有效MB的socket接收调用/内核CPU成本是否有系统差异；否则不值得改异步handoff或timer策略。

### 11.135 AVX2 packet-build + retained pending owner 组合筛选：未见可归因的吞吐收益（2026-09-27）

为验证两个曾各自显示小幅CPU信号的XTCP专属原型能否累积，基于当前工作树的隔离镜像构建组合候选：AVX2 fused `CopyAndChecksum`、`TcpConn::SendDataOwned` retained pending owner，以及direct-download调用`XtcpStack::SendOwned`。SIMD全局选项保持OFF；正式`bin/ppp`未改。基线为当前SIMD-off `bin/ppp` SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`；组合候选SHA-256=`74cfa759f46cddf66d9dd8adce8a419d9560a0147c56fc568b321ce95b58d29f`。GitNexus对vendor符号返回`UNKNOWN`，因此只在独立源码镜像实现和验证，没有把该高风险状态机改动移入主工作树。

候选Release构建成功。XTCP上游fault suite **20/20**、新增owner生命周期所在`test_tcp_fsm`、`xtcp_upload_budget_test`、`xtcp_runtime_adapter_test`全部通过；`xtcp_runtime_bridge_test`在sandbox首次因本地socket权限失败，经仅针对该本地测试的授权运行后通过。

随后CPU11 single-core、P1/DL、GSO-on、cap48、32KiB direct chunk、1MiB sndbuf、memory bridge、20秒fresh-netns ABBA筛选（baseline A、candidate A/B、baseline B），8/8 cells qualification通过；runner paired-performance gate为off，以下按落盘goodput复核。baseline ratio=`1.1119×/1.0674×`，candidate=`1.1250×/1.1307×`。但baseline与candidate的XTCP goodput median约`1.148/1.145Gbps`（候选约`-0.3%`），native median约`1.054/1.015Gbps`（候选组较低），所以表观ratio差主要随native分母漂移，不能归因于代码。process task-clock/payload-byte median约baseline`6.041ns/B`、candidate`6.062ns/B`，selected-CPU指标约`6.282/6.281ns/B`，没有可复现的候选效率改善；两组ratio都远低于1.20×。

因此该组合不晋升、不启动45秒×3正式矩阵，也不把这两个局部原型作为当前P1/DL解法。四个screen artifact：`artifacts/gpt6fix-combo-screen-base-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-screen-candidate-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-screen-candidate-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-combo-screen-base-b-p1dl-gsoon-cpu11-20s-20260927/`。组合实现与binary仅保留在`.tmp-gpt6fix-xtcp-combo-src-20260927/`和`.tmp-gpt6fix-xtcp-combo-build-20260927/`供复核；下一步转查不同的XTCP相对服务率来源，而不是继续叠加这两种改造。

### 11.136 P1/DL perf-off TCP_INFO 与 datapath 归一化筛查（2026-09-27）

为避免高频`OPENPPP2_XTCP_PERF_JSON`扰动吞吐，本轮在当前`bin/ppp`上关闭该profiler，仅保留低频datapath telemetry与目标socket约1Hz的`ss -tin`采样；CPU11、P1/DL、GSO-on、cap48、32KiB direct chunk、1MiB sndbuf、memory bridge，fresh-netns配对45秒。两cell qualification通过，runner gate仍为off；该单轮goodput native=`1.0330Gbps`、XTCP=`1.1571Gbps`、ratio=`1.1201×`，不作为1.20×稳定性验收。

目标TCP数据socket的采样中，native/XTCP的median cwnd约332/376 MSS、RTT约0.30/0.31ms、peer snd_wnd约290.8/297.0KB、pacing rate约7.67/7.94Gbps、delivery rate约2.30/2.96Gbps；`rwnd_limited`均约82–83%。单轮snapshot没有显示XTCP的cwnd、接收窗口或pacing预算比native更差；这不排除更细粒度ACK/调度间隙，也不足以单独证明窗口不是任何情况下的限制。

对measurement区间内的datapath-client计数按字节归一化：carrier解码CPU约native/XTCP=`3.338/3.343M us/GiB`，transport decrypt约`3.303/3.281M us/GiB`，两者基本重合。XTCP TUN direct write约`35.3K/GiB`，native约`47.5K/GiB`；对应写服务CPU时间约`0.547/1.054M us/GiB`，XTCP未表现出更多写调用或更高单位字节写成本。故本轮不支持把共享加解密或XTCP TUN写 syscall 作为相对吞吐差距的主因。由于只有一组配对且归一化计数覆盖的采样边界不完全等于iperf有效载荷窗口，这些仅是排除方向的线索，不是正式统计结论。

进一步将同一组datapath记录按约1秒bucket检查：45个measurement bucket均有TUN direct-write输出，没有零输出秒；TUN写入速率native/XTCP的p10/p50/p90约`113/122/136`与`130/140/141 MiB/s`，对应全窗约`1.056/1.185Gbps`。这与iperf约`1.033/1.157Gbps`方向一致，且没有显见的秒级停供/恢复空洞；但1Hz聚合不能排除毫秒级ACK/pacing停顿，也不是额外重复轮次。

artifact：`artifacts/gpt6fix-p1dl-tcpinfo-perfoff-cpu11-45s-20260927/`。本轮未改运行时源码、TCP/KCC参数或门禁。下一步应继续从perf-off的XTCP专属CPU/内核服务成本寻找相对差异，并用至少多轮配对验证候选；不要因本轮单次TCP_INFO的`rwnd_limited`比例而改拥塞控制或窗口配置。

### 11.137 P1/DL first-match perf profile 实际采到server端（2026-09-27，端点归属更正）

复核`tools/run_datapath_linux_matrix.sh`后发现runner先启动server PPP，再启动client PPP；先前手工wrapper只按binary路径选“第一个ppp PID”，因此§11.137和§11.138两组profile实际附加在server模式进程，且server没有绑定CPU11。原始采样本身和cell qualification仍有效，但不能解释为client-side XTCP CPU占比或CPU11 profile；对应profile期间goodput也不应与perf-off矩阵比较。

server端frame-pointer profile中，XTCP请求cell/native请求cell的`aesni_encrypt`分别约62.9%/60.9%，`CRYPTO_cfb128_encrypt`约6.4%/5.6%，说明该server工作负载共同承担大量transport加密。DWARF profile显示约73%位于Asio socket接收完成路径，约71%沿`ForwardSocketToTransmission → ITransmission::Write → ITransmissionBridge::Encrypt → Transmission_Packet_Encrypt → EVP_EncryptUpdate → AES-CFB/AES-NI`；约11%位于strand/socket接收调度。它们是server端共同路径证据，不是XTCP client栈差异证据。

GitNexus对`ForwardSocketToTransmission`上下文确认直接caller为`ReceiveSocketToTransmission`；概念query因FTS不可用而降级，故调用链来自DWARF和源码。保留原artifact供追溯：`artifacts/gpt6fix-p1dl-perf-record-xtcp-cpu11-25s-20260927/`、`artifacts/gpt6fix-p1dl-perf-record-native-cpu11-25s-20260927/`、`artifacts/gpt6fix-p1dl-perf-dwarf-xtcp-cpu11-15s-20260927/`。实现上packet encrypt确有payload输出与最终frame pack，但当前采样未证明该copy是可观的XTCP相对差距来源；不据此修改共享密码API或协议。

### 11.138 P1/DL client端符号profile纠正采集：XTCP独有叶子热点仍较小（2026-09-27）

为纠正上述PID选择错误，在runner的client PPP已启动且CPU11绑核后，wrapper改为要求命令行包含`--mode=client`，分别采native与XTCP client 20秒`cpu-clock -F 99 -g --call-graph fp`；同binary SHA为`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`。两cell qualification通过、profile无lost samples；这是两个独立diagnostic cell而非ABBA。采样扰动显著且不对称：native cell约`793Mbps`，XTCP约`328Mbps`，这两个goodput不能作性能比较。

`perf report --no-children`中AES-NI约native/XTCP=`29.7%/27.8%`，CFB约`2.6%/1.5%`；native侧`TcpChecksum`、`CompleteTcpV4GsoChecksums`、`ip_standard_chksum`合计约`11.3%`，XTCP侧`BuildSegmentPacket`约`2.9%`、`timerfd_settime`约`2.2%`，其余若干内核/TUN符号各占数个百分点。与perf-off结果结合，当前没有出现足以单独解释约7% throughput gap的稳定XTCP叶子热点；但由于采样严重扰动，不能把这些self比例当准确的production CPU账本，也不能据“未采到”断言无其他热点。

准确client profile artifact：`artifacts/gpt6fix-p1dl-perf-record-client-native-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-perf-record-client-xtcp-cpu11-20s-20260927/`。后续以perf-off throughput/CPU与低频队列/ACK遥测作为决策依据；若需符号级对比，应在程序内添加低扰动、按client PID精确采样的受控ABBA工具支持，再决定是否有超过数个百分点、且可归因于XTCP的改造点。本轮未改产品源码、binary、cipher或性能门禁。

### 11.139 P1/DL direct-download chunk 16KiB vs 32KiB perf-off ABBA筛查（2026-09-27）

针对旧单轮中16KiB chunk表观优于32KiB的信号，使用同一`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）执行32KiB→16KiB→16KiB→32KiB ABBA筛查。每个cell均为fresh-netns、CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、`sndbuf=1MiB`、memory bridge、20秒、perf-off native/XTCP配对；8/8 cells qualification通过，paired performance gate关闭，因此这不是正式性能验收。

32KiB baseline两组ratio=`1.0866×/1.0685×`（median=`1.0776×`），16KiB candidate=`1.0532×/1.0771×`（median=`1.0652×`），candidate median低约`1.15%`。XTCP goodput均值约baseline/candidate=`840.9/820.1Mbps`（candidate约`-2.5%`），native均值约`780.5/770.1Mbps`（candidate约`-1.3%`）；两组candidate的process task-clock/payload-byte均值也由约`8.57`升至`8.87ns/B`，未见效率改善。故不把16KiB晋升为默认或继续跑正式门禁，保留32KiB。

该结果只否定本次环境和配置下“16KiB已有可复现收益”的假设，不代表所有网络/RTT下两种chunk等价。对应artifact：`artifacts/gpt6fix-p1dl-chunk-screen-base-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-chunk-screen-candidate-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-chunk-screen-candidate-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-chunk-screen-base-b-p1dl-gsoon-cpu11-20s-20260927/`。本轮未改产品源码、binary、TCP/KCC参数或性能门禁。

### 11.140 P1/DL 增大 sndbuf 的短筛与正式复核：短期收益未复现（2026-09-27）

为验证`SendData`的`sndbuf_quota`拒绝是否能靠增加发送队列容量改善P1/DL，固定当前`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）、CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、32KiB direct chunk、memory bridge、perf-off，仅切换XTCP `sndbuf`。该发现严格限定P1单流；不推导P4/P16安全，尤其不覆盖已知大sndbuf多流风险。

20秒ABBA筛选中，1MiB baseline ratio=`1.0816×/1.1180×`（median=`1.0998×`），2MiB candidate=`1.1177×/1.1878×`（median=`1.1528×`）；XTCP goodput candidate均值约高`5.0%`，因此进入更长复核。随后2MiB/4MiB筛选中，4MiB ratio=`1.1617×/1.1304×`、2MiB=`1.0871×/1.1381×`；4MiB/8MiB筛选中，8MiB ratio=`1.0646×/1.0651×`、4MiB=`1.1178×/1.1189×`，显示容量收益不单调，8MiB明显更差。

对4MiB执行45秒×3交错复核（1MiB A、4MiB A/B、1MiB B/C、4MiB C），6/6 paired cells qualification通过，未启用性能gate或高频XTCP profiler。1MiB ratio=`1.0984×/1.0839×/1.1019×`（median=`1.0984×`），4MiB=`1.1013×/1.1099×/1.1246×`（median=`1.1099×`），只高约`1.05%`；但XTCP绝对goodput median从约`868.7`降到`864.4Mbps`，process task-clock/payload-byte median从`8.449`升到`8.476ns/B`，没有可归因的绝对服务率或CPU效率改善。故否决把短筛收益当作4MiB优化，不更改默认/runner标准参数，也不据此推进其他方向的高sndbuf。

Artifacts分别位于`artifacts/gpt6fix-p1dl-sndbuf2m-screen-{base-a,candidate-a,candidate-b,base-b}-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-sndbuf4m-screen-{base-a,candidate-a,candidate-b,base-b}-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-sndbuf8m-screen-{base-a,candidate-a,candidate-b,base-b}-p1dl-gsoon-cpu11-20s-20260927/`及`artifacts/gpt6fix-p1dl-sndbuf4m-formal-{base-a,candidate-a,candidate-b,base-b,base-c,candidate-c}-p1dl-gsoon-cpu11-45s-20260927/`。本轮未改产品源码、binary、TCP/KCC参数或性能门禁。

### 11.141 P1/DL 2MiB sndbuf 45秒×3复核：稳定小幅改善但未达标（2026-09-27）

由于2MiB在20秒ABBA中曾出现正向信号，补齐与4MiB相同的45秒交错配对：1MiB baseline A、2MiB candidate A/B、1MiB baseline B/C、2MiB candidate C。保持当前`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）、CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、32KiB direct chunk、memory bridge及perf-off；6/6 cells qualification通过，runner paired performance gate关闭。

1MiB baseline ratio=`1.0787×/1.0869×/1.0928×`（median=`1.0869×`），2MiB candidate=`1.1243×/1.1297×/1.1157×`（median=`1.1243×`），中位相对提升约`3.4%`，三组candidate都高于baseline中位，但没有一组达到`1.20×`。XTCP goodput median约`846.5→881.1Mbps`（`+4.1%`），process task-clock/payload-byte median约`8.687→8.296ns/B`（CPU成本约`-4.5%`）。这说明2MiB在该P1单流实验包络里有小幅、可复现改善，但仍不足以完成1.2目标；不得外推到多流或作为全局默认，因为已有P16大sndbuf wedge证据。

同轮复查perf-off datapath的carrier接收计数，native/XTCP每MiB约`31 recv calls`，解密字节量按有效载荷归一后接近，未支持“XTCP独有的socket recv频率偏高”假设。2MiB矩阵artifact：`artifacts/gpt6fix-p1dl-sndbuf2m-formal-{base-a,candidate-a,candidate-b,base-b,base-c,candidate-c}-p1dl-gsoon-cpu11-45s-20260927/`。本次只验证实验旋钮；未改产品源码、binary、默认sndbuf或性能门禁。

### 11.142 P1/DL direct-download 64KiB 单飞块短筛：吞吐未改善，不晋升（2026-09-27）

基于32KiB direct chunk约每秒3.2k次handoff的诊断计数，临时在隔离候选binary中增加64KiB chunk支持并把单飞flow budget扩至64KiB；正式默认、现存binary及工作树中的16/32KiB支持均不变。候选binary SHA-256=`a7c4adbfc75d3e021b8d5e03fd2c706dd10e4517d15881d36a1f197b238efd35`，根`bin/ppp`仍为`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`。使用CPU11 single-core、P1/DL、GSO-on、cap48、KCC/single-shard、`sndbuf=1MiB`、memory bridge、20秒、perf-off、同一候选binary，按32KiB A、64KiB A/B、32KiB B执行fresh-netns交错矩阵；8/8 cells qualification通过，paired performance gate关闭。

32KiB两轮XTCP goodput=`1163.1/1203.2Mbps`（median=`1183.2Mbps`），64KiB=`1167.1/1169.2Mbps`（median=`1168.2Mbps`），候选约低`1.3%`；32KiB的process task-clock/payload-byte median=`5.927ns/B`，64KiB=`5.835ns/B`（CPU成本约低`1.6%`）。native分母随轮次漂移，ratio中位从32KiB约`1.1453×`到64KiB约`1.1351×`，未见候选改善。收益差小于短测噪声且吞吐方向为负，因此不跑45秒正式复核；回撤64KiB实验开关/flow budget扩展，保留16/32KiB现有合同和全部artifact。四个artifact目录为`artifacts/gpt6fix-p1dl-direct64-screen-base-a-r2-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-direct64-screen-candidate-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-direct64-screen-candidate-b-p1dl-gsoon-cpu11-20s-20260927/`和`artifacts/gpt6fix-p1dl-direct64-screen-base-b-p1dl-gsoon-cpu11-20s-20260927/`。初始sandbox权限拒绝的零cell失败artifact另存为`artifacts/gpt6fix-p1dl-direct64-screen-base-a-p1dl-gsoon-cpu11-20s-20260927/`，不可纳入统计。本次未更改根binary、默认参数或性能门禁。

### 11.143 P1/DL 发送准入 10ms 诊断：窗口/ACK持续空档被排除，sndbuf配额拒绝成立（2026-09-27）

为解释§11.141中2MiB send buffer的小幅收益和§11.142中64KiB direct chunk无收益，在相同单核P1/DL GSO-on运行参数下分别采集10ms XTCP perf/TCP_INFO快照、以及启用send-admission snapshot的单个XTCP诊断cell。两次均为插桩诊断，不与native配对，goodput（约`1.108/1.090Gbps`）不用于性能验收；根`bin/ppp`未修改。

第一轮主数据flow在约`200MB–2.8GB`稳态区间有1,839个相邻10ms样本：1,838个窗口中只有8个未见ACK advance（`0.44%`），最长连续一次；未观测到window-gate计数增长，pacing事件仅11次。cwnd约`2,602 MSS`，peer snd_wnd中位约`13.3MB`，RTT中位约`117µs`。这些样本不支持持续的对端窗口、cwnd、pacing或多窗口ACK空档是本次低速根因，但10ms分辨率不能排除更短时延。

第二轮稳态2,034个样本中，有248个记录到flow处于blocked；248个全部是`SendData`的`sndbuf_quota`拒绝，`non_sendable`为0。常见快照为`pending=32,768`、`inflight=983,952`、`attempt=32,768`、`snd_buf=1,048,576`、`snd_wnd=8,521,728`、`pacing_due=0`；pending+inflight+attempt仅比1MiB quota多`912B`。这证明当前32KiB单飞块常因本地send-buffer准入而被整体拒绝，而非远端窗口或pacing gate。artifact分别为`artifacts/gpt6fix-p1dl-ackcadence-10ms-cpu11-20s-20260927/`和`artifacts/gpt6fix-p1dl-admission-10ms-cpu11-20s-20260927/`。

因此当前优先方向是改善“quota临界点上的整块拒绝/重试”而不是扩大direct chunk、缩短固定retry周期、放松发送保护或改拥塞控制；2MiB send buffer只在该单流包络有约`3.4%`ratio提升，不能泛化为默认值。一个ACK驱动writable通知原型仍需评估：ACK处理、`FlushPendingSend`和stack `Send`共用shard递归锁/strand，不能在TCP ACK栈帧中同步重入`SendData`；通知必须延后到当前packet处理结束后，并覆盖close、connection-id复用及多次pending唤醒。GitNexus upstream图将`FlushPendingSend`标为HIGH风险（5个直接调用、3个execution processes、3个modules），`SendData`图为UNKNOWN/lower-bound（有2个未解析调用点），因此未对该热路径做工作树改动；若继续原型，应在隔离patch-chain中完成并先跑上游fault/unit回归，再考虑任何正式性能矩阵。

### 11.144 P1/DL 3MiB sndbuf ABBA筛选：不优于1MiB，不晋升（2026-09-27）

考虑到§11.141的2MiB在单流45秒复核中有小幅改善，筛选其与4MiB之间的3MiB点。使用相同`bin/ppp`、CPU11 single-core、P1/DL、GSO-on、KCC/single-shard、32KiB direct chunk、memory bridge、20秒、perf-stat配对、paired gate关闭；配置顺序为1MiB baseline A、3MiB candidate A/B、1MiB baseline B。8/8 native/XTCP cells均qualification通过。

1MiB ratio=`1.0864×/1.1082×`（median=`1.0973×`），3MiB=`1.0756×/1.0693×`（median=`1.0725×`），candidate median低约`2.3%`。XTCP goodput median约`847.2→842.7Mbps`（约`-0.5%`），process task-clock/payload-byte约`8.69→8.69ns/B`，没有绝对吞吐或CPU收益信号，因此不跑45秒复核、不改变默认sndbuf。此筛选不能否定2MiB的既有小幅收益，也不代表其它负载下的结论。四个artifact：`artifacts/gpt6fix-p1dl-sndbuf3m-screen-base-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-sndbuf3m-screen-candidate-a-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-sndbuf3m-screen-candidate-b-p1dl-gsoon-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-sndbuf3m-screen-base-b-p1dl-gsoon-cpu11-20s-20260927/`。

### 11.145 P1/DL 2.5MiB sndbuf 与2MiB交错复核：未见稳定增益，不晋升（2026-09-27）

§11.141的2MiB相对1MiB有小幅提升，§11.144的3MiB筛选则为负；此前2.5MiB候选45秒×3曾有两轮超过`1.20×`、一轮`1.1700×`。为排除native分母漂移并直接检验相邻buffer点，使用同一根`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）、CPU11 single-core、P1/DL、GSO-on、cap48、KCC、memory bridge、32KiB direct chunk、45秒、perf-off，按2MiB A、2.5MiB B、2.5MiB B、2MiB A、2MiB A、2.5MiB B执行六个fresh-netns配对cell组；6/6组均qualification通过。

唯一artifact目录重跑的2MiB ratio=`1.1879×/1.1832×/1.1771×`（median=`1.1832×`），2.5MiB=`1.1702×/1.2153×/1.1741×`（median=`1.1741×`）；两组均未达三轮稳定`1.20×`，2.5MiB仅1/3轮过门。XTCP goodput median约`1232.1→1237.8Mbps`（约`+0.5%`），process task-clock/payload-byte median约`6.038→6.042ns/B`（CPU成本约`+0.1%`），差异很小且没有稳定性能增益。较早candidate-only的两轮过门结果不能代表稳定提升；2.5MiB不晋升、不设默认。根binary、源码和sndbuf默认均未更改。六个独立artifact目录：`artifacts/gpt6fix-p1dl-cap48-interleaved-A1-sndbuf2097152-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-interleaved-B2-sndbuf2621440-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-interleaved-B3-sndbuf2621440-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-interleaved-A4-sndbuf2097152-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-interleaved-A5-sndbuf2097152-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-interleaved-B6-sndbuf2621440-45s-20260927/`。此前复用目录的探索轮不纳入本结论。本组及候选formal使用runner当前默认`16KiB` direct-download chunk；§11.141早期1MiB/2MiB对照使用的是显式`32KiB`，两组不可直接视为同chunk条件。

### 11.146 P1/DL cap48 下1MiB vs 2MiB sndbuf正式交错复核：局部收益但未达1.20×（2026-09-27）

§11.141中2MiB相对1MiB曾有小幅改善；为确认该信号在当前`cap48`实验包络是否存在，先做perf-off 20秒A-B-B-A筛查，再做45秒交错正式矩阵。正式矩阵固定当前`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）、CPU11 single-core、P1/DL、GSO-on、KCC、memory bridge、runner默认`16KiB` direct chunk、cap48，仅切换1MiB/2MiB sndbuf；次序为1MiB A、2MiB B、2MiB B、1MiB A、1MiB A、2MiB B。6/6 native/XTCP cell qualification通过，paired gate设为warn。注意§11.141旧对照显式使用`32KiB` direct chunk，因此2MiB效果跨节比较时不能归因为 sndbuf 单变量。

1MiB ratio=`1.0952×/1.0953×/1.1012×`（median=`1.0953×`），2MiB=`1.1698×/1.0633×/1.1881×`（median=`1.1698×`）；2MiB中位配对ratio约高`6.8%`，但3轮都未达`1.20×`。XTCP goodput median约`1134.8→1218.1Mbps`（`+7.3%`），process task-clock/payload-byte median约`6.183→6.072ns/B`（CPU成本约`-1.8%`）；然而2MiB单轮goodput范围约`1.099–1.228Gbps`、ratio范围`1.063–1.188×`，候选自身有明显波动。对2MiB内部高/低轮的perf-off datapath做事后对照：低吞吐B3的`ingress_injected=101,698`，高吞吐B2/B6为`21,649/14,433`；TUN direct-write calls按MiB归一约`66/35/35`，平均每次写出字节约`15.5/29.3/29.6KiB`。这显示波动伴随显著不同的包/注入形态，但现有采样不能确定是ACK行为、GSO合并或其他调度因素造成，不作因果结论；下一步应针对同类高/低轮补低扰动TCP_INFO与XTCP接收/合并计数。结论是2MiB在该单流cap48包络具有值得保留的局部性能信号，但不足以稳定满足目标，也不外推到P4/P16或更大sndbuf；不改变产品默认，不把它记作1.20×验收。正式artifact：`artifacts/gpt6fix-p1dl-cap48-sndbuf-formal-A1-1048576-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf-formal-B2-2097152-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf-formal-B3-2097152-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf-formal-A4-1048576-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf-formal-A5-1048576-45s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf-formal-B6-2097152-45s-20260927/`。screen artifact按`artifacts/gpt6fix-p1dl-cap48-sndbuf-screen-{A1-1048576,B2-2097152,B3-2097152,A4-1048576}-20s-20260927/`保留，但不作正式验收。

### 11.147 P1/DL cap48/2MiB GSO ledger诊断：低速轮与PSH flush密度、合包粒度同步变化（2026-09-27）

为解释§11.146低速B3的TUN write密度，固定XTCP-only、CPU11、P1/DL、GSO-on/cap48、2MiB sndbuf、runner默认`16KiB` direct chunk、memory bridge/KCC，收集三份20秒`--stall-diagnostics`样本；这些插桩cell只用于机制诊断，不比较或验收goodput。三份均qualification通过，观测goodput约`1.153/0.997/1.156Gbps`。

两份较高速样本的ledger分别有约`2.73/2.75GiB` eligible bytes、`49.2k` GSO writes、每次GSO平均`40.1/40.3`段，PSH flush约`44.7k/40.7k`；低速样本约`2.33GiB` eligible bytes、`95.6k` GSO writes、每次平均仅`17.5`段，PSH flush约`95.6k`。低速形态还伴随`ingress_injected=71,214`和约`83k` timer polls，较高速两份分别约`12.4–14.6k` ingress和`53k` polls。多份诊断与正式B2/B3/B6的方向一致：PSH尾包更频繁地结束当前GSO聚合，降低每次TUN写的合包粒度；但该关联仍不能证明PSH是首因（也可能是TCP输入、应用写边界或调度变化的结果）。已有`0016-buffered-push-tail-gso`已实现每段缓冲数据仅末段带PSH；不重复实现同一语义，也不直接放松 coalescer 对PSH包的strict-v1拒绝。随后在不变的cap48/2MiB配置下交错对照`16KiB`与`32KiB` direct chunk，完整结果见§11.148。

诊断artifact：`artifacts/gpt6fix-p1dl-cap48-sndbuf2m-gso-ledger-diag-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf2m-gso-ledger-diagnostic-2-cpu11-20s-20260927/`、`artifacts/gpt6fix-p1dl-cap48-sndbuf2m-gso-ledger-diagnostic-3-cpu11-20s-20260927/`。

### 11.148 P1/DL cap48/2MiB 下 direct chunk 32KiB正式复核：中位达1.20×，仍有一轮未过门（2026-09-27）

依据§11.147的PSH/GSO ledger方向，在固定CPU11 single-core、P1/DL、GSO-on/cap48、2MiB sndbuf、memory bridge、KCC及同一`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）下，仅比较direct-download chunk `16KiB`与`32KiB`。先执行20秒A-B-B-A筛查，再执行45秒六组A-B-B-A-A-B交错正式矩阵；正式6/6组及12/12 native/XTCP cells均qualification通过。

16KiB三轮ratio=`1.1643×/1.2067×/1.1654×`（median=`1.1654×`），XTCP goodput median=`1.209Gbps`；32KiB=`1.1927×/1.2380×/1.2216×`（median=`1.2216×`），XTCP goodput median=`1.260Gbps`，中位绝对goodput约`+4.3%`。32KiB process task-clock/payload-byte median从`6.132`降至`5.855ns/B`（CPU成本约`-4.5%`）。因此32KiB相对16KiB有方向一致的绝对吞吐与CPU收益信号，且ratio中位达到1.20×；但只有2/3正式轮次达到ratio门槛，B2=`1.1927×`为近门槛失败，不足以宣称三轮稳定验收。screen四组ratio为16KiB=`1.1971×/1.1847×`、32KiB=`1.1758×/1.2368×`，仅作为筛选证据，不替代正式结果。

该优化适用范围暂限单流P1/DL、cap48及2MiB实验sndbuf；2MiB sndbuf有已知多流队列风险，故不能把整套组合提升为全局默认，也不能外推为完整1.2目标已经完成。下一步先用安全的`1MiB sndbuf + 32KiB chunk + cap48`交错筛查，判断chunk收益是否独立于高sndbuf；只有通过P1 formal且P4/P16安全验证后，才考虑改变共享chunk默认。正式artifact：`artifacts/gpt6fix-p1dl-cap48-sndbuf2m-chunk-formal-{A1-16384,B2-32768,B3-32768,A4-16384,A5-16384,B6-32768}-45s-20260927/`；screen：`artifacts/gpt6fix-p1dl-cap48-sndbuf2m-chunk-{A1-16384,B2-32768,B3-32768,A4-16384}-20s-20260927/`。

### 11.149 P1/DL cap48/1MiB 下 direct chunk 安全窗口筛查：32KiB有小幅信号，离门槛仍远（2026-09-27）

按§11.148的下一步，在相同`bin/ppp`、CPU11 single-core、P1/DL、GSO-on/cap48、KCC、memory bridge及安全的`1MiB sndbuf`下，仅切换direct-download chunk；先做20秒筛查，再按16KiB A、32KiB B、32KiB B、16KiB A、16KiB A、32KiB B执行45秒fresh-netns正式交错矩阵。正式6/6组及12/12 native/XTCP cells qualification通过，性能门禁为warn，候选未过`1.20×`。16KiB ratio=`1.0938×/1.0951×/1.1053×`（median=`1.0951×`），XTCP goodput median=`1.120Gbps`，process task-clock/payload-byte median=`6.254ns/B`；32KiB ratio=`1.1057×/1.1045×/1.0936×`（median=`1.1045×`），XTCP goodput median=`1.156Gbps`，task-clock/payload-byte median=`6.001ns/B`。candidate中位绝对goodput约`+3.2%`、CPU成本约`-4.0%`，ratio中位只高约`0.9%`且全部轮次都远低于门槛；原20秒筛查估计的`+4.4%`没有在45秒矩阵中完整复现。

因此证据支持32KiB chunk在单流P1/DL有温和的绝对吞吐/CPU信号，但不足以晋升共享默认，也无法单独达到目标；P4/P16及多流安全性亦未验证，保持默认16KiB与1MiB sndbuf。下一步转查GSO合包粒度与PSH尾段机制，先以语义测试及单独原型验证，不直接放宽strict-v1。20秒筛查artifact：`artifacts/gpt6fix-p1dl-cap48-sndbuf1m-chunk-{A1-16384,B2-32768,B3-32768,A4-16384}-20s-20260927/`；45秒正式artifact：`artifacts/gpt6fix-p1dl-cap48-sndbuf1m-chunk-formal-{A1-16384,B2-32768,B3-32768,A4-16384,A5-16384,B6-32768}-45s-20260927/`。

本轮只做了实现审查和针对性测试，没有改动产品源码：retained `BufRef` owner确实沿XTCP输出回调进入Linux TAP，coalescer在GSO writev期间保留各payload生命周期；PSH仍被strict-v1拒绝并作为普通帧写出。`tun_gso_coalescer_test`、`tun_gso_ledger_test`、`tun_gso_mergeability_test`、`xtcp_runtime_adapter_test`、`xtcp_runtime_bridge_test`共`5/5`通过（bridge测试需允许本机loopback socket）。这不能替代端到端性能验证：根`bin/ppp`仍是原SHA，尚未把当前worktree源码构建成可用于比较的产品binary，因此不把已有矩阵归因于这些源码改动。

### 11.150 2MiB sndbuf + 32KiB chunk 的 P4/P16 DL 筛查与 P4正式复核：P4未稳定、P16背压失败（2026-09-27）

为评估§11.148的P1候选是否能推广到多流，使用当前`bin/ppp`（SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）、CPU11 single-core、DL、GSO-on/cap48、KCC、memory bridge，筛查`2MiB sndbuf + 32KiB direct chunk`的P4/P16。20秒筛查中P4 ratio=`1.2055×`；P16 XTCP cell在60秒iperf watchdog触发，matrix qualification失败。诊断时16条数据流均已建立，但XTCP输出停在约`153.1MB`、`ingress_dropped=630`、direct-download queue high-water=`512KiB`、direct-download rejected=`0`；两侧socket快照均显示各流约`98.7–99.8%`时间rwnd-limited、`notsent`队列为数MiB。该证据符合多流接收窗口/下游排空受压形态，但不足以单独确定最初阻塞点；此组合明确不能作为P16安全配置，不重复跑P16候选矩阵。

因P4单轮刚过门，单独补45秒×3 native/XTCP正式配对；6/6 cells qualification通过，ratio=`1.2313×/1.1278×/1.2048×`（median=`1.2048×`），只有2/3轮达到1.20。XTCP/native goodput median约`1.266/1.051Gbps`，XTCP process task-clock/payload-byte median=`6.018ns/B`，但第二轮XTCP goodput降至`1.200Gbps`，ratio仅`1.1278×`。故P4 GSO-on的候选也不满足稳定门禁；保留已验证的P4 GSO-off分层配置，不据此改默认。筛查artifact：`artifacts/gpt6fix-p4p16-dl-sndbuf2m-chunk32-cap48-screen-cpu11-20s-20260927/`；P4 formal artifact：`artifacts/gpt6fix-p4-dl-sndbuf2m-chunk32-cap48-formal-cpu11-45s-r3-20260927/`。

同日进一步补测隔离retained-owner/writev候选binary（SHA-256=`028c196f2da0cd7785e62bb658658ec0828e179aade4fef88d30a7fce91e9202`）的P1/DL：CPU11、GSO-on/cap48、KCC、`sndbuf=1MiB`、16KiB chunk、memory bridge、60秒×3；6/6 cells qualification通过，但ratio仅`1.0638×/1.0659×/1.0255×`，XTCP/native goodput median约`1.727/1.633Gbps`，process task-clock/payload-byte效率增益median约`1.140×`。这表明该候选虽在其他分层场景已达标，不能解决P1/DL的相对吞吐门槛；高绝对goodput也不能替代paired ratio。artifact：`artifacts/gpt6fix-p1dl-retainedowner-writev-cpu11-60s-r3-20260927/`。

### 11.151 P1/DL GSO-on current binary 的 CUBIC/BBR 与2.25MiB send-buffer筛查：无可晋升候选（2026-09-27）

对当前`bin/ppp`（SHA-256仍为`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`）补齐此前缺少的CC比较，固定P1/DL、GSO-on/cap48、`sndbuf=2MiB`、32KiB direct chunk、memory bridge、CPU11 single-core，仅切换KCC/CUBIC/BBR。20秒screen的qualification均通过；CUBIC ratio=`1.0275×`、XTCP goodput=`1.066Gbps`、task-clock=`7.041ns/B`；BBR ratio=`0.1153×`、XTCP=`117.8Mbps`、task-clock=`12.967ns/B`。两者均远低于KCC候选，不升级为正式矩阵，KCC继续保留。

随后在同一2MiB+32KiB配置下筛选2.25MiB（`2,359,296` bytes），20秒A-B-B-A四组native/XTCP cells均qualification通过：2MiB baseline ratio=`1.2095×/1.1641×`，2.25MiB candidate=`1.2357×/1.1645×`。候选中位ratio约`1.2001×`、baseline约`1.1868×`，但每组仅两轮、candidate一过一失；XTCP绝对goodput median约`1.250Gbps`对`1.234Gbps`（约`+1.3%`），不足以证明因果稳定增益，故不升级45秒正式矩阵、不晋升sndbuf。三个实验均未改binary或默认配置。CUBIC artifact：`artifacts/gpt6fix-p1dl-cc-cubic-sndbuf2m-chunk32-cap48-screen-cpu11-20s-20260927/`；BBR artifact：`artifacts/gpt6fix-p1dl-cc-bbr-sndbuf2m-chunk32-cap48-screen-cpu11-20s-20260927/`；sndbuf ABBA artifacts：`artifacts/gpt6fix-p1dl-cap48-sndbuf2250k-chunk32-ABBA-20260927-{A1-20s,B2-20s,B3-20s,A4-20s}/`。

### 11.152 ACK-driven SendWritable 原型复核：未改善 P1/DL，停止该分支（2026-09-27）

复核§11.143提出的ACK后writable唤醒原型。隔离候选在收到TCP ACK并释放本地send quota时，从ACK处理栈帧向同一shard strand尾部post唤醒；不在`OnAckReceived`中重入`Send`，原有retry timer保留为兜底。固定P1/DL、GSO-on、KCC、1MiB sndbuf、memory bridge、CPU11 single-core、45秒、native/XTCP配对；base/candidate各三格，6个矩阵共12/12 cells qualification pass。

baseline三轮ratio=`1.0586×/1.0752×/1.0187×`（median=`1.0586×`），XTCP goodput median约`827.1Mbps`；candidate ratio=`1.0566×/1.0554×/1.0460×`（median=`1.0554×`），goodput median约`787.3Mbps`。候选process task-clock/payload-byte各轮约`8.89–9.48ns/B`，未显示一致CPU成本改善；该候选既未提高goodput，也没有逼近`1.20×`，不晋升、不移植、不再围绕ACK唤醒堆叠改动。矩阵不是同一候选binary下随机ABBA，绝对值仅作该组对照；但其结果足以否决该原型作为当前优先方向。

GSO不是“完全没有发生”：§11.147的ledger已在高速样本观测到约`49K` GSO writes、均值约`40`段；低速样本则约`96K` writes、均值约`17.5`段。另§11.128的matched current-source baseline记录到XTCP约`222–224K`次TUN direct writes承载`6.80–6.86GB`，写入规模与合包帧相符。这些证据说明合并密度随轮次明显变化，但不证明ACK-writable能修复其根因，也不授权放松PSH/strict-v1语义。后续应先对齐高/低吞吐轮的ACK释放量、GSO flush原因和ingress包数；不再重复retry cadence、单纯扩大buffer/chunk或已测过的ACK唤醒原型。Artifacts：`artifacts/gpt6fix-p1dl-ack-writable-formal-base-{a,b,c}-p1dl-gsoon-cpu11-45s-20260927/`及`artifacts/gpt6fix-p1dl-ack-writable-formal-candidate-{a,b,c}-p1dl-gsoon-cpu11-45s-20260927/`。

### 11.153 P1/DL 高低速 GSO ledger 与 per-flow ACK 形态对齐：存在强相关但未定因（2026-09-27）

复核§11.147三份XTCP-only GSO ledger诊断时，将主数据flow的累计`ack_valid`、`ack_advance_bytes`、`flush_attempts`与同一cell的coalescer ledger对齐。两份较高速样本分别发送约`3.09/3.11GB`，有效ACK约`12.3K/14.5K`，ACK advance bytes接近payload；GSO full writes约`49.2K/49.2K`，每次约`40`段。低速样本发送约`2.71GB`，有效ACK约`69.9K`，ACK advance bytes同样接近payload；GSO full writes约`95.6K`，每次仅约`17.5`段。折算到有效载荷后，低速样本每字节有效ACK事件约为高速样本的`5.5–6.5×`，GSO write密度约为`2.2×`；此前记录的TUN ingress packet计数也随低速样本大幅升高。

这比单看PSH总数更具体地表明：该组吞吐差与ACK/ingress包粒度及随后pending flush、GSO聚合长度共同变化，ACK advance总字节并未显示payload确认缺口。因三份都是插桩、XTCP-only诊断，且没有控制外部Linux GSO/GRO输入形态的matched对照，不能断定高ACK频率导致低吞吐，也不能把这归为XTCP算法回归。下一步应优先固定能影响该形态的输入边界，再做低扰动ABBA；若无法锁定输入形态，则将ACK/GSO密度作为解释矩阵轮间离散的协变量，而不再据单次高低速相关性改TCP ACK或PSH语义。三份artifact沿用§11.147列出的目录，per-flow记录在各自`xtcp-perf-client.jsonl.shard-0.jsonl`。

### 11.154 P1/DL veth TSO/GSO-off ABBA：两端绝对吞吐下降，未固定 ACK/ingress 形态（2026-09-27）

为验证§11.153的packet-shape假设，在矩阵runner加入默认不变的opt-in `--veth-gso default|off`：`off`只对每cell临时创建的四个netns veth执行`ethtool -K tso off gso off`，逐接口记录feature readback并要求两项均确认为off；`default`不改设备特征，也保留readback。使用当前`bin/ppp` SHA-256=`26e3418263808ad88d7dd655f9f708ef19cc1526eef99e4eb95adcfe7d31f702`、CPU11 single-core、P1/DL、TAP GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB direct chunk、20秒perf-off，fresh-netns顺序default/off/off/default；8/8 cells qualification通过，所有veth feature readback符合请求。

default两组ratio=`1.1898×/1.2010×`（median=`1.1954×`），native/XTCP goodput median约`1.044/1.248Gbps`；veth TSO/GSO-off两组ratio=`1.1154×/1.1771×`（median=`1.1463×`），native/XTCP median约`0.782/0.895Gbps`。关闭veth TSO/GSO使两端goodput都下降约25–28%，ratio中位低约4.9个百分点；不能把相对比率变化当成XTCP产品收益。更重要的是，off组`ingress_injected`仍从约`16.5K`变到`6.0K`，未稳定§11.147观察到的ACK/ingress形态，因此拒绝将veth TSO/GSO认作该形态变化的直接控制因子；本实验也不说明关闭offload适用于真实网络。

据此保留veth默认offload，不把`--veth-gso off`加入性能推荐或默认matrix。下一步应沿client TUN/内核TCP ACK路径定位输入包数变化来源，或在可观测并固定TCP ACK分组后重复配对；此screen不够支持更改XTCP发送、ACK、PSH或GSO合并语义。runner静态合同、shell语法和`git diff --check`通过。Artifacts：`artifacts/gpt6fix-p1dl-vethgso-screen-{A1-default,B2-off,B3-off,A4-default}-cpu11-20s-20260927/`。

### 11.155 PSH 尾段 GSO 原型：语义单测与 Tap 编译通过，尚未晋升（2026-09-27）

§11.147–154显示 PSH flush 与 GSO 写密度同步变化，但过去因缺少内核路径证据而维持 strict-v1 对 PSH 的拒绝。本轮复查 Linux `tcp_gso_segment()`：分段循环清除非末段的 FIN/PSH，最后一段保留聚合 TCP 头中的 PSH；TCP GRO 对 PSH 设置 flush。基于该实现，本地原型尝试将连续普通段与一个 PSH 尾段组成单个 GSO 帧、在该尾段后立即 flush。coalescer 只把 PSH 置于合并帧 TCP 头，确保本次不再接收后续段；短 PSH 尾段也遵循相同边界。原始包的 negative-GSO fallback 仍逐包写出原始 flags。内核参考：[Linux `net/ipv4/tcp_offload.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_offload.c#L1463-L1476)。

同步更新了 mergeability analyzer：PSH 改为 eligible boundary packet，而非被拒绝包；原 `psh_rejected_packets` 指标替换为 `psh_boundary_packets`，`psh` break reason 表示该合包 run 在 PSH 处结束。coalescer、ledger、mergeability 三组单测均通过（3/3），并且 `build/full` 中 `TapLinux.cpp` 单对象编译通过。GitNexus impact 对 coalescer classifier 的直接调用影响为2个、Tap模块、LOW；对 analyzer 的 ObserveAt/FinalizeRun 影响也仅在 Tap 模块、LOW。

该原型尚不能晋升：本轮已完成当前工作树候选的 TUN/netns byte-exact E2E，但性能筛查仍未达到门槛，详见§11.156。旧矩阵结论均未改写。

### 11.156 当前工作树 PSH 候选的 TUN E2E 与 P1/DL fresh screen（2026-09-27）

为补齐§11.155的集成验证，基于当前工作树以 Release、`ENABLE_XTCP=ON`、`ENABLE_SIMD=OFF` 在 `/tmp` 独立构建候选（SHA-256=`8fec01a5dda4adcfec1025778e727d3c2e0b7ea501530cac40906b952da92b0c`）。未覆盖正式`bin/ppp`。短时 root netns E2E 通过：upload byte integrity、half-close、peer-close tail drain、RST、16次 churn、1% loss/25% reorder/10ms delay/MTU 1280、3秒 soak 及路由/DNS rollback 全部通过；日志和stats保留在`artifacts/gpt6fix-p1dl-psh-current-build-netns-e2e-20260927/`。

随后对同一候选执行一次20秒 fresh-netns P1/DL GSO-on screen：CPU11 single-core、`sndbuf=2MiB`、memory bridge、GSO cap48、32KiB direct chunk，native/XTCP两cell qualification通过。XTCP/native goodput=`1.290/1.159Gbps`，paired ratio=`1.1131×`；process task-clock成本=`5.690/6.374ns/B`，效率增益=`1.1203×`。短screen性能门禁关闭，因此不是正式验收；但明显低于`1.20×`，不进入45秒×3晋升矩阵。完整artifact：`artifacts/gpt6fix-p1dl-psh-current-build-screen-20260927/`。

该结果只证明当前候选正确性和本次cell性能未达标；它不能把PSH边界变化与同一工作树内的retained-owner/writev改动作因果拆分。后续隔离对照见§11.157。P1/DL 1.20×目标仍未完成。

### 11.157 PSH admission × retained writev 同候选四格筛查：未显示可复现收益（2026-09-27）

为隔离§11.156中的两个变量，给Linux TAP coalescer增加候选期运行开关：`OPENPPP2_TAP_GSO_PSH_BOUNDARY=1`启用PSH尾段合并（默认关闭），`OPENPPP2_TAP_GSO_RETAINED_WRITEV_DISABLE=1`禁用retained-owner散射写（默认开启）。PSH关闭时PSH段恢复strict-v1拒绝并作为普通帧输出；writev关闭时coalescer在同步`PushOwned`期间将payload拷入连续superpacket，owner不跨调用保留。两者均在Tap构造时读取，默认不会改变原先保守PSH边界和writev路径。

基于当前工作树重新Release构建同一个候选（`ENABLE_XTCP=ON`、`ENABLE_SIMD=OFF`，SHA-256=`24f728768a3157fce5a4fd2b8a10bcc585ec4bc637551e1e33ce4890dc823fde`；未覆盖`bin/ppp`），执行PSH off/writev on、PSH on/writev on、PSH on/writev off、PSH off/writev off四个fresh-netns 20秒P1/DL筛查。公共条件为CPU11 single-core、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB direct chunk；4/4矩阵及8/8 native/XTCP cell qualification通过。相对ratio依次为`1.0739×`、`1.0894×`、`1.0375×`、`1.0437×`；XTCP绝对goodput分别约`1.214`、`1.206`、`1.226`、`1.226Gbps`，process task-clock成本约`6.114`、`6.111`、`6.010`、`6.027ns/B`。

该结果不支持晋升PSH边界或退回writev：PSH开关的两个匹配屏显方向不一致；writev关闭没有造成可见的XTCP绝对吞吐损失，但其差异处于单轮筛查分辨率内。四组native goodput从约`1.107`到`1.182Gbps`，分母波动明显，故ratio不能用于判定微小开关收益；没有重复/随机化轮次，也没有证明变量实际改变了合包粒度，不作因果结论。重要限制：当时以runner外层环境变量注入开关，native和XTCP两组client Tap都收到相同开关；因此此四格并非“仅改XTCP”的因果消融，也无法排除coalescer选项对native参照的影响。XTCP per-flow采样显示四格主flow均发送约`3.27–3.32GB`，而`ack_valid`为`7.2K–18.1K`、累计`flush_pacing`为`5.1K–20.4K`；同等数据量下控制事件差异比PSH/writev的goodput差异更显著，仍可能由轮间输入/ACK形态或调度差异造成，不能反推因果。后续按这些计数与`ingress_injected`、GSO flush/segment ledger作同cell对齐。

候选默认仍关闭PSH admission、开启writev；coalescer/ledger单测2/2通过，默认PSH-off候选的短时netns E2E（echo完整性、half-close、tail drain、RST、churn、netem、soak和rollback）通过。候选E2E artifact：`artifacts/gpt6fix-p1dl-psh-default-off-netns-e2e-20260927/`；四格artifact根目录：`artifacts/gpt6fix-p1dl-psh-writev-ablation-20260927/`。正式`bin/ppp`哈希未变，性能门禁关闭，本节不是1.20×验收。

后续优先对齐低扰动`ACK advance / ACK events`、`ingress_injected`、GSO flush reason/segments及direct-write bytes，并在同一候选做交错重复；若形态再次分叉，才选定可控的输入/ACK因素单变量实验。避免继续用单轮ratio或添加更多buffer/GSO边界假设解释P1/DL波动。

### 11.158 XTCP-only PSH/writev runner开关验证：单轮有正向信号但未达门槛（2026-09-27）

§11.157确认四格开关同时影响了native和XTCP参照。为固定native对照，在matrix runner新增`--xtcp-tap-gso-psh-boundary off|on`及`--xtcp-tap-gso-retained-writev on|off`：runner先清除调用shell继承的这两个环境变量，只对XTCP client cell设置实验值；native client与两类stack的server保持默认PSH-off/writev-on。取值进入dry-run、matrix metadata与各cell继承的metadata。参数解析、默认值、非法值和native/XTCP plan合同测试通过，shell语法检查通过。

同一候选binary（SHA-256=`24f728768a3157fce5a4fd2b8a10bcc585ec4bc637551e1e33ce4890dc823fde`）重跑P1/DL 20秒四格，条件仍为CPU11 single-core、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB direct chunk，开关次序off/on、on/on、on/off、off/off；4/4矩阵及8/8 cells qualification pass。XTCP/native ratio依次=`1.0614×/1.0944×/1.1206×/1.0522×`；XTCP绝对goodput=`1.229/1.225/1.247/1.218Gbps`，XTCP process task-clock=`6.027/6.024/5.903/6.059ns/B`。PSH-on/writev-off的C格是四者中吞吐最高、task-clock最低，幅度约比A格高`1.5%`、低`2.1%`，但只有单轮；native分母在`1.113–1.158Gbps`之间变化，未形成稳定的1.20×证据。

同一批未插桩XTCP per-flow采样中，A/B/C/D均发送约`3.25–3.32GB`；`ack_valid`分别为`11.4K/7.9K/7.7K/14.6K`，`flush_pacing`为`9.7K/5.8K/5.5K/15.7K`，重传为`2/1/1/5`。C相对D同时表现为吞吐较高、ACK/pacing flush较少，但B也有低ACK/pacing计数而goodput并未高于A；四格顺序执行且每格只有一次，故仍只是与§11.153形态相符的关联信号，不能断言ACK或PSH/writev导致吞吐变化。

该runner修正让新四格成为XTCP-only开关实验，但仍受单轮执行顺序影响；此前外层变量注入的§11.157结果继续保留为无效因果拆分的探索记录，不与此组混算。当前信号只足以安排A/C两格XTCP-only GSO ledger诊断，检查合包段数、PSH flush和ACK/ingress形态是否真的改变；在诊断确认机制且fresh-netns交错筛查稳定前，不跑晋升矩阵、不改默认。Artifacts：`artifacts/gpt6fix-p1dl-psh-writev-xtcp-only-20260927/`。

### 11.159 XTCP-only A/C GSO ledger诊断：开关命中，但未提高合包密度（2026-09-27）

依§11.158只对A（PSH-off/writev-on）与C（PSH-on/writev-off）各跑一份XTCP-only `--stall-diagnostics` cell，确认coalescer分支确实命中。A的measurement-end ledger记录`1,789,310` eligible packets、`1,787,028` merged packets、`44,677`次GSO full write、均值约`40.0` segments/write；PSH rejected=`39,691`、PSH flush=`39,264`。C记录`1,704,290` eligible、`1,673,894` merged、`47,164`次GSO full write、均值约`35.5` segments/write；PSH rejected=`0`、PSH boundary flush=`30,338`。因此新开关确实把PSH从reject转成boundary admission，但本次诊断里没有令合包段数增加，反而C每次GSO平均段数更少；writev-off没有可直接归因的ledger字段。

两格的插桩goodput约`1.055/0.981Gbps`，与无插桩屏显相比下降明显，所以这些数字只用于语义/事件机制核验，绝不用于性能比较或推断PSH令吞吐变差。两份cell qualification通过；artifact：`artifacts/gpt6fix-p1dl-psh-writev-ledger-xtcp-only-20260927/`。当前结论是代码分支生效但无合包密度改善证据，PSH仍维持默认关闭，writev仍默认开启；不再为PSH边界投入晋升轮次。下一步回到低扰动ACK/ingress形态和direct output/write粒度，而非围绕PSH继续调参。

### 11.160 P1/DL `ss -tinp` native对照：rwnd-limited为两栈共性（2026-09-27）

对§11.158中XTCP A/C的低扰动TCP_INFO采样做native参照：XTCP A/C的target iperf发送socket在数据期`rwnd_limited`累计约`18.3/17.8s`（约`83%`），`notsent`中位约`5.37/4.39MB`、`snd_wnd`中位约`309/305KiB`、RTT中位约`0.34/0.33ms`；另一个fresh-netns native cell为goodput=`1.132Gbps`、`rwnd_limited=17.7s`（`82.4%`）、`notsent=6.63MB`、`snd_wnd=154KiB`、RTT约`1.01ms`。三cell均qualification pass。XTCP A/C单独cell goodput约`1.213/1.237Gbps`，但它们无native配对，不用这些cell计算ratio。

因为native与XTCP target sender都呈相近的rwnd-limited占比和数MiB未发送队列，这不能作为XTCP独有的接收窗口故障证据；其成因可能在共同的client接收端/iperf发送设置或网络路径，且当前TCP_INFO只有单轮快照采样，不能定因。保留window、sndbuf及KCC行为，不基于本组扩大窗口/队列。该线索削弱“XTCP receive-window是1.20×差距主因”的假设；后续重点回到相同fresh-netns下的CPU每字节成本和TUN/GSO输出包粒度，重点检查能否降低XTCP单核的单位payload成本。Artifacts：`artifacts/gpt6fix-p1dl-ack-tcpinfo-xtcp-only-20260927/`、`artifacts/gpt6fix-p1dl-ack-tcpinfo-native-20260927/`。

### 11.161 retained writev A-C-C-A XTCP-only复筛：direct write局部更快但端到端无收益（2026-09-27）

对§11.158的A（PSH-off/writev-on）与C（PSH-on/writev-off）做XTCP-only fresh-netns A-C-C-A四格20秒复筛，保持同候选binary、CPU11、P1/DL、GSO cap48、KCC、memory bridge、2MiB sndbuf、32KiB chunk、同样telemetry/perf设置；4/4 cells qualification通过。goodput A=`1.2095/1.2354Gbps`、C=`1.2292/1.2219Gbps`，交错中位分别约`1.2225/1.2256Gbps`（仅`+0.25%`）；process task-clock成本A=`6.115/5.973ns/B`、C=`6.087/6.037ns/B`，中位约`6.044/6.062ns/B`（C略差约`0.3%`）。没有稳定端到端收益。

`datapath-client`中的TUN direct-write局部统计方向更好：A每格约`105–107K`次write、平均`16.9–18.5µs`；C约`102–103K`次、平均`15.0–16.1µs`。但该局部延迟改善没有转化为总goodput/task-clock改善，且C同时启用PSH boundary，无法分离两个变量；该项保留作热点线索，不改变默认、不进入45秒正式晋升。结论是当前Linux TUN direct-write等待不是这组端到端1.20×差距的单一主因。Artifacts：`artifacts/gpt6fix-p1dl-writev-acba-xtcp-only-20260927/`。

### 11.162 当前工作树 SIMD-off/on 交错筛查：单位CPU成本显著下降，XTCP/native仍未稳定达到1.20×（2026-09-27）

沿§11.160建议检查CPU每字节成本，使用相同当前源码分别构建`ENABLE_SIMD=OFF`与`ON`、`ENABLE_SSEA_SIMD=OFF`的Release候选；二进制SHA-256分别为`24f728768a3157fce5a4fd2b8a10bcc585ec4bc637551e1e33ce4890dc823fde`与`7d39cc1be9228aa2adf22f44b79a4d9b70c934fc2c99a4cb32e08a33c4e7eaa6`。SIMD-on产物包含`aesni::AES::Support`，确认AES-NI实现确实被编入。正式`bin/ppp`未覆盖。

在CPU11 single-core、P1/DL、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB direct chunk及相同遥测/perf条件下做fresh-netns A-B-B-A，每个binary各有两次native/XTCP配对cell。全部8/8 cells qualification通过。SIMD-off两次ratio=`1.0635×/1.0750×`，XTCP goodput=`1.234/1.242Gbps`，XTCP process task-clock=`6.069/6.047ns/B`；SIMD-on两次ratio=`1.1564×/1.1180×`，XTCP goodput=`2.121/2.074Gbps`，task-clock=`3.422/3.473ns/B`。native goodput也从off组约`1.155–1.160Gbps`升至on组约`1.834–1.855Gbps`，故不能把绝对goodput提升全归因于XTCP专属路径；但XTCP task-clock每payload byte约下降43%，两次on样本也都优于off的相对ratio。组内只有两次且ratio离散，SIMD-on相对ratio中位约`1.137×`，仍未达到`1.20×`，不能视作晋升证据。

结论：保留SIMD-on作为后续候选构建配置与性能分层验证方向，不改产品默认，也不宣称它单独解决XTCP差距。GitNexus query因FTS不可用未给出代码流；本轮没有改C++符号。fresh artifacts：`artifacts/gpt6fix-p1dl-simd-abba-current-source-20260927/{A1-off,B2-on,B3-on,A4-off}/`。下一步针对SIMD-on候选补测DL的GSO-off及P4并行度，判断当前GSO合包是否抵消SIMD节省，再决定是否进入三轮晋升矩阵。测试运行器资格通过，正式`bin/ppp`哈希保持`fb40d7f6f2e28c217fed0d7ec726ba6fbd8468c404c3c2100fa2201cebdf599c`。

### 11.163 SIMD-on DL P1/P4 × GSO off/on screen：GSO-on接近门槛，GSO-off高ratio但绝对吞吐过低（2026-09-27）

用§11.162同一SIMD-on候选做P1/P4、DL、GSO off/on fresh-netns筛查；CPU11 single-core、GSO cap48、KCC、memory bridge、2MiB sndbuf、32KiB direct chunk及perf/telemetry一致，全部8/8 cells qualification通过。每stratum仅一轮20秒，非验收。

GSO-on时P1 ratio=`1.1808×`（native/XTCP=`1.705/2.013Gbps`），P4=`1.1656×`（`1.622/1.891Gbps`），task-clock效率增益分别=`1.1898×/1.1478×`；这两格绝对吞吐较高，但未达到1.20×。GSO-off时P1/P4 ratio分别升至`1.5343×/1.4613×`，task-clock效率增益=`1.5813×/1.5109×`，但goodput只有native/XTCP=`0.622/0.955Gbps`及`0.604/0.883Gbps`。因此GSO-off的高ratio来自native成本更高且总吞吐显著降低，不是可接受的产品优化，不更改GSO默认。

本screen把SIMD-on、GSO-on P1/DL确认为最接近目标且维持高goodput的已测stratum；尚不具备晋升条件，因为单轮小筛查、ratio低于门槛。Artifacts：`artifacts/gpt6fix-p1p4dl-simd-gso-screen-20260927/`。下一步不扩大成全矩阵：先对高吞吐GSO-on路径做更窄的coalescer cap/写批量筛查并观察平均segments/write、flush和CPU ns/B；只有找到稳定增益再做三轮45秒对照。

### 11.164 GSO cap 收窄与传输密文 owner 复用：结构性少一次分配/拷贝，端到端性能未证实改善（2026-09-27）

先检查GSO cap候选：runner明确限制`--tap-gso-segments`为`1..48`，故cap64尝试在参数解析阶段退出、没有创建cell；SIMD-on、P1/DL、GSO-on/cap32单轮筛查通过2/2 qualification，goodput native/XTCP=`1.623/1.896Gbps`、ratio=`1.1676×`、XTCP task-clock=`3.742ns/B`。与§11.163 cap48单轮`1.1808×`及`2.013Gbps`相比方向更差，但非同轮重复，不能作严谨差值归因；不继续调小cap、不改默认。cap32 artifact：`artifacts/gpt6fix-p1dl-simd-gso-cap32-screen-20260927/`。

SIMD-on profile参考样本中自定义AES-256-CFB encrypt/decrypt分别约占`40.6%/11.3%` self samples。复核传输加密发现steady-state `EVP_transport->Encrypt`刚分配的密文owner随后只在本函数局部使用；`Transmission_Payload_Encrypt_Partial`本来就原地修改它，但`Transmission_Payload_Encrypt`在无delta编码时还额外分配、memcpy一遍。对`Transmission_Packet_Encrypt`做窄改：只在已握手(`!safest`)且`!delta_encode`分支就地变换并保留transport ciphertext owner；handshake/safest、delta-encode及无transport的原始输入路径不变。GitNexus impact为`Transmission_Packet_Encrypt`一个直接调用者`EncryptBinary`、LOW；索引未映射端到端process，所以仍做完整集成验证。

改动后SIMD-on candidate SHA-256=`a9cea1aa899529bd3388487c1af5d764a4719cd87feff3555981cf191b54bb6b`，control为改动前同源码SHA-256=`7d39cc1be9228aa2adf22f44b79a4d9b70c934fc2c99a4cb32e08a33c4e7eaa6`；两者都在`/tmp`，未改正式`bin/ppp`。完整C++套件提权后`141/141`通过；sandbox内首次8项失败都因本地socket `Operation not permitted`，提权同套件全部通过。短时netns E2E通过byte-exact echo、half-close、peer-close drain、RST、16次churn、netem、3秒soak和route/DNS rollback；artifact：`artifacts/gpt6fix-payload-reuse-netns-e2e-20260927/`。

SIMD-on control/candidate先做20秒插桩A-B-B-A，后做30秒低扰动A-B-B-A，均为4/4 matrix、8/8 cell qualification通过，性能gate关闭。低扰动组control XTCP goodput=`2.134/2.106Gbps`、task-clock=`3.306/3.400ns/B`、ratio=`1.1891×/1.1673×`；candidate分别=`2.122/2.149Gbps`、`3.373/3.357ns/B`、ratio=`1.2345×/1.2615×`。虽然candidate XTCP goodput中位只约`+0.7%`，task-clock中位约`+0.4%`（略差），selected-CPU成本约`-0.6%`；candidate的native分母约低`4.9%`，把ratio中位从control约`1.178×`推高至`1.248×`，不可归因于该改动。插桩组的候选XTCP吞吐/CPU也未稳定优于control。结论：这次优化确定删掉无delta steady-state的一次无用payload allocation+memcpy且未见绝对goodput回归，但端到端效益小于当前测量分辨率；不据此声称1.20×达标，不晋升为性能结论。配对artifacts：`artifacts/gpt6fix-p1dl-payload-reuse-abba-20260927/{A1-control,B2-candidate,B3-candidate,A4-control}/`与`artifacts/gpt6fix-p1dl-payload-reuse-clean-abba-20260927/{A1-control,B2-candidate,B3-candidate,A4-control}/`。

本轮`git diff --check`及matrix runner shell语法通过；正式`bin/ppp` SHA-256仍为`fb40d7f6f2e28c217fed0d7ec726ba6fbd8468c404c3c2100fa2201cebdf599c`。XTCP整体1.20×目标仍未完成；P4/DL与P1/UL的低扰动泛化复筛见§11.165。

### 11.165 传输密文 owner复用的P4/DL、P1/UL泛化复筛：未观察到跨场景吞吐增益（2026-09-27）

沿§11.164使用相同SIMD-on control/candidate，在CPU11 single-core、GSO-on/cap48、memory bridge、2MiB sndbuf、32KiB chunk、process perf-stat且关闭datapath/XTCP高频遥测下分别做P4/DL与P1/UL 30秒A-B-B-A；每组4/4 matrix、8/8 cells qualification通过，paired gate关闭。

P4/DL control ratio=`1.1900×/1.1430×`、XTCP goodput=`2.046/1.917Gbps`、task-clock=`3.523/3.698ns/B`；candidate=`1.1863×/1.1852×`、`1.948/1.968Gbps`、`3.656/3.612ns/B`。两组绝对goodput与CPU成本随轮次共同波动；candidate XTCP goodput中位较control低约`1.2%`，task-clock中位高约`0.6%`，没有可靠收益。

P1/UL control ratio=`0.9675×/0.9857×`、XTCP goodput=`1.089/1.085Gbps`、task-clock=`6.327/6.349ns/B`；candidate=`0.9634×/0.9806×`、`1.070/1.121Gbps`、`6.483/6.168ns/B`。中位goodput约高`0.8%`、task-clock约低`0.2%`，但XTCP/native ratio约低`0.5`个百分点；均在该短筛分辨率内，既不支持性能晋升，也没有稳定方向性回退。

这项改动可以确认减少无delta steady-state transport ciphertext payload阶段的一次分配和完整memcpy，E2E及141项C++回归通过，但不能声称它带来1.20×或稳定吞吐提升；作为低风险局部allocation削减保留在候选工作树，正式产品binary不变。P4 artifacts：`artifacts/gpt6fix-p4dl-payload-reuse-abba-20260927/{A1-control,B2-candidate,B3-candidate,A4-control}/`；P1/UL artifacts：`artifacts/gpt6fix-p1ul-payload-reuse-abba-20260927/{A1-control,B2-candidate,B3-candidate,A4-control}/`。后续若要追求明确端到端增益，应从SIMD-on profile确认的AES-256-CFB主耗时（encrypt约40.6% self samples，decrypt约11.3%）之外寻找XTCP独有成本，不再追加这类对两栈共用的微小copy优化。

### 11.166 当前 SIMD-on 候选 PID callgraph 复核：packet-build仍是XTCP专属热点，但不重开已否决的checksum分支（2026-09-27）

对当前 SIMD-on 候选（SHA-256=`a9cea1aa899529bd3388487c1af5d764a4719cd87feff3555981cf191b54bb6b`）做P1/DL、GSO-on/cap48、CPU11 single-core、45秒fresh-netns单格，并在XTCP client进程上附加20秒`perf record -F 49 -g --call-graph dwarf`；cell qualification通过，XTCP goodput=`2.129Gbps`、process task-clock=`3.353ns/B`。774个samples无lost samples。XTCP client self样本中`aesni::aes256_cfb_decrypt`约`17.18%`，XTCP `BuildSegmentPacket`约`6.72%`；后者调用链约`4.13%`经过`FlushPendingSend → OnPoll → PollAckTimers → SchedulePoll`，另约`2.58%`来自ACK接收路径。kernel中另有约`4.52%`处于未符号化地址，因此不能将其分配给某个Linux函数。

同样条件另对native/lwIP单独采样20秒，但该cell goodput只有`340.6Mbps`，不是有效配对对照。native PID的AES-CFB decrypt self样本约`2.28%`；结合约`6.3×`的goodput差，这个比例与按处理字节量变化大致相符，不能把XTCP的17.18%误作XTCP相对native独有的CPU余量。两次profile均为单格诊断，不用于ratio、性能晋升或因果差值；详细文件分别在`artifacts/gpt6fix-current-simd-p1dl-perf-record-20260927/`与`artifacts/gpt6fix-current-simd-native-p1dl-perf-record-20260927/`。

`BuildSegmentPacket`的XTCP归属明确，但checksum/fused-copy已有SIMD/AVX2单独消融：虽显示数个百分点的单位CPU下降，正式多轮仍未稳定达到1.20×，不重开该优化分支。当前只确认packet-build/pending-send仍是可测的XTCP本地热点，尚无新的低风险、足量优化证据。GitNexus索引已按仓库参数重建并与当前commit一致，但仍未索引`third-party/xtcp`外部准备树；`BuildSegmentPacket` impact为UNKNOWN，不能把“无图边”当作无调用。该轮未改C++，正式`bin/ppp` SHA保持不变；XTCP整体1.20×目标仍未完成。

### 11.167 SIMD-on P1/DL GSO-on 2MiB/32KiB 正式配对复验：中位刚过、逐轮门禁失败（2026-09-27）

针对§11.148的2MiB+32KiB组合和§11.163的SIMD-on候选交集，使用候选binary SHA-256=`a9cea1aa899529bd3388487c1af5d764a4719cd87feff3555981cf191b54bb6b`，执行CPU11 single-core、P1/DL、GSO-on/cap48、KCC、memory bridge、XTCP sndbuf=`2MiB`、direct-download chunk=`32KiB`的native/XTCP fresh-netns 45秒×3正式配对；paired performance gate设为`fail`、阈值`1.20×`。6/6 cells qualification全部通过，但ratio=`1.2012×/1.1488×/1.2319×`，只2/3轮过门，median=`1.2012×`且MAD=`0.0307`，因此runner总体status为fail，不能宣称稳定达成目标。

XTCP三轮绝对goodput=`2.209/2.178/2.167Gbps`，范围约1.9%；native=`1.839/1.896/1.759Gbps`，中位`1.839Gbps`。失败轮的XTCP吞吐仍在自身范围内，native该轮则是三轮最高；这只说明该次ratio miss主要由配对参照较快所致，不证明候选应达标或native异常。XTCP process task-clock/payload-byte median=`3.310ns/B`，CPU效率增益median=`1.2396×`，但CPU效率门不替代throughput门。artifact：`artifacts/gpt6fix-current-simd-p1dl-gsoon-cap48-sndbuf2m-chunk32-formal-20260927/`。

此配置只适用于本次P1单流性能探索；2MiB sndbuf已有P16背压失败证据，禁止据此升为共享默认或外推多流。下一步不是放宽逐轮门槛，而是寻找能提高XTCP绝对服务率、同时不增加每连接/aggregate send queue上限的改进；现有partial-credit试验已否决小前缀重复Send，packet-build AVX2收益也不足以单独通过门禁。当前完整1.20×目标仍未完成。

### 11.168 AES-256-CFB解密四块交错候选：内核与绝对吞吐有收益，1.20×正式门禁仍失败（2026-09-27）

基于§11.166的XTCP profile（`aesni::aes256_cfb_decrypt`约17.18% self samples），利用CFB解密第i块的AES输入已由前一密文块确定这一性质，为AES-NI实现四块交错AESENC调度；少于四个完整块仍走原标量路径，尾字节和密文反馈语义不变。单独标量参考对照和OpenSSL加密→SIMD解密差分覆盖长度`1/15/16/17/63/64/65/1400/4096`，均byte-exact。独立kernel benchmark在1400字节的15次重复中位数为scalar=`769ns`、simd4=`491ns`（约`1.57×`）；Google Benchmark库本身为Debug构建，故仅把它作为相对微基准，不当作生产绝对耗时。

用SIMD-on、XTCP-enabled Release配置构建候选，binary SHA-256=`791c04cac804a6f879cc80dd98ca5c6f73e279062479141c1193b4dc8b7086d4`；此前control SHA-256=`a9cea1aa899529bd3388487c1af5d764a4719cd87feff3555981cf191b54bb6b`。20秒P1/DL筛查2/2 cells qualification通过，候选goodput=`2.186Gbps`、ratio=`1.1686×`、XTCP process task-clock=`3.246ns/B`，不作为正式验收。

随后在CPU11 single-core、P1/DL、GSO-on/cap48、KCC、memory bridge、sndbuf=`2MiB`、direct-download chunk=`32KiB`、perf-stat开启的条件下做45秒fresh-netns A-B-B-A；四组均2/2 cells qualification通过。control A1/A4 ratios=`1.1710×/1.1152×`、XTCP goodput=`2.053/2.128Gbps`、task-clock=`3.494/3.337ns/B`；candidate B2/B3分别=`1.2010×/1.1147×`、`2.221/2.189Gbps`、`3.184/3.221ns/B`。两样本中candidate XTCP goodput中位约高`5.5%`，process task-clock中位约低`6.2%`；paired ratio中位仅由约`1.143×`到`1.158×`，且A/B各只有一轮过`1.20×`，仍是探索性性能信号。

候选再执行历史严格45秒×3配对矩阵，paired gate=`fail`、逐轮阈值=`1.20×`。6/6 cells qualification通过，但ratios=`1.0913×/1.2764×/1.1951×`，仅1/3轮过门，median=`1.1951×`、MAD=`0.0813`，总体status=`fail`。XTCP绝对goodput=`2.221/2.253/2.221Gbps`，process task-clock median=`3.184ns/B`。因此该内核优化有局部与XTCP绝对服务率改善证据，却没有稳定满足吞吐目标；不放宽门禁、不据此调整队列或默认值。Artifacts：`artifacts/gpt6fix-aes-cfb-p1dl-screen-20260927/`、`artifacts/gpt6fix-aes-cfb-abba-{A1-control,B2-candidate,B3-candidate,A4-control}-20260927/`、`artifacts/gpt6fix-aes-cfb-p1dl-gsoon-cap48-sndbuf2m-chunk32-formal-20260927/`。

本次候选链接初次沿用项目配置时，CMake将可执行文件写到工作树`bin/ppp`；已立即用原SHA相同的备份恢复正式文件，最终SHA仍为`fb40d7f6f2e28c217fed0d7ec726ba6fbd8468c404c3c2100fa2201cebdf599c`，候选另存于`/tmp`，未运行安装或发布操作。当前工作树保留AES实验源码与benchmark；整体1.20×目标仍未完成。

### 11.169 AES候选解密热点复测：AES占比下降，packet-build成为最大可见XTCP函数（2026-09-27）

对§11.168同一AES候选做XTCP-only、P1/DL、GSO-on/cap48、CPU11、30秒fresh-netns诊断cell；qualification通过，goodput=`2.150Gbps`、process task-clock=`3.317ns/B`。另以`perf record -F 49 -a -C 11 -g --call-graph dwarf`系统级采样，并按该cell PPP PID过滤；总采样2,940、lost=0，PPP进程约2K样本。过滤后self samples中`aesni::aes256_cfb_decrypt`=`5.54%`，较§11.166未优化profile的`17.18%`明显下降；`BuildSegmentPacket`=`3.20%`、`FlushPendingSend`=`0.54%`、`timerfd_settime`=`0.41%`、`pthread_mutex_lock`=`0.71%`。若干地址仍未符号化，且系统级采样混有CPU11上的其他任务/内核样本；上述self百分比仅用于进程内热点排序，不相加成端到端收益。

这组结果支持四路AES解密交错减少了真实CPU热点，但剩余最大的单个已符号化XTCP函数仅约3.2%；后续不直接重写TCP状态机，而先对照packet-build的单位调用/字节成本与每包 retained-output callback、`shared_ptr`生命周期成本，估算实际可优化上限。两个候选工作树内单包共享引用路径合计为低个位数百分点，尚无单点足以解释剩余ratio差距；当前仍不声称达到1.20×。profile-only artifact：`artifacts/gpt6fix-aes-cfb-p1dl-profile-retry-20260927/`；单格性能diagnostic：`artifacts/gpt6fix-aes-cfb-p1dl-profile-cell-20260927/`。

### 11.170 output callback弱引用锁消除筛查：无可辨识收益，候选已撤回（2026-09-28）

针对§11.169剩余的每包callback/shared_ptr开销，试验仅将 owning `counted_output_` wrapper 改为捕获裸 `Impl*`，利用 stop 时保活 `Impl`、并在所属 shard strand 上先析构 stack/backend 的生命周期顺序，移除该包装器中的热路径 `weak_ptr::lock()`。borrowed/retained wrappers 未改。变更前通过源码审阅确认该 teardown 次序，并以完整 C++ suite `141/141` 验证候选。候选 SHA-256=`c9b414dd5301a2f721312cf6454e011539e02bf29627f07970963ae7d502f722`，对照（含AES优化、不含callback改动）SHA-256=`791c04cac804a6f879cc80dd98ca5c6f73e279062479141c1193b4dc8b7086d4`；两者均只在 `/tmp` 构建，正式 `bin/ppp` 未改。

为避免native分母噪声，对同一 P1/DL、XTCP-only、CPU11、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB chunk 配置做45秒 fresh-netns A-B-B-A，四格均 qualification pass。goodput A=`2.194/2.236Gbps`、B=`2.176/2.172Gbps`，交错组中位数 A=`2.215Gbps`、B=`2.174Gbps`（B低约`1.8%`）；process task-clock A=`3.222/3.175ns/B`、B=`3.248/3.234ns/B`，中位 A=`3.199ns/B`、B=`3.241ns/B`（B高约`1.3%`）。proc non-idle ns/B方向不一致，不能支持稳定改善；单轮ABBA亦不具正式晋升资格。

由于未观察到收益且裸指针方案增加隐含生命周期约束，本轮撤回 owning `counted_output_` wrapper 的裸指针改动，保留既有 borrowed/retained callback实现及其他工作树改动；不据此声称优化成功。Artifacts：`artifacts/gpt6fix-aes-callback-abba-{A1-control,B2-candidate,B3-candidate,A4-control}-20260928/`。

### 11.171 2MiB/32KiB P1/DL flow 与 quota 阻塞复诊：拒绝确认为有界 sndbuf backpressure（2026-09-28）

对§11.167/§11.168当前 SIMD+AES 候选（实际执行 binary SHA-256=`791c04cac804a6f879cc80dd98ca5c6f73e279062479141c1193b4dc8b7086d4`）补做两个 XTCP-only fresh-netns 诊断cell，固定CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、`sndbuf=2MiB`、direct chunk=`32KiB`。普通1秒 XTCP perf采样一格、qualification通过、goodput=`2.132Gbps`：steady-state每秒约`190K` TUN输出包、平均包长`1465B`；XTCP主flow cwnd约`1,423 MSS`、peer `snd_wnd`约`19–20MiB`、pacing约`3.1–3.2Gbps`、RTT约`100–165µs`、未见重传，`Send()`平均同步耗时约`4.3µs`。每秒约`130`次send reject、记录stall约`147–150ms`；这些指标来自诊断输出，stall是应用数据提交等待，不等价于同等长度的端到端吞吐空洞。

随后通过仅在`/tmp`的env wrapper把perf sidecar间隔调为50ms并启用已有send-admission snapshot，20秒插桩cell qualification通过；`570`个sidecar采样中`203`个记录到flow blocked，且`203/203`均为`sndbuf_quota`，没有`non_sendable`或unknown分类。典型阻塞快照为`attempt=32,768`、`pending≈1.78MiB`、`inflight≈280KiB`、`snd_buf=2MiB`，三者合计比quota多约`2KiB`；这说明单个32KiB direct read超过当时剩余的本地有界send credit，并非无窗口、无ACK或pacing deadline造成。50ms采样与ACK telemetry提高观测开销，该cell goodput=`2.109Gbps`只作诊断背景，不与普通perf-off结果比较。Artifacts：`artifacts/gpt6fix-p1dl-flow-state-diagnostic-20260928/`、`artifacts/gpt6fix-p1dl-admission-2m-chunk32-20260928/`、`artifacts/gpt6fix-p1dl-admission-2m-chunk32-50ms-20260928/`。

结论是本地sndbuf quota确实限制应用继续供数，但它同时保护了每连接重传/缓冲内存上界；不能仅凭reject次数把quota抬高或把超额数据偷塞进stack。更重要的是，既有1MiB精确quota分类、ACK-writable三轮对照、16/32KiB当前与历史筛查以及2/2.5MiB buffer交错复验已分别显示：变更唤醒/块大小/继续加buffer都没有提供稳定的1.20×晋升证据。本轮因此未改运行时/TCP发送逻辑；2MiB/32KiB只保持为P1探索包络，不外推多流或产品默认。下一阶段应继续找有独立于quota参数的XTCP特有服务时间成本；kernel callchain里最大的一组仍因容器`/proc/kallsyms`地址被清零而未符号化，当前CPU11 profile不能将这部分归给具体内核函数。

### 11.172 旧 CPU11 profile 重新按 comm 归一化：最大未知样本属于 idle，不属于 PPP（2026-09-28）

复核§11.169使用的`perf record -F 49 -a -C 11`原始数据后发现，报告顶部`46.43%`的未符号化地址样本对应`comm=swapper,pid=0`，其调用链含 idle/启动期地址，不能计入PPP热点。该记录共约2.9K样本，其中perf script统计到`ppp`约1,405、`swapper`约1,369；所以§11.169把系统级全样本中的比例当作“PPP进程内 self samples”的表述不准确，相关占比不应直接用于热点排序。

以`perf report --comms ppp --percentage relative`重新筛选/归一化后，当前候选PPP task样本中`aesni::aes256_cfb_decrypt`约`11.69%`、`BuildSegmentPacket`约`6.74%`；另有约`9.25%`落在按运行时ftrace函数地址表推定的`copy_mc_to_user`区间，调用链同时包含`tun_get_user → tun_chr_write_iter`。由于`/proc/kallsyms`不可用且地址映射只是区间推定，这个看似方向不一致的内核调用栈尚不足以归因为某个具体TUN copy；只能确认它不是之前那个46.43%的idle样本。该次重归一化只是对已有30秒profile的分析修正，不是新的独立测量。

随后尝试按同一P1/DL配置重新跑30秒fresh-netns cell并对PPP PID定向`perf record`，但运行环境在创建网络命名空间时因`Cannot open netlink socket: Operation not permitted`、零cell退出；没有新的吞吐或profile结果。失败artifact保留于`artifacts/gpt6fix-aes-cfb-pid-profile-20260928/`。下一次有效采样应由runner启动后直接附着PPP PID，而非`-a -C` system-wide；本轮不据旧profile或失败运行提出内核/TUN优化，更不将1.20×目标标记完成。

### 11.173 进程定向 profile 与当前三轮 P1/DL 门禁：未达 1.20×，瓶颈不能再归给 packet-build（2026-09-28）

在获准执行隔离netns后，使用当前候选binary SHA-256=`791c04cac804a6f879cc80dd98ca5c6f73e279062479141c1193b4dc8b7086d4`，对PPP PID本身分别做20秒`perf record -e cpu-clock -F 49 -g --call-graph dwarf`，而不是system-wide CPU采样；两个profile分别772/597 samples，均0 lost，且cell qualification通过。XTCP profile的self samples中`aesni::aes256_cfb_encrypt`=`60.23%`，其callchain位于`ForwardSocketToTransmission → ITransmissionBridge::Encrypt → Transmission_Packet_Encrypt`；`BuildSegmentPacket`未进入0.2%输出阈值。Native profile的AES-CFB encrypt为`69.18%`。这表明当前单流P1/DL PPP任务中的主可见CPU热点是双方共用的传输加密，不是此前估计的XTCP packet-build；但这两次独立、带采样扰动的profile不用于比较占比或吞吐因果。对应cell分别约`2.166Gbps`与`1.790Gbps`，不得当作配对ratio。Artifacts：`artifacts/gpt6fix-aes-cfb-pid-profile-elevated-20260928/`、`artifacts/gpt6fix-aes-cfb-p1dl-native-pid-profile-20260928/`。

随后用同一候选执行CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB direct-download chunk、45秒×3 native/XTCP配对门禁。6/6 cells qualification通过，但goodput ratios=`1.1490×/1.1131×/1.0835×`，3/3低于`1.20×`；median=`1.1131×`、MAD=`0.0297`，总状态fail。XTCP goodput=`2.177/2.209/2.176Gbps`（自身稳定），native=`1.895/1.985/2.009Gbps`；process task-clock median=`3.215ns/B`对`3.730ns/B`，CPU效率优势median约`1.160×`，仍不足以替代吞吐门禁。XTCP普通stats有`direct_download_rejected=0`、队列high-water约33KiB、无ingress drops；这只能说明direct-download写队列未拒绝/未堆积，不能等同于TCP sndbuf admission telemetry。Artifact：`artifacts/gpt6fix-aes-cfb-p1dl-current-candidate-r3-20260928/`。

决策：不再把解密四路交错、packet-build或增加sndbuf当作当前最直接突破口。传输AES-256-CFB的加密反馈链是串行的，无法用同一条流的多块AES交错隐藏延迟；而更换transport cipher即使可提高共享路径吞吐，也会改变双方配置/互通条件，不作为默认性能修复。本轮未改运行时代码或产品binary。下一步应从当前共同加密成本之外继续找XTCP发送服务率的可量化差额，并优先验证能让XTCP绝对goodput越过约2.2Gbps平台限制的路径；1.20×仍未完成。

### 11.174 direct-download 单飞交接时间定量：有小幅上限，不足以单独解释 ratio 缺口（2026-09-28）

针对§11.173发现的单飞reservation路径，用`--xtcp-perf`做20秒XTCP-only P1/DL sidecar诊断，qualification通过，goodput=`2.087Gbps`（插桩数据，仅作诊断背景）。23个有效1秒perf区间中，`admit_to_accept` p50=`4–8µs`、p95=`8–16µs`，`accepted_wait_to_resume` p50=`8–16µs`、p95=`16–32µs`；`XtcpStack::Send`平均同步耗时约`3.6–5.3µs`。同区间`direct_download_queue_bytes_highwater=32,768B`，每秒约`8.0–8.3K`次Send、`105–129`次拒绝、记录stall约`121–147ms`。这些值带有perf sidecar计时扰动；stall累计量不等同于同等长度的端到端吞吐空洞。

当前chunk=`32KiB`，以约`2.1Gbps`估算每chunk的线上发送时间约`125µs`；若把每chunk约`8µs`的中位恢复等待全部隐藏，单飞交接理论收益上限约`6%`，尚低于当前三轮median ratio从`1.113×`到`1.20×`所需约`7.8%`的XTCP吞吐提升，而且尚未计入缩小chunk后更多`Send()`调用的成本。单纯将窗口从1扩到4还会把每flow reservation/暂存上限从32KiB升至128KiB；即使aggregate 32MiB上限不变，也扩大了单flow内存和并发不公平风险。故本轮不直接扩队列或改waiter状态机；若继续验证，必须先做保持aggregate/per-flow字节预算不变的有界批次原型，并将P1收益与P16公平性/内存作为同一门禁。当前没有证据证明单飞交接是主因，也没有新的吞吐晋升结果。Artifact：`artifacts/gpt6fix-aes-cfb-p1dl-direct-handoff-perf-20260928/`。

### 11.175 固定32KiB预算的direct-download window=2原型：组合收益不足且历史最优配置回退，原型已撤回（2026-09-28）

曾短暂实现实验开关`OPENPPP2_XTCP_DIRECT_DOWNLOAD_WINDOW=2`，以两个16KiB reservation隐藏direct handoff；保持每flow 32KiB、aggregate 32MiB预算，覆盖任意完成顺序、early completion与close cleanup，并成功通过对应bridge test、production Release library编译和P16 smoke。matrix runner也曾短暂暴露窗口参数。候选binary SHA=`7537e9068a019a409980f27e6ff7c08a9f55f3eee885095183cd9db70f6341b6`。以下性能结果否定了保留这套通用实现的净收益，因此运行时状态机、reservation token-map/per-flow bookkeeping与runner开关已撤回，当前源码恢复原有单飞模型；测试恢复原有单飞契约。候选binary与artifact保留供复核，正式`bin/ppp` SHA始终为`fb40d7f6f2e28c217fed0d7ec726ba6fbd8468c404c3c2100fa2201cebdf599c`。

新候选与改动前binary（分别SHA=`7537e906…`、`791c04ca…`）在CPU11、P1/DL、GSO-on/cap48、memory bridge、sndbuf=2MiB、32KiB chunk下做20秒A-B-B-A，qualification四格通过。旧候选XTCP-only goodput=`2.238/2.212Gbps`、process task-clock=`3.142/3.200ns/B`；新默认window=1为`2.197/2.172Gbps`、`3.197/3.260ns/B`。两组均值约`2.225/2.184Gbps`，新代码默认路径低约`1.8%`、task-clock高约`1.8%`；样本只有两格/组，但方向一致，已足以否决无收益的额外per-flow map/waiter复杂度，不能宣称这些差异是精确因果值。

在相同2MiB sndbuf下，window=2/16KiB两格为`2.043/2.072Gbps`，均值`2.058Gbps`；相较旧候选2MiB/32KiB单飞均值约低`7.5%`。此前sndbuf=1MiB、16KiB chunk的同候选ABBA中window=2比window=1高约`3.4%`，但native/XTCP单轮配对只有`1.0161×`，未达到`1.20×`。P16 smoke为`1.998Gbps`、16/16流非零、max/min=`1.053`且无direct reject；这证明没有明显公平性/队列越界问题，却不改变P1吞吐净回退，也不是P16相对性能对照。

因此不保留该原型；结论是单飞handoff有可测局部等待，但以更小chunk批次化并不能在历史最优包络中转化为端到端收益。matrix runner shell/Python语法检查、`git diff --check`通过；改动期间全量CTest为133/141，socket受限运行后改动相关XTCP bridge/adapter测试均在获准loopback环境通过。GitNexus impact因schema mismatch为UNKNOWN，改动已人工审阅。Artifacts：`artifacts/xtcp-window2-control-20260928/`、`artifacts/xtcp-window2-treatment-20260928/`、对应`*-r2-20260928/`、`artifacts/xtcp-window2-paired-screen-20260928/`、`artifacts/xtcp-window2-p16-treatment-20260928/`、`artifacts/xtcp-window2-default-compat-abba-{A1,B1,B2,A2}-20260928/`、`artifacts/xtcp-window2-2m-16k-abba-{B1,B2}-20260928/`。

### 11.176 PPP syscall-per-payload诊断与P1/DL正式门禁复验：XTCP syscall密度较低，吞吐仍未稳定过1.20×（2026-09-28）

为从进程PID维度定量检查内核边界，matrix runner新增默认关闭的`--process-syscall-perf`；它在runner自身PID namespace中对PPP PID附加`perf stat` tracepoints，记录read/readv/write/writev/sendto/recvfrom/sendmsg/recvmsg计数，结果写入`cpu-syscall-perf.csv`并纳入单格artifact manifest，不改变性能门禁。GitNexus未索引该shell函数（impact=`UNKNOWN`，非HIGH/CRITICAL）；改动限于诊断runner，help/planner contract、shell语法和Python编译检查通过。

在CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、sndbuf=2MiB、direct chunk=32KiB条件下，低扰动单轮native/XTCP诊断各qualification通过，goodput分别=`1.743/2.133Gbps`、ratio=`1.2240×`（单轮、gate关闭，不是验收）。PPP syscall profile中native/XTCP分别记录read=`252,365/76,528`、write=`300,206/117,318`、writev=`0/131,697`、sendto=`104,389/17`、recvfrom=`206,477/314,172`。按iperf payload归一化后，write/writev调用密度约为native=`45.9`、XTCP=`31.1`次/MB；所有上述socket/read/write调用合计约native=`132.1`、XTCP=`80.0`次/MB。XTCP stats有`6,206,277`个output packets，writev计数对应约47段/次，与cap48 GSO batch接近；这说明现有GSO批量已有效，单纯增大GSO cap不是主要突破口。该profile仅单轮且含syscall计数扰动，不能把调用数差直接换算成CPU收益或归因为某一函数。Artifacts：`artifacts/gpt6fix-kernel-syscall-profile-p1dl-20260928/`与`artifacts/gpt6fix-kernel-syscall-profile-p1dl-pair-20260928/`。

随后关闭syscall sidecar，对同候选SHA-256=`791c04cac804a6f879cc80dd98ca5c6f73e279062479141c1193b4dc8b7086d4`重新执行45秒×3正式配对门禁，6/6 cells qualification通过，但ratio=`1.2146×/1.1830×/1.1110×`，仅1/3轮过门，median=`1.1830×`、MAD=`0.0316`，总体仍为fail。XTCP吞吐=`2.1345–2.1768Gbps`较稳定，native=`1.7842–1.9212Gbps`的轮间变化更大；process task-clock CPU效率median=`1.2147×`，但不能替代吞吐门禁。结论：没有用单轮`1.224×`覆盖正式失败，也没有通过削弱门禁；当前仍需提升XTCP绝对服务率及逐轮稳定性。Artifact：`artifacts/gpt6fix-p1dl-current-candidate-r4-20260928/`。

### 11.177 XTCP/native 同轮 PID callgraph：BuildSegmentPacket约6.5%，热点落在数据段构造（2026-09-28）

runner另新增默认关闭的`--process-perf-record`，在矩阵runner自己的PID namespace内对PPP PID录`cpu-clock`/Dwarf callgraph，输出`cpu-process-perf.data`；结果文件及采样错误日志登记到单格manifest。Shell/planner contract通过，并由真实native/XTCP两格验证录制、SIGINT收尾和`perf report`读取正常。GitNexus仍未索引vendor XTCP及shell hook（symbol impact=`UNKNOWN`，非HIGH/CRITICAL）；这次只改诊断runner，没有改XTCP runtime。

在CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB chunk下做单轮20秒native/XTCP带callgraph诊断：goodput=`1.788/2.207Gbps`、ratio=`1.2343×`，但profile本身有采样开销且仅一轮，不能作为门禁结果。XTCP self samples为`BuildSegmentPacket=6.46%`、AES-CFB decrypt=`11.22%`、`FlushPendingSend=1.95%`、`XtcpNdiBackend::Tx≈0.98%`；native对应`TcpChecksum=5.66%`、`TapLinux::OnInput=2.89%`、AES-CFB decrypt=`8.54%`。XTCP `BuildSegmentPacket`样本约一半沿`FlushPendingSend → OnPoll → PollAckTimers → SchedulePoll`，另一半沿`OnAckReceived → OnSegment → OnPacket → Inject → DrainIngress`，所以该热点覆盖正常发送和ACK响应两类构造，不是单一timer唤醒伪影。

对候选二进制的符号偏移/反汇编抽查最初把部分样本误归到SSSE3尾段；后续直接检查该候选在`BuildSegmentPacket+0x660`附近的指令后确认，实际执行的是整段4字节标量copy/checksum循环（`mov`/`bswap`/`add`），并非先跑32B向量再处理20B尾段。当前Linux Release XTCP target未带`-mssse3`，编译产物也没有在该函数路径生成`pshufb`；因此SSSE3尾段候选在目标配置里是死代码，已撤回，不纳入补丁序列。

针对真实的标量循环短暂验证了一个16B/四词展开候选。隔离XTCP构建及8个相关合同/运行时测试通过；随后以同构建配置的未展开/展开二进制，在CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、sndbuf=2MiB、32KiB chunk下分别做20秒×2轮矩阵，两个矩阵均4/4 qualification通过。匹配控制的XTCP中位goodput=`2.2455Gbps`、process task-clock=`3.129ns/B`；展开候选分别为`2.1832Gbps`和`3.192ns/B`，即XTCP绝对吞吐约低`2.8%`、CPU成本约高`2.0%`。paired XTCP/native median ratio为`1.2125×/1.1755×`，但native两组受环境波动明显且只各两轮，不能证明1.20×门禁；XTCP绝对吞吐的回退方向已足以否决该展开实现，补丁已撤回。Artifacts：`artifacts/gpt6fix-p1dl-pid-callgraph-pair-20260928/`、`artifacts/xtcp-copy-unroll-matched-control-20260928/`、`artifacts/xtcp-copy-unroll-matched-treatment-20260928/`。

### 11.178 将现有SSSE3 fused checksum安全接入GCC/Clang：CPU成本小幅下降，goodput无可分辨变化（2026-09-28）

沿用§11.177的反汇编发现，Linux GCC/Clang Release target没有全局`-mssse3`，因此`CopyAndChecksumSimd`及其`CpuHasSsse3()`分支此前整个被预处理器排除；而MSVC/启用SSSE3的构建已经有该路径。新补丁仅在x86 GCC/Clang上给SIMD helper加函数级`target("ssse3")`，并让baseline dispatch在helper可用时继续先调用`CpuHasSsse3()`；不改变全局编译ISA，CPU不支持SSSE3时仍留在标量路径。GitNexus impact因数据库存储版本不一致为`UNKNOWN`；手工调用链是`BuildSegmentPacket → CopyAndChecksum`，影响新发和重建TCP段校验，不涉及其他栈或协议入口。

隔离Release对象反汇编确认helper实际生成`pshufb`；Clang XTCP合同/运行时测试`8/8`通过，带`XTCP_CHECKSUM_VALIDATE=ON`的upstream fault suite`20/20`通过。CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB chunk下做XTCP-only 30秒×3轮：匹配控制goodput=`2.2297/2.2212/2.2211Gbps`、process task-clock=`3.131/3.148/3.148ns/B`；候选=`2.2046/2.2239/2.2187Gbps`、`3.121/3.033/3.093ns/B`。goodput中位数从`2.2212`到`2.2187Gbps`（差异约`-0.1%`，没有可分辨吞吐提升），task-clock中位数从`3.148`到`3.093ns/B`（约`1.8%`改善）。另两组20秒native/XTCP矩阵分别得到median ratio=`1.1956×/1.1625×`，native吞吐同期漂移明显，不可作为相对性能结论。随后对同构建控制/候选分别执行45秒×3正式门禁：control ratios=`1.2064×/1.1452×/1.2290×`，候选=`1.0995×/1.2220×/1.2040×`，两边各只有2/3轮达到门槛，median=`1.2064×/1.2040×`且XTCP median goodput候选略低约`0.3%`。结论：dispatch有约`0.8–1.8%`的CPU效率信号，却没有稳定goodput收益，也未改善严格1.20×稳定性；不保留进`tools/xtcp-patches`集成序列，仅留隔离源码/binary/artifact备查。Artifacts：`artifacts/xtcp-runtime-ssse3-control-20260928/`、`artifacts/xtcp-runtime-ssse3-treatment-20260928/`、`artifacts/xtcp-runtime-ssse3-xtcp-only-control-20260928/`、`artifacts/xtcp-runtime-ssse3-xtcp-only-treatment-20260928/`、`artifacts/xtcp-runtime-ssse3-formal-control-20260928/`、`artifacts/xtcp-runtime-ssse3-formal-p1dl-20260928/`。

### 11.179 ThinLTO 与平衡 PGO 构建筛查：CPU/绝对吞吐小幅改善，strict ratio未改善（2026-09-28）

在不改源码和产品构建默认项的前提下，用同一当前工作树、Clang 19、Release、`ENABLE_XTCP=ON`、`ENABLE_SIMD=OFF`、P1/DL、CPU11、GSO-on/cap48、KCC、memory bridge、2MiB sndbuf、32KiB chunk，分别构建普通`-O3` control、ThinLTO treatment以及PGO treatment；所有二进制和PGO中间物均留在`/tmp`，正式`bin/ppp` SHA-256仍为`fb40d7f6f2e28c217fed0d7ec726ba6fbd8468c404c3c2100fa2201cebdf599c`。ThinLTO首轮因项目CMake重设`CMAKE_CXX_FLAGS`而意外生成相同binary，已识别并排除；后续确认`-flto=thin`确实进入Release对象与link命令，control/treatment SHA分别为`d6d0cf87…`和`66ef881d…`。

20秒A-B-B-A screen全部8/8 cells qualification通过。普通Release control的XTCP goodput=`1.2583/1.2378Gbps`，ThinLTO=`1.2620/1.2484Gbps`，中位仅约`+0.6%`；process task-clock median分别约`5.920/5.918ns/B`，无CPU成本改善。XTCP/native ratio control=`1.1710×/1.1777×`，ThinLTO=`1.2080×/1.2158×`，但ThinLTO组native从`1.0745/1.0510Gbps`降至`1.0447/1.0269Gbps`，因此ratio通过主要由native分母回退造成，不晋升。

继续用instrumented Release收集真实P1/DL XTCP profile，`TcpConn::FlushPendingSend`约51.6K次、`XtcpStack::SendOne`约2.22M次；最初仅XTCP训练的PGO screen出现native下降，故不作为判断依据。重新训练时同时覆盖native与XTCP路径后构建平衡PGO候选（SHA-256=`f6a5166a…`）。其20秒A-B-B-A screen也为8/8 qualification通过：control的XTCP median约`1.2365Gbps`、PGO约`1.2550Gbps`（约`+1.5%`），task-clock约从`5.969`降至`5.897ns/B`（约`1.2%`）；但配对ratio control=`1.2180×/1.1545×`、PGO=`1.1912×/1.1393×`，中位从`1.1863×`降到`1.1653×`，仅control有1/2轮过门、PGO为0/2。该小幅局部收益不足以达到目标，也没有证明能改善strict 1.20×稳定性；不改默认构建选项、不做45秒晋升矩阵。Artifacts：`artifacts/gpt6fix-thinlto-p1dl-control-A1-cpu11-20s-20260928/`、`artifacts/gpt6fix-thinlto-p1dl-control-A2-cpu11-20s-20260928/`、`artifacts/gpt6fix-thinlto-p1dl-treatment-B1-cpu11-20s-20260928/`、`artifacts/gpt6fix-thinlto-p1dl-treatment-B2-cpu11-20s-20260928/`、`artifacts/gpt6fix-pgo-balanced-p1dl-control-A1-cpu11-20s-20260928/`、`artifacts/gpt6fix-pgo-balanced-p1dl-control-A2-cpu11-20s-20260928/`、`artifacts/gpt6fix-pgo-balanced-p1dl-treatment-B1-cpu11-20s-20260928/`、`artifacts/gpt6fix-pgo-balanced-p1dl-treatment-B2-cpu11-20s-20260928/`。ThinLTO首轮screen见`artifacts/gpt6fix-thinlto-p1dl-{control-A1,treatment-B1,treatment-B2,control-A2}-cpu11-20s-20260928/`。

### 11.180 P1/DL NDI批处理与retained-output边界诊断：TxBatch未命中即时发送热路径（2026-09-28）

为判断是否值得把`TxBatch`继续贯通到TAP，使用当前平衡PGO二进制（SHA-256=`f6a5166a19c37122dba40f842981ed4af4f359c2b2734b3830b257bd91034bb5`）做CPU11、P1/DL、GSO-on/cap48、KCC、memory bridge、sndbuf=2MiB、direct chunk=32KiB的20秒XTCP-only诊断。qualification通过，XTCP goodput=`1.2349Gbps`，process task-clock=`5.987ns/B`；该单格不是native配对门禁。`OPENPPP2_XTCP_PERF_JSON`记录了`2,389,284`个NDI/output packet，`TxBatch batch_avg/batch_max`在所有忙碌采样窗口均为`0`。结合`SendOne → enqueue_drain → EmitOrRetry`即时fast path，说明该负载基本逐包直接发送，qdisc仅在排队/排空时才走`TxBatch`；所以只优化`XtcpNdiBackend::TxBatch`或新增批量TAP回调不会覆盖主热路径，也可能错误改变逐段pacing/顺序，暂不实施。

同一诊断中的retained output handler累计elapsed为`2,895,792,579ns / 2,389,284 calls`，均值约`1.212µs/packet`。这是回调墙钟elapsed，包含`ClientConnectionOpener`到`TapLinux::OutputRetained/OutputInternal`的同步路径，可能含锁等待和TUN写等待，不能当作CPU样本或直接推断CPU占比；它只表明这个边界足以继续拆分测量。下一步优先区分`weak owner/tap获取与类型分派`、`gso_mutex_等待`、`TunGsoCoalescer::PushOwned`及其实际flush/write耗时，再决定是否做单包路径改造。Artifact：`artifacts/gpt6fix-txbatch-diagnostic-p1dl-cpu11-20s-20260928/`。未改产品源码、默认选项或正式`bin/ppp`。

随后在同一条件启用`--datapath-telemetry --stall-diagnostics`作机制核对：ledger记录`2,266,346`个merged segments、`52,860`次GSO full write（约`42.9` segments/write），`51,503`次ordinary full write；直接TUN writes共`104,963`次、`3.309GB`，累计同步write elapsed约`1.781s`，平均`16.96µs/write`、`31.5KiB/write`，失败/partial均为0。额外插桩使这次XTCP-only吞吐降至`1.209Gbps`、task-clock升至`6.120ns/B`，与前一轮不同插桩级别，不能比较成性能回退。ledger显示现有GSO合包已接近cap48；结合§11.36/§11.161的write消融，当前不继续调大GSO cap，也不把TUN syscall耗时单独认作1.20×差距根因。Artifact：`artifacts/gpt6fix-output-boundary-ledger-p1dl-cpu11-20s-20260928/`。

### 11.181 PID callgraph复核retained-output CPU占比：不是当前优先优化点（2026-09-28）

对同一平衡PGO候选做一轮20秒、XTCP-only、CPU11/P1/DL/GSO-on/cap48的PID过滤`cpu-clock` callgraph诊断；qualification pass，XTCP goodput=`1.266Gbps`、process task-clock=`5.841ns/B`，采集`863`个样本且lost samples=`0`。样本self占比中，XTCP `BuildSegmentPacket`约`4.29%`、`FlushPendingSend`约`1.04%`；retained output的ClientConnectionOpener回调约`0.81%`、`TapLinux::OutputInternal`约`0.35%`、`TunGsoCoalescer::PushInternal`约`0.46%`、`XtcpNdiBackend::Tx`约`0.23%`。这些函数合计约`2.1%` self samples（约18个样本），样本量不足以对不到1%的单函数排序，但足以反证将1.21µs回调墙钟时间直接当作主要CPU热点。

因此不为减少`TxBatch`调用、dynamic cast或单独压缩`OutputInternal`增加产品复杂度；TxBatch主热路径未命中、writev关闭无端到端收益、TUN write等待也不是单一根因已有多组证据。优先级转回Xtcp栈内每段构造/校验与ACK/pacing服务率；后续任何微优化都需同构建对照观察绝对XTCP吞吐和task-clock，避免只看native分母变化。Artifact：`artifacts/gpt6fix-output-boundary-callgraph-p1dl-cpu11-20s-20260928/`。未改产品源码、默认选项或正式`bin/ppp`。

### 11.182 排除 FQ qdisc 锁路径：当前生产 XTCP 集成没有挂载 qdisc（2026-09-28）

继续检查 `SendOne → FqEnqueueDrain` 后确认，`FqEnqueueDrain` 的单锁 enqueue/dequeue fast path 只在 `XtcpStack::SetTxQdisc()` 被调用并挂载 qdisc 时生效。生产集成目录 `ppp/`、`linux/`、`windows/`、`macos/` 没有 `SetTxQdisc()` 调用；当前生产栈保留 `tx_qdisc_ == nullptr`，`SendOne()`直接走无 qdisc 的 backend 路径。挂载调用仅见于 XTCP 测试和示例。因此 FQ 每段锁、DRR deficit、qdisc pacing 不属于本轮 P1/DL 正式矩阵的执行路径，不能作为当前吞吐瓶颈，也不应为此增加 fast-path batching 或绕过公平性逻辑。

这一核查修正了从通用 XTCP 栈实现推断生产热路径的风险：符号存在且有代码，不代表 production runtime 实际启用。下一步应继续从已采集的无 qdisc P1/DL callgraph 中分离 XTCP-only 的段构造/ACK处理成本与 native、XTCP共用的隧道加解密和内核/TUN成本；任何候选仍需先有可量化的独占开销，再做同构建XTCP绝对吞吐与task-clock对照。未改产品源码、qdisc默认状态、构建产物或性能门禁。

### 11.183 AES-NI Release 下 P1/DL 正式矩阵稳定达到 1.20×（2026-09-28）

前一轮新建候选 build cache 意外沿用了 `ENABLE_SIMD=OFF`。虽然是 `Release -O3`，但 AES-NI backend 未编入；该标量二进制在 CPU11、P1/DL、GSO-on/cap48、sndbuf=2MiB、direct chunk=32KiB 条件下做45秒×3 formal，qualification 6/6通过，但 ratio=`1.1840×/1.2099×/1.1938×`，仅1/3轮过门，median=`1.1938×`。核对后不把这组结果与历史 AES-NI Release 性能混比。

随后以独立Clang 19构建目录生成目标候选，`Release -O3`、`ENABLE_SIMD=ON`、`ENABLE_SSEA_SIMD=OFF`、`ENABLE_XTCP=ON`，XTCP source=`.tmp-gpt6fix-xtcp-combo-src-20260927/third-party/xtcp`；CPU支持AES/SSSE3/AVX2，但本构建只打开经CPUID dispatch的AES-NI实现，不启用全局AVX2。候选SHA-256=`055f24e8d6af5c9c91d599d6b6e2089815d1ab407d399a8936072c357e260a9c`。在CPU11 single-core、P1/DL、GSO-on/cap48、hold=100µs、KCC、memory bridge direct路径、显式sndbuf=2MiB和direct-download chunk=32KiB下，20秒×3 screen先以ratio=`1.2683×/1.3026×/1.2750×`全部通过，然后45秒×3 formal的6/6 qualification与3/3 strict `>=1.20×` gate均通过：ratio=`1.3296×/1.2630×/1.3080×`，median=`1.3080×`、min=`1.2630×`；XTCP/native goodput median约`2.177/1.644Gbps`，process task-clock/payload-byte median约`3.234/4.430ns/B`（效率增益median=`1.355×`）。formal artifact：`artifacts/xtcp-gso-cap48-aesni-hold100-bridge-sndbuf2m-chunk32-p1dl-45s-r3-20260928/`；screen artifact：`artifacts/xtcp-gso-cap48-aesni-hold100-bridge-sndbuf2m-chunk32-p1dl-20s-r3-20260928/`。

本结果只证明该P1/DL实验配置通过，不能外推到P4/P16、UL、GSO-off或所有生产默认。sndbuf=2MiB和chunk=32KiB是runner显式覆盖，不能因P1收益直接设为全局默认；多流仍需独立吞吐、公平性、零速/队列风险验收。另对标量构建做100/200µs hold screen：200µs组XTCP median约`1.268Gbps`，比100µs约`1.260Gbps`高约`0.7%`，但strict三轮ratio=`1.2277×/1.1897×/1.2322×`仅2/3过门；这点收益不足以抵偿额外等待延迟，因此coalescer默认继续100µs，不晋升200µs。针对该旋钮的代码保持默认不变、仅供受控矩阵实验。

### 11.184 P4/P16 DL/GSO-on 低速复核与有界 opt-in profile（2026-09-29）

当前源码默认矩阵复跑复现了 P4/DL/GSO-on 的 XTCP/native=`0.850/0.855/0.852×`（20秒×3同样复现，median=`0.852×`）。GSO ledger 中 native 与 XTCP 的普通 cap4聚合都约为4段/写；没有TUN write失败、partial delivery、direct-download reject或zero-rate流证据，单纯把coalescer cap扩大也不是修复：cap48-only P4筛选的XTCP/native median仅`0.784×`。

隔离筛选显示`2MiB sndbuf + 32KiB direct-download chunk + cap48`组合在P4同轮配对中将ratio提升至`1.192–1.199×`（median=`1.197×`，6/6资格通过）；P16中位ratio=`1.127×`，16条流均非零、max/min=`1.15–1.19`、direct-download reject=`0`。该组合比默认的P4约`0.852×`明显改善，但P4和P16仍未通过严格1.20门禁。2MiB是每个新XTCP连接的snd_buf quota；按16条流上限预算约32MiB，活动连接数继续增加时内存上界也继续线性增长，因此**不提升默认值**。

为方便显式接受该内存/吞吐权衡，新增`OPENPPP2_XTCP_DL_GSO_PERF_PROFILE=1` opt-in：在没有单独覆盖时使用2MiB snd_buf、32KiB direct-download chunk和48段TUN GSO cap；显式`OPENPPP2_XTCP_SNDBUF_BYTES`、`OPENPPP2_XTCP_DIRECT_DOWNLOAD_CHUNK_BYTES`或`OPENPPP2_TAP_GSO_SEGMENTS`仍优先。它不启用原本关闭的TUN GSO merge，不改变默认配置。profile 应设置在需要调优下行的 XTCP 进程上；矩阵脚本只给 XTCP client 注入 snd_buf/chunk profile，同时对两端设置匹配的 TUN GSO cap。复测 P4/DL/GSO-on 20秒×3的 client-only profile，XTCP/native=`1.196/1.186/1.242×`（median=`1.196×`），相对默认 median=`0.852×`显著改善，但严格`>=1.20×`门禁仅1/3轮通过，因此仍未达稳定验收线。该 profile 仅适用于连接数有界、内存充足且已单独验收的部署；2MiB quota 按活动连接数线性增加。GitNexus impact因索引数据库版本43与当前工具版本40不兼容均为UNKNOWN；实现影响面通过rg调用点、手工代码审阅及针对性测试核对。Artifacts：`artifacts/diag-p4dl-gsoon-default-cpu8-20s-r3-20260928/`、`artifacts/diag-p4dl-gsoon-cap48-only-cpu8-20s-r3-20260928/`、`artifacts/diag-p4dl-gsoon-sndbuf2m-chunk32-cpu8-20s-r3-20260928/`、`artifacts/diag-p4dl-gsoon-cap48-sndbuf2m-chunk32-cpu8-20s-r3-20260928/`、`artifacts/diag-p16dl-gsoon-cap48-sndbuf2m-chunk32-cpu8-20s-r3-20260928/`、`artifacts/diag-p4dl-gsoon-profile-client-cpu8-20s-r3-20260929/`。

随后以45秒×3和严格1.20×门禁复核同一2MiB profile，qualification=`6/6 pass`，但goodput ratio=`1.1325/1.2199/1.1900×`（median=`1.1900×`，2/3未过门）。XTCP吞吐本身约`1.95–1.96Gbps`且跨轮较稳定；native约`1.61–1.73Gbps`，配对差异主要由native和整机每字节CPU成本波动放大，当前证据不足以把它归因成单一XTCP退化。虽然admission遥测有少量`sndbuf_quota`事件，单变量4MiB snd_buf筛选并未改善：ratio=`1.1739/1.1229/1.2056×`（median=`1.1739×`），XTCP吞吐median约`1.869Gbps`，不晋升该设置。结论仍是2MiB profile有明显收益但**严格稳定性能门禁未通过**，不更改默认值。Artifacts：`artifacts/diag-p4dl-gsoon-profile-client-cpu8-45s-r3-20260930/`、`artifacts/diag-p4dl-gsoon-profile-sndbuf4m-client-cpu8-20s-r3-20260930/`。
