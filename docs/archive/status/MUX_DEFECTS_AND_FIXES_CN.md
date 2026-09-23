# VMUX 设计缺陷台账与修复 / 优化方案
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md) · **English：**[VMUX Defect Ledger and Fix / Optimization Plan](MUX_DEFECTS_AND_FIXES.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **记录状态：**下文“进行中”是这份台账的历史快照，不代表当前开发状态。它保留当时已确认/疑似缺陷、根因、修复方案与优先级；技术术语保留英文。配对英文版见 `MUX_DEFECTS_AND_FIXES.md`。

## 背景与权衡（VMUX 的本质）

VMUX 在若干条长期保活的承载 TCP 子链路（linklayer）之上，复用任意多个逻辑连接（vmux_skt）。它换来的是：

- **突发能力**：多链路并行 + acceleration 流水线，短时可灌出大量帧。
- **连接及时性**：子链路预先建好并保活，新逻辑连接无需各自做 TCP/TLS 冷启动握手，首包延迟低。

代价是结构性的、不可消除，只能缓解：

- **TCP-over-TCP（嵌套可靠传输）**：被隧道的应用 TCP 与承载 TCP 各有一套重传/拥塞控制。承载链路一旦丢包/退避，会给内层制造延迟尖峰，内层再误判退避，两层控制环互相打架，表现为 loaded latency 飙升与 bufferbloat。承载链路越被打满越严重。
- **double control（双重控制平面）**：两层各自的 ACK 时钟/窗口/超时叠加，VMUX 自身又有控制帧（syn/syn_ok/fin/keep_alived/acceleration）与 flow v2 的 per-flow DSN + 重排超时。控制层越多，时序耦合越复杂，teardown/竞态越易出问题。

**总设计原则（由上述权衡推导）**：

1. 尽量把负载摊到多条承载链路，降低任一条被打满的概率。
2. 任何机制都不得让承载链路无界堆积或无背压。
3. 控制平面尽量薄；控制帧通道必须独立于数据洪泛。
4. 根治 TCP-over-TCP 的唯一途径是承载层换无拥塞控制传输（UDP/KCP），而非在 TCP 承载上继续堆调度。

---

## 方向修正：回归竞争法（2026-06，依据原作者评审）

本节记录一次重要的方向修正，避免后续重走弯路。

### 评审结论（原作者）

多链路 flow 改造早期版本尝试用 **per-connection → link 的绑定（affinity）** 来分散负载（早期的 `flow`/`balance` 严格 affinity）。原作者评审指出这是**负优化**，要点：

1. **绑定使负载不可预测**：分配时某链路负载低，但连接被绑上去后，若它突然变成高压流（下载/流媒体），就被锁死在该链路；该链路可能同时绑了多个高压流 → 堆积 → 拖垮整体。
2. **最坏退化单 TCP**：多个高压流恰好绑到同一条承载 TCP → 等效退化成单 TCP VMUX，完全失去多链路优势（这是各大代理 VMUX 方案的通病）。
3. **流状态不可预测、存在竞态窗口**：A 流先发、B 流晚发，真实网络里 B 可能先到；人为按发送序绑定/重排只会制造无谓等待。迁移链路至少要 2 个 RTT，且拥塞是动态过程，预测不可靠。
4. **正确做法是竞争法**：让多条 TCP 链路**竞争**当前发送权（谁空闲谁发），负载与速度自适应、可控，不存在某链路背压过高拖慢整体。这正是 VMUX 早前版本的做法，也是最高效的。
5. **TCP-over-TCP 是流控天然缺陷**：不在 VMUX 调度层解，也不是上 QUIC 能解；在调度上想花样方向就错了。

### 修正后的设计

- **保留竞争法作为所有模式的发送侧策略**，移除 per-connection 绑定（affinity）。
- **把"绑定"与"per-flow 定序"解耦**：原作者反对的是*绑定*，不是*接收端 per-flow 定序*。二者可拆开 —— 发送侧竞争法（满负载、自适应、无绑定）+ 接收侧 per-flow DSN 重排（把队头阻塞隔离到单连接），叠加后既符合竞争法，又消除连接间 HoL。这就是修正后的 `balance`。
- **模式重定义**（提交 `aa3bbdc`）：
  - `compat` = 上游原版（竞争法 + 全局定序）。
  - `flow` = 时延导向新方向（竞争法 + 全局定序 + 可选 turbo）。
  - `balance` = 竞争法发送 + per-flow 定序（原 flow_v2 去掉绑定）。
  - `stripe` = 实验性逐包轮询 + per-flow 定序。
- **删除 `mux.flow-v2` 配置项**；per-flow 定序由 `mode∈{balance,stripe}` 自动协商。
- **新增 `mux.turbo` / `--mux-mode-turbo`**：flow 的时延优化（最优链路首包 + 预热承载扩**竞争池**，而非绑定/迁移）。

### turbo 的设计边界（重要）

turbo 必须**符合竞争法**，不得违背上述修正：

- **最优链路首包**：新连接的首包选当前心跳质量最好的承载链路发送，只为降低首包时延；**不**把该连接绑定到这条链路——后续帧仍回到竞争池由所有链路竞争。只考虑"向前质量"（当前/历史心跳），不做向后预测。
- **预热承载**：后台异步新开承载 TCP，就绪后**加入竞争池**（让竞争法有更多链路可抢），**不**做连接迁移（迁移要 ≥2 RTT 且不可靠）。
- 设计目标：延迟优先、速度其次（75–95%）。不做连接拆分（绕不开竞态）。

### turbo 实现状态

- **最优链路首包 —— 已实现**：`vmux_linklayer.last_active_` 在 `linklayer_update()` 中于每个入站帧刷新；`select_turbo_linklayer()` 选最近最活跃的存活链路；`post_internal` 在 `mux.turbo` 开启且 flow 模式下把 `cmd_syn` 路由到该链路，**不绑定**（后续帧正常竞争）。信号是“最近活跃度”而非 RTT —— 刻意近似、零新增控制帧。无空闲 turbo 链路时 fail-open 回竞争法。
- **后台承载预热 —— 已实现**：turbo 拆分 base / hard / current 池状态，在 flow-mode 会话中提高承载硬上限，并由运行时 controller 每个 cooldown 窗口 grow 或 retire 一条承载链路。额外链路加入同一个竞争池；shrink 用 per-link `retiring_` + `inflight_` drain 后再 Dispose。不新增 resize 控制帧，`max_connections` 仍是 base 会话不变量。

---

## 缺陷台账

严重度：🔴 阻断 / 🟠 高 / 🟡 中低 / ✅ 已闭环。

### D1 — teardown 堆破坏（malloc abort / 进程退出）🔴 已确认（读代码坐实结构，崩溃点待 ASan）

- 根因：`syncobj_` 锁域与 vmux strand 域互不重叠。`finalize()` 是唯一持 `syncobj_` 访问 `tx_links_/tx_queue_/skts_/flows_/affinity_links_` 的地方；发送 drain、completion 回调、`add_linklayer` 全部仅靠 strand 串行、不持锁。`~vmux_net()` 直接调 `finalize()`（可 off-strand），于是两域并发改同一批 `std::list`/map → double-free / use-after-free。
- 放大因素：flow 多链路改动使 teardown 时在途 write completion 由 1 个增至 N 个（窗口约放大 N 倍）；acceleration 高频 pump 进一步放大。
- 触点：`vmux_net.cpp` `~vmux_net()`→`finalize()`、`underlyin_sent` completion、`process_tx_*`、`add_linklayer`。

### D2 — 发送完成回调缺乏在途/纪元保护 🔴 已确认

- `underlyin_sent` 的 completion 即便加了 `disposed_` 守卫，仍是 TOCTOU；无 in-flight 计数，teardown 无法得知还有多少 async_write/async_read completion 未归。
- 现状：已加 `disposed_` 原子守卫（概率压制，见“已落地修复”）。

### D3 — 读路径 completion vs transmission Dispose 🟠 疑似（待 ASan 栈坐实）

- `forwarding` 在 connection strand 上 `Read`；`ITcpipTransmission::Dispose` 将 `Finalize`（关 socket）post 到同一 strand（这一对安全）。但 `base94_decode`/`make_shared_alloc` 的 per-read 分配 + Asio async_read completion 真实栈指向“completion 提前踩已释放对象”。
- 决定 D2/D3 修复落在 vmux_net 层还是 transmission 层，必须以 ASan 栈为准。

### D4 — flow_v2 严格 affinity 方向已移除 ✅ 被竞争法取代

- 早期疑似缺陷建立在“flow-v2 需要同连接同链路 affinity”这个前提上。原作者评审后明确反对绑定，认为这是负优化。
- 当前 `balance` 有意使用与 `compat` 相同的竞争法发送；flow-v2 只把接收侧定序改为 per-flow DSN。同连接跨链路乱序是可接受行为，由 per-flow reorder 缓冲和 timeout 有界处理。

### D5 — DSN 单调性 ✅ 已核对无缺陷（排除项）

- DSN 在入队前分配，且 `tx_flow_seq_[cid]++` 全程在 mux strand 串行；acceleration 为串行流水线。无论 acceleration 开关，同连接帧 DSN 严格递增。

### D6 — acceleration 无背压，加重 TCP-over-TCP bufferbloat 🟠 已确认机制

- acceleration 在 completion 里立即 pump 下一个 read→post，不看承载链路队列深度，更快灌满承载 TCP，放大嵌套拥塞负反馈。

### D7 — flow v1（compat 回退）单 primary 链路漏斗 🟠 部分已解

- 旧 flow 全部连接挤单链路，首包被大流队头阻塞（曾测得 `tx.queue.depth` 数千、网页卡约 10s）。多链路改造已解“双方支持 flow_v2”场景；对端为旧版（协商回退 compat）时仍退回单链路漏斗（兼容性代价）。

### D8 — reorder 超时默认 2000ms 偏大 🟡 已确认

- `PPP_MUX_FLOW_REORDER_TIMEOUT=2000`。真丢帧或 D4 触发乱序时要等满 2s 才推进 → 秒级卡顿。可配置但默认偏大，理想贴近链路 RTT（数百 ms）。

### D9 — flow_v2 需两端同时升级 🟡 设计约束（部署陷阱，非缺陷）

- 协商为交集，一端旧版即回退 compat。已在文档与协商逻辑 fail-safe 处理。

### D10 — ICMP 重复 echo ✅ 已修复

- `EchoOtherServer` 在 static echo 成功后仍发第二份标准 ECHO → ping DUP。已由提交 `49956b3 fix(icmp): avoid duplicate static echo replies` 修复（`se_ok` 成功即 return）。

### D11 — tx_queue_ 无界、无背压、控制帧与数据帧共队列 🔴 已确认（telemetry 铁证，最高优先）

- 现象（stress-logs/until-fail-20260601-124147）：ppp 不崩但全挂。`mux.link.send=12528 / recv=8`、`tcpip.peer_connect.fail.mux=533`、`mux.tx.queue.depth=46113-57943`、出站大量 SYN 无 SYN-ACK、HTTP 96/96 fail、ping 正常无 DUP。
- 根因链：接收侧停滞（D4 触发的 DSN 空洞等）→ 对端 SYN-ACK/数据/ACK 回不来 → 发送侧 `tx_queue_` 无上限、无背压，持续 `emplace_back` → 队列爆炸 → 新连接 `cmd_syn` 与心跳和数据帧共享同一 FIFO，被积压饿死 → 新 TCP 全部建连失败；ping 因走 gateway echo 不经逐连接队列而正常。
- 唯一“刹车” `rx_congestions`/`tx_acceleration_` 是接收侧逐连接拥塞窗口，依赖对端反馈，接收一停该反馈环也断，且不约束 `tx_queue_` 总深度。
- 危害评级高于偶发崩溃：不崩、不自愈、对用户表现为“整条隧道对新连接死亡”。

---

## 修复方案

### 阶段 A：发送侧韧性（修 D11，最高优先，不依赖 ASan）

**A1 控制帧与数据帧分离（优先队列）**
- 在 `post_internal` 入队时区分 `is_session_control`/`is_connection_control`（syn/syn_ok/fin/keep_alived/acceleration/mux_mode_set）与 `is_per_flow_data`（push/fin 数据）。
- 控制帧入**队头**或独立的高优先 `tx_ctrl_queue_`，drain 时永远优先于数据队列抽干。
- 目标：即使数据洪泛、`tx_queue_` 爆炸，新连接 SYN 与心跳仍能挤出去，避免“心跳饿死 → mux 被判超时 close_exec → 雪崩”。
- 约束：不改线格式、不改协商；仅发送侧排队策略。

**A2 tx_queue_ 背压上界**
- 为数据队列设上限（按字节或帧数，默认值可由 `mux.congestions` 推导或新增 `mux.tx.queue.max`）。
- 超限时对**数据**施加背压：暂停 `forward_to_rx_socket` 的 read pump（停止从本地 socket 读，让被隧道的应用 TCP 自己退避——这正是利用 TCP-over-TCP 的内层控制把压力反推给应用），而非无限入队。控制帧不受此限。
- 队列回落到低水位后恢复 read。形成对称的高/低水位背压（类似 TCP 滑窗）。

**A3 接收停滞自愈强化**
- 复核 `flow_evict_expired` 在“接收协程仍在跑但某 flow 卡住”与“接收协程整体停滞”两种情形下都能推进；必要时引入独立看门狗：当 `recv` 长时间不增长而 `tx_queue_` 持续高位时，主动降级该会话（close_exec 重建）而非永久挂死。

### 阶段 B：接收定序调优（修 D8）

**B1 reorder 超时默认下调**
- 将默认 `flow.reorder.timeout` 从 2000ms 下调至贴近 RTT 量级（建议 300–500ms，仍可配置），缩短 per-flow DSN 缺口被跳过前的“卡住→自愈”时间。

### 阶段 C：生命周期模型修正（修 D1/D2/D3，待 ASan 栈）

**C1 atomic disposed** ✅ 已落地（见下）。

**C2 strand-only finalize**
- `~vmux_net()` 不再直接调 `finalize()`；保证 `finalize` 永远在最后一个 shared_ptr 释放前由 vmux strand 完成；析构仅做 trivial 成员释放。
- 需核对所有持有/释放点（exchanger 的 `mux_.reset()`），确保 reset 前已 `close_exec()` 且 finalize 已在 strand 跑完。

**C3 in-flight / epoch 计数**
- 为会话维护在途 I/O 计数（发起 async_read/async_write +1，completion −1）和/或 epoch 序号。
- teardown 等 in-flight 归零再释放容器/transmission；或用 epoch 让晚到 completion 自我识别“属于上一纪元”而丢弃。
- **必须覆盖三条路径**：普通 drain、acceleration 快路径、读路径（forwarding async_read completion）。
- 具体形态（计数加在 vmux_net 层还是 transmission 层）以 ASan 栈指向的释放点为准。

### 阶段 D：性能优化（修 D6，非阻断，排期）

**D-opt1 acceleration 背压感知**
- acceleration pump 前检查承载链路队列深度/在途量，高则降速，避免灌满承载 TCP 放大 bufferbloat。与 A2 的水位机制协同。

**D-opt2（探索性）承载层去 TCP-over-TCP**
- 对 loaded latency 敏感的部署，建议 mux 跑在 UDP/KCP 承载上，让可靠性只由内层 TCP 负责一次。属部署建议 + 长期方向，非本轮代码改动。

---

## 优先级与依赖

| 缺陷 | 严重度 | 阶段 | 依赖 |
|------|--------|------|------|
| D11 tx 无界/控制帧饿死 | 🔴 | A1/A2/A3 | 无（证据齐，立即可做） |
| D1/D2/D3 崩溃 | 🔴 | C2/C3 | **等 ASan 栈** |
| D4 严格 affinity | ✅ | 已被取代 | 竞争法方向 |
| D8 超时偏大 | 🟡 | B1 | 独立调优 |
| D6 acceleration 背压 | 🟠 | D-opt1 | 排期 |
| D7/D9 兼容 | 🟡 | 文档已记 | — |
| D5/D10 | ✅ | 已闭环 | — |

**建议执行顺序**：A（D11 韧性，止住“不崩但全挂”）→ B（D8 接收定序调优）→ C（D1/D2/D3 崩溃，待 ASan）→ D（性能优化）。A 与 B 不依赖 ASan，可先行；C 必须等栈。

---

## 已落地修复（截至本文件）

- `49956b3` fix(icmp): avoid duplicate static echo replies — 修 D10。
- `d8fe453` fix(mux): make session disposed_ flag atomic — C1，D1/D2 的概率压制（非根因）。
- `cefbc6f` fix(mux): guard send-completion callback against post-teardown reentry — D1/D2 概率压制。
- `a96d9aa` feat(mux): flow mode spreads frames across links via auto-negotiated flow-v2 — 引入多链路（解 D7 的双新版场景，同时引出 D4）。

## 复测记录摘要

- until-fail-20260601-124147：复现断流。send=12528/recv=8，fail.mux=533，tx.queue.depth≈46113–57943，出站 SYN 无 SYN-ACK，HTTP 96/96 fail，ping 正常。→ 坐实 D11（+D4 触发）。
- until-fail-20260601-125620：未复现。fresh 重启跑 10 轮，存活，最大 loss 7.5%，HTTP 最大 bad 7/96，无 crash/double-free。→ D11 为特定时序进入的自锁态，非必现。
