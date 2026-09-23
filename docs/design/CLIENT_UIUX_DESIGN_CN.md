# OpenPPP2 Client 管理器 UI/UX 设计
> Status: Active
> Type: Design
> Last verified: 8c8a888

> **用途：**记录桌面 Client 管理器的状态绑定 UI/UX 设计和实现对照。
> **适用对象：**桌面 Client 开发者、设计评审者和维护者。
> **当前状态：**v2 设计基线；实现位于 `desktop/client/`，以代码为准，不是稳定接口或跨平台发布承诺。
> **最后核对依据：**`desktop/client/`、`ppp/app/ApplicationMainLoop.cpp`、`ppp/app/client/VEthernetExchanger.cpp` 与本仓库平台代码，2026-07-22。
> **上一层索引：**[Design Documents](README.md)

> **核对提示：**本文档的可用性矩阵记录当前实现和设计约束。桌面 Client 当前以进程事件和统计流驱动本地状态；它不是 `RuntimeSnapshot` 生命周期契约的消费者。

> 日期：2026-07-22
> 范围：Windows/macOS Client 管理器（Tauri + Svelte），配套 `SUB_CLIENT_DESIGN_CN.md`
> 实现：`desktop/client/` · 历史预览：`docs/design/mockups/client-connected.html`

## 0. 修订说明

初版的问题：界面元素建立在编造的数据上。本版的规则是——**每个出现在屏幕上的字段，都必须能指到本仓库中的现存代码**；指不到的，要么删掉，要么明确标注为“需要新增”并列入 §6 决策清单。数据可得性结论来自对 `go/ppp`、`ppp/`、`android/`、`ios/` 和 `desktop/client/` 的代码核查。

## 1. 数据可得性矩阵（本设计的事实基础）

| 信息 | 客户端能拿到吗 | 依据 |
|---|---|---|
| 节点名称 / 副标题 | ✅ 订阅 `nodes[].name` / `subtitle` | `go/ppp/Subscription.go` |
| 节点地址:端口 | ✅ 解析订阅 `nodes[].server`（`ppp://host:port/` URI） | 同上 |
| 协议/传输/密钥 | ✅ 订阅 `nodes[].key.*` | 同上 |
| 用户 GUID | ✅ 订阅 `client.guid` | `go/ppp/Subscription.go` |
| 订阅更新时间 | ✅ 顶层 `updatedAt` | 同上 |
| 节点延迟 | ⚠️ 桌面 wrapper 自测 TCP 连接延迟（不是隧道 RTT） | `desktop/client/src-tauri/src/pinger.rs` |
| 连接状态/握手事件 | ⚠️ 桌面 Client 解析进程 telemetry/stderr 事件并维护本地状态；不是 `RuntimeSnapshot` 消费者 | `desktop/client/src/lib/runtime/tauri.js`、`desktop/client/src-tauri/src/process.rs` |
| 进程退出 | ✅ wrapper 接收 OS 退出码（可为空）和 stderr 文本；不是固定的 `0/-1` 契约 | `desktop/client/src-tauri/src/process.rs` |
| 连接时长 | ✅ wrapper 本地计时 | `desktop/client/src/lib/runtime/tauri.js` |
| 上传/下载速度、累计流量 | ✅ 已实现：`--stats-json` NDJSON + 桌面 wrapper 差分 | `ppp/app/ApplicationMainLoop.cpp`、`desktop/client/src-tauri/src/stats.rs` |
| 链路质量（quality%/等级/错误计数） | ✅ `link.*` 位于 stats 行内 | `ppp/app/runtime/RuntimeStatsJson.h`、`desktop/client/src-tauri/src/stats.rs` |
| 活动链路数（mux_active_links） | ✅ stats 的 `runtime.mux_active_links` | `ppp/app/runtime/RuntimeSnapshotJson.h` |
| 结构化运行态（phase/effective_path/last_error） | ✅ stats 的 `runtime` 对象；UI 透传引擎字符串 | 同上 |
| TUN IP/网关/掩码、本地代理端口 | ✅ wrapper 自有（启动参数和自己生成的配置） | `desktop/client/src-tauri/src/launch_options.rs` |
| 进程 PID / 运行时长 | ✅ wrapper 进程状态和本地计时 | `desktop/client/src-tauri/src/process.rs`、`desktop/client/src/lib/runtime/tauri.js` |
| 运行时版本 / 平台 | ⚠️ 侧栏当前为静态展示，不应作为实时引擎事实 | `desktop/client/src/lib/components/Sidebar.svelte` |
| 流量额度/剩余量/到期时间 | ❌ 订阅不含，仅管理端 API 与服务器间内部协议有 | `go/ppp/User.go`、`go/ppp/Subscription.go` |
| 节点在线状态 | ❌ 订阅不含，仅管理端 `/api/v1/servers` | `go/ppp/Admin.go` |
| 节点负载 | ❌ **代码中不存在此概念** | 本仓库未定义对应字段 |

### 矩阵直接推出的设计结论

1. **主屏是“状态 + 指标 + 节点表”。** 连接后首屏按重要性排：连接状态 → 本机运行指标（速度/累计流量/链路质量/活动链路）→ 节点表。
2. **速度/流量等指标已由 `--stats-json` 落地**；无 stats 时 UI 隐藏指标区。
3. **延迟由 wrapper 自测 TCP 握手**，语义是“直连参考延迟”，不是隧道内 RTT；当前为事件驱动探测（bootstrap/刷新/保存节点/连接成功），不是固定 30s 轮询。
4. 节点列表同时覆盖订阅节点和手动节点：基础字段为名称、副标题、地址；手动节点显示本地来源并可编辑。v1 不伪造旗标、在线状态或负载字段。
5. **“连接数”的诚实口径**：展示 `mux_active_links`（活动链路）与原始 `effective_path` 字符串；不要写成“连接数”。

## 2. 信息架构

```text
侧边导航
├── 连接          状态、当前节点、会话事件（主屏）
├── 节点          全量节点表：名称/地址/延迟/连接操作、收藏
├── 订阅          订阅 URL 管理、updatedAt、手动刷新、缓存状态
├── 日志          telemetry 事件流：过滤、搜索、导出
├── ── 高级 ──
├── 配置          启动参数表单（TUN/DNS/MUX/策略）+ 高级原始 JSON
└── 设置          开机启动偏好、托盘行为、退出时断开/保留、语言/外观占位

托盘：状态 + 连接/断开最近节点 + 显示窗口 + 退出（无最近节点列表）
```

没有"诊断"页：v1 能诊断的东西（进程是否活着、最后一条错误、订阅是否拉得动）全部内联在"连接"屏和"日志"屏，不值得单开一页。

## 3. 主屏设计（连接）

```text
┌────────────────────────────────────────────────────┐
│ ● 已连接                                  [断开]    │
│   东京 01 · 47.102.x.x:32000                        │
│   延迟 32 ms（直连参考）· 已连接 02:14:36            │
├────────────────────────────────────────────────────┤
│ 本机（stats 导出，按采样更新）                        │
│   ↓ 12.4 Mbps   ↑ 2.1 Mbps   链路质量 99.2% 优      │
│   累计 ↓ 1.8 GB ↑ 214 MB     活动链路 4 · effective_path │
│   TUN 10.8.0.2/24 gw 10.8.0.1 · 代理 127.0.0.1:1080 │
├────────────────────────────────────────────────────┤
│ 会话事件                                            │
│   19:03:11  session established role=main          │
│   19:03:09  exchanger connected                    │
│   19:03:07  tcp connected 47.102.x.x:32000         │
├────────────────────────────────────────────────────┤
│ 常用节点                          全部节点 →        │
│   东京 01    47.102.x.x:32000    32 ms   [当前]    │
│   大阪 02    103.85.x.x:24000    48 ms   [连接]    │
│   新加坡 01  156.234.x.x:20000   86 ms   [连接]    │
└────────────────────────────────────────────────────┘
```

- 状态行就是 Hero。状态点 + 一个词（已连接/连接中/未连接/已断开），右侧一个动作按钮。没有旋钮、没有辉光、没有动画装饰。
- **本机指标卡**：纯文本等宽数字行，不画图。速度由 wrapper 对相邻累计字节样本做差分得出；链路质量和活动链路来自 stats 快照；TUN/代理是 wrapper 自己的启动参数。无 stats 时整张卡隐藏，不显示“--”占位。
- “会话事件”卡片展示 desktop Client 收到的 telemetry/进程事件。它是本地状态证据和排障入口，不是跨表面的生命周期权威。
- 常用节点表是第二动作区：一键切换。延迟数值旁边不配色阶圆点以外的装饰。

### 节点屏

全量表格，列：收藏 | 名称 | 副标题 | 地址 | 延迟（事件驱动 TCP 探测）| 操作。搜索框过滤名称/地址。连接页“常用节点”当前取列表前 4 项。手动节点显示本地来源并提供编辑/删除；不显示伪造的负载或在线徽标。

### 订阅屏

订阅 URL 卡片：地址、名称（`name`）、节点数、上次成功同步时间、订阅文档 `updatedAt`、手动刷新、Token 轮换提示文案。拉取失败时显示“使用 N 小时前的缓存”；缓存文件存在性即缓存状态。服务器会发出 ETag，但当前桌面 Client 不保存或发送 `If-None-Match`，不得把它描述为已实现的缓存协商。

## 4. 状态模型（桌面 Client 的本地事件模型）

桌面 Client 的状态来自进程 telemetry/stderr 事件、stats 样本和 OS 退出状态；这些是 wrapper 的本地模型，不是稳定的引擎 `RuntimeSnapshot` 契约。

```text
disconnected ──启动进程──> connecting
connecting ──已识别的 connected telemetry 事件──> connected
connecting ──已识别的 failed telemetry 事件──> error
connected ──成功退出──> disconnected
任何状态 ──非成功退出──> error（保留可用的退出码和诊断文本）
任何状态 ──订阅刷新失败──> 状态不变 + 顶栏“使用缓存”提示
```

| 场景 | 界面表达（全部内联，无弹窗） |
|---|---|
| 连接中 | 状态点黄色 + 事件卡显示收到的连接进展；进度感来自实际事件而不是进度条动画 |
| 握手失败 | 事件卡显示可用诊断文本，状态转 error，按钮变“重试” |
| ppp 异常退出 | 状态行显示退出信息；主按钮“重新连接”（日志在侧栏日志页，Hero 无单独“查看日志”按钮） |
| 订阅不可达 | 订阅屏和顶栏显示“使用 X 前的缓存”，节点照常可用 |
| 额度耗尽/到期 | 客户端**无法预知**；若事件流表明认证失败，UI 如实显示该事件，不提前编造额度 UI |
| Windows 提权 | 平台启动、提权与失败呈现仍需在目标环境验证 |

已知坑（实现时必须处理）：Windows 失败路径有 `PauseWindowsConsole()` 会等按键挂住进程（`ppp/app/PppApplication.cpp:57-61`），wrapper 需以无控制台方式创建进程并验证该路径；非 TTY 下 TUI 自动禁用，stdout 静默是**正常现象**，不要误判为卡死。

## 5. 视觉系统（反"模板感"的约束）

- **单色系**：背景 `#0B0D10`，卡片 `#101318`，边框 `rgba(255,255,255,.07)`。唯一彩色是状态色（绿/黄/红/灰），只用于状态点、状态词、关键按钮。禁止大面积渐变、辉光、毛玻璃。
- **主按钮是白底黑字**，不是发光彩色按钮。交互重量靠对比度，不靠光效。
- **数字一律 tabular-nums**；地址、GUID、事件行用等宽字体——这是网络工具，终端感是优点不是缺点。
- **表格优先**：节点用表格不用卡片网格。表格是数据的诚实形态，卡片网格是营销页的形态。
- 密度：13px 基准字号，行高 1.5，页边距 24px。不追求"大气留白"，桌面工具一屏要装得下 15 个节点。
- 动效只保留：状态切换 150ms 颜色过渡、事件行新条目淡入。`prefers-reduced-motion` 下全关。

## 6. 差距清单（决策点）

### 6.1 stats 导出（已实现）

`--stats-json=<path|stdout>` 已落地；桌面 Client 传该标志并消费 NDJSON。详见 [CLI 参考](../reference/CLI_REFERENCE.md) 与 `RuntimeStatsJson.h`。

契约（每个 stats 样本一行，NDJSON）：

```json
{
  "type": "ppp-stats",
  "version": 1,
  "monotonic_ms": 8080123,
  "rx_bytes": 1932734464,
  "tx_bytes": 224690176,
  "link": { "quality_percent": 99.2, "grade": "Good",
            "error_count": 12, "success_count": 14803 },
  "runtime": { "phase": "connected", "role": "client",
               "requested_mux_mode": "...", "effective_mux_mode": "...",
               "mux_active_links": 4, "p2p_state": "...",
               "effective_path": "direct",
               "last_error": { "code": 0, "severity": "", "retryable": false,
                               "user_message_key": "", "diagnostic_detail": "" } }
}
```

wrapper 语义：速度 = 相邻两行字节差分 ÷ 间隔；累计流量透传；`effective_path` 当前原样展示；无 stats 时隐藏指标卡。

### 6.2 Sub 订阅文档扩展（可选，v1.x）

在 `nodes[]` 增加 `flag` 和地区/备注；若需额度展示再加可选 `quota`。不改现有字段语义。

### 6.3 退出时结构化错误

进程退出事件仍走 `client://process`；`last_error` 可来自最终 stats 行。stderr 仍作补充诊断。

## 7. 落地映射（Tauri + Svelte，已实现）

- 代码：`desktop/client/`（Svelte 4 + Vite；`src-tauri` Tauri 2）。
- Rust：`process.rs`、`stats.rs`、`telemetry.rs`、`pinger.rs`、`config.rs`、`manual_nodes.rs`、`launch_options.rs`、`preferences.rs`、`desktop.rs`。
- 前端 runtime：`src/lib/runtime/{model,mock,tauri,index}.js`；路由 `connection|nodes|subscription|logs|config|settings`。
- 节点表为普通表格（无虚拟滚动）；延迟为事件驱动探测；语言/外观设置为占位偏好。
- 命令与事件清单见 [项目接口全景图 §9](../reference/PROJECT_INTERFACE_MAP_CN.md)。

## 8. 预览

实现优先：`desktop/client/`。历史 mockup：`docs/design/mockups/client-connected.html`。
