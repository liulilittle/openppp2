# 多代理补齐 P2P v2 持续直连

> Status: Implemented; production entry wired; cross-platform runtime acceptance remains incomplete
> Type: Design
> Last verified: 2026-10-07；本地实现提交 `c10eb0f`、`6a6c436` 的隔离测试通过，生产构建 gate 与客户端/server 接线已启用；设备和真实 NAT 验收尚未完成。
> **Purpose:** 保存 P2P v2 持续直连的实现方案与多代理分工。
> **Audience:** OPENPPP2 协议、网络、平台及测试维护者。
> **Parent index:** [Design Documents](../README.md)

本地实现提交 `c10eb0f`、`6a6c436` 已进入生产源码。核心 production gate 在 `ppp/p2p/P2PCapabilityGate.h` 默认开启，并由各平台的 `ENABLE_P2P_V2_PRODUCTION` 构建开关控制；服务端 v2 offer 路径 `ppp/app/server/VirtualEthernetP2PV2.cpp` 仍会检查该 gate。默认配置选择 `p2p.enabled=true`；Linux、Android 默认 `direct-preferred`，Windows 与桌面 macOS 在真实 NAT 验收前默认 `relay`，需显式设置 `p2p.mode=direct-preferred` 才尝试直连。显式 `p2p.enabled=false` 或能力失败时回 relay。

## 目标

补齐 Linux、Android 的直连实现与隔离自动化验收，支持多候选探测、持续连接和平滑换钥。保留 v1 编码及到期规则，生产 v2 开关默认开启；iOS 继续走 relay。

本轮不修改系统路由、DNS，不启动 PPP 或特权 netns 测试。真实 NAT、Android 后台与网络切换、Linux 绕过 TUN 的证据作为后续上线条件。

## 协议与实现

- **共用受保护的 transport。** STUN、Probe、业务数据和换钥使用同一个 socket、唯一接收回调。移除临时 STUN socket 和 detached 查询线程。每个 STUN server 立即查询、500ms 后原事务重试一次、1000ms 截止；最多尝试三个 server，首个有效响应结束收集。严格验证来源、transaction ID 和报文长度，关闭时取消事务。

- **STUN 请求兼容配置。** `p2p.stun.request-profile` 默认 `standard`，发送 20B Binding Request；显式设置 `tailnode` 时发送 40B 请求，包含 SOFTWARE `tailnode` 和 CRC32 FINGERPRINT，用于兼容 Tailscale STUN。配置值去除首尾空白并转小写，未知值规范化为 `standard`。这些属性不代表已认证身份，也不授权启用直连。

- **显式协商 v2。** INFO 注册增加 `supported-versions`，server 状态返回支持版本；只有双方及 server 均支持 v2 才发送 `offer-v2`。旧端保持现有行为，已选择 v2 后失败不得静默降级。新增 `authenticated-offer-v2`、双方候选 revision、`local-candidates`、`current-offer-hash`，以及 `renew`、`key-active` 动作。

- **冻结候选快照。** 每端最多两个 IPv4 候选：host 和同 transport 获得的 STUN 地址；合计四个候选、最多四个 endpoint pair。排除 relay socket 的 ObservedEndpoint。revision 使用非零 uint64 十进制字符串；相同 revision 必须对应相同集合，旧 revision 不覆盖新登记。哈希绑定角色、session、revision、数量及排序后的端点。候选更新只修改 latest，不改写 active 或 pending 快照。

- **多 peer 独立上下文。** 客户端按虚拟 IPv4 地址保存最多 16 个 peer context，各自拥有 channel 密钥、probe、liveness 及 renew/key-active 报告计时。受保护 UDP socket、STUN、候选 revision 历史和 socket 恢复共用；STUN 维护每 15 秒重试收集，不改写已冻结的 peer 快照。status 回显 peer VIP，只确认对应 context。runtime 汇总只要任一 peer Direct 即为 Direct，但业务出站仍按目标 VIP 选择该 peer 的状态；其他 peer 继续 relay。共享 socket 故障清理全部 peer 的直连状态。

- **独立认证域。** v2 offer 绑定双方身份、session、epoch、单调递增 key generation、前驱 offer hash、候选 revision 和全部期限。exporter/HKDF 使用独立 v2 标签；exporter context 固定为 145 字节。同步更新 Noise carrier 与底层 purpose、标签和长度校验，保持 v1 的 113 字节语义。数据包保留现有布局，以 version=2 严格分流。

- **固定发起方选路，双向 priming。** 按 peer ID 稳定确定 initiator。双方同时探测最多四个 pair，为 address/port-restricted NAT 建立过滤许可；每个事务初发后 2 秒原字节重试一次，4 秒结束探测窗。initiator 以首个有效 ACK 锁定 pair，通过 `KEY_COMMIT` 提名；responder 的初始 ACK 只缓存认证事务，不自行选路。Commit 将 responder 收窄到选定 pair，保留既有轮次、反向 ACK 与期限，仅双向 Ready 后提交并回复 `KEY_COMMIT_ACK`。Commit 同样最多发送两次、间隔 2 秒；客户端 receipt 起算的 setup 最长 10 秒。重复请求只返回缓存的原 ACK，不消耗新 nonce。

- **平滑换钥。** 每个 channel 最多 current、pending、previous 三槽，各自拥有独立 key、sequence、replay 和固定期限。key lifetime 为 60 秒，首次接收后 40 秒申请刷新；previous 只接收，截止为 `min(切换后5秒, 原key到期)`。健康 current 在 pending 建链时继续传输。initiator 只有完成本地双向 Ready 后，才能通过 CommitACK 或匹配的新 key 数据确认切换；responder 提交后立即发送新 key 心跳。重发、切换和重复 offer 均不延长期限。

- **协调服务端刷新。** 每个 session pair 最多一个 pending offer，同时 renew 合并；保留现有 10 秒节流，重新注册不能重置冷却。双方提交后每秒重报幂等的 `key-active`，server 确认双方后更新 current。exporter 生成限时 10 秒；服务端 pending 协调记录自生成完成保留最多 60 秒，避免 exporter/relay 延迟提前拒绝报告，但不延长客户端 10 秒 setup 或 60 秒 key 期限。异步 exporter 和投递回调核查 generation、transmission、offer ID 与冻结快照。Commit 前刷新失败仅清理 pending；Commit 已发而结果不明时，在 setup 截止前有界回 relay。丢失本地 current 后只发零 predecessor renew，等待 server 保守期限（双方报告确认后最多 60 秒）再协商，不能直接接受仍有效旧钥的零前驱。

- **补齐安全与生命周期。** 控制流在复制、投递和鉴权前限流：来源 IP 4/s、burst 8；relay session 8/s、burst 16。来源表最多 256 项，空闲 60 秒回收，满表时丢弃未知来源。正常已建立路径的数据不套用控制包速率限制。v2 Probe/ACK 固定 158B、Commit/ACK 190B、迁移控制包 126B；padding 纳入认证，ACK 不得大于已认证请求，无效包不回复。

  已知 offer hash 且来源匹配该 peer 登记候选或已选端点时，使用该 peer 独立的 source 4/s、burst 8 与 session 8/s、burst 16 接收预算；此分流检查不代替报文认证。每 peer 控制出站另有独立 session 8/s、burst 16 预算，最多 16 个 context。未知来源与 STUN 继续使用客户端共享接收预算，不因其他 peer 的建链消耗独立预算。

- **安全迁移与恢复。** 新来源数据先做不提交状态的 AEAD/replay 校验，不交付、不改 endpoint、不刷新 liveness；验证后才允许一个有限迁移挑战。MigrateACK 匹配该挑战的新 endpoint，不套用初始候选成员检查。迁移与换钥串行：Commit 前可取消 pending 刷新，迁移完成后重新 renew；Commit 后地址变化回 relay。取消通过匹配的 `cancel-offer-hash` 协调。心跳按独立发送时钟运行，旧 key 包不维持新 key 的 liveness。超时、socket 错误和停止统一清理 key、replay、端点及计时器，保护基础 relay session；恢复退避为 1、2、4、8、10 秒。

  每个 peer 的控制出站队列最多保留 32 个不同的目标地址/报文组合，重复项合并；队列有效期不超过 2 秒，也受 offer、key 或 setup 截止时间约束。队列溢出或过期会取消探测并清空待发控制包；若刷新尚未 Commit，则保留健康的 current key。transport 发送失败进入共享 socket 恢复流程（`ppp/app/client/VEthernetP2PV2.cpp`）。Linux DNS 实机验证不构成 P2P NAT 直连验收；真实 NAT 与设备行为仍未验收。

- **禁止 nonce 回绕。** sequence 到 `UINT32_MAX-4096` 时请求刷新；耗尽后禁止旧 key 新发送并转 relay，不能重置同 key counter。v2 接收窗口接受已认证的数值更大序号，即使跨度超过半个 uint32 范围，仍拒绝 sequence wrap、重复及窗口外旧包；失败认证不能提交窗口变化。保持 v1 行为不变。

## 并行分工

先冻结接口：由 `P2PV2Channel` 封装 `AcceptOffer`、`HandleControl`、`SealData/OpenData`、`Tick`、`Reset`，对接线层返回回复包及刷新、激活、回退事件，密钥和认证证明留在内部。

| 负责人 | 独占工作 |
|---|---|
| Subagent 1 | native transport、同 socket 异步 STUN、解析与 transport 测试 |
| Subagent 2 | v2 编码、exporter/HKDF、认证、三槽换钥及 session 单测 |
| Subagent 3 | 多候选 coordinator、虚拟时钟、Fake NAT、完整隔离集成测试与 sanitizer |
| Subagent 4 | 客户端 transport 恢复、生命周期接线与真实状态测试 |
| Subagent 5 | 服务端 offer、刷新及 key-active 协调与真实状态测试 |
| Subagent 6 | 协议、状态机、双语测试说明和独立文档验收 |
| Subagent 7 | Linux/Android/Windows 构建清单与平台编译边界核查 |
| 主代理 | INFO schema、共享构建文件、CI、交叉审查和最终集成验收 |

各代理先进行影响分析，不同时编辑共享文件；提交前运行 GitNexus 变更检测并检查实际 diff。

## 验证与验收

2026-10-05 至 2026-10-07：正式 standalone CMake 已接入 offer、channel、Noise、coordinator、limiter、同 socket STUN/native 和真实 IPv4 parser 集成测试，并加入真实客户端/server/carrier 接线的对象编译目标。普通 P2P 与原有 Noise 回归 30 targets 通过；focused 测试在 ASan/UBSan/LSan 和独立 TSan 下通过，其中 integration 16 cases 包含虚拟时间 180 秒持续换钥及 100 次生命周期循环。Linux 生产库已在 `ENABLE_P2P_V2_PRODUCTION=ON` 下完成编译；Android、iOS CMake 和 Windows 工程均明确注入生产宏。隔离 native socket 测试在当前 sandbox 因禁止创建 socket 未运行通过，由 Ubuntu CI 执行。统一入口为 `sh scripts/run-p2p-v2-isolation.sh [normal|asan|tsan]`；构建时可用 `-DENABLE_P2P_V2_PRODUCTION=OFF` 紧急关闭，运行时仍可用 `p2p.enabled=false` 回 relay。

后续并行续验：真实根项目 Linux Release 全量 283 项编译和链接通过，恢复修复后重新增量链接并确认 no work，生产构建无测试宏。独立根链接 `p2p_v2_exchanger_recovery_test` 实例化真实 Exchanger，9 个用例在普通、ASan/UBSan/LSan 和独立 TSan 下全部通过；可重复入口为 `sh scripts/run-p2p-v2-exchanger-recovery.sh [normal|asan|tsan] -DTHIRD_PARTY_LIBRARY_DIR=/path/to/native-deps`，测试开关默认关闭。

环境边界：integration harness 模拟 NAT、relay 与时钟；独立根链接恢复测试执行真实恢复 coroutine、旧 callback 隔离、认证 v2 重连和 Update/FRP 维护，但替换了登记、transport、relay/exporter 等依赖边界。真实 INFO 交付、原生 socket 创建/保护、Android SDK/真机、Windows MSBuild、真实 NAT 与绕过 TUN 未验收。GitNexus 数据库版本不兼容，使用源码调用分析与 diff 替代。

- 新增离线 `p2p_v2_integration_test`：使用真实 offer 编解码、认证、session、coordinator 和 IPv4 parser，仅模拟网络、NAT、relay 与时钟；禁止伪造 ACK proof 跳过握手。
- 新增非特权 `p2p_native_socket_stun_test`：证明保护发生在首发包前，STUN、Probe、data 共用本地端口。若本地 sandbox 禁止 socket，明确记录限制，由 Ubuntu CI 执行。
- 覆盖第二候选成功、丢包重试、重复和乱序、候选更新竞态、错误来源/角色/session/epoch、限流边界、不放大、合法及伪造迁移、旧 generation 回调、nonce 耗尽与回绕。
- 虚拟时间推进至少 180 秒，验证多次换钥持续 Direct、旧 key 接收窗口、CommitACK 丢失恢复、刷新失败及硬过期；完成 100 次连接、刷新、回退和停止循环。
- 从源码重建相关 C++ 测试，运行 focused ASan/UBSan 与独立 TSan；CI 加入 P2P tooling，修复 Android bounded logcat 检查，完成 Linux 应用接线对象编译和现有源码清单检查；Android 编译与设备行为仍需对应工具链验收。
- 更新协议、状态机和中英文开发说明，验证双语文档严格构建。验收报告区分生产接线、隔离测试与真实网络证据，不将源码接线表述为跨平台设备 runtime 验收。
