# openppp2 深度代码优化与安全审核报告
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 生成时间：2026-05-09（首版） / 2026-05-09（续审追加 §14）
> 范围：`/mnt/e/Desktop/openppp2-next/openppp2`
> 语言：中文
> 类型：性能、安全、协议、构建依赖、可维护性综合审核
> 修订：§14 聚焦近期 2 个未推送提交（`ed61d5b`、`d483885`）与 7 个未提交工作区文件的针对性审核，与 §1–§13 的项目全景审核互为补充

---

## 1. 审核范围

本次审核通过多个 subagent 并行完成，覆盖以下维度：

- **安全审计**：加密、TLS、密钥、认证、输入校验、日志泄露、命令注入、证书与配置风险。
- **性能与架构审计**：传输层、网络层、DNS、Firewall、内存池、异步写队列、锁竞争、可扩展性。
- **传输协议审计**：握手状态机、帧长度、base94/obfuscation、WebSocket、DoS、teardown 并发。
- **构建与供应链审计**：CMake、CI、vendored 依赖、Android 依赖、安全编译选项、artifact 发布。
- **代码质量审计**：`stdafx.h`、配置系统、错误码体系、跨平台条件编译、生命周期管理、测试缺失。

### 主要代码范围

- `ppp/transmissions/*`
- `ppp/cryptography/*`
- `ppp/ssl/*`
- `ppp/net/*`
- `ppp/io/*`
- `ppp/threading/*`
- `ppp/coroutines/*`
- `ppp/app/client/*`
- `ppp/app/server/*`
- `ppp/app/protocol/*`
- `ppp/configurations/*`
- `ppp/diagnostics/*`
- `ppp/stdafx.h`
- `linux/*`, `windows/*`, `darwin/*`, `android/*`
- `CMakeLists.txt`, `.github/workflows/*`, `build-*.sh`, `build_windows.bat`
- `common/*`, `go/*`, `go/guardian/webui/*`
- `appsettings.json`, `go/appsettings.json`, `starrylink.net.key`, `starrylink.net.pem`, `cacert.pem`

> 复核说明：维护者确认根目录部分配置文件、证书和私钥为示例文件，可以随 release 分发，不作为 release 阻断项。`cacert.pem` / `cacert.sha256` 为公共 CA bundle 及其校验值，不属于私钥或生产凭据泄露范围。

### 项目规模

- 核心源码总量约：`105,063` 行。
- 主要语言：C++17、Go、JavaScript/Svelte、CMake、Shell、PowerShell。
- 主要依赖：Boost.Asio/Beast、OpenSSL、jemalloc、lwIP、JsonCpp/nlohmann/json、Svelte/Vite、Android NDK。

---

## 2. 总体结论

openppp2 是一个复杂的跨平台网络隧道/代理/VPN 运行时，覆盖传输加密、虚拟网卡、DNS、路由、WebSocket、服务端交换器、客户端网络切换器等模块。

代码中已有一些工程化改进：

- 错误码体系使用 X-macro 管理。
- `ITransmission` 主状态已部分改为 atomics。
- 部分 Android DNS/timer 崩溃路径已有集中状态对象修复。
- 部分 DNS redirect buffer 已从共享改为 per-call。
- IPv4 broadcast 已有限制。
- IPv6 NDP proxy 已避免每 tick 直接 shell/sysctl。

### 风险状态总览

#### P0 — 已关闭

| # | 问题 | 状态 |
|---|------|------|
| 3 | TLS/WSS 证书校验关闭 & 主机名校验缺失 | ✅ **历史问题，已修复**：WSS 后端默认 `verify_peer=true`；`SslSocket` 通过 `SSL_set1_host()` 设置主机名校验（见 §3.2、§3.3） |
| 4 | 异步写队列缺少背压 | ✅ **历史问题，已修复**：已增加 pending items/bytes 水位线与拒绝策略，关闭慢连接拖垮队列的 P0 风险（见 §4.1） |
| 5 | 传输帧长度缺少策略上限，内存/slowloris DoS | ✅ **历史问题，已修复**：已实施长度上限（PPP_BUFFER_SIZE 65536 字节），关闭内存膨胀/超大帧风险；per-frame 读取超时已转 P1 慢读 DoS 加固项（见 §5.1） |
| S0-1 | 服务端 SSL 上下文忽略证书/私钥加载错误 + 密码回调顺序错误 | ✅ **发版前复核新增，已修复（2026-05-30）**：`CreateServerSslContext` 改为回调先注册、逐步检查 `ec` 并 fail-fast，加密私钥恢复可用（见 §17.2） |

#### P1 — 治理中 / 待选择

| # | 问题 | 说明 |
|---|------|------|
| 5a | per-frame 读取超时（从 P0 帧长度项拆出） | **已转 P1**：列为慢读 DoS 加固项（见 §5.1） |
| 6 | Dispose/Finalize/Socket/Timer 并发竞态 | 多个路径存在跨线程竞态风险（见 §15 风险分级） |

#### P2 / 长期债务

| # | 问题 | 说明 |
|---|------|------|
| 7 | 构建系统硬编码路径、vendored 依赖、过期 Android OpenSSL/NDK | 供应链与可维护性问题 |
| 8 | 缺少 C++ 测试、lint、静态分析、安全扫描 | 记录在案，暂不治理 |
| 12 | Firewall 规则匹配热路径优化 | ✅ **最小侵入优化已实施（2026-05-11）**：减少后缀拼接临时分配并移除冗余自拷贝（§4.6 OPT-P2-12b/c）；剩余 RCU 快照 + trie 后续迭代；**RCU 设计文档已完成（2026-05-11）**：`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`，涵盖 C++17 `atomic_load/store` 快照方案、线程安全模型、语义保持要求、测试/基准计划和迁移步骤 |
| 17 | Android ProtectorNetwork JNI 上下文访问边界 | ✅ **已完成最小代码修复并通过复审（2026-05-11）**：`jni_`/`env_` 只在 `syncobj_` 下 snapshot，Java/JNI 外部调用移到锁外；见 `docs/p2-governance-decisions-cn.md` P2-17 |

#### 非阻断 / 可选治理（不作为 release 阻断项）

| # | 问题 | 说明 |
|---|------|------|
| 1 | 根目录示例 RSA 私钥/证书/配置 | 维护者确认为示例资产，可随 release 分发。建议启动时检测示例 key/cert 时输出醒目 warning（已部分实施，见 §3.5） |
| 2 | 默认/示例加密设计偏弱 | MD5 KDF、无 salt、RC4、AES-CFB 无认证、默认 plaintext 等；启动时仅 warning 提示，不拒绝启动、不 fail-closed |

---

## 3. 安全漏洞

### 3.1 示例 RSA 私钥/证书被 CI 打包与用户误用风险

**位置：**

- `starrylink.net.key:1-27`
- `appsettings.json:14,16`（协议/传输示例密钥）
- `appsettings.json:100-103`（证书路径与示例密码）
- `appsettings.json:129`（backend-key 示例值）
- `go/appsettings.json`（开发环境占位数据库/服务配置）
- `.github/workflows/build-linux-amd64.yml`
- `.github/workflows/build-windows-x64.yml`
- `.github/workflows/build-windows-arm64.yml`

**严重性：中 / Medium（信息性风险，非 release 阻断项）**

> 复核调整：维护者说明根目录 `starrylink.net.key`、`starrylink.net.pem` 属于示例文件。在缺少其用于当前生产服务的证据时，本项不再按 P0「生产密钥泄露」处理。
>
> **维护者确认：示例文件（私钥、证书、示例配置）可以随 release 分发，不作为 release 阻断项。**

仓库中包含示例 RSA 私钥：

```text
-----BEGIN RSA PRIVATE KEY-----
```

同时示例配置文件引用：

```json
"certificate-key-file": "starrylink.net.key",
"certificate-key-password": "test"
```

CI 构建流程会把示例证书/私钥复制进 artifact。经维护者确认，示例文件可以随 release 分发。

`cacert.pem` 是 Mozilla/curl 风格的 CA 根证书 bundle，`cacert.sha256` 是其校验值；二者不是秘密，不应归入私钥或生产凭据泄露范围。其治理重点是来源、完整性校验、更新机制和过期根证书维护。

**影响：**

- 若该私钥确为示例文件且未用于生产服务，则不应定性为当前生产密钥泄露。
- 但该私钥已经公开，任何使用该示例私钥/证书部署 WSS 服务的用户，都等同于使用公开私钥。
- 示例配置中包含固定协议密钥、固定代理凭据、固定本地地址、`certificate-key-password: "test"` 等，不适合生产环境。
- 若后续发现该证书/私钥曾用于真实线上服务，才应升级为 P0 并执行吊销、轮换和历史清理。

**修复建议（非阻断，可选改进）：**

1. 将 `starrylink.net.key`、`starrylink.net.pem` 明确标注为测试/示例资产，例如移动到 `examples/certs/`，并使用 README 或文件名标明 `DO-NOT-USE-IN-PRODUCTION`。
2. 在程序启动时检测到示例证书、示例私钥、固定示例 key、`certificate-key-password: "test"` 等，可输出醒目 warning（已部分实施，见 §3.5）。
3. 文档中明确说明：仓库根目录配置、证书、私钥仅为示例，不是生产默认配置。
4. 若未来确认该私钥曾用于真实生产服务，则升级为 P0，并执行吊销、轮换、历史清理和发布公告。
5. 继续启用 secret scanning，但为示例文件建立显式 allowlist/注释，避免误报掩盖真正泄露。

---

### 3.2 WSS/TLS 后端连接关闭证书校验

**位置：**

- `ppp/app/server/VirtualEthernetManagedServer.cpp:1003-1014`

**严重性：高 / High**

> **✅ 已修复：** WSS 后端连接现在默认 `verify_peer = true`，启用 TLS 证书校验。
> 见 `VirtualEthernetManagedServer.cpp` 中 `IWebSocket::Run()` 方法。

原代码中显式设置：

```cpp
bool verify_peer = false;
```

这会导致 TLS 加密存在，但不验证服务端身份。

**影响：**

- WSS 后端连接容易被 MITM。
- 攻击者可伪造证书。
- 流量可能被篡改或劫持。
- 用户误以为 WSS 是安全通道。

**修复方案：**

已将 WSS 后端默认改为 `verify_peer = true`。`SslSocket::Run()` 在 `verify_peer_` 为 true 时，
通过 `SSL_set1_host()` 设置 OpenSSL 主机名校验证书链（见 §3.3 修复）。

**修复建议（已实施）：**

1. ✅ 生产默认强制 `verify_peer = true`。
2. 私有证书应使用私有 CA。
3. 支持证书 pinning / 公钥 pinning。
4. 关闭校验只能在 debug/insecure 模式显式开启。
5. 关闭校验时输出高危告警。

---

### 3.3 TLS 客户端缺少统一主机名校验

**位置：**

- `ppp/net/asio/templates/SslSocket.h:89-116`
- `ppp/ssl/SSL.cpp:264`

**严重性：高 / High**

> **✅ 已修复：** `SslSocket::Run()` 现在在 `verify_peer_` 为 true 时通过 `SSL_set1_host()` 设置
> OpenSSL 主机名校验，确保证书链验证包含 hostname 匹配。`host_` 为空且 `verify_peer_` 为 true 时
> 直接返回失败，避免静默跳过主机名校验。

原代码设置了 SNI：

```cpp
SSL_set_tlsext_host_name(GetSslHandle(), host_.data())
```

但通用 `SslSocket` 路径中未统一设置主机名校验。

**修复方案（已实施）：**

在 `SslSocket::Run()` 中，SNI 设置之后、`PerformSslHandshake()` 之前，添加：

```cpp
if (verify_peer_) {
    if (host_.empty()) {
        ppp::diagnostics::SetLastErrorCode(
            ppp::diagnostics::ErrorCode::SslWebSocketRunInvalidHostOrPath);
        return false;
    }
    if (!SSL_set1_host(GetSslHandle(), host_.data())) {
        return false;
    }
}
```

`SSL_set1_host()`（OpenSSL ≥ 1.0.2 / BoringSSL）在 `SSL_VERIFY_PEER` 模式下自动
验证证书的 SubjectAltName 或 Subject CN 是否匹配预期主机名。

**修复建议（已实施）：**

- ✅ `verify_peer_` 为 true 时通过 `SSL_set1_host()` 设置主机名校验。
- ✅ `host_` 为空且 `verify_peer_` 为 true 时返回失败（`SslWebSocketRunInvalidHostOrPath`）。
- DNS DoH/DoT 中已有主机名校验实践，建议抽象复用。

---

### 3.4 弱密钥派生与自定义密码学设计

**位置：**

- `ppp/cryptography/EVP.cpp:272-315`

**严重性：高 / High**

问题代码：

```cpp
EVP_BytesToKey(
    _cipher,
    EVP_md5(),
    NULLPTR,
    (Byte*)password.data(),
    (int)password.length(),
    1,
    _key.get(),
    _iv.get()
)
```

后续还使用：

```cpp
ComputeMD5(...)
rc4_crypt(...)
```

当前 KDF 存在：

- MD5；
- 无 salt；
- 1 次迭代；
- IV 确定性派生；
- 自定义 RC4 混合；
- 无现代 AEAD 认证保护。

**修复建议：**

1. 新协议默认优先使用当前已支持的最强非遗留密码；AEAD（如 AES-256-GCM 或 ChaCha20-Poly1305）需在项目支持确认后启用。
2. KDF 使用 Argon2id、scrypt 或 PBKDF2-HMAC-SHA256。
3. 每会话随机 salt。
4. 每包随机 nonce/IV。
5. RC4/MD5 仅保留 legacy 兼容模式，并默认禁用。

---

### 3.5 默认密钥可预测，默认 plaintext 开启

> **⚠️ 已实施非阻断安全提示（P0-2）— 2026-05-10**
>
> 用户明确要求：弱 key、示例 key、短 key 只能 warning，不得 fail-closed，不得阻断启动。
> plaintext=true 可以显式配置，显示醒目提示但不拒绝启动。
>
> 已实施：在 `AppConfiguration.cpp` 配置归一化完成后检测以下场景并设置
> `kWarning` 级别错误码（`ConfigWeakKeyDefault`、`ConfigWeakKeyShort`、
> `ConfigPlaintextEnabled`），不改变任何默认值，不阻断启动：
>
> - protocol_key 或 transport_key 等于已知默认值 `"ppp"` → `ConfigWeakKeyDefault`
> - protocol_key 或 transport_key 长度 < 8 字节 → `ConfigWeakKeyShort`
> - `key.plaintext == true` → `ConfigPlaintextEnabled`
>
> 后续可增强 warning 的可见性，例如在日志、管理界面、诊断输出中高亮展示；生产模式也应保持非阻断策略，不拒绝启动、不 fail-closed。
>
> **P1-5 已实施（2026-05-11）**：新增 `AppConfiguration::EmitSecurityDiagnostics()` 方法，在启动时发射完整的安全诊断报告（含每个发现的独立警告 + 汇总行），通过 telemetry 和控制台双通道输出。详见 `docs/p1-governance-decisions-cn.md` §P1-5。
>
> **P1-7 已实施（2026-05-11）**：新增遗留密码算法检测警告。在 `AppConfiguration::Loaded()` 的安全姿态警告块中，当 `key.protocol` 或 `key.transport` 使用遗留算法族（RC4、DES/3DES、Blowfish、CAST5、SEED、IDEA）或密码密钥长度低于 128 位时，设置 `ConfigLegacyCipherAlgorithm` 或 `ConfigLegacyCipherShortKey` 警告码。同时发出 `ConfigLegacyKdfMd5` 信息性警告码，标记内部使用 MD5 的密钥派生。这些警告不阻断启动、不改变默认值，保持向后兼容。详见 `docs/SECURITY.md` §17 和 `docs/SECURITY_CN.md` §17。

**位置：**

- `ppp/configurations/AppConfiguration.cpp:262-267`
- `ppp/configurations/AppConfiguration.cpp:803-808`

**严重性：高 / High**

问题代码：

```cpp
config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
config.key.transport_key = BOOST_BEAST_VERSION_STRING;
config.key.plaintext = true;
```

**影响：**

- 默认密钥公开可预测。
- 默认配置可能明文传输。
- 用户未配置 key 时系统仍启动，导致弱部署。

**修复建议：**

1. ~~禁止默认弱 key 启动。~~ → 已调整为：检测并高亮提示，不阻断启动。
2. 首次启动生成随机高熵 key。
3. `plaintext` 默认关闭。
4. ~~配置中出现 `"ppp"`、`"test"`、空 key 时拒绝启动。~~ → 已调整为：检测并高亮提示，不阻断启动。

---

### 3.6 默认 AES-CFB 缺少认证完整性

**位置：**

- `ppp/stdafx.h:368-369`

```cpp
PPP_DEFAULT_KEY_PROTOCOL  = "aes-128-cfb";
PPP_DEFAULT_KEY_TRANSPORT = "aes-256-cfb";
```

**严重性：中高 / Medium-High**

AES-CFB 只提供机密性，不提供认证完整性。如果协议层没有额外 HMAC 或 AEAD tag，攻击者可能对密文做可控篡改。

**修复建议：**

- 默认优先改为当前已支持的最强非遗留密码；AEAD（如 `aes-256-gcm` 或 `chacha20-poly1305`）需在项目支持确认后启用。
- CFB 仅 legacy 兼容。
- 所有包必须有 tag。
- tag 验证失败立即丢包并关闭连接。

---

### 3.7 仍支持 RC4 / RC4-MD5 / RC4-SHA1

**位置：**

- `ppp/cryptography/rc4.cpp:341-346`
- `ppp/cryptography/rc4.cpp:365-370`

**严重性：中高 / Medium-High**

RC4 已被废弃，RC4-MD5、RC4-SHA1 均不应再作为安全算法。

**修复建议：**

- 默认禁用全部 RC4。
- 配置加载时拒绝 RC4。
- 若必须兼容，使用 `legacy=true` 显式开关。
- 日志中输出高危告警。

---

### 3.8 macOS/Darwin 使用 `system()` 拼接 shell 命令

**位置：**

- `ppp/app/client/VEthernetNetworkSwitcher.cpp:1081-1085`
- `ppp/app/client/VEthernetNetworkSwitcher.cpp:1184-1188`
- `darwin/ppp/tun/utun.cpp:187-190`

**严重性：中 / Medium**

问题代码：

```cpp
snprintf(cmd, sizeof(cmd),
    "ifconfig %s inet %s %s netmask %s up",
    name.data(), ip.data(), gw.data(), mask.data());

system(cmd);
```

**修复建议：**

- 禁止 `system()`。
- 使用 `posix_spawn` / `execve` 参数数组。
- 或调用平台 API。
- 对接口名、IP、mask 做白名单校验。

---

## 4. 性能与稳定性问题

### 4.1 异步写队列无背压，可能 OOM

> **✅ 已实施背压（P0-3）— 2026-05-10；✅ 已修正三条缺陷 — 2026-05-11**
>
> 已添加 `pending_items_` / `pending_bytes_` 原子计数器和
> `max_pending_items_`（默认 4096）/ `max_pending_bytes_`（默认 16 MiB）
> 阈值。入队前检查阈值，超限时返回 `AsyncWriteQueueBackpressure`
> 错误并拒绝写入。计数器在写完成（evtf 回调）、写启动失败、
> 和 Finalize 清理三条路径上对称更新。
> 阈值可通过 `SetMaxPendingItems()` / `SetMaxPendingBytes()` 配置，
> 设为 0 表示 unlimited。`GetPendingItems()` / `GetPendingBytes()`
> 可用于运行时监控。
>
> **CodeReviewer 审查修正（2026-05-11）：**
> 1. **pending_bytes_ 扣减归零 bug**：立即派发失败路径先调用 `Clear()`
>    （将 `packet_length` 置零）再 `fetch_sub(packet_length)`，
>    导致永远扣减 0。修正为先保存 `packet_length` 再 `Clear()`，
>    使用保存值扣减。
> 2. **临界区穿透**：背压阈值检查在 `syncobj_` 锁外、计数递增在锁内，
>    并发 WriteBytes 可全部通过检查再全部递增，突破限制。修正为
>    检查 + 递增在同一 `syncobj_` 临界区内作为原子 accept/reservation。
> 3. **阈值 data race**：`max_pending_items_` / `max_pending_bytes_` 为
>    普通 int，setter 并发写、WriteBytes 并发读构成 data race。修正为
>    `std::atomic<int>`，setter 将负数 clamp 到 0（0 仍表示 unlimited）。
>
> 未实施：慢连接断开策略、上游暂停读取通知。这些需要与传输层
> 和 TAP 层协调，属于后续独立优化项。

**位置：**

- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:106-147`

**优先级：P0**

当前写队列在已有写操作进行时直接追加：

```cpp
q->queues_.emplace_back(context);
return true;
```

没有最大 pending item、最大 pending bytes、高水位、丢弃策略、暂停上游读取或慢连接断开策略。

**影响：**

- 队列无限增长。
- 内存暴涨。
- 延迟无限增加。
- 最终 OOM。

**修复建议：**

增加：

```text
max_pending_items
max_pending_bytes
pending_items_
pending_bytes_
```

超过阈值时：

- 返回失败；
- 丢弃低优先级包；
- 断开慢连接；
- 通知上游暂停读取。

---

### 4.2 写队列 `disposed_` 普通 bool 存在数据竞争

> **✅ 已修复（P0-6，原子化 disposed_ + Finalize one-shot）— 2026-05-11**
>
> 修复方案：`bool disposed_` → `std::atomic_bool disposed_{false}`。
> `Finalize()` 入口使用 `disposed_.exchange(true, std::memory_order_acq_rel)`
> 实现 one-shot 语义：第一个调用者执行 drain，后续调用者（Dispose、析构、
> 并发线程）立即返回，不重复操作。
> WriteBytes / DoTryWriteBytesUnsafe / DoTryWriteBytesNext 等所有读路径
> 使用 `load(std::memory_order_acquire)`。保持现有锁内 re-check 行为不变。
> 不改变 WriteBytes public 签名，不重构 backpressure 逻辑。

**位置：**

- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:37-43`
- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:82-84`
- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:106-109`

**优先级：P0**

`disposed_` 是普通 bool，但存在锁外读、锁内写。C++ 中这属于数据竞争，行为未定义。

**修复建议：**

```cpp
std::atomic_bool disposed_{false};
```

或所有读写都统一在同一把锁内。

---

### 4.3 DNS cache 命中时复用共享 response 并原地改 transaction id

> **✅ 已修复（P0-5，copy-on-read）— 2026-05-10**
>
> 修复方案：`Get()` 命中缓存时，在锁内取出 `cached_response` / `cached_length`，
> 锁外分配 `local_copy`（`make_shared_alloc<Byte>`），`memcpy` 后仅在 `local_copy`
> 上写 `usTransID`，最后返回 `local_copy`。原始缓存 buffer 不再被修改，彻底消除
> 并发 Get() 线程互相覆盖 transaction id 的数据竞争。本修复独立于其他 P0 项，
> 不改变函数签名，不改变 `Add`/`Update`/`Clear`。

**位置：**

- `ppp/app/server/VirtualEthernetNamespaceCache.cpp:156-194`

**优先级：P0**

cache 命中后直接修改共享 response：

```cpp
((dns_hdr*)response.get())->usTransID = trans_id;
```

多个线程/会话同时命中同一个 DNS cache 时，会互相覆盖 transaction id。

**修复建议：**

- cache 中保存 immutable payload。
- 每次 Get 复制一份 response。
- 或只缓存 body，不缓存前 2 字节 transaction id。

---

### 4.4 传输层每包多次分配与拷贝

**位置：**

- `ppp/transmissions/ITransmission.cpp:267-290`
- `ppp/transmissions/ITransmission.cpp:383-414`
- `ppp/transmissions/ITransmission.cpp:563-612`
- `ppp/transmissions/ITransmission.cpp:676-689`

典型写路径中，一个包可能经历：

1. 加密输出分配；
2. base94 输出分配；
3. header + payload 拼接分配；
4. 多次 `memcpy`；
5. `shared_ptr<Byte>` 控制块分配。

**修复建议：**

- 使用 scatter-gather write。
- per-session scratch buffer。
- MTU size slab。
- 减少 `shared_ptr<Byte>`。
- 握手后完全跳过 base94。

示例：

```cpp
std::array<boost::asio::const_buffer, 2> bufs = {
    boost::asio::buffer(header),
    boost::asio::buffer(payload)
};
```

---

### 4.5 DNS redirect 每个查询创建 socket/timer/buffer

**位置：**

- `ppp/app/server/VirtualEthernetExchanger.cpp:802-827`
- `ppp/app/server/VirtualEthernetExchanger.cpp:829-875`
- `ppp/app/server/VirtualEthernetExchanger.cpp:891-917`

每个 DNS redirect 请求都会创建 UDP socket、timer、buffer，并同步 `send_to`。

**修复建议：**

- per-exchanger/per-upstream socket 池；
- `async_send_to`；
- outstanding DNS 请求表；
- timer wheel；
- recv buffer 池；
- 限制 outstanding DNS 数。

---

### 4.6 Firewall 域名匹配每次复制完整规则表

> **✅ P2-12 最小侵入优化已实施 — 2026-05-11**
>
> 已完成以下两项保持匹配语义的热路径优化（详见 `ppp/net/Firewall.cpp`）：
>
> 1. **OPT-P2-12b**：后缀候选拼接从 `next += "." + label`（构造临时
>    `"."` 字符串 + `operator+` 分配）改为 `next += '.'; next.append(label)`
>    （char 追加 + 原地 append，避免构造临时拼接字符串；`next` 自身仍可能按需扩容）。
>
> 2. **OPT-P2-12c**：移除 `next = next.data()` 冗余 C-string → string 赋值
>   （与 `next` 自身内容完全相同，纯浪费）。
>
> **剩余较大优化（后续迭代）：**
> - RCU 规则快照（`std::atomic_load/store` free functions）消除域名表复制。
> - 反向 trie 或 `string_view` 后缀匹配替代线性 suffix walk。
> - 单趟 normalize 替代 `LTrim(RTrim(ToLower(...)))` 三临时串链。
>
> **RCU 设计文档（2026-05-11）：** 完整设计文档已编写：`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`。
> 包含 C++17 RCU 快照方案详设、读写线程安全模型、为何不用 C++20 `atomic<shared_ptr>`、
> 语义保持矩阵、测试/基准计划、五阶段迁移步骤和回滚策略。
> 功能暂不实施，待测试基础设施就绪后启用。
>
> 详见下方原始分析。

**位置：**

- `ppp/net/Firewall.cpp:331-380`
- `ppp/net/Firewall.cpp:389-449`

每次 DNS/domain 查询都会复制规则表，然后进行字符串拆分、trim、后缀拼接和 hash lookup。

**修复建议：**

使用 C++17 RCU 规则快照（基于 `std::atomic_load` / `std::atomic_store` free functions）：

```cpp
std::shared_ptr<const RuleSet> rules_;

// 读取快照
std::shared_ptr<const RuleSet> snapshot = std::atomic_load(&rules_);

// 发布更新
std::atomic_store(&rules_, new_rules);
```

> **注：** C++20 起可迁移为 `std::atomic<std::shared_ptr<const RuleSet>>`，接口更简洁，但当前项目基线为 C++17，须使用上述 free function 形式。

域名匹配改为反向 trie 或 `string_view` 后缀匹配。

---

### 4.7 内存池全局锁 + block 线性扫描

**位置：**

- `ppp/threading/BufferswapAllocator.cpp:120-156`
- `ppp/threading/BufferswapAllocator.cpp:163-180`
- `ppp/threading/BufferblockAllocator.cpp:327-347`

**修复建议：**

- per-thread cache；
- per-io_context cache；
- size-class slab；
- pointer -> block 地址区间索引；
- tcache / lock-free freelist；
- allocator telemetry。

---

## 5. 传输协议风险

### 5.1 传输帧长度缺少策略上限，存在 DoS

> **✅ 已实施长度上限（P0-4A），关闭内存膨胀/超大帧 P0 — 2026-05-10；✅ 补齐内存 base94 路径 — 2026-05-11**
>
> 已在四个解码路径的 payload length 确定后、分配/读取前添加 `PPP_BUFFER_SIZE`
> （65536 字节）上限检查：
>
> - `base94_decode(cfg, allocator, data, datalen, kf, outlen)` — 内存 base94 解码路径
>   （CodeReviewer 指出遗漏，2026-05-11 补齐）
> - `base94_decode(transmission, y, outlen)` — 网络 base94 解码后的 payload_length
> - `Transmission_Packet_Decrypt()` — EVP header 解密后的 payload_len（内存解密路径）
> - `Transmission_Packet_Read()` — EVP header 解密后的 payload_len（网络读取路径）
>
> 超限帧返回 `ProtocolFrameInvalid` 错误并拒绝处理。`payload_length == PPP_BUFFER_SIZE`
> 仍为合法值（严格大于才拒绝）。
>
> **P0 仅要求帧长度上限，已完成。** Per-frame 读取超时已降级为 P1 后续治理项
> （见 §8 P1、§12 第二批），需要设计 Boost.Asio deadline_timer/cancellation 与
> async_read 的集成，并通过异步 IO 测试验证生命周期安全性，不在 P0 范围。
> ITcpipTransmission 和 WebSocket 路径的长度限制需后续评估。
>
> **设计文档（2026-05-11）：** 完整设计/治理文档已编写：`docs/PER_FRAME_READ_TIMEOUT_DESIGN.md`（英文）、
> `docs/PER_FRAME_READ_TIMEOUT_DESIGN_CN.md`（中文）。包含 Boost.Asio timer/cancellation 生命周期、
> 三条读取路径（TCP/WS/WSS）的风险分析、QoS 交互设计、配置模式、测试要求和实施检查清单。
> 治理决策记录见 `docs/p1-governance-decisions-cn.md` P1-1。功能暂不实施，待测试基础设施和平台验证后启用。

**位置：**

- `ppp/transmissions/ITransmission.cpp:914-920`
- `ppp/transmissions/ITransmission.cpp:529-537`
- `ppp/transmissions/ITcpipTransmission.cpp:163-174`
- `ppp/transmissions/templates/WebSocket.h:238-258`

读包逻辑根据包头长度直接分配：

```cpp
auto payload = ReadBytes(transmission, y, payload_len);
```

底层：

```cpp
MakeByteArray(allocator, length);
async_read(... length ...);
```

缺少握手前最大长度、握手后最大数据帧、控制帧最大长度和 per-frame read timeout。
> **状态更新（2026-05-11）：** 绝对帧长度上限已通过 `PPP_BUFFER_SIZE` 实施（P0 ✅）。
> 多级上限（pre-handshake / control / data）和 per-frame read deadline 列为 P1 后续优化。

**修复建议：**

设置多级上限：

```text
pre-handshake max frame: 4KB
control frame max: 8KB
absolute max: configurable but capped
```

并添加 per-frame read deadline。

---

### 5.2 WebSocket 握手角色疑似反置

**位置：**

- `ppp/transmissions/templates/WebSocket.h:103-116`
- `ppp/transmissions/templates/WebSocket.h:204-208`
- `ppp/transmissions/IWebsocketTransmission.cpp:96`
- `ppp/transmissions/IWebsocketTransmission.cpp:206`

`HandshakeClient()` 传入 false，最终使用 `HandshakeType_Server`；`HandshakeServer()` 传入 true，最终使用 `HandshakeType_Client`。

**修复建议：**

明确两层语义：

- WebSocket 层：TCP 主动连接方是 client。
- PPP 层：session_id 交换方向是 client/server。

并增加 TCP、WS、WSS、mux、proxy、client/server 双端集成测试。

---

### 5.3 WebSocket / TCP socket 成员并发访问存在竞态

**位置：**

- `ppp/transmissions/templates/WebSocket.h:125-171`
- `ppp/transmissions/ITcpipTransmission.cpp:54-66`
- `ppp/transmissions/ITcpipTransmission.cpp:153-174`
- `ppp/transmissions/ITcpipTransmission.cpp:195-245`

`socket_` 是普通 `shared_ptr` 成员。读写路径复制，Finalize 路径 move，可能并发读写 shared_ptr 成员本身。

**修复建议：**

- socket 访问统一放 strand；
- 或 mutex/atomic shared_ptr；
- Finalize one-shot；
- ShiftToScheduler 期间禁止并发读写。

> **✅ 已修复（WebSocket disposed_ one-shot）— 2026-05-11**
>
> 修复方案：
> - `WebSocket::disposed_` 从 `bool` 改为 `std::atomic_bool disposed_{false}`；
> - `Finalize()` 开头使用 `disposed_.exchange(true, std::memory_order_acq_rel)` 实现 one-shot；
> - 所有读路径统一为 `disposed_.load(std::memory_order_acquire)` 显式 acquire load（风格/审计一致性治理，非 P0 阻断）；
> - socket_ shared_ptr 并发保护见下方 §5.3 socket_ 部分。

> **✅ 已修复（socket_ shared_ptr 并发保护）— 2026-05-11**
>
> 修复方案（C++17 `std::atomic_load`/`std::atomic_store` free functions）：
> - WebSocket.h：所有 `socket_` 读取改为 `std::atomic_load(&socket_)`，
>   构造器写入改为 `std::atomic_store(&socket_, ...)`，Finalize 移出改为
>   `std::atomic_load` + `std::atomic_store(&socket_, {})`。
> - ITcpipTransmission.cpp：同样模式应用于 ReadBytes / DoWriteBytes /
>   ShiftToScheduler / Finalize 路径。
> - 不改变 public API，不使用 C++20 `std::atomic<std::shared_ptr<T>>`。
> - `GetSocket()` 也使用 `std::atomic_load`。
> - 性能影响：`std::atomic_load/store(shared_ptr*)` 在主流实现中使用全局
>   spinlock，对 WebSocket/TCP 高频读路径有微小开销；可接受为安全性让步。

---

### 5.4 server `VirtualEthernetExchanger::Finalize()` 非原子 one-shot

**位置：**

- `ppp/app/server/VirtualEthernetExchanger.cpp:173-247`

问题代码：

```cpp
if (disposed_) return;
disposed_ = true;
```

`disposed_` 是普通 bool，且无锁。

**修复建议：**

```cpp
if (disposed_.exchange(true)) {
    return;
}
```

并将 map 资源 move 到局部后锁外释放。

> **✅ 已修复（P0-6A，exchanger disposed_ 原子化）— 2026-05-11**
>
> 修复方案：
> - `bool disposed_` → `std::atomic_bool disposed_{false}`；
> - `Finalize()` 开头使用 `disposed_.exchange(true, std::memory_order_acq_rel)` 实现 one-shot；
> - `IsDisposed()` 改为 `disposed_.load(std::memory_order_acquire)`；
> - 所有 `if (disposed_)` 读取通过 `std::atomic_bool::operator bool()` 隐式 load（seq_cst）；
> - 构造函数移除 `disposed_(false)` 初始化（使用类内默认值）。
> - 不改变 Finalize 的 map-move-to-local 锁外释放语义（已由前序重构实现）。

---

### 5.5 endpoint wire format 1 字节 host 长度可能截断

**位置：**

- `ppp/app/protocol/VirtualEthernetLinklayer.cpp:372-383`
- `ppp/app/protocol/VirtualEthernetLinklayer.cpp:103-140`

问题代码：

```cpp
stream.WriteByte(static_cast<Byte>(address_string.size()));
stream.Write(address_string.data(), 0, address_string.size());
```

若 hostname 长度 > 255，长度字段截断，但完整字符串仍被写入，导致解码端错帧。

**修复建议：**

```cpp
if (address_string.size() > 255) {
    return ProtocolFrameInvalid;
}
```

更优方案是升级为 2 字节长度字段，但需要版本协商。

---

### 5.6 `VirtualEthernetPacket::UnpackBy()` 缺少 `header_length <= packet_length`

**位置：**

- `ppp/app/protocol/VirtualEthernetPacket.cpp:233-238`
- `ppp/app/protocol/VirtualEthernetPacket.cpp:272-291`

只检查：

```cpp
header_length >= sizeof(PACKET_HEADER)
```

未检查：

```cpp
header_length <= packet_length
```

**修复建议：**

```cpp
if (header_length > packet_length) {
    return ProtocolFrameInvalid;
}
```

同时 `MemoryStream::Write()` 对负 length 也应防御。

---

## 6. 架构与可维护性问题

### 6.1 `ppp/stdafx.h` 是超级头文件

**位置：**

- `ppp/stdafx.h:1-2228`

`stdafx.h` 混合了平台宏、编译器宏、Boost/Asio/Beast、默认配置、DNS 列表、类型工具、日志宏、第三方库 hack、自定义 STL traits。

**修复建议：**

拆分为：

```text
ppp/base/Platform.h
ppp/base/Compiler.h
ppp/base/Constants.h
ppp/base/Types.h
ppp/base/Log.h
ppp/third_party/BoostCompat.h
ppp/base/StringConvert.h
```

---

### 6.2 伪造 Boost.Beast 版本宏

**位置：**

- `ppp/stdafx.h:272-284`

问题代码：

```cpp
#ifndef BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION 322
#define BOOST_BEAST_VERSION_STRING "ppp"
#endif
```

这会欺骗预处理器，阻止真实 Boost.Beast 版本头正常展开。同时 `BOOST_BEAST_VERSION_STRING` 又被用作默认密钥。

**修复建议：**

- 删除这段伪造宏。
- 使用项目自有版本宏：`PPP_BUILD_VERSION_STRING`。

---

### 6.3 默认 DNS 列表缺逗号导致字符串拼接

**位置：**

- `ppp/stdafx.h:372-462`

**问题：**

```cpp
"120.53.53.53"          // ← 原文末尾无逗号

PPP_PREFERRED_DNS_SERVER_1,   // 宏展开为 "8.8.8.8"
```

C/C++ 隐式相邻字符串拼接会将两个条目合并为 `"120.53.53.538.8.8.8"`，导致该条目成为非法 IP，且数组总元素少一个。

> **✅ 已修复（P2-3）— 2026-05-11**

**修复内容：**

1. 在 `"120.53.53.53"` 末尾补齐逗号，消除隐式字符串拼接。
2. 在数组前后增加 `// ---- PPP_PUBLIC_DNS_SERVER_LIST begins/ends ----` 边界注释，明确标注宏展开条目的逗号分隔要求。
3. 已逐项审查全部 56 个条目（含 2 个 `#define` 宏展开项），确认修复后每个条目均以逗号正确分隔。

**后续建议（可选，不阻断）：**

- ✅ 已实现轻量编译期防护：在数组末尾增加 `static_assert` 固定元素计数为 56，任何隐式字符串拼接导致的条目减少都会在编译期报错。修改列表时需同步更新断言中的数字。
- ✅ 已提供只读脚本 `scripts/check-dns-ipv4.py`，可逐项校验每个条目的 IPv4 格式（含宏展开解析）。脚本不接入 CI、不改构建、不依赖网络，仅作为开发者本地手动校验工具。
- 未接入 CI 自动门控（当前 56 条人工可控，无需构建阻断）。参见 [`dns-server-list-governance-cn.md`](dns-server-list-governance-cn.md) §4 了解脚本用法与互补策略。

---

### 6.4 `AppConfiguration` 职责过重

**位置：**

- `ppp/configurations/AppConfiguration.h`
- `ppp/configurations/AppConfiguration.cpp`

一个类同时负责默认值、JSON 解析、校验、平台能力判断、字段归一化、派生值计算、序列化。

**修复建议：**

拆分：

```cpp
AppConfigurationParser
AppConfigurationValidator
AppConfigurationNormalizer
AppConfigurationSerializer
PlatformCapabilities
```

---

### 6.5 平台条件编译严重内联在业务逻辑中

**位置：**

- `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- `ppp/app/ApplicationInitialize.cpp`
- `ppp/configurations/AppConfiguration.cpp`

**修复建议：**

抽象平台策略接口：

```cpp
RouteManager
DnsConfigurator
TapAdapter
FirewallManager
NetworkProtectionBackend
```

按平台实现：

```text
platform/windows/WindowsRouteManager.cpp
platform/linux/LinuxRouteManager.cpp
platform/macos/MacOSRouteManager.cpp
platform/android/AndroidNetworkBackend.cpp
```

---

## 7. 构建、依赖与供应链风险

### 7.1 Android OpenSSL 1.1.1i 过旧

**位置：**

- `build-android-local.sh`
- `.github/workflows/build-android.yml`

OpenSSL 1.1.1 系列已停止常规支持，1.1.1i 更早。

**修复建议：**

- 升级 OpenSSL 3.0 LTS / 3.2 / 3.3。
- 或使用 BoringSSL / 系统 Conscrypt。
- 固定版本和 hash。

---

### 7.2 Android NDK r20b 过旧

**位置：**

- `build-android-local.sh`
- `.github/workflows/build-android.yml`

**修复建议：**

升级到当前受支持 NDK。

---

### 7.3 第三方依赖硬编码路径

**位置：**

- `CMakeLists.txt`
- `android/CMakeLists.txt`
- `build-openppp2-by-cross.sh`
- `build-android-local.sh`

默认路径如：

```text
/root/dev
/root/android
/tmp/ndk
E:\Dev\...
```

**风险：**

- 构建不可复现。
- 本机目录污染可引入恶意库。
- CI/开发环境不一致。

**修复建议：**

- CMake Presets。
- vcpkg manifest。
- FetchContent。
- 明确版本和 hash。
- 不允许默认 `/root`、`/tmp`。

---

### 7.4 编译警告大量被压制

**位置：**

- `CMakeLists.txt`
- `android/CMakeLists.txt`
- `ppp.vcxproj`

包括：

```text
-Wno-format
-Wno-implicit-function-declaration
-Wno-null-dereference
-Wno-deprecated-declarations
_CRT_SECURE_NO_WARNINGS
```

**修复建议：**

- 逐步打开 `-Wall -Wextra -Wformat=2`。
- 安全构建使用 `-Werror`。
- warning suppression 按文件局部化。

---

### 7.5 存在 `-fno-stack-protector` 路径

**位置：**

- `CMakeLists.txt`
- `android/CMakeLists.txt`

**修复建议：**

删除 `-fno-stack-protector`，Release 默认：

```text
-fstack-protector-strong
-D_FORTIFY_SOURCE=2/3
-fPIE -pie
-Wl,-z,relro,-z,now
```

---

### 7.6 CI 缺少测试、安全扫描和 hardening 验证

缺失：

- C++ 单元测试；
- ctest；
- clang-tidy；
- cppcheck；
- CodeQL；
- govulncheck；
- npm audit；
- OSV scanner；
- Dependabot；
- SBOM；
- checksec/readelf；
- release artifact 签名。

**修复建议：**

引入：

```text
CodeQL
Dependabot
OSV-Scanner
Syft SBOM
Trivy
govulncheck
npm audit
clang-tidy
cppcheck
checksec
cosign / minisign / GPG signing
```

---

### 7.7 Android GeoIP/GeoSite 二进制规则文件直接提交仓库

**位置：**

- `android/android/app/src/main/assets/rules/geoip.dat`（~19.3 MB）
- `android/android/app/src/main/assets/rules/geosite.dat`（~4.2 MB）

**风险：**

- 仓库体积膨胀约 23 MB；每次更新产生大 binary diff。
- 来源为 MetaCubeX/meta-rules-dat（聚合 MaxMind GeoLite2 CC BY-SA 4.0 + v2ray/domain-list-community MIT），**聚合产物的再分发许可尚未独立确认**。
- 无版本标注、无更新策略、无生成记录。

**已采取措施：**

- 添加 `android/android/app/src/main/assets/rules/README.md`：说明用途、文件、来源、许可证风险、更新流程。
- 添加根 `.gitattributes`：将 `*.dat` 标记为 `binary`，抑制文本 diff 噪音。

> **✅ 治理文档已强化（2026-05-11）；分发策略已由维护者确认为非阻断（2026-05-11）**
>
> 补充措施：
> - `README.md` 说明用途、文件、来源、许可证风险、更新流程。
> - 审计文档明确"不删除 .dat、不破坏 Android 运行时资产需求"的前提下，将治理推进到更稳妥状态。
> - .dat 文件保留在仓库中以维持 Android 构建完整性。
>
> **维护者确认：GeoIP/GeoSite 规则文件可以分发，不作为 release 阻断项。**

**后续建议（非阻断）：**

1. 维护者建议确认 MetaCubeX/meta-rules-dat 聚合产物的许可兼容性，或取得上游明确授权。
2. 每次 .dat 更新建议在 commit message 中注明上游版本和下载日期。
3. 仓库体积优化可考虑 Git LFS 或构建时下载，但不阻断当前发布。

---

## 8. 优先级修复建议

### P0：必须立即处理

1. ~~TLS/WSS 开启证书链校验与主机名校验，禁止生产路径默认关闭校验。~~ → **✅ 已修复：WSS 后端默认 `verify_peer=true`；`SslSocket` 通过 `SSL_set1_host()` 设置主机名校验（见 §3.2、§3.3）。**
2. ~~禁止生产默认弱 key、固定 key 和 plaintext。~~ → **已调整为：检测并高亮提示弱 key/plaintext；不阻断启动（见 §3.5 状态更新）。**
3. ~~写队列加背压。~~ → **✅ 已实施：pending_items/pending_bytes + 阈值拒绝（见 §4.1 状态更新）。**
4. ~~传输帧加最大长度与超时。~~ → **✅ 已实施长度上限（PPP_BUFFER_SIZE 65536 字节），P0 帧长度上限已完成；per-frame 读取超时降级为 P1（见 P1 新增第 10 项）。**
5. ~~修复 DNS cache transaction id 并发覆盖。~~ → **✅ 已修复：copy-on-read（见 §4.3 状态更新）。**
6. ~~修复主要 Dispose/Finalize one-shot。~~ → **⚠️ 核心传输/写队列/Exchanger(server+client)/WebSocket/socket_ 已修复，全仓治理仍需分级复核（见 §15）。**

> 复核调整：`starrylink.net.key` / `starrylink.net.pem` 经维护者说明属于示例资产，在无证据表明其仍用于生产服务时，不列入 P0 生产密钥泄露。

### P1：短期重要优化

1. ~~CI/release 禁止默认打包示例私钥、示例证书和含固定凭据的根目录 `appsettings.json`；改为发布 `appsettings.example.json` 或最小安全模板。~~ → **维护者确认示例文件可以分发，不作为 release 阻断项（见 §3.1）。建议启动时检测示例 key/cert 时输出醒目 warning。**
2. 为示例证书、示例私钥、示例配置增加启动告警（已部分实施，见 §3.5）。
3. AEAD 加密迁移。
4. 禁用 RC4/MD5 KDF。
5. DNS redirect socket/timer 池化。
6. Firewall 匹配优化。**RCU 设计文档已完成（2026-05-11）**：`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`；最小侵入优化已实施（§4.6 OPT-P2-12b/c），RCU 快照 + trie 后缀匹配待测试基础设施就绪后实施。
7. Android 依赖升级。
8. 消除 `system()` / `popen()` shell 命令执行路径。**治理设计文档已完成（2026-05-12）：** `docs/SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md`；治理决策 `docs/p1-governance-decisions-cn.md` P1-8。后续 TapLinux pilot 优先选择 cleaner withdrawal 边界（`DeleteRoute6`/`DeleteIPv6NeighborProxy`/`DisableIPv6NeighborProxy`/`DeleteIPv6Address`），而非 route-add 边界。
9. 增加 CodeQL / govulncheck / npm audit / OSV。
10. Per-frame 读取超时（慢读 DoS 加固）：需设计 Boost.Asio deadline_timer/cancellation 与 async_read 集成，覆盖 ITransmission / ITcpipTransmission / WebSocket 路径，通过异步 IO 测试验证 timer 生命周期安全性（见 §5.1）。**设计文档已完成（2026-05-11）：** `docs/PER_FRAME_READ_TIMEOUT_DESIGN.md` / `docs/PER_FRAME_READ_TIMEOUT_DESIGN_CN.md`；治理决策 `docs/p1-governance-decisions-cn.md` P1-1。

### P2：中期架构改善

1. 拆 `stdafx.h`。
2. 重构 `AppConfiguration`。
3. 平台策略接口化。
4. 引入 Result/ErrorEvent。
5. 增加 C++ 单元测试/fuzz。
6. 建立 SBOM、artifact 签名和 hardening 检查。
7. 改造内存池为 per-thread/per-context cache。
8. 为 route / DNS / lease 建立索引和时间轮。

---

## 9. 实施示例

### 9.1 写队列背压示例

```cpp
struct QueueLimits {
    size_t max_items = 4096;
    size_t max_bytes = 16 * 1024 * 1024;
};

bool IAsynchronousWriteIoQueue::CanEnqueue(size_t bytes) const noexcept {
    return pending_items_ < limits_.max_items &&
           pending_bytes_ + bytes <= limits_.max_bytes;
}
```

写入时：

```cpp
if (!CanEnqueue(packet_length)) {
    diagnostics::SetLastErrorCode(ErrorCode::AsyncWriteQueueBackpressure);
    return false;
}

pending_items_++;
pending_bytes_ += packet_length;
```

完成后扣减：

```cpp
pending_items_--;
pending_bytes_ -= context->packet_length;
```

---

### 9.2 TLS 主机名校验示例

> **已实施方案：** 由于 `SslSocket` 模板通过 `GetSslHandle()` 访问原生 SSL 句柄，
> 使用 `SSL_set1_host()`（OpenSSL ≥ 1.0.2 / BoringSSL）在 TLS 层设置主机名校验，
> 与 `CreateClientSslContext()` 中的 `set_verify_mode(verify_peer)` 配合使用。

```cpp
if (verify_peer_) {
    if (host_.empty()) {
        diagnostics::SetLastErrorCode(ErrorCode::SslWebSocketRunInvalidHostOrPath);
        return false;
    }

    // OpenSSL ≥ 1.0.2 / BoringSSL: sets expected hostname for certificate verification.
    // Works with the verify_peer mode set by CreateClientSslContext().
    if (!SSL_set1_host(GetSslHandle(), host_.data())) {
        return false;
    }
}
```

替代方案（`boost::asio::ssl::host_name_verification`）需要直接访问 `ssl::stream` 对象：

```cpp
if (verify_peer_ && !host_.empty()) {
    ssl_socket_->next_layer().set_verify_callback(
        boost::asio::ssl::host_name_verification(host_)
    );
}
```

---

### 9.3 Dispose one-shot 示例

```cpp
class Disposable {
private:
    std::atomic_bool finalized_{false};

public:
    void Finalize() noexcept {
        if (finalized_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        auto socket = std::move(socket_);
        auto timer = std::move(timer_);

        Close(socket);
        Cancel(timer);
    }
};
```

---

### 9.4 传输帧长度限制示例

```cpp
static constexpr int MAX_HANDSHAKE_FRAME = 4 * 1024;
static constexpr int MAX_CONTROL_FRAME   = 8 * 1024;
static constexpr int MAX_DATA_FRAME      = PPP_BUFFER_SIZE;

bool ValidateFrameLength(int len, FramePhase phase) noexcept {
    if (len <= 0) return false;

    switch (phase) {
        case FramePhase::Handshake:
            return len <= MAX_HANDSHAKE_FRAME;
        case FramePhase::Control:
            return len <= MAX_CONTROL_FRAME;
        case FramePhase::Data:
            return len <= MAX_DATA_FRAME;
    }

    return false;
}
```

---

### 9.5 DNS cache 修复示例

```cpp
std::shared_ptr<Byte> CloneDnsResponseWithId(
    const std::shared_ptr<const Byte>& cached,
    int len,
    uint16_t trans_id,
    const AllocatorPtr& allocator)
{
    auto out = BufferswapAllocator::MakeByteArray(allocator, len);
    if (!out) return nullptr;

    memcpy(out.get(), cached.get(), len);
    reinterpret_cast<dns_hdr*>(out.get())->usTransID = trans_id;
    return out;
}
```

---

## 10. 建议新增测试矩阵

### P0：安全/协议边界测试

1. 传输帧 fuzz：
   - length = 0；
   - length = 1；
   - length = 65535；
   - header_length > packet_length；
   - base94 header 错位；
   - 握手前非法帧。

2. 握手状态机：
   - TCP；
   - WS；
   - WSS；
   - mux；
   - proxy；
   - client/server 角色校验。

3. DNS cache 并发：
   - 多线程命中同一 record；
   - transaction id 不串扰。

4. Dispose 幂等：
   - read fail + write fail + timer timeout 同时发生；
   - 多次 Dispose；
   - 析构时未显式 Dispose。

### P1：配置测试

1. 空配置。
2. 默认 key。
3. 弱密码。
4. 端口越界。
5. IPv6 mode。
6. DNS server object/array/string。
7. websocket path。
8. certificate key missing。
9. plaintext 默认值。
10. `key.kl/key.kh` 越界。

### P2：性能基准

1. 小 UDP 包 PPS。
2. TCP tunnel throughput。
3. DNS redirect QPS。
4. Firewall domain rule 大规则集。
5. memory allocator lock wait。
6. write queue depth under slow peer。
7. Android DNS/timer teardown 压测。

---

## 11. 预期收益

### 性能收益

- 写队列不再无限膨胀。
- 慢连接不会拖垮进程。
- DNS 高 QPS 成本显著下降。
- 小包高 PPS 场景分配/拷贝减少。
- Firewall 大规则集匹配延迟下降。
- IPv6/lease/session 扩展性提升。
- 尾延迟降低。

### 安全收益

- 示例文件已确认可以分发；启动时检测到示例 key/cert/password 时输出醒目 warning。
- TLS MITM 风险大幅降低。
- 默认配置从"不安全可启动"变成"带醒目 warning 的可启动配置"；弱 key/plaintext 不拒绝启动，仅输出高亮告警提示。
- 弱加密和无认证加密逐步退出。
- 命令注入面收窄。
- 供应链风险可观测、可追踪。

### 可维护性收益

- 平台代码隔离。
- 配置解析可测试。
- 错误信息更可定位。
- `stdafx.h` 不再成为全局耦合点。
- Dispose 生命周期更一致。
- CI 可防止回归。

### 用户体验收益

- 连接失败原因更明确。
- DNS 响应更稳定。
- Android teardown 崩溃概率降低。
- 高并发下更不容易卡死/OOM。
- TLS/WSS 安全预期更符合用户直觉。

---

## 12. 最终执行顺序建议

### 第一批：立即修

1. ~~TLS/WSS 开启证书链校验与主机名校验。~~ → ✅ 已修复：WSS 后端默认 `verify_peer=true`；`SslSocket` 通过 `SSL_set1_host()` 设置主机名校验（见 §3.2、§3.3）。
2. ~~禁止生产默认弱 key、固定 key 和 plaintext。~~ → 已调整为：检测并高亮提示弱 key/plaintext；不阻断启动（见 §3.5）。
3. ~~写队列加背压。~~ → ✅ 已实施（见 §4.1）。
4. ~~传输帧加最大长度与超时。~~ → ✅ 已实施长度上限（PPP_BUFFER_SIZE），P0 帧长度上限完成；读取超时降级为 P1（见 §8 P1 第 10 项）。
5. ~~修复 DNS cache transaction id 并发覆盖。~~ → ✅ 已修复（见 §4.3）。
6. ~~修复主要 Dispose/Finalize one-shot。~~ → ⚠️ 核心传输/写队列/Exchanger(server+client)/WebSocket/socket_ 已修复，全仓治理仍需分级复核（见 §15）。

### 第二批：短期修

1. ~~CI/release 排除示例私钥、示例证书和含固定凭据的完整配置，改为发布安全模板。~~ → 维护者确认示例文件可以分发（见 §3.1）；建议启动时检测示例 key/cert 时输出醒目 warning。
2. 对示例 key/cert/password 增加启动告警（已部分实施，见 §3.5）。
3. AEAD 加密迁移。
4. 禁用 RC4/MD5 KDF。
5. DNS redirect socket/timer 池化。
6. Firewall 匹配优化。**RCU 设计文档已完成（2026-05-11）**（见 `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`）；最小侵入优化已实施（§4.6 OPT-P2-12b/c）。
7. Android 依赖升级。
8. 消除 `system()` shell 拼接。
9. 增加 CodeQL / govulncheck / npm audit / OSV。
10. Per-frame 读取超时（慢读 DoS 加固）：Boost.Asio deadline_timer/cancellation 集成，覆盖全部异步读路径（见 §5.1、§8 P1 第 10 项）。**设计文档已完成（2026-05-11）**（见 `docs/PER_FRAME_READ_TIMEOUT_DESIGN.md`）。

### 第三批：中期重构

1. 拆 `stdafx.h`。
2. 重构 `AppConfiguration`。
3. 平台策略接口化。
4. 引入 Result/ErrorEvent。
5. 增加 C++ 单元测试/fuzz。
6. 建立 SBOM、artifact 签名和 hardening 检查。

---

## 13. 附：本次 subagent 结果状态

- 安全审计：完成。
- 构建/依赖/供应链审计：完成。
- 性能与架构审计：补跑完成。
- 传输协议/握手/边界审计：补跑完成。
- 代码质量与可维护性审计：补跑完成。
- 原始并行中的一个高阶模型不可用，另一个返回为空，已用可用 subagent 补审。

---

## 14. 续审（2026-05-09）：未推送提交与工作区修改

> 本节专门审核 §1–§13 之后产生的增量修改，聚焦于 Android 稳定性修复、TLS 握手并发安全、传输层原子化、DNS 异步生命周期统一这四条主线。
> 与首版重叠的发现（如默认密钥、写队列背压、`stdafx.h` 拆分）不再重复，仅在本节末以"与首版关联"小节做交叉指引。

### 14.1 续审范围

| 项目 | 内容 |
|---|---|
| **未推送提交** | `ed61d5b`（Timer SetTimeout 句柄局部移动）、`d483885`（DNS IPFrame 跨异步调用保活） |
| **未提交工作区** | 7 个文件 / 约 1500 行差异 |
| **核心模块** | `ppp/threading/Timer.cpp`、`ppp/dns/DnsResolver.cpp`、`ppp/ssl/SSL.cpp`、`ppp/transmissions/ITransmission.{h,cpp}`、`ppp/app/client/VEthernetNetworkSwitcher.cpp`、`android/CMakeLists.txt` |

### 14.2 已提交但未推送的修复

#### 14.2.1 `ed61d5b` — Timer SetTimeout 用户句柄局部移动

**位置：** `ppp/threading/Timer.cpp:366`

将 `t->TickEvent` 内部 lambda 改为 `mutable noexcept`，先 `sender->Dispose()`，再把 `handler` 移到栈局部 `local`，最后 `local(sender)`。本意是让用户 lambda 中的 `shared_ptr` capture 在 **当前栈帧** 析构，而不是被延迟到外层 `Callable<outer-lambda>` 的析构链中累积栈深度，触发 Android 内核栈守护页（`SI_KERNEL`）。

**评估：**

- 修复方向正确：把析构成本从延迟链摊到本帧。
- 但仍依赖"所有 capture 在本帧析构能成功"，若用户 lambda 自己又 capture 了多层 `shared_ptr<Timer>`，仍可能产生递归。
- 与 §14.3.1 的 `-DFUNCTION` 一起部署后，整体回溯路径已显著变浅。

#### 14.2.2 `d483885` — DnsResolver 异步链中保活 `IPFrame`

**位置：** `ppp/app/client/VEthernetNetworkSwitcher.cpp:3550-3733`

为四个 `ResolveAsync*` lambda 与 `YieldContext::Spawn` 的协程额外捕获 `packet`（`(void)packet` 抑制 `-Wunused-lambda-capture`），保证 `IPFrame` 生命周期跨越所有异步阶段。

**评估：**

- 之前仅捕获 `frame`/`messages` 的 `BufferSegment` 视图，但底层 `IPFrame` 已在 `PacketInput` 返回时释放，触发 `~IPFrame()` 与正在执行的 DnsResolver 异步操作竞争。
- 修复以最小代价（5 行 capture）解决 `SIGSEGV / SI_KERNEL` ~8 秒崩溃，是典型的 **upstream-minimal-fix**，符合 bug 修复纪律。

### 14.3 工作区未提交大改动综览

| 文件 | 行数变化 | 主题 |
|---|---|---|
| `ppp/dns/DnsResolver.cpp` | +650 / −340 | `CompletionState` / `StunCompletionState` 集中所有权重写 DoH/DoT/UDP/TCP/STUN 异步链 |
| `ppp/transmissions/ITransmission.h` | +160 / −180 | `unsigned int : N` bitfield → 4×`std::atomic_bool` |
| `ppp/transmissions/ITransmission.cpp` | +80 / −60 | 配套 `.load(acquire)` / `.store(release)`、`std::atomic_load/store` 包裹 cipher `shared_ptr` |
| `ppp/ssl/SSL.cpp` | +130 / −60 | 客户端 SSL 上下文创建加进程级互斥、Android 跳过 `set_default_verify_paths`、删除 `"DEFAULT"` cipher 调用、握手前预排序 X509_STORE |
| `ppp/threading/Timer.cpp` | +20 / −80 | 撤销旧的"两段式延迟析构"，依赖 Android `-DFUNCTION` 切换为 `std::function` |
| `ppp/app/client/VEthernetNetworkSwitcher.cpp` | +18 / −6 | 在 ICMP echo 处理前过滤掉非 `ICMP_ECHO/ICMP_ER` 类型 |
| `android/CMakeLists.txt` | +1 | `ADD_DEFINITIONS(-DFUNCTION)` |

### 14.4 关键性能问题

#### **P-1：Android 跳过 TLS 会话缓存**

**位置：** `ppp/dns/DnsResolver.cpp:669-697`

```cpp
ssl_session_st* DnsResolver::AcquireTlsSession(const ppp::string& host_key) noexcept {
#if defined(__ANDROID__)
    (void)host_key;
    return NULLPTR;
#endif
    // ...
}
void DnsResolver::StoreTlsSession(const ppp::string& host_key, ssl_session_st* session) noexcept {
#if defined(__ANDROID__)
    (void)host_key;
    if (session != NULLPTR) {
        SSL_SESSION_free(reinterpret_cast<SSL_SESSION*>(session));
    }
    return;
#endif
    // ...
}
```

**影响：** 每次 DoH/DoT 查询都做完整 TLS 握手（1.5–2 RTT + ECDHE）。移动端 CPU 弱、RTT 高，影响最大化。

**修复建议：**

1. 定位真正的根因（疑为 BoringSSL session cache 在并发握手时崩溃）。
2. 过渡期使用进程内 LRU + `std::mutex` 保护，而非整体禁用。

**📋 2026-05-11 复核状态：** 在当前可用 git 历史/refs 中，未发现审计描述的 `#if defined(__ANDROID__)` 禁用守卫；`git log --all -S "__ANDROID__" -- ppp/dns/DnsResolver.cpp` 无匹配。TLS session cache 在当前可见历史中自引入之日起（commit `a35bb74`）即在所有平台生效，commit `ab00160` 已对其进行了重大加固（LRU 驱逐、`CompletionState` 集中资源所有权、`SSL_SESSION_up_ref` 生命周期修正）。从静态代码审查看，线程安全与引用计数模型未发现明显问题，但仍需 Android/BoringSSL 真机、sanitizer 与 telemetry 验证。

**📋 详细设计文档：`docs/ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md`** — 涵盖代码考古、当前实现分析、加固方案（session TTL / telemetry 增强 / 连接复用）、安全边界、验证矩阵。治理记录：`docs/p2-governance-decisions-cn.md` P2-19。

#### **P-2：客户端 SSL_CTX 创建被全局锁串行化**

**位置：** `ppp/ssl/SSL.cpp:224-230`（`CreateClientSslContext`）

**📋 当前状态：核心修复已完成（2026-05-11 复核）**

原始代码使用 `std::mutex` 覆盖整个 `CreateClientSslContext`，包括 CA 加载、cipher 配置等磁盘 I/O 和 CPU 密集操作。当前代码已替换为 `std::once_flag` + `std::call_once`，仅保护一次性全局 OpenSSL/BoringSSL 初始化：

```cpp
// 当前代码（SSL.cpp:224-230）—— 已修复
static std::once_flag s_ssl_ctx_init_once;
std::call_once(s_ssl_ctx_init_once, []() noexcept {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx != NULLPTR) {
        SSL_CTX_free(ctx);
    }
});
// 此后 CA 加载、cipher 配置、verify_peer、X509 排序均在锁外并发执行
```

**影响：** 一次性 warmup 仅阻塞首次调用（约 1-5ms），后续调用不再被 openppp2 自己的全局 mutex 串行化。DoH/DoT 高并发场景不再因该 mutex 退化为串行，但仍存在每次创建 `SSL_CTX`、CA 加载、OpenSSL/BoringSSL 内部锁与 `X509_STORE` 排序等需验证/可优化成本。

**剩余优化项：** DoH/DoT 每次查询仍创建新 SSL_CTX（含完整 CA 加载和 store 排序）。SSL_CTX 复用可进一步降低开销，需在具备集成测试和性能基准后评估。

**📋 详细设计文档：`docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`**

### 14.5 关键安全问题

#### **S-1：Android 上禁用 `set_default_verify_paths()` 但缺少替代 CA 来源**

**位置：** `ppp/ssl/SSL.cpp:175-177`、`ppp/ssl/SSL.cpp:247-250`

```cpp
#if !defined(__ANDROID__)
    ssl_context->set_default_verify_paths();
#endif
```

**风险等级：高**（前提：`verify_peer == true`）

Android 上没有等价 CA 加载路径。若上游配置了 `verify_peer = true`：

- 严格情况下握手会因找不到根证书而失败；
- 宽松情况下可能被错误地静默通过。

**修复示例：**

```cpp
#if defined(__ANDROID__)
    const auto& ca = ppp::configurations::GetAndroidCaBundlePath();
    if (!ca.empty()) {
        boost::system::error_code ec;
        ssl_context->load_verify_file(ca, ec);
        if (ec) {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::SslInternalError);
            return NULLPTR;
        }
    }
#else
    ssl_context->set_default_verify_paths();
#endif
```

可通过 JNI 从 `AndroidCAStore` 导出系统根，或在 APK 内置 Mozilla CA bundle，启动时拷贝到 `filesDir` 并在配置中传入路径。

#### **S-2：`SSL_CTX_set_cipher_list(ctx, "DEFAULT")` 被彻底删除**

**位置：** `ppp/ssl/SSL.cpp:188-200`、`ppp/ssl/SSL.cpp:253-264`

**风险等级：低**

BoringSSL 不识别字符串 `"DEFAULT"`，会清空 cipher list 并触发 `ssl_cipher_ptr_id_cmp` 崩溃。删除是必要的；但 OpenSSL 用户可能希望显式排除弱套件。

**修复建议：** 按密码学库分支：

```cpp
#if defined(OPENSSL_IS_BORINGSSL)
    // BoringSSL 内置默认列表已足够安全
#else
    SSL_CTX_set_cipher_list(ssl_context->native_handle(),
        "HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES:!3DES:!EXPORT");
#endif
```

### 14.6 加固建议

#### **S-3：`CompletionState::slot0..slot3` 类型擦除**

**位置：** `ppp/dns/DnsResolver.cpp:64-67`

```cpp
std::shared_ptr<void> slot0;
std::shared_ptr<void> slot1;
std::shared_ptr<void> slot2;
std::shared_ptr<void> slot3;
```

**隐患：** `std::static_pointer_cast<T>` 失去编译期类型校验。后续若调整槽位顺序，会无声地把指针解释为错误类型。

**建议：** 使用 `std::variant<...>` 或继承式专用结构（`DohState : CompletionState` / `DotState`），让类型在编译期固定。

> **📋 设计文档已补充（2026-05-12）**
>
> 详见 `docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md`，涵盖：
> - 各协议（DoH/DoT/UDP/TCP/STUN）slot 使用模式逐行分析
> - 三种改进方案（variant payload / 继承式结构 / accessor 封装）及对比矩阵
> - 生命周期、异步 lambda 捕获、strand/线程边界、slot0 复用的详细分析
> - 实施路径与前置条件
>
> 治理记录：`docs/p2-governance-decisions-cn.md` P2-20。功能暂不实施，待测试基础设施就绪后启用。

#### **S-4：`std::atomic_load/store(shared_ptr*)` 在 C++20 已弃用**

**位置：** `ppp/transmissions/ITransmission.cpp:87-88`、`1695-1696`、`1715-1716`

C++17 标准下可用，C++20 起触发 deprecated 警告，C++26 移除。

**建议：** 包装一层兼容工具，便于以后切到 `std::atomic<std::shared_ptr<T>>`：

```cpp
template<class T>
std::shared_ptr<T> atomic_load_compat(const std::shared_ptr<T>* p) noexcept {
    return std::atomic_load(p);
}
```

> C++20 迁移时应删除 helper 并改用 `std::atomic<std::shared_ptr<T>>` 成员函数；
> 不在 helper 内使用 `static_assert(false, ...)` 阻断过渡期编译。

> **📋 设计文档已补充（2026-05-11）**
>
> 详见 `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md`，涵盖：
> - C++17 选择理由与 C++20/C++26 弃用/移除时间线
> - helper API 形态（`atomic_load_compat` / `atomic_store_compat`，不提供 `atomic_exchange_compat`）
> - Base/Derived 显式转换规则（模板推导冲突与解决方案）
> - "移出"（take-and-clear）模式的限制（`atomic_load + atomic_store({})` 不等价于 `atomic exchange`）
> - 替换范围（当前仓库所有 `atomic_load/store` 调用点清单）
> - 测试要求与 C++20 迁移步骤

#### **S-5：`UnixSocketAcceptor` macOS 加速链已收敛但需保留遥测**

详见 §1–§13 与 `docs/TCP_NAT_AUDIT_REPORT.md`。结论：保持当前的"单 outstanding accept + 启动顺序保障"，不要再改回多并发 accept。

### 14.7 隐性缺陷

#### **B-1：Timer.cpp 极简化依赖 `-DFUNCTION` 编译开关** ✅ 已实施

**位置：** `android/CMakeLists.txt:14`、`ppp/threading/Timer.cpp:6-11`

若任一交叉编译目标（如老 NDK、Linux 静态打包）漏掉 `-DFUNCTION`，会回退到旧 `ppp::function` 析构路径，重新触发 Android `SI_KERNEL` 栈溢出崩溃。

**已实施：** `Timer.cpp` 顶部已加 `#error` 守卫（2026-05-11）。当 `__ANDROID__` 已定义而 `FUNCTION` 未定义时，编译立即终止并给出明确错误信息。

```cpp
#if defined(__ANDROID__) && !defined(FUNCTION)
#  error "Android Timer.cpp requires -DFUNCTION (std::function backend); \
          ppp::function backend has a deep destructor recursion known crash."
#endif
```

或在 `stdafx.h` 中对 `__ANDROID__` 自动 define `FUNCTION`。

#### **B-2：ICMP 非 `ECHO/ER` 类型直接丢弃**

**位置：** `ppp/app/client/VEthernetNetworkSwitcher.cpp:565-582`

```cpp
if (frame->Type != IcmpType::ICMP_ECHO && frame->Type != IcmpType::ICMP_ER) {
    return false;
}
elif (IPAddressIsGatewayServer(frame->Destination, ...)) {
    // 网关 echo 处理
}
```

**功能影响：**

- 隧道内 `traceroute` 失效（依赖 `TIME_EXCEEDED`）。
- 路径 MTU 发现（PMTUD）失效（依赖 `DEST_UNREACH / Frag-Needed`）。
- `PORT_UNREACH` 不再回送给应用，UDP 短连接不会快速失败。

**长期方案：** 让 `VEthernetExchanger` 走一条 **无定时器的无状态注入路径** 处理 ICMP 错误，从而既保留 `traceroute / PMTUD` 又规避旧的定时器崩溃。当前是为稳定性做的临时折衷，**必须备忘录化并定期回看**。

**📋 设计文档已补充：`docs/ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md`**（2026-05-11）。文档涵盖：非 Echo ICMP 类型分析与优先级、无 Timer 依赖的直注路径设计、速率限制与安全边界、配置开关方案、实施步骤与回滚策略。当前状态为"已完成设计，暂不实施"。

#### **B-3：DoH/DoT 异步链中 `state->slot0` 复用**

**位置：** `ppp/dns/DnsResolver.cpp:1748-1752`、`2023-2027`

length-prefix 阶段完成后用 `response` buffer 覆盖原 `request` buffer。期间假定 `request` 已完整发送、不再被 boost::asio 引用——这是对调用顺序的隐式契约。

**建议：** 用专用 `slot_response`，让 `slot0` 始终保留 request 直到 `~CompletionState`：

```cpp
struct CompletionState final {
    // ...
    std::shared_ptr<void> request;   // 始终保留至生命周期结束
    std::shared_ptr<void> response;  // 单独槽
    std::shared_ptr<void> auxbuf;    // 长度前缀等
};
```

> **📋 与 S-3 合并设计（2026-05-12）**
>
> `docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md` §3.2/§3.4 详细分析了 DoT/TCP 的 slot0 复用模式，
> §4.2 分析了复用的隐式契约风险，§7.4 给出了各方案的消除策略。
> 治理记录：`docs/p2-governance-decisions-cn.md` P2-20。

**📋 详细设计文档：`docs/DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md`** — 涵盖 DoT/TCP 链 slot0 复用的完整代码位置分析、隐式契约（Asio handler 触发顺序、write buffer 生命周期、shared_ptr 延长生命周期）、风险分析（潜在 UAF 条件、handler 顺序变更、重构脆弱性、可读性）、三种修复候选方案对比（命名字段 / 显式释放 / typed state 子类）及后续评估路径。治理记录：`docs/p2-governance-decisions-cn.md` P2-21。当前状态为"已完成设计，暂不实施"。

#### **B-4：obfuscation 标志校验失败后的冗余写** ✅ 已修复

**位置：** `ppp/transmissions/ITransmission.cpp:1432`

```cpp
ppp::diagnostics::SetLastErrorCode(
    ppp::diagnostics::ErrorCode::ObfuscationFlagsMismatch);
handshaked_.store(false, std::memory_order_release);   // ← 已删除（冗余）
return 0;
```

新逻辑只在末尾 `handshaked_.store(true)`，此处 `handshaked_` 还从未被置 true。

**建议：** 删除该行避免误导后续阅读者。

**状态：** 已删除冗余 `handshaked_.store(false)`。`handshaked_` 初始值即为 `false`，此失败路径在 `store(true)` 之前返回，store(false) 为 no-op，已移除。

### 14.8 边界场景一览

| 场景 | 影响 | 处理方案 |
|---|---|---|
| `make_shared_object` 抛异常 vs 返回 NULL | 部分 Resolver 路径同时检查 NULL 并捕获 `std::exception` | `make_shared_object` 已封装 `(std::nothrow)` 语义返回 NULL，建议在工具头中固化为 `noexcept` 契约 |
| `io_context.stop()` 后 `timer.async_wait` 未 fired | `CompletionState` 析构时 timer 仍持有 raw 指针 | stop 后 lambda 不再 dispatch，shared_ptr 计数会在 io_context 销毁时归零，安全 |
| DNS 完成回调内重新发起解析 | 之前观察到旧流仍 in-flight | 新模型在 `Complete()` 内 `move(callback)` 后再调用，已规避重入问题 |
| `ITransmission::Dispose()` 与读协程并发 | 旧 bitfield 共享存储被并发写 | 新原子化已修复 |
| Android `ProtectorNetwork` JNI 上下文并发访问 | `jni_` shared_ptr 与 `JoinJNI()` / `DetachJNI()` 并发读写，或锁内调用 Java/JNI 造成长持锁/潜在死锁 | ✅ 已修复：`Protect()` 与 posted lambda 仅在 `syncobj_` 下 snapshot `jni_`/`env_`，`ProtectJNI(env, sockfd)` 在锁外执行；见 P2-17 |

### 14.9 架构与可维护性

#### **A-1：项目级 `elif` 宏滥用**

**位置：** `ppp/stdafx.h:197-199`

```cpp
#ifndef elif
#define elif else if
#endif
```

**影响：** 与 Python 关键字混淆；IDE 与静态分析器易误报；阅读成本增加。

**建议：** 长期内分批清理为 `else if`，新代码禁止使用。

#### **A-2：`CompletionState` / `StunCompletionState` 重复**

**位置：** `ppp/dns/DnsResolver.cpp:45-145` 与 `162-205`

**建议：** 模板化合并：

```cpp
template<class TResult, class TCallback>
struct AsyncCompletionState final {
    std::atomic<bool> completed{ false };
    TCallback callback;
    // 公共 timer / socket / stream 槽
    void Complete(TResult result) noexcept { /* ... */ }
};
```

可减少约 60 行重复。

> **📋 与 S-3 合并设计（2026-05-12）**
>
> `docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md` §3.6 和 §4.3 分析了两个结构体的重复点和合并策略。
> 方案 B（继承式专用结构）通过共享 `CompletionStateBase` 基类自然减少重复。
> 治理记录：`docs/p2-governance-decisions-cn.md` P2-20。

#### **A-3：`DnsResolver.cpp` 单文件 4500+ 行**

**建议：** 拆为：

```text
ppp/dns/DnsResolverDoH.cpp
ppp/dns/DnsResolverDoT.cpp
ppp/dns/DnsResolverUdp.cpp
ppp/dns/DnsResolverStun.cpp
ppp/dns/DnsResolverCore.cpp
```

便于增量编译与 PR 评审。

#### **A-4：注释中的非 ASCII 替换字符 / BOM 残留**

**位置：** 多处 `ppp/transmissions/ITransmission.h` 注释中存在 `鈥?`（U+FFFD）。

**原因：** Windows CRLF 与 UTF-8 BOM 混合，git 自动转换出错。

**建议：** 添加 `.gitattributes`：

```text
*.h text eol=lf working-tree-encoding=UTF-8
*.cpp text eol=lf working-tree-encoding=UTF-8
```

并统一以 UTF-8（无 BOM）保存源码。

### 14.10 依赖与构建

| 项 | 现状 | 建议 |
|---|---|---|
| C++17 | 全平台一致 | 评估升级 C++20 以使用 `std::atomic<std::shared_ptr<T>>` 与 `<concepts>`；迁移路径详见 `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md` |
| BoringSSL vs OpenSSL | 通过 `__ANDROID__` 分支区分 | 引入显式宏 `PPP_CRYPTO_BORINGSSL` / `PPP_CRYPTO_OPENSSL`，避免与平台宏耦合 |
| Boost 1.87+ | `docs/BOOST_187_COMPATIBILITY.md` 已记录 | 保持 |

### 14.11 优先级整理

#### 优先级 1（关键 / 必须修复）

1. **修复 Android TLS 信任链缺口（S-1）**：`set_default_verify_paths()` 关掉后，必须确保 `verify_peer` 路径仍有 CA 数据；与 §3.2、§3.3 形成端到端 TLS 加固闭环。
2. **强制 `-DFUNCTION` 在所有 Android 构建里出现（B-1）** ✅ 已实施：在 `ppp/threading/Timer.cpp` 顶部加 `#error` 守卫。
3. **缩小 `s_ssl_ctx_init_mutex` 临界区（P-2）** ✅ 核心修复已完成：`once_flag` 已消除全局 mutex 串行化，剩余优化项（SSL_CTX 复用）详见 `docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`。

#### 优先级 2（重要）

4. 类型安全的 `CompletionState`（S-3 / A-2）：`std::variant` 或继承结构替换 `shared_ptr<void>` 槽。**📋 设计文档已补充（2026-05-12）**：`docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md`；治理记录 `docs/p2-governance-decisions-cn.md` P2-20。
5. 删除冗余 `handshaked_.store(false)`（B-4）✅ 已完成。
6. 保留 ICMP 错误回送的最小路径（B-2）：让 PMTUD/traceroute 在 Android 下也可用；至少增加开关 `enable_icmp_error_passthrough`。**📋 设计文档已补充：`docs/ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md`**
7. 澄清并加固 Android TLS 会话缓存（P-1）：当前可用 git 历史中未发现 Android 禁用守卫；后续仅评估 TTL、telemetry、协议隔离与真机验证，不再使用“恢复缓存”口径。

#### 优先级 3（锦上添花）

8. 拆分 `ppp/dns/DnsResolver.cpp`（A-3）。
9. 清理 `elif` 宏（A-1）；UTF-8 BOM 修复（A-4）。
10. 引入 `atomic_load_compat` 包装（S-4），便于 C++20 升级。**📋 设计文档已补充：`docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md`**

### 14.12 关键修复示例

#### 14.12.1 Android CA 加载兜底

```cpp
// ppp/ssl/SSL.cpp - CreateClientSslContext
#if defined(__ANDROID__)
    const auto& ca = ppp::configurations::GetAndroidCaBundlePath();
    if (!ca.empty()) {
        boost::system::error_code ec;
        ssl_context->load_verify_file(ca, ec);
        if (ec) {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::SslInternalError);
            return NULLPTR;
        }
    }
#else
    ssl_context->set_default_verify_paths();
#endif
```

#### 14.12.2 缩小 SSL 全局初始化锁

> **📋 已实施。** 当前代码（`SSL.cpp:224-230`）已使用 `once_flag` 替代 `mutex`。详细设计和剩余优化项见 `docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`。

```cpp
// ppp/ssl/SSL.cpp - CreateClientSslContext
static std::once_flag s_ssl_globals_once;
std::call_once(s_ssl_globals_once, []() {
    SSL_CTX* warmup = SSL_CTX_new(TLS_client_method());
    if (warmup) SSL_CTX_free(warmup);
});
// 此后无需全局锁；CA 加载、cipher 配置可并发
```

#### 14.12.3 Android 必须有 `-DFUNCTION` 守卫 ✅ 已实施

```cpp
// ppp/threading/Timer.cpp - 顶部（已落盘，2026-05-11）
#if defined(__ANDROID__) && !defined(FUNCTION)
#  error "Android Timer.cpp requires -DFUNCTION (std::function backend); \
ppp::function has a deep destructor recursion known crash."
#endif
```

### 14.13 与首版（§1–§13）的关联指引

| 续审条目 | 首版相关章节 | 关联性 |
|---|---|---|
| S-1 Android CA 加载 | §3.2 WSS/TLS 关闭证书校验、§3.3 主机名校验缺失 | 共同构成 TLS 端到端校验闭环 |
| P-2 SSL_CTX 全局锁 | §6.5 平台条件编译 | 跨平台互斥设计模式；📋 **设计文档：`docs/SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`** |
| B-2 ICMP 丢弃 | §5.5 / §5.6 协议帧边界检查 | 同属"为安全/稳定性而牺牲功能"的折衷 |
| A-3 DnsResolver 拆分 | §6.1 拆 `stdafx.h` | 同属"超大单元拆分"治理思路 |
| S-3 类型擦除 slot | §14.6 S-3、§14.9 A-2、§14.7 B-3 | 同属 CompletionState 类型安全治理；**📋 设计文档：`docs/DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md`** |
| S-4 `atomic_load(shared_ptr*)` | §6.1 / §6.2 stdafx 与 Beast 版本宏 | C++ 标准升级路径；详见 `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md` |

### 14.14 总体结论

| 维度 | 评级 | 理由 |
|---|---|---|
| 正确性 | ⭐⭐⭐⭐ | 已修复 macOS TCP NAT 链、Android Timer/DNS/SSL 三类崩溃；ITransmission 原子化收敛旧的 strand-only 假设 |
| 性能 | ⭐⭐⭐ | 移动端 TLS 缓存关闭与全局 SSL 锁是当前主要瓶颈 |
| 安全 | ⭐⭐⭐ | Android CA 加载缺口需立刻补上；默认弱 key 安全默认值仍待处理 |
| 可维护性 | ⭐⭐⭐ | 大文件 + `shared_ptr<void>` 槽 + 注释 BOM 是中期债务 |

**核心建议：** 先合入当前未提交修复（Timer.cpp / DnsResolver.cpp / SSL.cpp / ITransmission.{h,cpp} / VEthernetNetworkSwitcher.cpp / android/CMakeLists.txt），再按 §14.11 优先级 1 的三项依次落地，可在不破坏已有 macOS/Android 修复的前提下补齐安全与性能短板。同时持续推进首版 §8 的 P0/P1 项（写队列背压 ✅、传输帧长度上限 ✅、per-frame 读取超时 P1）。

---

## 15. Dispose / Finalize 全仓治理风险分级

> **状态：核心传输/写队列/Exchanger/WebSocket/socket_ 已修复，P0/P1/P2 分级治理已完成一轮。**
>
> 本节对全仓 `disposed_` / `Finalize()` 路径进行风险分级，明确哪些是 P0/P1（真正跨线程并发读写 / double-finalize），哪些是 strand/thread-confined（中等风险），哪些是单线程生命周期（低风险）。
>
> **已修复的核心组件（P0 atomic + one-shot）：**

| 组件 | 文件 | `disposed_` 类型 | one-shot | 状态 |
|---|---|---|---|---|
| `IAsynchronousWriteIoQueue` | `ppp/net/asio/IAsynchronousWriteIoQueue.h` | `std::atomic_bool` | `exchange(acq_rel)` | ✅ 已修复 |
| `VirtualEthernetExchanger`（server） | `ppp/app/server/VirtualEthernetExchanger.h` | `std::atomic_bool` | `exchange(acq_rel)` | ✅ 已修复 |
| `VEthernetExchanger`（client） | `ppp/app/client/VEthernetExchanger.h` | `std::atomic_bool` | `exchange(acq_rel)` | ✅ 已修复 |
| `WebSocket` | `ppp/transmissions/templates/WebSocket.h` | `std::atomic_bool` | `exchange(acq_rel)` | ✅ 已修复 |
| `ITransmission` | `ppp/transmissions/ITransmission.h` | `std::atomic_bool` | `store(release)` | ✅ 已修复 |
| `VirtualEthernetMappingPort` | `ppp/app/protocol/VirtualEthernetMappingPort.h` | `std::atomic<int>` | `exchange(TRUE)` | ✅ 已修复 |
| `VEthernet` | `ppp/ethernet/VEthernet.h` | `std::atomic<bool>` | — | ✅ 已是 atomic |
| `VNetstack` | `ppp/ethernet/VNetstack.h` | `std::atomic<int>` | — | ✅ 已是 atomic |
| `IForwarding` | `ppp/transmissions/proxys/IForwarding.h` | `std::atomic<bool>` | — | ✅ 已是 atomic |
| `VirtualEthernetSwitcher`（server） | `ppp/app/server/VirtualEthernetSwitcher.h` | `std::atomic<bool>` | — | ✅ 已是 atomic |

> **socket_ shared_ptr 并发保护**：WebSocket 和 ITcpipTransmission 的 `socket_` 成员已通过 `std::atomic_load/store` free functions 保护（见 §5.3）。

### 15.1 P0/P1 — 高风险跨线程

这些类的 `disposed_` 为普通 `bool` 或 bitfield，且存在跨 strand/线程的并发读写或 double-finalize 风险：

| 组件 | 文件 | `disposed_` 类型 | 风险说明 | 优先级 | 状态 |
|---|---|---|---|---|---|
| `VEthernetExchanger`（client） | `ppp/app/client/VEthernetExchanger.h` | `std::atomic_bool` | bitfield 已拆为独立 `std::atomic_bool`；`Finalize()` 使用 `exchange(acq_rel)` one-shot；所有读路径使用 `load(acquire)` | ~~**P0**~~ | ✅ 已修复 |

> **修复详情：**
> - bitfield 中的 `disposed_` 已拆为独立 `std::atomic_bool disposed_{false}`；
> - `static_echo_input_` 保持独立 `bool`，不再与 `disposed_` 混在同一个 bitfield。
> - `Finalize()` 入口使用 `disposed_.exchange(true, std::memory_order_acq_rel)` one-shot，避免 double-finalize。
> - 所有读路径改为 `disposed_.load(std::memory_order_acquire)`，确保跨 strand 可见性。
> - 包括 `Post()` 模板中的 `#else` 路径也已更新为显式 acquire load。

### 15.2 Strand / Thread-Confined — 中等风险

这些类的 `disposed_` 为普通 `bool`，但运行在单一 strand 或线程上，当前并发风险较低。若未来 strand 假设被打破（如跨 strand 调用），则需要升级为 atomic：

| 组件 | 文件 | `disposed_` 类型 | 线程模型 | 建议 | P1-2 状态 | P2-16 状态 |
|---|---|---|---|---|---|---|
| `InternetControlMessageProtocol` | `ppp/net/asio/InternetControlMessageProtocol.h:210` | `bool` | 单 strand，异步回调在同 strand | 确认 strand 保护；必要时升级 atomic | ✅ 已复核：strand-confined，不改 | ✅ P2-16 二次复核确认：strand 假设成立 |
| `VEthernetLocalProxyConnection` | `ppp/app/client/proxys/VEthernetLocalProxyConnection.h:137` | `std::atomic_bool` | ~~单 strand~~ 跨线程 | 已升级 atomic | ✅ P1-2 已改为 `std::atomic_bool` | — |
| `VEthernetLocalProxySwitcher` | `ppp/app/client/proxys/VEthernetLocalProxySwitcher.h:139` | `std::atomic_bool` | ~~单 strand~~ 跨线程 | 已升级 atomic | ✅ P1-2 已改为 `std::atomic_bool` | — |
| `ITransmissionQoS` | `ppp/transmissions/ITransmissionQoS.h:157` | `bool` | mutex-protected（`syncobj_`） | 确认锁保护；必要时升级 atomic | ✅ 已复核：mutex-protected，不改 | ✅ P2-16 二次复核确认：锁保护完整 |

### 15.3 单线程生命周期 — 低风险

这些类的 `disposed_` 为普通 `bool`，但仅在单一线程内访问，无并发风险：

| 组件 | 文件 | `disposed_` 类型 | 线程模型 | 建议 | P2-16 状态 |
|---|---|---|---|---|---|
| `Timer` | `ppp/threading/Timer.h:155` | `bool` | 单 executor，`Dispose()` 可跨线程 post 回 executor | 保持现状；如需跨线程直接 Start/Stop/析构或 mutating setter 则重新评估 | ✅ P2-16 复核确认：当前 executor-confined 假设成立 |

> **P2-16 复核说明（2026-05-11）：**
> `Timer::_disposed_` 的读路径（`Start()`、`Next()`）和写路径（`Finalize()`）均在 executor 线程上。
> `Dispose()` 通过 `boost::asio::post` 将 `Finalize()` 投递到 executor 线程。
> 析构函数的 `Finalize()` 仅在所有 `shared_ptr` 引用释放后运行（`Next()` 的 async_wait 回调持有 `self` 引用）。
> `tick_event_guard_`（`std::atomic<bool>`）是独立的回调开关，用于让 `OnTick()` 在执行用户回调前观察到 `Finalize()` 已清除回调许可；与 `_disposed_` 的 plain `bool` 设计不矛盾。
> 无需代码修改。约束已记录在 P2 治理文档中。

### 15.4 治理结论

当前已修复的组件覆盖了**核心传输路径**（ITransmission、IAsynchronousWriteIoQueue）、**服务端交换器**（VirtualEthernetExchanger server）、**客户端交换器**（VEthernetExchanger client）、**WebSocket 传输层**和 **socket_ shared_ptr 并发保护**。

> **✅ P1-3 已治理（WebSocket disposed_ 显式 load 风格统一）— 2026-05-11**
>
> `WebSocket.h` 中所有 `if (disposed_)` 隐式 atomic bool 转换读取已统一为
> `disposed_.load(std::memory_order_acquire)` 显式 acquire load。
> `Finalize()` 中 `disposed_.exchange(true, std::memory_order_acq_rel)` 保持不变。
> 这是风格/审计一致性治理，不是 P0 阻断项。不改变逻辑、不改变 public API。

**全仓 Dispose/Finalize 治理尚未完成**，仍需：

1. ~~**P0**：修复 `VEthernetExchanger`（client）的 bitfield `disposed_`，改为 `std::atomic_bool` + `exchange` one-shot。~~ → **✅ 已修复：bitfield 拆为独立 `std::atomic_bool`，`Finalize()` 使用 `exchange(acq_rel)` one-shot，所有读路径使用 `load(acquire)`。**
2. ~~**P1**：逐一确认 §15.2 中 strand/thread-confined 类的 strand 保护是否完整，必要时升级为 atomic。~~ → **✅ P1-2 已完成：2 个类改为 atomic（VEthernetLocalProxyConnection、VEthernetLocalProxySwitcher），2 个类记录约束不改（InternetControlMessageProtocol、ITransmissionQoS）。**
3. ~~**P2**：对 §15.3 中单线程类保持现状，仅在 strand 假设变化时升级。~~ → **✅ P2-16 已完成：只读复核确认 Timer 当前 executor-confined 假设成立，并记录后续触发条件。**

> **✅ P2-16 已治理（Dispose/Finalize 分级治理尾项复核）— 2026-05-11**
>
> 对 §15.2 中 P1-2 未修改的 2 个类（InternetControlMessageProtocol、ITransmissionQoS）和 §15.3 中的 Timer 进行只读代码复核：
> - **InternetControlMessageProtocol**：确认 strand-confined 假设成立。`Echo()` 调用方均在 exchanger executor 线程上；`Dispose()` 通过 `boost::asio::post` 投递 `Finalize()`；析构函数在所有 `EchoAsynchronousContext` 引用释放后运行。
> - **ITransmissionQoS**：确认 mutex-protected 假设成立。所有 `disposed_` 读写在 `syncobj_` 锁内；`bandwidth_`/`traffic_` 已是 `std::atomic`。
> - **Timer**：确认当前 executor-confined 假设成立。`_disposed_` 读写均在 executor 线程上；跨线程 `Dispose()` 是允许路径，会 post 回 executor 执行 `Finalize()`；`tick_event_guard_`（`std::atomic<bool>`）是独立的回调许可开关。
> - **风格检查**：未发现隐式 atomic bool 读取风格问题（不同于 P1-3 WebSocket 案例）。
> - **治理文档**：复核结论和后续触发条件已记录在 `docs/p2-governance-decisions-cn.md`。
> - 不改变行为、不改变 public API、不原子化。
>
> **仍不宣称全仓 Dispose/Finalize 已完成。** 当前 P0/P1/P2 分级治理已覆盖所有已知候选类。后续触发条件见下方。

**后续触发条件（P2-16 前置条件变更时重新评估）：**

| 触发条件 | 影响类 | 动作 |
|---|---|---|
| `InternetControlMessageProtocol::Echo()` 被从非 executor 线程调用 | InternetControlMessageProtocol | 升级 `disposed_` 为 `std::atomic_bool` |
| `ITransmissionQoS` 的 `disposed_` 出现锁外读写路径 | ITransmissionQoS | 升级 `disposed_` 为 `std::atomic_bool` 或将锁外路径纳入锁保护 |
| `Timer` 被跨线程直接调用 `Start()`/`Stop()`/mutating setter，或析构路径不再满足 executor 生命周期约束 | Timer | 重新评估并按需升级 `_disposed_` 为 `std::atomic_bool` |
| 新增使用 `disposed_` + `Finalize()` 模式的类 | 新类 | 按 §15.1–§15.3 分级评估 |

---

## 16. `std::shared_ptr` 并发访问规范

> 本节定义仓库中 `std::shared_ptr` 成员在多线程/strand 环境下的使用规范。
> 当前项目使用 C++17，部分路径已通过 `std::atomic_load/store` free functions 保护（见 §5.3）。

### 16.1 核心规则

1. **同一个 `shared_ptr` 对象并发读写必须使用 `std::atomic_load` / `std::atomic_store`。**
   - C++ 标准（§[util.smartptr.shared.atomic]）明确：对同一个 `shared_ptr` 实例的并发读写（非仅读）构成 data race，行为未定义。
   - "读写"包括：一个线程 copy（读 control block + 增加 refcount）、另一个线程 reset/move（写 control block + 可能释放）。

2. **C++17 使用 free functions：**
   ```cpp
   // 读取（拷贝）
   auto local = std::atomic_load(&member_ptr);

   // 写入（替换）
   std::atomic_store(&member_ptr, new_value);

   // 移出（取出并清空）—— ⚠️ 非原子交换，见下方说明
   auto local = std::atomic_load(&member_ptr);
   std::atomic_store(&member_ptr, {});
   ```

   **⚠️ 关于"移出（取出并清空）"模式的限制：**
   上述 `atomic_load` + `atomic_store({})` 是两次独立的原子操作，**不等价于** `atomic exchange`。
   在并发场景下，两个线程可能同时 `atomic_load` 到相同的 `shared_ptr` 值（都获得非空引用），然后各自 `atomic_store({})`，导致同一个对象被两个消费者"取走"——**不保证唯一取走语义**。
   如果需要"唯一所有权转移"（exactly-once take），C++17 下应使用标准 `std::atomic_exchange(shared_ptr*)` free function；
   若 take-and-clear 之外还有复合不变量，则使用 `strand` / `mutex` 将整个复合操作保护为临界区。升级 C++20 后可使用 `std::atomic<std::shared_ptr<T>>::exchange()` 实现真正的原子交换。
   > **📋 详见 `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md` §4（移出模式限制与 atomic_exchange 分析）**

3. **C++20 才考虑 `std::atomic<std::shared_ptr<T>>`：**
   - `std::atomic<std::shared_ptr<T>>` 是 C++20 标准（§[util.smartptr.atomic]），提供 `load()`、`store()`、`exchange()`、`compare_exchange_*()` 等成员函数。
   - 当前项目使用 C++17，不可使用此类型。
   - 升级 C++20 后，优先迁移到 `std::atomic<std::shared_ptr<T>>`，因为 free functions 在 C++20 起已弃用。

4. **不要混用普通 copy/move 与 `atomic_load/store` 操作同一个 `shared_ptr` 成员：**
   - 如果一个成员在某些路径使用 `std::atomic_load/store`，则**所有**对它的读写都必须使用 `atomic_load/store`。
   - 混用会导致：atomic 路径与 non-atomic 路径之间没有 happens-before 关系，non-atomic 路径可能观察到撕裂的 control block。

### 16.2 性能评估

- `std::atomic_load/store(shared_ptr*)` 在主流实现（libstdc++、libc++、MSVC STL）中使用**全局 spinlock**（hash table of mutexes），不是 lock-free。
- 对**高频路径**（如每包 read/write 中的 `socket_` 访问），spinlock contention 可能成为瓶颈。
- **替代方案：**
  - **strand 保护**：将所有 `shared_ptr` 访问序列化到同一个 strand，无需 atomic。这是 Boost.Asio 的推荐模式。
  - **mutex 保护**：用 `std::mutex` 保护 `shared_ptr` 成员的所有读写。spinlock 开销更可控。
  - **所有权转移**：在初始化时 copy 到局部变量，后续使用局部变量。适用于生命周期由调用者管理的场景。
  - **裸指针 + shared_from_this**：在 strand 保护下，使用裸指针访问，避免 `shared_ptr` copy 开销。

### 16.3 当前仓库应用

| 成员 | 文件 | 保护方式 | 备注 |
|---|---|---|---|
| `WebSocket::socket_` | `ppp/transmissions/templates/WebSocket.h` | `std::atomic_load/store` | 已修复（§5.3） |
| `ITcpipTransmission::socket_` | `ppp/transmissions/ITcpipTransmission.cpp` | `std::atomic_load/store` | 已修复（§5.3） |
| `ITransmission::cipher_` | `ppp/transmissions/ITransmission.cpp` | `std::atomic_load/store` | 已修复 |

### 16.4 新代码检查清单

在新增或修改涉及 `shared_ptr` 成员的代码时，必须检查：

- [ ] 该 `shared_ptr` 成员是否会被多个线程/strand 并发访问？
- [ ] 是否存在一个线程 copy、另一个线程 reset/move 的场景？
- [ ] 如果是高频路径，是否评估了 `atomic_load/store` 的 spinlock 开销？
- [ ] 是否可以改为 strand 保护或 mutex 保护？
- [ ] 所有读写路径是否统一使用 `atomic_load/store`（不要混用）？
- [ ] 未来升级 C++20 时，是否应迁移到 `std::atomic<std::shared_ptr<T>>`？

### 16.5 C++20 迁移路径

> **📋 详见 `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md` §2、§7**

当项目升级到 C++20 时：

1. 将所有 `std::atomic_load/store(shared_ptr*)` 替换为 `std::atomic<std::shared_ptr<T>>`。
2. 使用 `load()` / `store()` / `exchange()` 成员函数。
3. 对需要 CAS 的场景，使用 `compare_exchange_weak/strong`。
4. 删除所有 free function 调用，避免 deprecated 警告。
5. 评估 `std::atomic<std::shared_ptr<T>>` 的 lock-free 实现（部分平台已支持）。

---

## 17. 续审（2026-05-30）：稳定发版前 SSL 服务端上下文复核

> 本节记录 `v2.0.0` tag 之后、稳定发版前针对 `ppp/ssl/SSL.cpp` 的一次专项复核。
> 与首版 §3.2 / §3.3（客户端 TLS 校验、主机名校验）和续审 §14.4 / §14.5（客户端 SSL_CTX 锁缩小、Android CA 兜底）不重叠：本次聚焦**服务端** `CreateServerSslContext`，该函数此前各版审计均未单独覆盖。

### 17.1 复核范围

| 项目 | 内容 |
|------|------|
| **触发** | 稳定发版前全量复核，重点排查内存安全、并发、资源管理、加密默认值 |
| **核心模块** | `ppp/ssl/SSL.cpp`（`CreateServerSslContext`） |
| **调用方** | `ppp/net/asio/templates/SslSocket.h:97`（服务端 WSS 监听建立 TLS 上下文） |

### 17.2 关键缺陷

#### **S0-1：服务端 SSL 上下文忽略证书/私钥加载错误 + 密码回调注册顺序错误** ✅ 已修复（2026-05-30）

**位置：** `ppp/ssl/SSL.cpp` — `CreateServerSslContext`

**严重性：高 / High（发版稳定性确定性缺陷）**

**问题描述：**

修复前的实现存在两处确定性缺陷：

1. **错误码被吞掉。** `use_certificate_chain_file()` / `use_certificate_file()` / `use_private_key_file()` 均传入 `ec` 但**完全不检查**返回值。调用方 `SslSocket.h` 仅检查 `!ssl_context_`（即 `make_shared` 是否成功），而 context 分配几乎总会成功。后果：证书链/叶证书/私钥文件缺失、损坏、cert 与 key 不匹配时，服务端仍返回一个"看似可用"的 `SSL_CTX`，问题被推迟到**每次 TLS 握手**才以模糊错误暴露，运维极难定位根因。与同文件 `VerifySslCertificate()`（每步检查 `ec` 并返回失败）行为不一致。

2. **密码回调注册顺序错误。** `set_password_callback()` 在 `use_private_key_file()` **之后**才注册。对于加密的 PEM 私钥，OpenSSL/BoringSSL 在解析私钥时回调尚未安装，密码无法传入，加密私钥必然加载失败。默认 `appsettings.json` 中 `certificate-key-password: "test"` 表明该路径应被支持，但修复前不可用。

**修复方案：**

- 将 `set_password_callback()` 移到三个 `use_*_file()` **之前**注册。
- 对 `set_password_callback` 与每个 `use_*_file` 的 `ec` 逐一检查，失败时设置错误码并返回 `NULLPTR`，与 `VerifySslCertificate()` 风格对齐：
  - 密码回调 / 证书链 / 叶证书加载失败 → `ErrorCode::SessionHandshakeFailed`
  - 私钥加载失败 → `ErrorCode::CryptoAlgorithmUnsupported`
- 调用方 `SslSocket.h` 已有 `if (!ssl_context_) return false`，返回 `NULLPTR` 可被正确捕获，无需改动调用方。

**效果：** 证书/私钥配置错误在服务启动构建上下文时即 fail-fast 暴露，而非拖到运行期握手；带密码的加密私钥恢复可用。

### 17.3 已复核确认为良好（排除误报）

| 项 | 结论 |
|----|------|
| 客户端 `CreateClientSslContext` verify_peer | ✅ 默认 `true`，CA 全部加载失败时握手 fail-closed，非静默降级（见 §3.2 / §14.5） |
| `config.key.plaintext = true` 默认值 | ✅ **非安全缺陷**：`EncryptBinary` 始终执行二进制加密，`plaintext` 仅控制是否额外套 base94 文本封装（混淆），不等于"不加密"（见 `ITransmission.cpp` Encrypt/Decrypt 路径） |
| 非标准 RC4（`RC4_MAXBIT=0xff`） | ✅ 索引经 `% sboxlen` 约束，无越界；属密码学卫生问题，已列 §3.7 / P1，非内存安全或发版阻断项 |
| base94 编解码 / 帧长度边界 | ✅ 有 `PPP_BUFFER_SIZE` 上限与完整性校验（见 §5.1） |

### 17.4 发版结论

本次专项复核新增并关闭 1 项高危确定性缺陷（S0-1）。其余历史项状态不变：示例私钥/证书/配置（§3.1）、弱密码学默认（§3.4–§3.7）经维护者确认为非阻断项，按现有启动告警路线处理。建议在标准构建环境（`build_windows.bat Release x64` 或 Linux cmake 构建）回归编译验证后发版。

---

## 18. 续审（2026-05-31）：跨平台静态运行模拟

> 本节记录稳定发版前对四个平台（Windows / Linux / macOS / Android）平台集成层的"静态运行模拟"审计——即不实际运行，而是通读入口（`main.cpp` / `ppp/app/*`）与平台代码（`windows/`、`linux/`、`darwin/`、`android/`），推演启动期 / 运行期 / 关闭期的行为与失败路径。
> 重点是平台集成层（TAP/TUN、路由、DNS、防火墙、系统代理、JNI 桥接），与 §3–§5（传输/加密/协议）和 §14（客户端 SSL、Android 并发）互补。

### 18.1 复核范围

| 平台 | 模块 |
|------|------|
| Windows | `windows/ppp/{tap,net,win32,app,ipv6}` |
| Linux | `linux/ppp/{tap,net,ipv6,diagnostics}` |
| macOS | `darwin/ppp/{tun,tap,ipv6}` |
| Android | `android/libopenppp2.cpp`、`android/OpenPPP2VpnProtectBridge.cpp`、`linux/ppp/net/ProtectorNetwork.cpp` |

### 18.2 确定性缺陷（✅ 已修复，2026-05-31）

#### **R0-1：macOS utun netmask 被错设为 IP** ✅ 已修复

**位置：** `darwin/ppp/tun/utun.cpp`（`utun_open`）

`utun_set_if_ip_gw_and_mask` 的第三参数（注释标 `// mask`）实际传入 `Ipep::ToAddress(ip)`，`strings[]` 数组为 `{ip, gw, ip}`，`mask` 形参从未使用。运行期 utun 接口掩码被设成 IP 地址，子网/路由判断错误。

**修复：** `strings[2]` 改为 `Ipep::ToAddress(mask).to_string()`。

#### **R0-2：Windows 系统代理地址设错** ✅ 已修复

**位置：** `windows/ppp/net/proxies/HttpProxy.cpp` — `SetSystemProxy(server, bypass)`

`ipi.lpszProxy = bypass_bstr`（应为 `server_bstr`），`server_bstr` 声明后未使用。系统代理被指向 bypass 列表而非真正的代理地址，客户端系统代理功能不可用。

**修复：** `ipi.lpszProxy = server_bstr`。

#### **R0-3：Windows PAC 参数被忽略** ✅ 已修复

**位置：** `windows/ppp/net/proxies/HttpProxy.cpp` — `SetSystemProxy(server, pac, enable)`

`_bstr_t pac_bstr(server.data())` 应为 `pac.data()`，导致传入的 PAC URL 永远等于 server。

**修复：** `pac_bstr(pac.data())`。

#### **R0-4：Linux/Android ProtectorNetwork::Recvfd socket fd 泄漏** ✅ 已修复

**位置：** `linux/ppp/net/ProtectorNetwork.cpp` — `Recvfd`

`F_GETFL` 失败（return -1013）与 `F_SETFL` 失败（return -1014）两个分支在 `socket()` 成功后未 `Closesocket(sock)` 即返回，而后续 bind/listen 失败分支均有关闭。protect-socket 为高频路径，失败时会累积泄漏 fd 直至耗尽。

**修复：** 两个失败分支补 `Socket::Closesocket(sock)`。

#### **R0-5：Linux GetDefaultGateway 未初始化变量 UB** ✅ 已修复

**位置：** `linux/ppp/tap/TapLinux.cpp` — `GetDefaultGateway`

`int calli;` 未初始化，`sscanf_s` 返回 <2 时既不赋值又被 `if (calli)` 读取；且 `/proc/net/route` 逐行循环中不重置，上一行命中后残留 `true`，导致默认网关/出口网卡误判。

**修复：** 在每行 `sscanf_s` 之后、分支判断之前 `calli = false`。

### 18.3 已知项 / 待治理（本次未修，按既有计划处理）

> 2026-05-31 第二轮：在用户"一次性完美发版"要求下，对 R1 系列逐项核查并尽可能修复。结论更新见下表"状态"列与 §18.6。

| # | 平台 | 位置 | 问题 | 状态 |
|---|------|------|------|------|
| R1-1 | Windows | `win32/Win32Native.cpp` 未处理异常过滤器 | 崩溃 `exit(-1)` 不走 `Dispose()`，系统代理（HKCU `ProxyEnable=1`）残留，用户"突然断网"至重启 | ✅ **已修复**：见 §18.6 R1-1 |
| R1-2 | Windows | `Win32Native.cpp` TAP `DeviceIoControl` | overlapped IO 误用：栈上 `OVERLAPPED` 提前析构、未 `GetOverlappedResult`，`ERROR_IO_PENDING` 当失败，存在栈破坏隐患 | ✅ **已修复**：见 §18.6 R1-2 |
| R1-3 | Linux/macOS | `TapLinux` / `LINUX_IPv6Auxiliary` / `utun.cpp` | IO 线程同步 `system()`/`popen()`（fork+exec 10–100ms）周期性挂起连接收发 | ⏸ **维持现状（不在发版窗口改）**：见 §18.6 R1-3 |
| R1-4 | Android | `libopenppp2.cpp` getter JNI `Invoke` | 同步阻塞默认 executor，executor 卡在 shell 调用时拖住 UI 线程致 ANR | ⏸ **维持现状**：依赖 R1-3，见 §18.6 R1-4 |
| R1-5 | Android | `libopenppp2.cpp` | `client_` / `network_interface_` 跨线程无锁读写同一 shared_ptr | ✅ **已修复（client_）**：见 §18.6 R1-5 |
| R1-6 | Windows | `PreventReturn` + `Win32Event` | 单例锁误把已存在事件当作获取成功；TOCTOU | ✅ **已修复**：见 §18.6 R1-6 |
| R1-7 | Windows | `TapWindows` DHCP 选项 | 实参错位 + `sizeof(*bytes)` 只拷 1 字节（应 4）；IP 选项错用 mask | ✅ **已修复**：见 §18.6 R1-7 |
| R1-8 | Android | tun fd 所有权 | 疑似 native 接管 Java fd 未 `dup()` 导致 double-close | ❌ **误报，不修**：见 §18.6 R1-8 |

### 18.6 第二轮（2026-05-31）R1 逐项处置

#### **R1-1：Windows 崩溃路径系统代理残留** ✅ 已修复

`Seh_UnhandledExceptionFilter`（`win32/Win32Native.cpp`）写完 minidump 后直接 `exit(-1)`，不还原系统代理。新增 `ppp::net::proxies::HttpProxy::EmergencyRestoreSystemProxy()`（`windows/ppp/net/proxies/HttpProxy.{h,cpp}`）并在 `exit(-1)` 前调用：

- **仅在本进程确实启用过系统代理时生效**：由 `s_system_proxy_engaged` 原子标志守护（`SetSystemProxy(...)` 按 `enable` 更新），避免清掉用户自己设置的代理。
- **崩溃安全**：只用裸 Win32（`RegOpenKeyExW`/`RegSetValueExW`/`InternetSetOption`），不分配堆内存，可在 SEH 过滤器中安全运行。
- 清 `ProxyEnable=0` / `ProxyServer` / `AutoConfigURL` 并通知 WinINet 刷新。

#### **R1-2：DeviceIoControl overlapped 误用** ✅ 已修复

TAP 句柄以 `FILE_FLAG_OVERLAPPED` 打开。修复前 `OVERLAPPED` 在 `do/while` 块内提前析构、未等待完成即 `CloseHandle(hEvent)`，且 `ERROR_IO_PENDING` 被当失败。改为：`OVERLAPPED` 提升到函数作用域；`ERROR_IO_PENDING` 时调用 `GetOverlappedResult(..., TRUE)` 同步等待真正完成后再关句柄、再判定结果。

#### **R1-5：Android `client_` 跨线程竞态** ✅ 已修复

`client_` 的写入在 `open_switcher`（默认 executor 线程，经 `Invoke` 派发）、读取在多个 JNI getter（同 executor）与 `PostJNI`（protector 私有 io_context 线程）。两个 io_context 不同线程并发读写同一 `shared_ptr` 属 UB。按 §16 仓库规范，全部 13 处访问改用 `std::atomic_load` / `std::atomic_store` / `std::atomic_exchange`（与 `ITransmission::protocol_`/`transport_` 同一惯用法）。`network_interface_` 仅在 executor 单线程访问，暂不改。

#### **R1-6：Windows 单例锁失效** ✅ 已修复

`Win32Event::OpenKernelEventObject` 修复前：`OpenEventA` 成功（=已有别的实例）时仍返回 0（成功），第二个实例误以为拿到了单例锁。改为：create 模式（`openOrCreate=false`）下，若 `OpenEventA` 命中已存在对象则报争用（返回 1）；`CreateEventA` 后检测 `ERROR_ALREADY_EXISTS` 关闭 open→create 竞态窗口。open 模式（`openOrCreate=true`）语义保持不变。
> 注：未引入 `Global\` 命名空间前缀——该项为环境相关的作用域变更，无法在本机 Windows 验证，强行加上若全局对象创建失败反而会破坏单例，故按既有 per-session 行为保留。

#### **R1-7：Windows TAP DHCP 选项** ✅ 已修复

两处缺陷一并修复：(1) 调用点实参由 `(ip, mask, gw, gw, ...)` 改为 `(ip, gw, mask, gw, ...)`，与形参 `(ip, gw, mask, dhcp, ...)` 对齐；(2) 三个 4 字节选项的拷贝循环由 `sizeof(*xxx_bytes)`（=1，只拷 1 字节）改为 `sizeof(ip/mask/gw/dhcp)`（=4），并修正 IP 选项错用 `mask_bytes` 为 `ip_bytes`（此前 `ip_bytes` 声明后未使用）。仅影响传统 TAP-Windows 路径，Wintun 不受影响。

#### **R1-3 / R1-4：IO 线程同步 shell 调用 / Android getter ANR** ⏸ 维持现状

`TapLinux`（`SetIPv6Address`/`AddRoute6`/`SetMtu`/`QueryIPv6NeighborProxy` 等）、`LINUX_IPv6Auxiliary`、`darwin/utun.cpp` 从 ASIO IO 线程同步 `system()`/`popen()`。源码注释已明确这是"已接受的当前 Linux 网络管理模型限制（见 P1-8）"。将其迁出事件循环属线程模型级改造，需配套 deadline_timer/cancellation 与异步 IO 测试验证 timer 生命周期安全，**在发版窗口内改动的回归风险高于其收益**。维持既有治理计划（P1-8 / `docs/SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md`），不在本次发版改。R1-4 是 R1-3 在 Android getter 路径上的表现，随 R1-3 一并处理。

#### **R1-8：Android tun fd 所有权** ❌ 误报，不修

复核当时 Android Java 侧日志（历史工作区路径不在本文档中保留）出现 **`detached tun fd=54`**，证明 Java 通过 `ParcelFileDescriptor.detachFd()` 将 fd 所有权移交 native，Java 侧不再 close。因此 native 接管并在 `ITap::Finalize` 关闭该 fd 是**正确**的；若按原建议 `dup()`，反而会造成 fd 泄漏。本项判定为误报，不做修改。

### 18.4 已确认健壮的部分

- Android JNI：`AttachCurrentThread`/`DetachCurrentThread`、`NewGlobalRef`/`DeleteGlobalRef` 严格配对；`ProtectorNetwork` 锁边界正确（仅锁内 snapshot `jni_`/`env_`，Java 调用在锁外，无持锁回调死锁，见 §14.8 / P2-17）。
- Windows：IPv6 回滚顺序完整且有快照校验；WMI/COM 生命周期干净；提权检查健壮；Wintun 收发循环无死循环；netsh IPv6 命令有白名单注入防护。
- Linux：命令注入面已系统性收敛（`IsSafeShellToken`/`IsSafeSysctlKey` 白名单 + 统一 `RunSystemCommand` 出口 + strtol 严格解析），未发现可利用注入点。

### 18.5 发版结论

本次跨平台静态模拟首轮关闭 5 项确定性缺陷（R0-1 ~ R0-5）。第二轮（2026-05-31）对 R1 系列逐项处置：**R1-1/R1-2/R1-5/R1-6/R1-7 已修复**，R1-8 经日志核查判定为误报（Java 侧 `detachFd()` 已移交所有权，native 关闭正确），**R1-3/R1-4 为维护者已知的线程模型级治理项，在发版窗口内不改以规避回归风险**。核心传输/加密/并发治理成熟度保持良好。

仍需注意：本机无 Windows/Linux/macOS/Android 工具链，以上修改均未做编译验证，仅做了大括号配平与 API/错误码存在性核对。**发版前必须在四个平台标准构建环境分别回归编译，并对 Windows 系统代理崩溃还原（R1-1）、TAP DHCP 配置（R1-7）、Android 连接/统计路径（R1-5）做针对性冒烟测试。**
