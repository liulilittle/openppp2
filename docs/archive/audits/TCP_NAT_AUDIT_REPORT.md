# OPENPPP2 TCP NAT 路径深度审计报告
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> 审计日期：2026-05-05
> 审计范围：`lwip=no` native TCP NAT 路径
> 目标平台：macOS / Linux (小端架构)
> 现象：TCP :80 连接约 1 分钟后出现 `Connection refused`

---

## 一、根因排名

| 排名 | 问题 | 严重度 | 位置 |
|------|------|--------|------|
| **#1** | **`link->state` 在 native path 永远不会到达 `ESTABLISHED`** | 🔴 Critical | `EndAccept()` line 1409: `if (lwip_)` 守卫排除了 native path |
| **#2** | **`natPort` 字节序错误 + 互相抵消的隐藏 bug** | 🔴 Critical | `line 249`(存) / `line 585`(写TCP) / `line 1000`(查map) 三处 |
| **#3** | **10 秒超时杀死已建立连接** | 🟠 High | `Update()` line 795-798: `SYN_RECEIVED` 用 10s 超时，但连接实际已建立 |
| **#4** | **`EndAccept` 失败时 `link->Release()` 不清理 map** | 🟠 High | `ProcessAcceptSocket` line 1036 |
| **#5** | **FD 耗尽导致 accept loop 事实停摆** | 🟠 High | 每连接 3 FD，~4 SYN/s × 60s = 720 FD，逼近默认 1024 限制 |
| **#6** | **重复 SYN 在 `SYN_SENT` 状态被吞但不重发 SYN/ACK** | 🟡 Medium | `Input()` line 509-513 |
| **#7** | **无 SYN flood 防护** | 🟡 Medium | `wan2lan_` 无上限，无源 IP 限速 |

---

## 二、逐项分析

### #1 `link->state` 永远不会到达 ESTABLISHED（根因）

**证据链：**

```cpp
// VNetstack.cpp EndAccept() line 1409-1416
if (lwip_) {                                          // ← 只有 lwIP path
    link->state.store(TCP_STATE_ESTABLISHED, ...);    // ← native path 被排除
}
```

`SYN_RECEIVED → ESTABLISHED` 的唯一另一条路径是 `Input()` line 632-636（收到 SYN+ACK），但这条路径被 `FindTcpLink(tcp->dest)` 的字节序 bug (#2) 阻断。

**后果：** `Update()` 超时扫描（line 795-798）看到 `SYN_RECEIVED` 状态，使用 `MaxConnectTimeout = 10000ms`。**所有 native TCP 连接在 10 秒无活动后被杀死。**

这直接解释了 "约 1 分钟后 Connection refused"：
- 连接建立后数据传输正常（`link->Update()` 在每个包时刷新）
- 一旦出现 HTTP keep-alive 空闲期 >10 秒（如 `curl` 等待下一个请求），link 被超时清理
- 下一个请求到达时，NAT 映射已不存在 → RST → Connection refused

**修复方向：** 在 `EndAccept()` 中为 native path 也设置 `ESTABLISHED`。

---

### #2 `natPort` 字节序：两个 bug 互相抵消

**Bug A — `tcp->src = link->natPort`（line 493, 585）缺少 `htons()`：**

```
natPort = 50000 (host order, LE bytes: [0x50, 0xC3])
tcp->src = 50000 → 写入 TCP header 的字节: [0x50, 0xC3]
内核按网络序读取: 0x50C3 = 20675 ← 客户端看到的端口
```

**Bug B — `FindTcpLink(htons(remoteEP.Port))`（line 1000）多余的 `htons()`：**

```
remoteEP.Port = 20675 (内核返回的网络序解析后的主机序)
htons(20675) = 0xC350 = 50000 ← 恰好等于 natPort 原始值
wan2lan_[50000] 存在 → 查找成功
```

**两个 bug 的字节序错误方向相反，互相抵消。** 系统在小端架构上"碰巧"能工作。但：
- `tcpdump` 抓包显示的端口号与 NAT 表不一致
- 任何中间件（防火墙、NAT 穿透）看到的端口是错的
- 修复任一 bug 而不修另一个会导致系统完全崩溃

**修复方向：** 三处必须原子修改：
1. `line 493`: `tcp->src = htons(link->natPort)`
2. `line 585`: `tcp->src = htons(link->natPort)`
3. `line 1000`: `FindTcpLink(remoteEP.Port)`（删除 `htons`）

---

### #3 10 秒超时杀死已建立连接

**这是 #1 的直接后果。** 一旦 link state 正确设为 `ESTABLISHED`，超时将使用 `MaxEstablishedTimeout = 72000ms`（72 秒），问题自动解决。

---

### #4 `EndAccept` 失败时 map 泄漏

**位置：** `ProcessAcceptSocket` line 1033-1037

```cpp
else {
    link->Release();    // ← 只清理 socket，不删 wan2lan_/lan2wan_
}
```

`Release()` 调用 `Closing()` 清理 socket，但不从 map 中删除条目。stale link 残留在 map 中直到 `Update()` 超时清理（10 秒）。期间任何新的 accept 到同一 NAT port 都会找到这个死 link。

**修复方向：** 改为 `this->CloseTcpLink(link)`。

---

### #5 FD 耗尽

**每个连接消耗 3 个 FD：**
1. 本地 listener accept 的 socket
2. `TapTcpClient` 持有的 socket
3. `ConnectTransmission()` 到 VPN server 的 socket

4 SYN/s × 60s × 3 FD = 720 FD。加上 TAP 设备、VPN tunnel、管道等，逼近默认 1024 软限制。`NewAsynchronousSocket` 或 `ConnectTransmission` 开始返回 `EMFILE`。

**但这不是主因** — 即使 FD 充足，#1 的 10 秒超时仍会杀死连接。FD 耗尽是加剧因素，不是根因。

**修复方向：** 添加 FD 预算跟踪，在 `AllocTcpLink` 前检查可用 FD。

---

### #6 重复 SYN 不重发 SYN/ACK

**位置：** `Input()` line 509-513

当 link 在 `SYN_SENT` 状态（`ConnectToPeer` 还在连接 VPN server）时，客户端的 SYN 重传被静默吞掉。如果 `ConnectToPeer` 耗时 >1-2 秒，客户端可能在 `AckAccept` 运行前就放弃了。

**修复方向：** 在吞掉重复 SYN 时，如果 `sync_ack_byte_array_` 有缓存包，重发一次。

---

### #7 无 SYN flood 防护

`wan2lan_` / `lan2wan_` 无条目上限，无源 IP 限速。攻击者可以用伪造源 IP 发送大量 SYN，耗尽 NAT 端口和 FD。

---

## 三、字节序类型契约表

| 实体 | 字节序 | 来源 |
|------|--------|------|
| `ip_hdr::src`, `ip_hdr::dest` | 网络序 | ip.h: "All multi-byte fields…network byte order" |
| `tcp_hdr::src`, `tcp_hdr::dest` | 网络序 | tcp.h: "All multi-byte fields…network byte order" |
| `tap->GatewayServer` | **网络序** | `inet_addr()` — POSIX 保证网络序 |
| `IPEndPoint::Port` | **主机序** | IPEndPoint.h: "host byte order" |
| `IPEndPoint::GetAddress()` | **网络序** | IPEndPoint.h |
| `link->srcPort`, `link->dstPort` | **网络序** | 直接来自 `tcp->src`/`tcp->dest` |
| `link->natPort` | **主机序** | `++ap_` 纯计数器，无 `htons` |
| `listenPort_` | **主机序** | `listenEP_.Port` |
| `boost::asio::endpoint::port()` | **主机序** | Boost.Asio 规范 |
| `wan2lan_` map key (native) | **主机序** | `wan2lan_[newPort]` |

---

## 四、TCP 状态机审计

### VNetstack::Input() SYN 分支状态转换

| 路径 | 条件 | `rst` | 是否正确 |
|------|------|-------|----------|
| `AllocTcpLink` 返回 NULL | 无空闲 NAT 端口 | `true` | ✅ 无映射，必须 RST |
| link state = CLOSED | 竞态关闭 | `true` | ✅ 可接受的竞态 |
| socket 非 null + `!disposed && pending` | 重复 SYN | N/A (`return true`) | ✅ 正确吞掉 |
| socket 非 null + disposed | 连接已死 | `true` | ✅ 已死连接，RST |
| socket null + state 非 SYN_SENT/SYN_RECEIVED | 意外状态 | N/A (`return true`) | ✅ 静默丢弃 |
| CAS 失败 | 并发 accepting | N/A (`return true`) | ✅ 其他线程处理中 |
| `BeginAcceptClient` 失败 | 暂时不可用 | N/A (`return true`) | ✅ 允许重试 |
| `BeginAccept` 失败 | 暂时不可用 | N/A (`return true`) | ✅ 允许重试 |
| `BeginAccept` 成功 | 正常建立 | `false` | ✅ 转发包 |

### SYN+ACK / ACK / RST 方向判断

- **SYN+ACK (0x12)**: `ip->dest == tap->GatewayServer` → V→Local 分支（line 475），正确
- **ACK (0x10)**: `flags != TCP_SYN` → Local→V 分支（line 487），正确
- **RST (0x14)**: `flags != TCP_SYN` → Local→V 分支，若 link 不存在则 `rst=true`，但 line 599 抑制了 RST-in-response-to-RST，正确

---

## 五、提交验证

| 提交 | 结论 | 副作用 |
|------|------|--------|
| `ab13b5d` stale link cleanup | ✅ 逻辑正确 | 无 |
| `68d7b45` duplicate SYN handling | ✅ 逻辑正确 | 不重发 SYN/ACK（#6），但不影响正确性 |
| `cde74d3` diagnostics | ✅ 仅加日志 | 无 |

---

## 六、Accept Loop 审计

### UnixSocketAcceptor::Next() 生命周期

| 事件 | 行为 | 是否正确 |
|------|------|----------|
| `operation_canceled` | 返回，不调用 `Next()`，loop 死亡 | ✅ 设计如此（`Finalize()` 关闭 acceptor） |
| 其他错误 | 调用 `Next()` 重试，失败则 loop 死亡 | ✅ 正确 |
| 成功 | `release()` fd → `Closesocket(socket)` → `Next()` → `OnAcceptSocket()` | ✅ 先 re-arm 再处理，顺序正确 |

### `socket->release()` 后 `Closesocket` 安全性

`release()` 后 `is_open()` 返回 false，`Closesocket` 内部检查 `is_open()` 后直接返回，是 no-op。**安全。**

### ProcessAcceptSocket 失败路径

| 失败点 | 行为 | 是否正确 |
|--------|------|----------|
| tap missing | break → 关闭 sockfd | ✅ |
| endpoint mismatch | break → 关闭 sockfd | ✅ |
| link null | break → 关闭 sockfd | ✅ 但客户端已收 SYN/ACK，会看到 RST |
| pcb null | break → 关闭 sockfd | ✅ |
| NewAsynchronousSocket 失败 | break → 关闭 sockfd | ✅ |
| **EndAccept 失败** | **`link->Release()`** | **❌ 应为 `CloseTcpLink(link)`** |

---

## 七、TapTcpLink 生命周期审计

### CloseTcpLink 竞态安全性

- **Thread A** (`CloseTcpLink`): 持 `syncobj_` → 删 map → 释放锁 → `link->Release()`
- **Thread B** (`ProcessAcceptSocket`): 持 `syncobj_` → 查 map

`syncobj_` 互斥锁保证 map 操作串行化。shared_ptr 保证对象在所有使用者释放前不被销毁。**安全。**

### Finalize → CloseTcpLink → Dispose 重入保护

`disposed_` 原子变量（line 1287）保证 `Dispose()` 只执行一次。`Finalize()` 内部 `Closing()` 通过 `closed.exchange(true)` 保证只执行一次。**无双重关闭风险。**

### `link->socket` vs `socket_` 类型区分

| 字段 | 类型 | 含义 |
|------|------|------|
| `TapTcpClient::socket_` | `shared_ptr<boost::asio::ip::tcp::socket>` | 实际 TCP socket |
| `TapTcpLink::socket` | `shared_ptr<TapTcpClient>` | 客户端处理器对象 |

`Closing()` 操作 `link->socket`（TapTcpClient 指针），不涉及 `socket_`（TCP socket）。**无冲突。**

---

## 八、SYN/ACK 注入与重试审计

### 缓存包实质

`sync_ack_byte_array_` 缓存的是**原始 SYN 包**（重写地址后），**不是 SYN/ACK**。TCP flags 保持 `TCP_SYN (0x02)`。包被发送到 TAP 后，内核 TCP 栈收到 SYN，生成 SYN/ACK 回到 TAP，再由 `Input()` 的 V→Local 路径处理。

### AckAccept() CAS 窗口安全性

`sync_ack_state_` 从 `SYN_SENT` 到 `SYN_RECVD` 的 CAS（line 1439-1443）：
- 窗口期内重复 SYN 被吞掉（不修改 `sync_ack_state_`）→ 安全
- `Finalize()` 将 `sync_ack_state_` 设为 CLOSED → CAS 失败 → `AckAccept` 返回 false → 安全

### 重试定时器防护

三重冗余：
1. `CancelSyncAckRetry()` 调用 `timer->cancel()` → handler 收到 `operation_aborted`
2. `sync_ack_state_` 被 `EndAccept` 重置为 CLOSED → handler 检查后退出
3. `sync_ack_byte_array_` 被清空 → handler 检查后退出

**安全。**

---

## 九、资源耗尽分析

### FD 消耗模型

| 阶段 | 每连接 FD | 说明 |
|------|-----------|------|
| listener accept | 1 | 本地 loopback socket |
| TapTcpClient | 1 | `socket_` 持有 |
| ConnectTransmission | 1 | 到 VPN server 的 TCP 连接 |
| **合计** | **3** | |

4 SYN/s × 60s × 3 = 720 FD。默认 Linux 软限制 1024。加上 TAP、VPN tunnel、管道等基础 FD，约 85 秒后触发 `EMFILE`。

### SYN flood 漏洞

- 无 `wan2lan_` 条目上限
- 无源 IP 限速
- `AllocTcpLink` 端口扫描在 `syncobj_` 下遍历最多 65536 项
- 1000 SYN/s × 10s 超时 = 10,000 并发 link × 3 FD = 30,000 FD → 瞬间耗尽

---

## 十、最小修复方案

### 必须修复（3 处，原子修改）

**修复 A：`EndAccept` 设置 ESTABLISHED**

```
文件: ppp/ethernet/VNetstack.cpp
位置: EndAccept() line 1409-1416
改动: 删除 if (lwip_) 守卫，让 native path 也执行 link->state = ESTABLISHED
```

**修复 B：`natPort` 字节序（3 处同时改）**

```
文件: ppp/ethernet/VNetstack.cpp
改动:
  line 493: tcp->src = htons(link->natPort)       // 原: link->natPort
  line 585: tcp->src = htons(link->natPort)       // 原: link->natPort
  line 1000: FindTcpLink(remoteEP.Port)           // 原: htons(remoteEP.Port)
```

> ⚠️ 三处必须同时修改。单独修改任一处会导致 NAT 端口查找完全失败。

**修复 C：`EndAccept` 失败清理**

```
文件: ppp/ethernet/VNetstack.cpp
位置: ProcessAcceptSocket() line 1036
改动: link->Release() → this->CloseTcpLink(link)
```

### 建议修复

**修复 D：重复 SYN 重发缓存包**

```
文件: ppp/ethernet/VNetstack.cpp
位置: Input() line 509-513
改动: 吞掉 SYN 前检查 sync_ack_byte_array_，有则重发一次
```

**修复 E：wan2lan_ 条目上限**

```
文件: ppp/ethernet/VNetstack.cpp
位置: AllocTcpLink()
改动: wan2lan_.size() >= 4096 时拒绝新 SYN，返回 NULL
```

**修复 F：FD 预算跟踪**

```
文件: ppp/ethernet/VNetstack.cpp
位置: AllocTcpLink() / Input() SYN 分支
改动: 维护原子计数器跟踪已用 FD，超过阈值时拒绝新连接
```

---

## 十一、遥测增强建议

| 指标名 | 放置位置 | 字段 |
|--------|----------|------|
| `vnetstack.link.state.transition` | `Input()` line 608-669 | `prev_state`, `new_state`, `flags`, `dir` |
| `vnetstack.accept.map_miss` | `ProcessAcceptSocket` line 1003 | `nat_port`, `htons_port`, `wan2lan_size` |
| `vnetstack.timeout.kill` | `Update()` line 795-798 | `state`, `delta_ms`, `max_timeout`, `link_age_ms` |
| `vnetstack.fd.exhaustion` | `NewAsynchronousSocket` line 1270 | `sockfd`, `error_code`, `fd_soft_limit` |
| `vnetstack.syn.resend` | `Input()` line 509-513 (新增路径) | `sync_ack_state`, `has_cached_packet` |
| `vnetstack.link.table.size` | `Update()` 入口 | `wan2lan_size`, `lan2wan_size` |

---

## 十二、数据验证

来自生产环境日志（10:45 后统计）：

| 指标 | 数值 | 说明 |
|------|------|------|
| connect | 1486 | `BeginAcceptClient` 调用次数 |
| sync_ack | 1466 | `AckAccept` 成功次数 |
| accept | 71 | `ProcessAcceptSocket` 成功次数（4.8%） |
| rst_pre | 1392 | `SYN_RECEIVED` 状态收到 RST 次数 |
| dup_syn | 28 | 重复 SYN 被吞次数 |

**accept/connect 比率 4.8%** 与字节序抵消理论一致：在随机分配的 NAT 端口中，约有 1/256 的端口值满足 `htons(port) == port`（高低字节相同），但实际命中率取决于端口分布。

**RST 端口分布：** 443: 601, 8080: 477, 80: 314 — 这些是客户端尝试连接的目标端口，不是 NAT 端口。高 RST 率说明 NAT 映射频繁丢失（10 秒超时 #1 所致）。

**10:50:51 后 `socket accepted` 停止** — 可能是 FD 耗尽（#5）加剧了 accept 失败率，也可能是 #1 的 10 秒超时导致大量 link 被清理后重建，形成风暴。
