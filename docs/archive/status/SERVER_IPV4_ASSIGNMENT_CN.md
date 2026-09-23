# 服务端自动下发 IPv4 方案
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **状态**: 已实施。`IPv4LeasePool` 类已实现并集成到 `VirtualEthernetSwitcher`（`ipv4_pool_` 成员，`.h:837`）。
> **实现文件**: `ppp/app/server/IPv4LeasePool.h`、`ppp/app/server/IPv4LeasePool.cpp`

## 目标

客户端默认不需要显式配置隧道 IPv4。

- 如果客户端传入：

  ```bash
  --tun-ip=10.0.0.2 --tun-gw=10.0.0.1 --tun-mask=255.255.255.252
  ```

  则优先使用手动 IPv4 配置。

- 如果客户端没有传入完整手动 IPv4 配置，则默认向服务端发起 IPv4 分配请求。

服务端不需要显式 `enabled` 配置。

- 只要配置了：

  ```json
  {
    "server": {
      "ipv4-pool": {
        "network": "10.0.0.0",
        "mask": "255.255.255.0"
      }
    }
  }
  ```

  即自动启用 IPv4 下发。

- 如果没有配置 `server.ipv4-pool`，则保持旧行为。

---

## 客户端行为

### 1. 手动模式

当客户端显式传入完整三元组：

```bash
--tun-ip=<ip> --tun-gw=<gateway> --tun-mask=<mask>
```

例如：

```bash
--tun-ip=10.0.0.2 --tun-gw=10.0.0.1 --tun-mask=255.255.255.252
```

客户端使用手动模式，并在握手中携带：

```json
{
  "client-ipv4-request": {
    "mode": "manual",
    "address": "10.0.0.2",
    "gateway": "10.0.0.1",
    "mask": "255.255.255.252"
  }
}
```

### 2. 自动模式

当客户端没有传入完整三元组时，默认进入自动模式：

```json
{
  "client-ipv4-request": {
    "mode": "auto"
  }
}
```

不需要配置：

```json
"ip": "auto"
```

---

## 服务端配置

### 最小配置

```json
{
  "server": {
    "ipv4-pool": {
      "network": "10.0.0.0",
      "mask": "255.255.255.0"
    }
  }
}
```

### 规则

- 不需要 `enabled`。
- 不配置 `start` / `end`。
- 不配置 `ttl`。
- 不配置 `gateway`。
- 配置了 `ipv4-pool` 即启用。
- `gateway` 默认等于：

```text
network + 1
```

例如：

```text
10.0.0.0/24 -> 10.0.0.1
10.0.0.0/30 -> 10.0.0.1
```

---

## 地址计算规则

服务端从：

```text
network
mask
```

计算：

```text
broadcast = network | ~mask
gateway   = network + 1
```

可扫描范围：

```text
network + 1 到 broadcast - 1
```

但默认 `gateway = network + 1` 不分配给客户端。

所以第一个自动分配地址通常是：

```text
network + 2
```

例如：

```text
network:   10.0.0.0
mask:      255.255.255.252
gateway:   10.0.0.1
client:    10.0.0.2
broadcast: 10.0.0.3
```

---

## 服务端只做两个检查

服务端对候选 IP 或客户端手动 IP 只检查两项：

1. 是否已经被其它 session 占用；
2. 是否是 broadcast 地址。

即：

```text
occupied_by_other_session == false
is_broadcast == false
```

不额外检查：

- 是否是 network address；
- 是否是 gateway；
- 是否在 network/mask 范围内；
- 是否是保留地址；
- 是否与默认 gateway 冲突。

自动分配算法自身仍然可以从合理范围扫描，默认跳过 gateway，但手动 IP 校验只做上述两个检查。

---

## 租约生命周期

不配置 TTL。

IPv4 租约和 session 生命周期绑定：

```text
session created      -> acquire/confirm IPv4
session alive        -> hold IPv4
session disconnected -> release IPv4
```

会话断开后立即释放 IP。

---

## 自动分配流程

### 请求

客户端没有传入完整手动 IPv4：

```json
{
  "client-ipv4-request": {
    "mode": "auto"
  }
}
```

### 服务端处理

1. 确认 `server.ipv4-pool` 已配置；
2. 从地址池扫描候选 IP；
3. 对候选 IP 检查：
   - 未被其它 session 占用；
   - 不是 broadcast；
4. 分配给当前 session；
5. 下发给客户端。

### 响应

```json
{
  "client-ipv4": {
    "enabled": true,
    "mode": "auto",
    "accepted": true,
    "conflict": false,
    "address": "10.0.0.2",
    "gateway": "10.0.0.1",
    "mask": "255.255.255.252"
  }
}
```

---

## 手动 IP 流程

### 请求

客户端传入：

```bash
--tun-ip=10.0.0.2 --tun-gw=10.0.0.1 --tun-mask=255.255.255.252
```

握手中携带：

```json
{
  "client-ipv4-request": {
    "mode": "manual",
    "address": "10.0.0.2",
    "gateway": "10.0.0.1",
    "mask": "255.255.255.252"
  }
}
```

### 服务端处理

服务端只检查：

1. `10.0.0.2` 是否被其它 session 占用；
2. `10.0.0.2` 是否是 broadcast 地址。

### 手动 IP 无冲突

如果可用，服务端确认该 IP：

```json
{
  "client-ipv4": {
    "enabled": true,
    "mode": "manual",
    "accepted": true,
    "conflict": false,
    "address": "10.0.0.2",
    "gateway": "10.0.0.1",
    "mask": "255.255.255.252"
  }
}
```

客户端继续使用自己的手动配置。

### 手动 IP 冲突或为 broadcast

如果客户端请求 IP：

- 已被其它 session 占用；或
- 是 broadcast；

服务端拒绝该 IP，并自动分配一个不冲突、非 broadcast 的 IP。

响应：

```json
{
  "client-ipv4": {
    "enabled": true,
    "mode": "manual",
    "accepted": false,
    "conflict": true,
    "reason": "conflict",
    "requested-address": "10.0.0.2",
    "address": "10.0.0.4",
    "gateway": "10.0.0.1",
    "mask": "255.255.255.0"
  }
}
```

客户端必须使用服务端下发的新 IP。

---

## 地址池耗尽

如果服务端无法找到：

```text
未被其它 session 占用
且不是 broadcast
```

的可用 IP，则响应失败：

```json
{
  "client-ipv4": {
    "enabled": true,
    "accepted": false,
    "conflict": false,
    "reason": "pool-exhausted"
  }
}
```

连接应失败。

---

## 服务端未配置 ipv4-pool

### 客户端自动模式

如果客户端未传手动 IPv4，且服务端没有配置：

```json
server.ipv4-pool
```

则服务端无法下发 IPv4。

推荐响应：

```json
{
  "client-ipv4": {
    "enabled": false,
    "accepted": false,
    "reason": "pool-unavailable"
  }
}
```

客户端连接失败。

### 客户端手动模式

如果客户端传入手动 IPv4，且服务端没有配置 `ipv4-pool`，则保持旧兼容行为。

服务端不做地址池检查，只接受客户端手动配置。

---

## 数据结构建议

### 配置结构

```cpp
struct ServerIPv4PoolConfiguration {
    bool        configured = false;
    ppp::string network;
    ppp::string mask;
};
```

解析规则：

```text
如果 JSON 中存在 server.ipv4-pool:
    configured = true
否则:
    configured = false
```

### 请求结构

```cpp
struct ClientIPv4Request {
    bool        enabled = false;
    bool        manual = false;

    ppp::string address;
    ppp::string gateway;
    ppp::string mask;
};
```

含义：

```text
enabled=false:
    旧客户端/无请求

enabled=true, manual=false:
    自动请求

enabled=true, manual=true:
    手动请求
```

### 响应结构

```cpp
struct ClientIPv4Assignment {
    bool        enabled = false;
    bool        accepted = false;
    bool        conflict = false;

    ppp::string mode;
    ppp::string reason;

    ppp::string requested_address;
    ppp::string address;
    ppp::string gateway;
    ppp::string mask;
};
```

---

## IPv4LeasePool 接口

已实现：

```text
ppp/app/server/IPv4LeasePool.h
ppp/app/server/IPv4LeasePool.cpp
```

接口：

```cpp
class IPv4LeasePool final {
public:
    struct Result {
        bool ok = false;
        bool accepted = false;
        bool conflict = false;

        ppp::string reason;

        boost::asio::ip::address_v4 address;
        boost::asio::ip::address_v4 gateway;
        boost::asio::ip::address_v4 mask;
        boost::asio::ip::address_v4 requested_address;
    };

    bool Configure(
        const boost::asio::ip::address_v4& network,
        const boost::asio::ip::address_v4& mask
    ) noexcept;

    Result AcquireAuto(uint64_t session_id) noexcept;

    Result AcquireManual(
        uint64_t session_id,
        const boost::asio::ip::address_v4& requested
    ) noexcept;

    void Release(uint64_t session_id) noexcept;

private:
    bool IsBroadcast(uint32_t ip) const noexcept;
    bool IsLeasedByOtherSession(uint64_t session_id, uint32_t ip) const noexcept;
    bool TryLease(uint64_t session_id, uint32_t ip) noexcept;
};
```

---

## 核心算法

### 自动分配

```cpp
Result IPv4LeasePool::AcquireAuto(uint64_t session_id) noexcept {
    for (uint32_t ip = network + 1; ip < broadcast; ++ip) {
        if (ip == gateway) {
            continue;
        }

        if (IsBroadcast(ip)) {
            continue;
        }

        if (IsLeasedByOtherSession(session_id, ip)) {
            continue;
        }

        if (TryLease(session_id, ip)) {
            return ok_auto(ip);
        }
    }

    return failed("pool-exhausted");
}
```

### 手动分配

```cpp
Result IPv4LeasePool::AcquireManual(
    uint64_t session_id,
    const boost::asio::ip::address_v4& requested
) noexcept {
    uint32_t ip = requested.to_uint();

    if (!IsBroadcast(ip) && !IsLeasedByOtherSession(session_id, ip)) {
        if (TryLease(session_id, ip)) {
            return ok_manual(ip);
        }
    }

    Result reassigned = AcquireAuto(session_id);
    reassigned.accepted = false;
    reassigned.conflict = true;
    reassigned.requested_address = requested;

    if (!reassigned.ok) {
        reassigned.reason = "pool-exhausted";
    }
    else if (IsBroadcast(ip)) {
        reassigned.reason = "broadcast";
    }
    else {
        reassigned.reason = "conflict";
    }

    return reassigned;
}
```

### Release

```cpp
void IPv4LeasePool::Release(uint64_t session_id) noexcept {
    auto it = ip_by_session_.find(session_id);
    if (it == ip_by_session_.end()) {
        return;
    }

    leases_by_ip_.erase(it->second);
    ip_by_session_.erase(it);
}
```

---

## Telemetry

建议事件：

```text
server.ipv4_pool.configured
server.ipv4_pool.acquire_auto
server.ipv4_pool.acquire_manual
server.ipv4_pool.acquire_success
server.ipv4_pool.manual_accept
server.ipv4_pool.manual_conflict
server.ipv4_pool.broadcast_reject
server.ipv4_pool.reassign_success
server.ipv4_pool.exhausted
server.ipv4_pool.release
client.ipv4_assignment.request_auto
client.ipv4_assignment.request_manual
client.ipv4_assignment.applied
client.ipv4_assignment.failed
```

---

## 兼容性

### 旧客户端

旧客户端如果没有发送 `client-ipv4-request`：

- 服务端没有 `ipv4-pool`：完全旧行为；
- 服务端有 `ipv4-pool`：可以按旧行为处理，也可以视为 `auto`，第一版建议只对新客户端请求 auto 生效，避免协议行为突变。

### 新客户端

新客户端默认发送 auto 请求。

### 手动配置

手动配置仍兼容，只是服务端会检查：

```text
是否被其它 session 占用
是否 broadcast
```

如冲突则下发替代地址。

---

## 推荐实现顺序

1. 扩展配置解析：
   - `server.ipv4-pool.network`
   - `server.ipv4-pool.mask`

2. 扩展协议字段：
   - `client-ipv4-request`
   - `client-ipv4`

3. 新增 `IPv4LeasePool`：
   - session 生命周期租约；
   - 只检查占用和 broadcast；
   - 自动扫描分配。

4. 服务端接入：
   - session 建立时确认/分配 IP；
   - session 断开时释放 IP；
   - 冲突时下发替代 IP。

5. 客户端接入：
   - 没有完整 `--tun-ip/--tun-gw/--tun-mask` 时默认 auto；
   - 收到 assignment 后覆盖本地待配置 IPv4；
   - pool unavailable / exhausted 时失败。

6. 远端 Release build 验证。
