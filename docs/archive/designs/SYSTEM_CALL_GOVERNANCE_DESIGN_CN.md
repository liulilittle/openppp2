# Shell 命令执行路径（`system()` / `popen()`）治理设计文档
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **文档性质**：设计文档，暂不实施。
> **不得声称已替换 `system()` / `popen()`。** 本文档仅描述后续治理方向、技术方案和分阶段计划。
> **关联治理项**：P1-8（`docs/p1-governance-decisions-cn.md` §1.8）
> **关联审计文档**：`docs/openppp2-deep-code-audit-cn.md` §3.8、§8 P1 第 8 项
> **创建日期**：2026-05-12
> **更新日期**：2026-05-12（补充 Phase 3 实施检查清单、前置条件、与 cleaner withdrawal 边界的顺序关系、回滚/验收要点）
> **状态**：设计文档完成，暂不实施。Phase 3 尚未启动代码替换。

---

## 1. 现状总结

### 1.1 全仓 `system()` / `popen()` 调用清单（草案）

当前只读复核识别到全仓存在多处 `system()` / `popen()` / shell 命令执行路径，分散于跨平台核心代码和三个平台目录。下表为治理清单草案；实施前必须以 `rg '\b(system|popen)\s*\('` 重新生成并确认完整清单，不应将当前表格视为最终数量口径。

`system()` 路径主要依赖命令返回码；`popen()` 路径还依赖 stdout 读取与解析，替换时必须保留输出读取语义，不能简单套用 `posix_spawn` 返回码模型。

| 文件 | 行号 | 用途 | 平台 | 风险级别 |
|------|------|------|------|----------|
| `ppp/app/client/VEthernetNetworkSwitcher.cpp` | 1085, 1188 | 网络切换 shell 命令 | 跨平台 | 中 |
| `ppp/app/ConsoleUI.cpp` | 1795 | shell 命令输出读取（`popen()`） | 跨平台/Unix-like | 中 |
| `ppp/stdafx.cpp` | 1123, 1128 | `system("cls")` / `system("clear")` 清屏 | 跨平台 | 低 |
| `common/unix/UnixAfx.cpp` | 695, 717, 740 | Unix shell 命令输出读取（`popen()`） | Unix-like | 中 |
| `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp` | 84, 352, 598 | IPv6 路由管理 (`ip -6 route ...`) | Linux | 高 |
| `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp` | 148, 543 | IPv6 路由/邻居状态查询（`popen()`） | Linux | 中 |
| `linux/ppp/tap/TapLinux.cpp` | 257 (`ExecuteIpCommand`) | 统一的 `system()` 包装函数 | Linux | 高 |
| `linux/ppp/tap/TapLinux.cpp` | 684, 695 (`SetRouteToLinux`) | IPv4 路由管理 (`route add/delete`) | Linux | 高 |
| `linux/ppp/tap/TapLinux.cpp` | 408 (`QueryIPv6NeighborProxy`) | `popen()` 查询 sysctl | Linux | 中 |
| `linux/ppp/diagnostics/UnixStackTrace.cpp` | 33, 100 | `addr2line` 调用与输出读取 | Linux | 低 |
| `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` | 57, 92 | IPv6 路由状态查询（`popen()`） | macOS | 中 |
| `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` | 217, 238, 242, 271, 306, 414 | IPv6 路由管理 (`route -n inet6 ...`) | macOS | 高 |
| `darwin/ppp/tun/utun.cpp` | 143, 190, 223 | utun 接口配置 (`ifconfig`/`route`) | macOS | 中 |
| `windows/ppp/win32/Win32Native.cpp` | 777 | `system("pause")` | Windows | 低 |
| `windows/ppp/app/client/lsp/PaperAirplaneLspY.cpp` | 327 | `system("pause")` | Windows | 低 |

### 1.2 高风险路径特征

存在 shell 字符串拼接的高风险路径具有以下共性：

1. **动态参数拼接**：将接口名、IP 地址、前缀长度等运行时数据拼入 shell 命令字符串。
2. **阻塞 IO 线程**：`system()` 执行阻塞式 `fork()+exec()`，每次调用阻塞调用线程 10–100ms。调用方通常在 ASIO IO 线程回调中触发（如 `OnTick`、`AddIPv6Exchanger`）。
3. **部分路径有参数校验**：`TapLinux.cpp` 已有 `IsSafeShellToken()` 白名单校验（允许 `[a-zA-Z0-9:._\-%/]`），降低了 shell 注入风险，但其他文件（如 `LINUX_IPv6Auxiliary.cpp`）未统一使用该校验。

### 1.3 已有安全措施

`TapLinux.cpp` 中已实施的安全措施：

| 措施 | 位置 | 描述 |
|------|------|------|
| `IsSafeShellToken()` | 行 72–89 | 白名单字符集校验，拒绝含 shell 元字符的参数 |
| `ExecuteIpCommand()` | 行 251–264 | 统一的 `system()` 包装函数，含空命令检查和错误码设置 |
| Telemetry span | 多处 | `SpanScope` 包裹 add/delete 操作，记录执行时长 |
| Telemetry counter | 多处 | `Count()` 记录操作次数 |
| Telemetry histogram | 多处 | `Histogram()` 记录执行耗时分布 |
| Telemetry gauge | 多处 | `Gauge()` 记录活跃路由/代理数量 |
| Error codes | 多处 | `SetLastErrorCode()` 设置结构化错误码 |

---

## 2. 治理原则

### 2.1 核心约束

1. **不直接 fail-closed**：替换 `system()` 后的行为必须与当前行为等价或更安全。不得因替换导致原本成功的操作失败。
2. **保持兼容**：不改变 public API 签名，不改变调用方期望的返回值语义。
3. **分平台逐步替换**：不要求一次性替换所有平台的 `system()` 调用。每个平台可独立治理、独立验证。
4. **不阻断当前 release**：治理项不作为 P0 或当前 release 的阻断条件。

### 2.2 技术原则

| 原则 | 描述 |
|------|------|
| **优先封装命令构造** | 将命令参数构造逻辑与执行逻辑分离，便于审计和测试 |
| **参数白名单** | 对所有动态参数执行白名单校验（参考 `IsSafeShellToken()`） |
| **日志/telemetry** | 所有替换后的操作必须保留或增强现有的 telemetry 覆盖 |
| **避免 shell 注入** | 替换方案必须消除 shell 解释层，使用参数数组直接传入 exec |
| **替换目标** | Linux: `execve`/`posix_spawn` → `netlink` → `ioctl`；macOS: `posix_spawn` → `ioctl`/`route` API；Windows: `CreateProcess` 或平台 API |

### 2.3 不变性约束

- 不得在替换过程中改变操作语义（如 `route replace` 变为 `route add`）。
- 不得移除现有的 `IsSafeShellToken()` 校验（即使替换为 netlink/ioctl，校验仍可作为参数合法性守卫保留）。
- 不得降级 telemetry 覆盖（已有的 `Count`/`Histogram`/`Gauge`/`SpanScope` 必须保留）。

---

## 3. TapLinux 重点分析

### 3.1 TapLinux.cpp 中的 `system()` 调用分类

`TapLinux.cpp` 中的 `system()` 调用可分为两个逻辑边界：

#### 边界 A：route-add 边界（`SetRouteToLinux` 函数，行 647–705）

```cpp
static bool SetRouteToLinux(UInt32 address, int prefix, UInt32 gw, bool action_add_or_delete) noexcept {
    // ...
    if (action_add_or_delete) {
        int status = system(cmd);       // 行 684：单次 add
        // ...
    }

    bool any = false;
    for (;;) {
        int status = system(cmd);       // 行 695：循环 delete（直到无更多匹配）
        if (status != 0) { break; }
        else { any = true; }
    }
    return any;
}
```

特征：
- 通过 `route add/delete` 命令操作 IPv4 路由表。
- **delete 路径有循环**：`for(;;)` 循环调用 `system()` 直到失败，用于删除可能存在的多条匹配路由。
- 被 `AddRoute2`/`DeleteRoute2` 和 `AddRoute`/`DeleteRoute`（当 `ifc_ctl_sock_compatible_route=true` 时）调用。
- 无 telemetry 覆盖（无 `SpanScope`/`Count`/`Histogram`）。
- 无 `IsSafeShellToken()` 校验（参数来自 `IPEndPoint::ToAddressString()`，风险较低但非零）。

#### 边界 B：cleaner withdrawal 边界（`ExecuteIpCommand` 调用链）

通过 `ExecuteIpCommand()` 统一包装调用 `system()` 的操作：

| 函数 | 操作类型 | 用途 | 是否 withdrawal |
|------|----------|------|-----------------|
| `SetIPv6Address()` | add | 设置 IPv6 地址 | 否 |
| `DeleteIPv6Address()` | delete | 删除 IPv6 地址 | **是** |
| `AddRoute6()` | add | 添加 IPv6 路由 | 否 |
| `DeleteRoute6()` | delete | 删除 IPv6 路由 | **是** |
| `EnableIPv6NeighborProxy()` | enable | 启用 NDP 代理 | 否 |
| `DisableIPv6NeighborProxy()` | disable | 禁用 NDP 代理 | **是** |
| `AddIPv6NeighborProxy()` | add | 添加 NDP 代理条目 | 否 |
| `DeleteIPv6NeighborProxy()` | delete | 删除 NDP 代理条目 | **是** |
| `SetMtu()` | set | 设置 MTU | 否 |
| `QueryIPv6NeighborProxy()` | query | 查询 NDP 代理状态（`popen()`） | 否 |

### 3.2 为什么后续优先选择 cleaner withdrawal 边界

**决策：后续治理 TapLinux 时，优先选择 withdrawal（delete/disable）路径作为 pilot，而非 route-add 路径。**

理由如下：

#### 3.2.1 cleaner withdrawal 已有 clean one-shot management operation

Withdrawal 函数的执行模式是一次性操作（one-shot）：

```
DeleteIPv6Address()    →  ip -6 addr del <addr>/<prefix> dev <iface>
DeleteRoute6()         →  ip -6 route del <addr>/<prefix> dev <iface> [via <gw>]
DisableIPv6NeighborProxy()  →  sysctl -w net.ipv6.conf.<iface>.proxy_ndp=0
DeleteIPv6NeighborProxy()   →  ip -6 neigh del proxy <addr> dev <iface>
```

每个函数构造一条命令、执行一次、返回结果。没有循环、没有条件分支、没有重试逻辑。

相比之下，route-add 边界中的 `SetRouteToLinux()` 有以下复杂性：
- add/delete 两条路径在同一函数中，通过 `action_add_or_delete` 布尔参数分支。
- delete 路径有 `for(;;)` 循环，语义上是"删除所有匹配的路由"，替换为 netlink 时需要在用户空间实现等价的批量删除逻辑。
- 通过 `ifc_ctl_sock_compatible_route` 全局变量选择是否走 `SetRouteToLinux`（`route` 命令）还是 `SetRoute`（`ioctl`），两条路径语义不完全等价。

#### 3.2.2 cleaner withdrawal 可复用既有 add-path telemetry 模板

Withdrawal 函数可复用现有 add-path telemetry 模板，且部分 withdrawal 函数已有 telemetry 基础，为后续替换提供了可观测性对比起点：

| Withdrawal 函数 | 现有 telemetry |
|-----------------|----------------|
| `DeleteRoute6()` | `Log(kDebug)` + 无 SpanScope（但 `AddRoute6()` 有 `SpanScope("tap.ipv6.route.add")` + `Count` + `Histogram` + `Gauge`） |
| `DeleteIPv6NeighborProxy()` | `SpanScope("tap.ipv6.neighbor.delete")` + `Log(kDebug)` + `Histogram("tap.ipv6.neighbor.delete.us")` |
| `DisableIPv6NeighborProxy()` | `SpanScope("tap.ipv6.neighbor.proxy.disable")` + `Histogram("tap.ipv6.neighbor.proxy.disable.us")` |
| `DeleteIPv6Address()` | 无 telemetry（但 `SetIPv6Address()` 有 `SpanScope("tap.ipv6.address.set")` + `Histogram`） |

**注意**：`DeleteRoute6()` 和 `DeleteIPv6Address()` 的 telemetry 覆盖不完整。治理时应**先补齐 withdrawal 函数的 telemetry**（添加 `SpanScope`/`Count`/`Histogram`），再进行 `system()` 替换。这样可以：
1. 在替换前建立性能基线。
2. 替换后通过对比 telemetry 数据验证行为等价性。
3. 即使暂不替换 `system()`，补齐 telemetry 本身也是有价值的改进。

`AddRoute6()` 的完整 telemetry 覆盖（`SpanScope` + `Count` + `Histogram` + `Gauge` + `Log`）可作为 withdrawal 函数补齐 telemetry 的模板。

#### 3.2.3 withdrawal 路径的替换风险更低

| 维度 | withdrawal 边界 | route-add 边界 |
|------|-----------------|----------------|
| 操作语义 | 删除/禁用（幂等） | 添加/创建（需处理已存在） |
| 失败后果 | 路由/代理残留，下次清理可重试 | 路由缺失，可能影响连通性 |
| 回滚难度 | 重新执行 add 命令即可 | 需要知道之前的路由状态 |
| netlink 替换复杂度 | 单条 `RTM_DELROUTE` / `RTM_DELNEIGH` 消息 | 需处理 `NLM_F_REPLACE` 语义、metric、flags |
| 验证方法 | 检查路由/代理不存在即可 | 需检查路由/代理存在且属性正确 |

#### 3.2.4 决策总结

| 决策 | 选择 | 理由 |
|------|------|------|
| TapLinux pilot 范围 | withdrawal 边界 | one-shot 操作、已有 telemetry 基线、替换风险低 |
| 首批替换函数 | `DeleteRoute6()`、`DeleteIPv6NeighborProxy()`、`DisableIPv6NeighborProxy()`、`DeleteIPv6Address()` | 操作语义简单、幂等、可独立验证 |
| route-add 边界 | 暂不替换，作为第二批 | 需要更多设计（`SetRouteToLinux` 循环删除语义、`ifc_ctl_sock_compatible_route` 分支） |
| `SetMtu()` / `SetIPv6Address()` / `AddRoute6()` 等 | 第二批或第三批 | 与 withdrawal 使用相同的替换技术，可复用 wrapper |

### 3.3 TapLinux 现有安全措施评估

| 措施 | 当前状态 | 治理后是否保留 |
|------|----------|----------------|
| `IsSafeShellToken()` | 有效，白名单 `[a-zA-Z0-9:._\-%/]` | 保留（即使替换为 netlink，仍可作为参数合法性守卫） |
| `ExecuteIpCommand()` | 统一包装，含空命令检查 | 替换为 netlink 后该函数将逐步废弃 |
| `SetRouteToLinux()` 中的地址参数 | 来自 `IPEndPoint::ToAddressString()`，格式受控 | 保留 |
| `popen()` in `QueryIPv6NeighborProxy()` | 读取 sysctl 值，参数已校验 | 替换为直接读取 `/proc/sys/net/ipv6/conf/<iface>/proxy_ndp` |

---

## 4. 全仓治理方案

### 4.1 替换目标矩阵

| 平台 | 当前机制 | 替换目标 | 优先级 |
|------|----------|----------|--------|
| **Linux IPv4 路由** | `system("route ...")` / `ioctl(SIOCADDRT)` | `ioctl(SIOCADDRT/SIOCDELRT)`（`SetRoute()` 已有实现） | 高 |
| **Linux IPv6 路由/地址** | `system("ip -6 ...")` | `netlink`（`RTM_NEWROUTE`/`RTM_DELROUTE`/`RTM_NEWADDR`/`RTM_DELADDR`） | 高 |
| **Linux NDP 代理** | `system("ip -6 neigh ...")` / `system("sysctl ...")` | `netlink`（`RTM_NEWNEIGH`/`RTM_DELNEIGH`） / 直接读写 `/proc/sys/` | 高 |
| **Linux MTU** | `system("ip link set ...")` | `ioctl(SIOCSIFMTU)`（`SetInterfaceMtu()` 已有实现） | 中 |
| **macOS 路由/接口** | `system("route ...")` / `system("ifconfig ...")` | `posix_spawn` + 参数数组 → 后续考虑 `route` API / `ioctl` | 中 |
| **macOS utun** | `system("ifconfig/route")` | `posix_spawn` + 参数数组 | 中 |
| **跨平台网络切换** | `system()` shell 命令 | `posix_spawn`（Linux/macOS）/ `CreateProcess`（Windows） | 低 |
| **Windows pause/cls** | `system("pause")` / `system("cls")` | 低风险，可保留或替换为平台 API | 低 |
| **Linux addr2line** | `system()` / `popen()` | `posix_spawn` + 参数数组（调试路径，低优先级） | 低 |

### 4.2 Wrapper 层设计

#### 4.2.1 `ExecuteIpCommand()` 替换方案

当前 `ExecuteIpCommand()` 是 `system()` 的统一包装。替换方案分两层：

**第一层（短期）**：将 `system()` 替换为 `posix_spawn()`，保留 shell 命令构造逻辑但消除 shell 解释层：

```cpp
// 概念示意，非最终实现
static bool ExecuteIpCommandEx(const char* argv[], int argc, ErrorCode failure_code) noexcept {
    pid_t pid;
    int status = posix_spawn(&pid, argv[0], nullptr, nullptr, const_cast<char**>(argv), environ);
    if (status != 0) { ... }
    waitpid(pid, &status, 0);
    // ...
}
```

**第二层（中期）**：为每个操作类别实现专用的 netlink/ioctl wrapper：

```cpp
// 概念示意，非最终实现
namespace ppp::tap::netlink {
    bool AddIPv6Route(const char* iface, const char* addr, int prefix, const char* gw) noexcept;
    bool DelIPv6Route(const char* iface, const char* addr, int prefix, const char* gw) noexcept;
    bool AddIPv6Address(const char* iface, const char* addr, int prefix) noexcept;
    bool DelIPv6Address(const char* iface, const char* addr, int prefix) noexcept;
    bool AddNDPProxy(const char* iface, const char* addr) noexcept;
    bool DelNDPProxy(const char* iface, const char* addr) noexcept;
}
```

#### 4.2.2 参数白名单

`IsSafeShellToken()` 当前允许的字符集：`[a-zA-Z0-9:._\-%/]`。

替换为 netlink/ioctl 后，参数不再经过 shell 解释，但仍应保留白名单校验作为防御性编程：
- IPv6 地址：`[a-fA-F0-9:]`
- 接口名：`[a-zA-Z0-9._\-]`（Linux 接口名限制）
- 前缀长度：整数范围校验 `[0, 128]`
- MTU：整数范围校验 `[1280, 9000]`

### 4.3 `SetRouteToLinux()` 特殊处理

`SetRouteToLinux()` 的 delete 路径（行 693–704）有循环删除语义：

```cpp
for (;;) {
    int status = system(cmd);
    if (status != 0) { break; }
    else { any = true; }
}
```

这表示"删除所有匹配的路由条目，直到 `route delete` 返回非零"。替换为 netlink 时有两种选择：

| 方案 | 描述 | 复杂度 |
|------|------|--------|
| **A. Netlink 批量删除** | 发送 `RTM_DELROUTE` 并设置 `NLM_F_MATCH` 标志（如果内核支持），或先 `RTM_GETROUTE` 列举所有匹配条目再逐一删除 | 中 |
| **B. 保留 `posix_spawn` 过渡** | 短期内用 `posix_spawn("route", ...)` 替换 `system()`，消除 shell 解释层但保留命令行工具依赖 | 低 |

**建议**：方案 B 作为过渡，方案 A 作为长期目标。

---

## 5. 分阶段计划

### Phase 0：Inventory（清点与风险分级）

| 步骤 | 描述 | 产出 | 前置条件 |
|------|------|------|----------|
| 0.1 | 确认全仓 `system()`/`popen()` 调用清单（grep 验证） | 完整调用清单表（本文档 §1.1 仅为草案） | 无 |
| 0.2 | 为每个调用点标注风险级别（高/中/低） | 完整风险矩阵（本文档 §1.1 仅为草案） | 无 |
| 0.3 | 确认每个调用点的调用线程（IO 线程 / 专用线程 / 启动路径） | 线程模型标注 | 代码审计 |
| 0.4 | 确认每个调用点的现有 telemetry 覆盖 | telemetry 缺口列表 | 代码审计 |

**当前状态**：§0.1–0.2 已形成草案但需实施前重新生成和复核。§0.3–0.4 需在实施前补充。

### Phase 1：补齐 Telemetry 基线

| 步骤 | 描述 | 优先级 |
|------|------|--------|
| 1.1 | 为 `DeleteRoute6()` 添加 `SpanScope`、`Count`、`Histogram`、`Gauge` | 高 |
| 1.2 | 为 `DeleteIPv6Address()` 添加 `SpanScope`、`Count`、`Histogram` | 高 |
| 1.3 | 为 `SetRouteToLinux()` 添加 `SpanScope`、`Count`、`Histogram` | 中 |
| 1.4 | 为 `LINUX_IPv6Auxiliary.cpp` 中的 `system()` 调用添加 telemetry | 中 |

**注意**：补齐 telemetry 本身不替换 `system()`，是低风险的独立改进，可先行实施。

### Phase 2：TapLinux Pilot — Cleaner Withdrawal 边界

| 步骤 | 描述 | 替换技术 | 验证方法 |
|------|------|----------|----------|
| 2.1 | `DeleteIPv6Address()` → netlink `RTM_DELADDR` | netlink | 对比 telemetry + 手动检查 `ip -6 addr show` |
| 2.2 | `DeleteRoute6()` → netlink `RTM_DELROUTE` | netlink | 对比 telemetry + 手动检查 `ip -6 route show` |
| 2.3 | `DeleteIPv6NeighborProxy()` → netlink `RTM_DELNEIGH` | netlink | 对比 telemetry + 手动检查 `ip -6 neigh show proxy` |
| 2.4 | `DisableIPv6NeighborProxy()` → 直接写 `/proc/sys/net/ipv6/conf/<iface>/proxy_ndp` | procfs | 对比 telemetry + 手动检查 `sysctl net.ipv6.conf.<iface>.proxy_ndp` |
| 2.5 | `QueryIPv6NeighborProxy()` → 直接读 `/proc/sys/net/ipv6/conf/<iface>/proxy_ndp` | procfs | 对比 `popen()` 输出 |

**前置条件**：

| 序号 | 条件 | 当前状态 |
|------|------|----------|
| C-1 | Phase 1 telemetry 基线补齐 | ❌ 未开始 |
| C-2 | netlink wrapper 库实现（至少 `RTM_DELROUTE`/`RTM_DELADDR`/`RTM_DELNEIGH`） | ❌ 未开始 |
| C-3 | Linux 手动验证环境 | ⚠️ 需确认 |

### Phase 3：TapLinux 扩展 — Add 边界 + SetMtu

> **定位：Phase 3 是 Phase 2（cleaner withdrawal 边界）的后续扩展，不是并行任务。**
>
> 与 cleaner withdrawal 边界的顺序关系：
>
> | 顺序 | 阶段 | 范围 | 当前优先级 |
> |------|------|------|------------|
> | 1 | **Phase 2** | cleaner withdrawal 边界（`DeleteRoute6`、`DeleteIPv6Address`、`DeleteIPv6NeighborProxy`、`DisableIPv6NeighborProxy`、`QueryIPv6NeighborProxy`） | **当前优先** |
> | 2 | **Phase 3** | add 边界 + `SetMtu` + `SetRouteToLinux`（后续扩展） | **Phase 2 完成后启动** |
>
> Phase 2 选择 withdrawal 路径作为 pilot 的理由已在 §3.2 中详述（one-shot 操作、已有 telemetry 基线、替换风险低、幂等语义）。Phase 3 中的 add 路径引入了更复杂的语义（`ip -6 route replace` 替换语义、`NLM_F_REPLACE` 标志、已存在条目的处理），因此必须在 Phase 2 的 netlink wrapper 和验证模式成熟后再行推进。
>
> **当前状态**：Phase 3 尚未启动。以下为设计层面的实施检查清单，不构成代码变更。

#### 3.P3-0 前置条件（Phase 3 启动前必须满足）

| 序号 | 前置条件 | 说明 | 依赖 |
|------|----------|------|------|
| P3-C1 | **Phase 2 全部步骤完成并通过验收** | Phase 2 的 netlink wrapper（`RTM_DELROUTE`/`RTM_DELADDR`/`RTM_DELNEIGH`）已稳定运行 | Phase 2 |
| P3-C2 | **Phase 2 netlink wrapper 扩展支持 add 操作** | 在 Phase 2 的 `RTM_DEL*` wrapper 基础上，增加 `RTM_NEWROUTE`/`RTM_NEWADDR`/`RTM_NEWNEIGH` 支持 | P3-C1 |
| P3-C3 | **`replace` 语义的 netlink 实现验证** | `AddRoute6()` 使用 `ip -6 route replace`，netlink 等价操作需要 `NLM_F_REPLACE` 或先 GET 再 DEL+NEW。必须验证内核版本兼容性 | P3-C2 |
| P3-C4 | **ioctl `SIOCSIFMTU` 路径验证** | 确认 `SetInterfaceMtu()`（已有 ioctl 实现）在所有目标内核版本上可正常工作 | 代码审计 |
| P3-C5 | **`SetRouteToLinux()` 的 IPv4 路由语义分析** | 确认 `route add -host/-net` 与 `SIOCADDRT` ioctl 的行为等价性，特别是 metric、flags 差异 | 代码审计 |
| P3-C6 | **Phase 2 telemetry 对比基线已收集** | Phase 2 替换前后的 telemetry 数据对比结果可接受，证明 netlink wrapper 的可靠性 | Phase 2 验收 |

#### 3.P3-1 实施检查清单：`AddRoute6()` → netlink `RTM_NEWROUTE`

| 检查项 | 描述 | 状态 |
|--------|------|------|
| P3-1.1 | 复用 Phase 2 的 netlink socket 管理（socket 创建、绑定、错误处理） | 待实施 |
| P3-1.2 | 实现 `RTM_NEWROUTE` 消息构造，支持以下变体：default route、带 `via` 的路由、不带 `via` 的路由 | 待实施 |
| P3-1.3 | 处理 `replace` 语义：使用 `NLM_F_REPLACE | NLM_F_CREATE` 标志，或先 `RTM_GETROUTE` 检查再决定 NEW/REPLACE | 待实施 |
| P3-1.4 | 处理 `onlink` 标志（`ip -6 route replace ... via ... onlink`）：netlink 中对应 `RTNH_F_ONLINK` | 待实施 |
| P3-1.5 | 保留现有 telemetry：`SpanScope("tap.ipv6.route.add")` + `Count("tap.ipv6.route.add")` + `Histogram("tap.ipv6.route.add.us")` + `Gauge("tap.ipv6_routes")` + `Log(kDebug)` | 待实施 |
| P3-1.6 | 保留 `IsSafeShellToken()` 参数校验（作为防御性守卫） | 待实施 |
| P3-1.7 | 保留 `SetLastErrorCode(ErrorCode::RouteReplaceFailed)` 错误码设置 | 待实施 |
| P3-1.8 | netlink 失败时回退到 `ExecuteIpCommand()`（过渡期安全网，可选） | 待评估 |

**复杂度说明**：`AddRoute6()` 当前有 4 种命令变体（default/non-default × with/without gateway），且使用 `replace` 语义而非 `add`。netlink 的 `NLM_F_REPLACE` 标志在内核 4.x+ 支持，但需验证 3.x 内核（Android）的兼容性。

#### 3.P3-2 实施检查清单：`SetIPv6Address()` → netlink `RTM_NEWADDR`

| 检查项 | 描述 | 状态 |
|--------|------|------|
| P3-2.1 | 实现 `RTM_NEWADDR` 消息构造，携带 `IFA_ADDRESS` + `IFA_LOCAL` 属性 | 待实施 |
| P3-2.2 | 处理 `replace` 语义：`ip -6 addr replace` 对应 netlink `NLM_F_REPLACE | NLM_F_CREATE` | 待实施 |
| P3-2.3 | 前缀长度范围校验保留：`IPv6_MIN_PREFIX_LENGTH` ≤ prefix ≤ `IPv6_MAX_PREFIX_LENGTH` | 待实施 |
| P3-2.4 | 保留现有 telemetry：`SpanScope("tap.ipv6.address.set")` + `Histogram("tap.ipv6.address.set.us")` | 待实施 |
| P3-2.5 | 保留 `IsSafeShellToken()` 参数校验 + `SetLastErrorCode(ErrorCode::TunnelAddressConfigureFailed)` | 待实施 |

#### 3.P3-3 实施检查清单：`AddIPv6NeighborProxy()` → netlink `RTM_NEWNEIGH`

| 检查项 | 描述 | 状态 |
|--------|------|------|
| P3-3.1 | 实现 `RTM_NEWNEIGH` 消息构造，设置 `NTF_PROXY` 标志 | 待实施 |
| P3-3.2 | 使用 `NLM_F_REPLACE` 实现 `ip -6 neigh replace proxy` 语义 | 待实施 |
| P3-3.3 | 保留现有 telemetry：`SpanScope("tap.ipv6.neighbor.add")` + `Count` + `Histogram` + `Gauge` + `Log(kDebug)` | 待实施 |
| P3-3.4 | 保留 `IsSafeShellToken()` 参数校验 + `SetLastErrorCode(ErrorCode::IPv6NDPProxyFailed)` | 待实施 |

#### 3.P3-4 实施检查清单：`EnableIPv6NeighborProxy()` → 直接写 procfs

| 检查项 | 描述 | 状态 |
|--------|------|------|
| P3-4.1 | 将 `sysctl -w net.ipv6.conf.<iface>.proxy_ndp=1` 替换为直接写 `/proc/sys/net/ipv6/conf/<iface>/proxy_ndp` | 待实施 |
| P3-4.2 | 写入值为 `"1"`，使用 `open()` + `write()` + `close()`，无需 fork | 待实施 |
| P3-4.3 | 保留现有 telemetry：`SpanScope("tap.ipv6.neighbor.proxy.enable")` + `Histogram` | 待实施 |
| P3-4.4 | 错误处理：`open()` 失败 → `SetLastErrorCode(IPv6NDPProxyFailed)`；`write()` 返回值校验 | 待实施 |
| P3-4.5 | 接口名安全校验保留（procfs 路径注入风险虽低但应防御） | 待实施 |

**注意**：Phase 2 的 `DisableIPv6NeighborProxy()` 已使用相同技术（写 procfs `=0`），Phase 3.4 直接复用 Phase 2 的 wrapper，仅改变写入值。

#### 3.P3-5 实施检查清单：`SetMtu()` → `ioctl(SIOCSIFMTU)`

| 检查项 | 描述 | 状态 |
|--------|------|------|
| P3-5.1 | 将 `ip link set dev <iface> mtu <mtu>` 替换为 `ioctl(sock, SIOCSIFMTU, &ifr)` | 待实施 |
| P3-5.2 | 复用或参考 `SetInterfaceMtu()`（已有的 ioctl 实现）的模式 | 待实施 |
| P3-5.3 | MTU 范围校验保留：`std::max(1280, std::min(9000, mtu))` | 待实施 |
| P3-5.4 | 保留 `IsSafeShellToken()` 接口名校验 | 待实施 |
| P3-5.5 | 错误处理：`ioctl()` 失败 → `SetLastErrorCode(TunnelMtuConfigureFailed)` | 待实施 |
| P3-5.6 | 考虑添加 telemetry：当前 `SetMtu()` 无 `SpanScope`/`Histogram`，治理时可顺便补齐 | 待评估 |

**复杂度说明**：`SetMtu()` 是所有 Phase 3 步骤中最简单的——单一 ioctl 调用、无 replace 语义、无循环。可作为 Phase 3 的低风险验证点；但 Phase 3 的治理边界仍是 TapLinux add 路径扩展，且必须在 Phase 2 cleaner withdrawal boundary 完成后再启动。

#### 3.P3-6 实施检查清单：`SetRouteToLinux()` → posix_spawn 过渡 / netlink 最终

| 检查项 | 描述 | 状态 |
|--------|------|------|
| P3-6.1 | **过渡方案**：将 `system(cmd)` 替换为 `posix_spawn()` + 参数数组，消除 shell 解释层 | 待实施 |
| P3-6.2 | 参数数组构造：`["route", action, "-host"/"-net", addr, "gw", gw]` 或 `["route", action, "-net", addr, "netmask", mask, "gw", gw]` | 待实施 |
| P3-6.3 | **delete 路径循环语义保留**：`for(;;)` 循环调用 `posix_spawn()` 直到失败，语义不变 | 待实施 |
| P3-6.4 | 最终方案：替换为 `ioctl(SIOCADDRT/SIOCDELRT)`，复用 `SetRoute()` 已有实现 | 待实施 |
| P3-6.5 | 验证 `ifc_ctl_sock_compatible_route` 分支路径的行为一致性 | 待实施 |
| P3-6.6 | 补齐 telemetry：当前 `SetRouteToLinux()` 无 `SpanScope`/`Count`/`Histogram` | 待实施 |

**复杂度说明**：`SetRouteToLinux()` 是 Phase 3 中最复杂的步骤。`for(;;)` 循环删除语义在 netlink 中没有直接等价操作（需先 `RTM_GETROUTE` 列举再逐一 `RTM_DELROUTE`）。建议使用 posix_spawn 过渡，最终迁移到 `ioctl(SIOCADDRT/SIOCDELRT)`（与 `SetRoute()` 统一）。

#### 3.P3-7 实施顺序建议

基于复杂度递增原则，建议以下实施顺序：

| 顺序 | 步骤 | 复杂度 | 理由 |
|------|------|--------|------|
| 1 | 3.P3-5 `SetMtu()` → ioctl | 低 | 单一 ioctl、无 replace 语义、有 `SetInterfaceMtu()` 参考 |
| 2 | 3.P3-4 `EnableIPv6NeighborProxy()` → procfs | 低 | 直接复用 Phase 2 的 procfs wrapper |
| 3 | 3.P3-2 `SetIPv6Address()` → netlink | 中 | replace 语义，但模式与 Phase 2 的 `RTM_DELADDR` 对称 |
| 4 | 3.P3-3 `AddIPv6NeighborProxy()` → netlink | 中 | replace + proxy 标志，模式与 Phase 2 的 `RTM_DELNEIGH` 对称 |
| 5 | 3.P3-1 `AddRoute6()` → netlink | 高 | 4 种变体 + replace + onlink 标志 |
| 6 | 3.P3-6 `SetRouteToLinux()` → posix_spawn/netlink | 高 | 循环删除语义 + IPv4 特殊性 |

#### 3.P3-8 回滚要点

| 步骤 | 回滚方法 | 回滚影响 | 恢复难度 |
|------|----------|----------|----------|
| 3.P3-5 `SetMtu()` | 恢复 `system("ip link set ...")` 调用 | MTU 设置回退为 shell 命令 | 低，需复验 |
| 3.P3-4 `EnableIPv6NeighborProxy()` | 恢复 `system("sysctl -w ...")` 调用 | NDP 代理启用回退为 shell 命令 | 低，需复验 |
| 3.P3-2 `SetIPv6Address()` | 恢复 `system("ip -6 addr replace ...")` 调用 | IPv6 地址设置回退为 shell 命令 | 低，需复验 |
| 3.P3-3 `AddIPv6NeighborProxy()` | 恢复 `system("ip -6 neigh replace proxy ...")` 调用 | NDP 代理添加回退为 shell 命令 | 低，需复验 |
| 3.P3-1 `AddRoute6()` | 恢复 `system("ip -6 route replace ...")` 调用 | IPv6 路由添加回退为 shell 命令 | 低到中，需复验 |
| 3.P3-6 `SetRouteToLinux()` | 恢复 `system("route ...")` 调用 | IPv4 路由操作回退为 shell 命令 | 中，需复验循环删除语义 |

**Phase 3 回滚预期低风险**：`system()` 是当前的已知工作实现，回滚会恢复到当前已知行为。每个函数的替换应设计为可独立回滚；回滚后仍需在目标环境复跑功能、telemetry 和错误码验收，避免命令路径、权限、内核状态或并发路由状态差异带来误判。

**与 Phase 2 回滚的顺序关系**：如果 Phase 2 已完成替换且回滚 Phase 3 某个函数，不会影响 Phase 2 的替换状态。两个 Phase 的回滚是正交的。

#### 3.P3-9 验收要点

| 验收项 | 验收方法 | 判定标准 |
|--------|----------|----------|
| **功能等价性** | 对比替换前后的路由/地址/代理状态 | `ip -6 addr show`、`ip -6 route show`、`ip -6 neigh show proxy` 输出一致 |
| **telemetry 等价性** | 对比替换前后的 SpanScope/Count/Histogram/Gauge 数据 | 操作耗时分布无显著变化（允许 netlink 略快于 system()） |
| **错误码一致性** | 注入失败场景（如无效接口名），验证 `GetLastErrorCode()` 返回值 | 错误码与替换前一致 |
| **参数校验保留** | 传入含 shell 元字符的参数，验证 `IsSafeShellToken()` 仍拒绝 | 返回 false，不执行操作 |
| **IO 线程阻塞改善** | 测量替换前后 IO 线程的阻塞时间 | netlink/procfs/ioctl 路径应显著低于 `system()`，具体阈值以目标环境基线为准 |
| **`SetRouteToLinux` 循环语义** | 创建多条匹配路由，验证 delete 路径全部清除 | 替换前后行为一致 |
| **回滚验证** | 执行回滚后重新运行上述验收项 | 回滚后恢复到当前已知 `system()` 行为，并通过同一验收集 |

**验收前提**：验收项中的"对比"操作需要在相同网络拓扑、相同内核版本下进行。建议使用 TUN 接口 + 固定路由配置的自动化脚本。

### Phase 4：其他平台

| 步骤 | 描述 | 替换技术 |
|------|------|----------|
| 4.1 | `LINUX_IPv6Auxiliary.cpp` → netlink | netlink |
| 4.2 | `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` → `posix_spawn` | posix_spawn |
| 4.3 | `darwin/ppp/tun/utun.cpp` → `posix_spawn` | posix_spawn |
| 4.4 | `VEthernetNetworkSwitcher.cpp` → `posix_spawn`/`CreateProcess` | 平台 API |
| 4.5 | 低风险项（`pause`/`cls`/`addr2line`）评估是否值得替换 | 待评估 |

### Phase 5：清理

| 步骤 | 描述 |
|------|------|
| 5.1 | 废弃 `ExecuteIpCommand()` 函数 |
| 5.2 | 废弃 `SetRouteToLinux()` 函数（如果已被 netlink 完全替代） |
| 5.3 | 更新 `IsSafeShellToken()` 文档，说明其作为参数合法性守卫的新角色 |
| 5.4 | 更新本文档状态为"已完成" |

---

## 6. 回滚策略

### 6.1 逐函数回滚

每个 Phase 中的每个函数替换都是独立的。如果某个函数的替换引入问题，可以单独回滚该函数，不影响其他已替换的函数。

### 6.2 回滚方法

1. **代码回滚**：`git revert` 对应的提交。
2. **运行时回滚**：不实现运行时开关（避免增加复杂度）。如果需要紧急回滚，通过重新部署旧版本二进制实现。
3. **telemetry 对比**：替换前后的 telemetry 数据对比是验证等价性的主要手段。如果替换后 telemetry 数据出现异常（如操作耗时显著增加、失败率上升），应触发回滚评估。

### 6.3 回滚影响评估

| 被替换函数 | 回滚影响 | 恢复难度 |
|------------|----------|----------|
| `DeleteRoute6()` | 路由删除回退为 `system()` | 低，需复验行为等价 |
| `DeleteIPv6NeighborProxy()` | NDP 代理删除回退为 `system()` | 低，需复验 |
| `DisableIPv6NeighborProxy()` | NDP 代理禁用回退为 `system()` | 低，需复验 |
| `DeleteIPv6Address()` | IPv6 地址删除回退为 `system()` | 低，需复验 |
| `SetMtu()`（Phase 3） | MTU 设置回退为 `system()` | 低，需复验 |
| `EnableIPv6NeighborProxy()`（Phase 3） | NDP 代理启用回退为 `system()` | 低，需复验 |
| `SetIPv6Address()`（Phase 3） | IPv6 地址设置回退为 `system()` | 低，需复验 |
| `AddIPv6NeighborProxy()`（Phase 3） | NDP 代理添加回退为 `system()` | 低，需复验 |
| `AddRoute6()`（Phase 3） | IPv6 路由添加回退为 `system()` | 低到中，需复验 |
| `SetRouteToLinux()`（Phase 3） | IPv4 路由操作回退为 `system()` | 中，需复验循环删除语义 |

所有 withdrawal 函数（Phase 2）和 add 边界函数（Phase 3）的回滚都应恢复到当前已知 `system()` 行为，预期风险较低，但仍需在目标环境复跑验收。Phase 2 与 Phase 3 的回滚应保持正交——回滚 Phase 3 不影响 Phase 2 的替换状态，反之亦然。

---

## 7. 风险评估

| 风险 | 级别 | 缓解措施 |
|------|------|----------|
| netlink 消息构造错误导致路由操作失败 | 中 | 先在非生产环境验证；保留 telemetry 对比基线 |
| netlink socket 权限不足（Android VpnService 环境） | 中 | Phase 2 前验证 Android netlink 可用性；不可用时保留 `posix_spawn` 过渡方案 |
| procfs 路径在某些 Linux 发行版上不存在 | 低 | `proxy_ndp` sysctl 在主流支持 IPv6 的 Linux 上通常可用，但 Phase 2/3 启动前仍需在目标环境验证 |
| `posix_spawn` 替换 `system()` 后环境变量差异 | 低 | 显式传递 `environ`；验证 `PATH` 包含 `ip`/`route` 命令路径 |
| 替换过程中引入新的阻塞行为 | 低 | netlink/procfs 路径预期显著低于 `system()`，但必须以目标环境 telemetry 基线验证 |
| `SetRouteToLinux()` 循环删除语义在 netlink 中等价实现不完整 | 中 | Phase 3.P3-6 使用 `posix_spawn` 过渡，不要求立即实现 netlink 批量删除 |
| **Phase 3：`NLM_F_REPLACE` 在旧内核（<4.x）上不支持** | 中 | Phase 3 启动前验证目标内核版本；不支持时使用 GET+DEL+NEW 三步替代 |
| **Phase 3：`AddRoute6()` 的 `onlink` 标志在 netlink 中映射不完整** | 低 | `RTNH_F_ONLINK` 在主流内核上支持；需验证 Android 内核 |
| **Phase 3：`SetRouteToLinux()` 的 `route add -net netmask` 与 `SIOCADDRT` 语义差异** | 中 | 需详细对比 metric、flags、loopback 行为；建议 posix_spawn 过渡 |

---

## 8. 与现有代码的关系

### 8.1 不改变的代码

- `IsSafeShellToken()`：保留，作为参数合法性守卫。
- `ExecuteIpCommand()`：在 Phase 2 中逐步被绕过，Phase 5 中废弃。
- `SetRoute()`（ioctl 路径）：不受影响，这是已有的非 `system()` 实现。
- `SetInterfaceMtu()`（ioctl 路径）：不受影响。

### 8.2 不触碰的领域

- 不修改 DNS/CompletionState/ICMP/SSL/TLS 相关代码或文档。
- 不修改 `ppp/app/client/VEthernetNetworkSwitcher.cpp`（跨平台，Phase 4）。
- 不修改 `darwin/` 或 `windows/` 平台代码（Phase 4）。
- 不修改构建系统（CMakeLists.txt）。

---

## 9. 前置条件与触发条件

### 实施前置条件

| 序号 | 条件 | 说明 | 适用阶段 | 当前状态 |
|------|------|------|----------|----------|
| C-1 | Phase 1 telemetry 基线补齐 | withdrawal 函数的 telemetry 覆盖完整 | Phase 2+ | ❌ 未开始 |
| C-2 | netlink wrapper 库存在 | 至少覆盖 `RTM_DELROUTE`/`RTM_DELADDR`/`RTM_DELNEIGH` | Phase 2+ | ❌ 未开始 |
| C-3 | Linux 手动验证环境 | 可创建 TUN 接口并验证路由操作 | Phase 2+ | ⚠️ 需确认 |
| C-4 | Android netlink 可用性验证 | 确认 `VpnService` 环境下 netlink socket 可用 | Phase 2+ | ❌ 未验证 |
| C-5 | Phase 2 全部步骤完成并通过验收 | Phase 2 的 netlink wrapper 已稳定运行 | **Phase 3** | ❌ 未开始 |
| C-6 | netlink wrapper 扩展支持 add 操作 | 在 `RTM_DEL*` 基础上增加 `RTM_NEWROUTE`/`RTM_NEWADDR`/`RTM_NEWNEIGH` | **Phase 3** | ❌ 未开始 |
| C-7 | `replace` 语义的 netlink 实现验证 | `NLM_F_REPLACE` 在目标内核版本（含 Android 3.x）上兼容性验证 | **Phase 3** | ❌ 未开始 |
| C-8 | `ioctl(SIOCSIFMTU)` 路径验证 | 确认 `SetInterfaceMtu()` 在所有目标内核版本上正常工作 | **Phase 3** | ❌ 未开始 |
| C-9 | Phase 2 telemetry 对比基线已收集 | Phase 2 替换前后 telemetry 数据对比结果可接受 | **Phase 3** | ❌ 未开始 |

### 触发条件

| 触发条件 | 动作 |
|----------|------|
| 引入基本集成测试框架 | 可开始 Phase 2 |
| 发现 `system()` 路径被利用的安全事件 | 提升治理优先级 |
| Android 用户报告路由操作阻塞 IO 线程 | 提升 Phase 2 优先级 |
| 维护者确认开始 P1-8 治理 | 启动 Phase 0.3–0.4 |
| Phase 2 全部验收通过 | 可开始 Phase 3（按 §3.P3-7 建议顺序） |
| Phase 3 需求变更（如新增 IPv6 路由操作） | 重新评估 Phase 3 范围 |

---

## 10. 当前约束

- **本文档是设计文档，不触发代码变更。**
- **不得声称已替换 `system()` / `popen()`。**
- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该项的代码改动。
- 实施时必须保持所有 public API 签名不变。
- 实施时必须保持或增强现有 telemetry 覆盖。

---

*创建时间：2026-05-12*
*关联治理项：`docs/p1-governance-decisions-cn.md` §1.8（P1-8）*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §3.8、§8 P1 第 8 项*
