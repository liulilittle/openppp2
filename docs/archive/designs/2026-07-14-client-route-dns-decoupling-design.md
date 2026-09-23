# Client Route/DNS 模块解耦设计

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> Status: Approved
> Type: Design
> Owner: Client networking
> Created: 2026-07-14
> Last verified: 5bcccce
> Related objective: 解耦模块，使其各司其职

## 1. 背景

当前客户端已经完成 UDP 会话表和端口能力的初步抽离，但路由与 DNS 仍以
`VEthernetNetworkSwitcher` 为状态仓库和隐式服务定位器：

- Switcher 直接拥有 RIB、FIB、默认路由、网卡映射、DNS Server 集合和应用状态；
- `RouteHostPorts` 用二十余个回调暴露宿主字段，并返回可变容器裸指针；
- `DnsHostPortsFor()` 返回缓存对象引用，锁释放后 teardown 可以销毁该对象；
- DNS 接口出现具体 `VEthernetNetworkSwitcher` / `VEthernetExchanger` 类型；
- 部分模块以无操作 deleter 构造 `shared_ptr`，类型表达的所有权与真实生命周期不一致。

这些问题使文件虽然分开，职责和生命周期仍然耦合。本设计先完成客户端 Route/DNS
领域的真实解耦，并建立后续拆分 Exchanger、VMUX 的边界规则。

## 2. 目标与非目标

### 2.1 目标

1. Switcher 只负责组装、启动、停止和模块间协调，不再保存 Route/DNS 领域状态。
2. Route 模块独占路由状态、事务应用与回滚流程。
3. DNS 模块独占 DNS 拦截器、可达地址和会话上下文。
4. 平台路由调用通过操作型接口隔离，协调逻辑不包含平台实现。
5. 公共边界不暴露可变容器裸指针、具体宿主类型或伪共享所有权。
6. 所有跨异步边界对象都具有可证明的所有权或失效协议。
7. CI 能阻止新增反向 include、`.inc` 声明碎片和 RouteHostPorts 扩张。

### 2.2 非目标

- 本阶段不改变隧道协议、包格式、路由策略或 DNS 功能语义。
- 本阶段不同时重写 Client/Server Exchanger、VMUX 或所有平台网络实现。
- 不通过批量格式化制造无关 diff。
- 不引入通用服务定位器、依赖注入框架或新的全局单例。

## 3. 组件边界

### 3.1 `VEthernetNetworkSwitcher`

Switcher 是 composition root：创建模块，按顺序启动和停止模块，并把外部事件转发给
对应协调器。迁移期间保留的旧方法必须是无状态委托；不得新增 Route/DNS 字段或
访问子模块内部容器。

### 3.2 `route::RouteState`

`RouteState` 是 Route 领域唯一状态所有者，包含：

- 当前 RIB/FIB；
- peer-prefix RIB/FIB；
- 捕获的默认路由；
- 已应用标记与 apply-ready 标记；
- 路由所需的网卡快照；
- DNS 可达地址的路由视图。

状态只能通过意图明确的方法更新，例如 `ReplaceRib`、`MarkApplied`、
`ReplaceDefaultRoutes`、`ResetAfterRollback`。读取使用只读快照或遍历回调，不返回内部
容器地址。

### 3.3 `route::RouteCoordinator`

`RouteCoordinator` 负责：

- 根据配置和网络接口生成 `RouteSpec`；
- 捕获系统基线；
- 按确定顺序应用路由；
- 记录已完成步骤并在失败时逆序回滚；
- 停止时幂等恢复基线；
- 在成功回滚后重置 `RouteState`。

它依赖 `RouteState`、`IRoutePlatform` 和只读配置快照，不持有 Switcher 指针，也不直接
调用 DNS 实现。

### 3.4 `route::IRoutePlatform`

平台接口表达操作而不是宿主字段：

```cpp
struct RouteSpec final {
    uint32_t network = 0;
    uint32_t gateway = 0;
    int prefix = 0;
    ppp::string interface_name;
};

class IRoutePlatform {
public:
    virtual ~IRoutePlatform() noexcept = default;
    virtual RouteInformationTablePtr CaptureDefaults() noexcept = 0;
    virtual bool Add(const RouteSpec& route) noexcept = 0;
    virtual bool Delete(const RouteSpec& route) noexcept = 0;
    virtual bool RestoreDefaults(const RouteInformationTablePtr& routes) noexcept = 0;
};
```

Linux、Windows、Darwin 适配器封装现有系统调用。Android/iOS 通过移动端适配器表达其
已有的全路由行为，不用空 lambda 假装完整桌面能力。

### 3.5 `dns::DnsController`

`DnsController` 独占 `DnsInterceptor`、DNS 可达地址和活动 DNS 会话。它接受构造时稳定
依赖：配置快照、TAP 输出、缓冲区分配器和定时器接口。隧道会话通过
`IDnsTunnelTransport` 注入：

```cpp
class IDnsTunnelTransport {
public:
    virtual ~IDnsTunnelTransport() noexcept = default;
    virtual bool SendDnsDatagram(
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        const void* packet,
        int packet_size) noexcept = 0;
};
```

DNS 公共头不声明具体 Switcher/Exchanger。每个隧道连接对应一个按值或
`shared_ptr<const ...>` 持有的 `DnsSessionContext`，调用方从不持有缓存内部引用。
Controller 只保存 transport 的 `weak_ptr`；连接停止后调用会明确失败，不延长 Exchanger
生命周期。

## 4. 数据流

### 4.1 路由启动

1. Switcher 创建平台适配器、`RouteState` 和 `RouteCoordinator`。
2. 网络接口就绪后，Switcher 把不可变接口/配置快照交给 Coordinator。
3. Coordinator 调用 `CaptureDefaults()`，将基线写入 RouteState。
4. Coordinator 生成 RouteSpec 列表并逐项 `Add()`。
5. 每次成功操作加入本地 undo log；全部成功后才 `MarkApplied()`。
6. 任一步失败则逆序执行 undo log，并在恢复完成后清空事务状态。

### 4.2 DNS 查询与响应

1. Exchanger 实现 `IDnsTunnelTransport`，建立连接时向 DnsController 打开 session。
2. 数据包分发器把 DNS 查询交给 DnsController，而不是读取 Switcher 字段。
3. Controller 根据自身策略生成处理计划：本地响应、隧道发送或 TAP 输出。
4. 异步响应只持有 `DnsSessionContext` 和 transport 弱引用。
5. transport 已失效时取消响应并返回明确错误，不访问已销毁的 Exchanger。

### 4.3 停止与回滚

停止顺序固定为：

1. 禁止创建新 DNS session；
2. 取消 DNS timer 并使活动 session 失效；
3. 停止数据包入口和 Exchanger；
4. RouteCoordinator 删除本次应用的路由并恢复系统基线；
5. RouteState 在回滚成功后 reset；
6. 释放平台适配器和控制器。

该顺序保证没有异步 DNS 回调访问已释放 transport，也不会在路由状态清空后丢失回滚
所需信息。

## 5. 生命周期与并发规则

- 所有权方向固定为 `Switcher -> Coordinator/Controller -> State/Session`。
- 下层只能通过接口或 `weak_ptr` 回调上层能力，不得保存 Switcher 裸指针或强引用。
- 缓存对外返回值或共享不可变快照，不返回受内部锁保护对象的引用。
- RouteState 只由 RouteCoordinator 写；跨线程读取必须取得快照。
- DNS session 的关闭是幂等操作，timer 回调执行前必须检查 session generation/active 状态。
- 平台操作不在持有 RouteState 锁时执行，避免系统调用阻塞状态访问。
- rollback 失败必须保留尚未恢复的状态和错误信息，不能伪装为已 reset。

## 6. 错误处理

- RouteCoordinator 返回包含失败阶段的结果；继续沿用项目 `SetLastError` 约定。
- 应用失败与回滚失败分别记录，回滚错误不得覆盖原始应用错误。
- DNS transport 过期返回 session-disposed/transport-missing 类错误，不抛异常。
- `IsValid()` 不再用于掩盖平台缺失能力；构造函数必须获得该平台真正支持的依赖。
- teardown 允许重复调用，第二次调用不得再次执行系统副作用。

## 7. 测试设计

### 7.1 RouteState 单元测试

- 状态替换和只读快照；
- reset 只在 rollback 完成后清空；
- 外部无法获得内部可变容器地址。

### 7.2 RouteCoordinator 单元测试

使用 fake `IRoutePlatform` 验证：

- 正常应用顺序；
- 第 N 步失败后的逆序回滚；
- restore 失败时状态保留；
- 重复 stop 不产生第二次系统调用；
- Linux/Windows/Darwin 生成的 RouteSpec 语义与现有实现一致。

### 7.3 DNS 生命周期测试

- teardown 与 `DnsSessionContext` 读取并发时无悬空引用；
- transport 销毁后异步响应安全失败；
- timer 取消后回调不再输出数据；
- 本地缓存、隧道发送和 TAP 输出路径保持原行为。

### 7.4 架构门禁

新增工具测试并在 CI 检查：

- `protocol` 不得 include client/server；
- client 不得 include server；
- Route/DNS 公共接口不得出现具体 Switcher/Exchanger；
- 不得新增 `.inc` 文件；
- 不得新增返回可变容器裸指针的 Ports 字段；
- `RouteHostPorts` 回调数只能下降，最终删除；
- 公共头中的 `stdafx.h` 数量只能下降。

## 8. 迁移阶段

### Phase A：边界门禁与状态归属

先加入可测试的 repository-layout 检查器，再落地 RouteState。Switcher 的兼容访问器转为
委托，随后删除对应成员。

### Phase B：路由操作边界

实现 `IRoutePlatform` 和 fake，先迁移 Linux，再迁移 Windows、Darwin、移动端。迁移完成
后删除 RouteHostPorts 和平台空实现。

### Phase C：DNS 会话与生命周期

引入 `DnsController`、`IDnsTunnelTransport` 和稳定 session context；替换
`DnsHostPortsFor()` 缓存引用，迁移 packet dispatcher 和 teardown，最后删除 IDnsHost 及
具体宿主 overload。

### Phase D：后续领域拆分

完成本设计后，按相同规则继续：

1. 从 Client/Server Exchanger 抽出 FRP、KeepAlive、StaticEcho、VMUX coordinator；
2. 让 VMUX 依赖中立连接接口，不 include client/server 具体连接类；
3. 删除仅持有 `owner_` 的薄包装、无状态转发方法和遗留 friend；
4. 每个领域建立独立状态、窄接口、生命周期测试和架构门禁。

Phase D 分别编写独立设计与实施计划，但不得破坏本设计确立的依赖方向。

## 9. 验收标准

第一阶段完成必须同时满足：

1. Switcher 不再拥有 Route/DNS 领域状态；
2. RouteHostPorts、IDnsHost 和具体宿主 factory 被删除；
3. Route/DNS 公共接口没有可变容器裸指针或伪 `shared_ptr`；
4. DNS session 不返回跨锁引用，ASan 生命周期测试通过；
5. 路由部分失败能自动恢复启动前状态；
6. Linux、Windows、Android/iOS 相关编译检查及 C++ 测试通过；
7. 架构边界检查进入 CI，且基线不能增长；
8. 行为文档的英文和 `_CN.md` 配对内容已同步。

这些证据全部具备前，不把“文件变小”或“新增 Manager”视为解耦完成。
