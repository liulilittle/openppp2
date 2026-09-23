# 启动与生命周期
> Status: Active
> Type: Architecture
> Last verified: `main.cpp`, `ppp/facade/`, and `ppp/app/` lifecycle sources, 2026-07-22
>
> **用途：**说明原生 `ppp` 进程如何准备、bootstrap、发布状态和拆除。
> **适用对象：**排查生命周期行为的贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md)

## 入口与进程 owner

```text
main.cpp
  -> ppp::facade::RunApplication(argc, argv)
  -> PppApplication::GetInstance().Run(argc, argv)
  -> PreparedArgumentEnvironment(...)
  -> Executors::Run(...)
  -> RunPreparedApplication(...)
  -> PppApplication::Main(...)
```

`RunApplication()` 是外层错误输出壳：运行 application、必要时补充通用诊断信息，并向标准错误输出结果。真正的启动与关闭工作由 `PppApplication` 持有。

`Run()` 初始化全局支持、准备参数和配置、进入 executor 运行时，并在 executor 返回后释放进程级状态。请求 restart 时，只有 executor 退出之后才会替换进程（Windows 用 `CreateProcessA`，非 Windows 构建用 `execvp`）。

## `Main()` 前的准备

`PreparedArgumentEnvironment()` 会：

1. 处理 help 和早期 statistics 输出设置；
2. 加载并规范化配置；
3. 将 `--mode` 解析为 `server`、`client` 或 `proxy`；
4. 推导 client/proxy 角色标志；
5. 在 proxy mode 或设置 `client.proxy-only` 时应用代理默认值；
6. 构造 `NetworkInterface` 输入并配置运行时 DNS cache 全局状态；
7. 配置 telemetry 开关和 sink；
8. 根据已加载配置设置 executor 数量。

模式先于 proxy 默认值解析。仅设置 `client.proxy-only` 不会把默认 server 角色改为 client；必须使用 `--mode=client` 或 `--mode=proxy` 选择 client 家族运行时。

## 主 bootstrap

`Main()` 先用已选角色初始化 `RuntimeLifecycle`，再请求早期展示阶段。它会在按角色分发 loopback 环境之前执行权限和单实例门禁。

| 角色 | Bootstrap | 说明 |
|---|---|---|
| Server | `PrepareServerLoopbackEnvironment()` | 准备 server IPv6 宿主状态、创建 `VirtualEthernetSwitcher`、打开并启动 accept loop。失败会回滚宿主准备。 |
| Client | `PrepareClientLoopbackEnvironment()` | 打开设备、创建 `VEthernetNetworkSwitcher`、应用 client 设置并打开 client 运行时。 |
| Proxy | 带 proxy mode 的 client bootstrap | 跳过 `Main()` 中的权限门禁；它不只是完整 client 配置的另一种拼写。 |

在桌面类目标上，proxy-only 运行时可以用 `TapStub` 代替内核设备。这是刻意不注入数据包的 stub。Android/iOS 被该分支排除，使用各自的平台集成路径。

终端 UI 是可选的。只有运行时 bootstrap 成功后才会尝试启动；终端不适用或 `ConsoleUI::Start()` 失败都不会让隧道 bootstrap 失败。

## Runtime snapshot 与周期 tick

bootstrap 后，`NextTickAlwaysTimeout()` 先安排一次即时维护调用，再以约 1000 ms 重挂。`OnTick()` 将活跃事实投影到 `RuntimeLifecycle`：

- 运行中的 server 通过 server readiness 请求 `connected`；
- 没有 client exchanger 时请求 `connecting`；
- exchanger 正在重连时请求 `reconnecting`；
- exchanger 已建立时更新 client readiness 并请求 `connected`；
- 其他 client exchanger 状态请求 `handshaking`。

client 的 `connected` 由 session、adapter、route、DNS 和 policy 事实共同门控。因此即使请求 `connected`，在所有必需事实 ready 前，对外仍可能显示 `applying_policy`。

`OnTick()` 还会采样流量、MUX 与 P2P 展示，写入可选 `--stats-json` 样本，刷新 TUI 字符串，并执行 restart 与路由刷新策略。

可见 phase 流（`starting` 到 `connected`、重连、`stopping` 与最终的 idle/failed）描述当前 application 行为。它不是强制状态迁移语法：生命周期对象校验 generation 和 stop owner，只对 connected 的 readiness 门控作特殊处理。

## Shutdown 与 restart

关闭请求会将工作 post 到默认 executor，而不是同步销毁运行时。该路径调用 `Dispose()`，并在一秒后调度 `Executors::Exit()`。

`Dispose()` 尝试获得当前 lifecycle generation 的 stop owner，停止 TUI，拆除已转移的 server/client 运行时，清除 tick timer，并 flush/shutdown telemetry。清理完成回调以 `idle` 或 `failed` 调用 `RuntimeLifecycle::CompleteStop()`。

排查关闭时要注意两个边界：

- `Release()` 在 executor 返回后才释放单实例保护；`Dispose()` 不释放该保护。
- 不能承诺每个失败或退出路径都有最终 snapshot。部分启动失败会在 `Begin()` 后直接返回，而 executor 退出与异步拆除完成是独立调度的。

restart 策略和 UI 命令最终复用同一关闭路径；只有 executor 退出后才发生进程替换。

## 源码阅读顺序

1. `main.cpp`
2. `ppp/facade/ApplicationBootstrap.cpp`
3. `ppp/app/PppApplication.cpp`
4. `ppp/app/ApplicationConfig.cpp`
5. `ppp/app/ApplicationInitialize.cpp`
6. `ppp/app/ApplicationClientBootstrap.cpp` 或 `ApplicationServerBootstrap.cpp`
7. `ppp/app/ApplicationMainLoop.cpp`
8. `ppp/app/runtime/RuntimeLifecycle.h`
