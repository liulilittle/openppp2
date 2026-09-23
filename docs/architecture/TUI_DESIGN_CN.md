# TUI 设计
> Status: Active, optional runtime surface
> Type: Architecture boundary
> Last verified: `ppp/app/ConsoleUI.*`, TUI adapter, and main-loop sources, 2026-07-22
>
> **用途：**说明原生终端 UI，不把它当作运行时权威。
> **适用对象：**贡献者与运维。
> **上一层索引：**[架构](README_CN.md) · **English:** [TUI Design](TUI_DESIGN.md)

## 可选启动

`ConsoleUI::ShouldEnable()` 要求标准输出是 TTY，并拒绝 truthy 的 `PPP_NO_TUI` 环境标志。application 只有在 loopback/runtime bootstrap 成功后才尝试 `ConsoleUI::Start()`。终端 UI 初始化失败会记录 optional-UI 诊断，原生运行时仍可继续运行。

`ConsoleUI::Start()` 创建独立的 render 与 input thread。`Dispose()` 在网络运行时 teardown 前停止并 join 这些线程。源码证明它可选且失败不致命；源码本身没有把 UI 标记为实验性产品表面。

## 数据路径与权威

```text
PppApplication::OnTick()
  -> RuntimeLifecycle 更新
  -> 最新 RuntimeSnapshot
  -> tui::BuildStatusLines(snapshot)
  -> ConsoleUI status 与 info buffer
```

`RuntimeSnapshot.phase`、MUX 字段、P2P 状态与失败详情是 TUI adapter 的主要输入。`OnTick()` 还会独立采样流量、链路质量和环境信息，再合并成显示的 status/info 行。因此渲染出的控制台状态不是 `RuntimePhase` 的一对一直接展示。

生命周期权威应使用 `RuntimeSnapshot`/`RuntimeLifecycle`。错误状态和终端文本是诊断/展示，不是独立的健康权威。

## 命令

内置命令带 namespace：

- `openppp2 help`
- `openppp2 restart`
- `openppp2 reload`
- `openppp2 exit`
- `openppp2 info`
- `openppp2 clear`
- `openppp2 telemetry ...`

未知的裸输入会被报告为未知命令，**不会**回退执行 shell。`openppp2 info` 从 UI buffer 复制周期缓存的 info 行，而不是在 input thread 上遍历或序列化 runtime graph。

## 运维边界

TUI 适用于本地观察，并通过与其他请求相同的 application 路径请求 shutdown/restart。它不是稳定自动化 API、生命周期真相来源，也不能保证进程已达到健康的 connected 状态。需要自动化时应使用结构化 stats/snapshot 和已按源码核对的接口。
