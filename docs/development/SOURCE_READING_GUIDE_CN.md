# 源码阅读指南
> Status: Active
> Type: Development guide
> Last verified: 2026-07-22
>
> **用途：**在依赖设计摘要前，先沿当前原生应用路径阅读源码。
> **适用对象：**新贡献者和审阅者。
> **上一层索引：**[开发文档](README_CN.md) · **English：**[Source Reading Guide](SOURCE_READING_GUIDE.md)

## 目标

按本顺序阅读后，应能解释当前树中进程如何加载配置、进入 executor、选择角色并到达 client 或 server 运行时。

## 1. 从可执行程序边界开始

按以下顺序阅读：

1. `main.cpp` 调用 `ppp::facade::RunApplication(argc, argv)`。
2. `ppp/facade/ApplicationBootstrap.cpp` 获取 `PppApplication`、调用 `Run`，并在非零结果时输出诊断三元组。
3. `ppp/app/PppApplication.cpp` 初始化全局状态、准备参数/配置，并把已准备的应用交给 `Executors::Run`。
4. `ppp/threading/Executors.cpp` 附加默认 `io_context`、投递入口回调、运行循环，并在退出时解除附加。
5. `ppp/app/PppApplication.cpp` 中的 `RunPreparedApplication` 处理 utility/help 路径、安装关闭处理，随后调用 `PppApplication::Main`。
6. `ppp/app/ApplicationInitialize.cpp` 执行非 proxy 权限边界、建立角色/配置实例锁、启动控制台界面并初始化运行时生命周期状态。
7. `ppp/app/ApplicationMainLoop.cpp` 和 `ppp/app/runtime/` 包含周期工作、关闭协调和运行时快照。

架构概览只是地图，不能替代这一顺序：[启动与生命周期](../architecture/STARTUP_AND_LIFECYCLE_CN.md)。

## 2. 接着阅读参数和配置

1. `ppp/app/ApplicationMode.cpp` — 默认角色和 CLI 模式解析。
2. `ppp/app/ApplicationConfig.cpp` — help 处理、配置候选顺序、命令行覆盖、规则路径和运行时统计输出。
3. `ppp/app/ApplicationHelp.cpp` — 实际输出的选项清单和平台专用 help 行。
4. `ppp/configurations/AppConfiguration.h` 和 `.cpp` — JSON 加载、默认值、规范化和安全诊断。
5. [配置参考](../reference/CONFIGURATION_CN.md)和[CLI 参考](../reference/CLI_REFERENCE_CN.md) — 面向读者的契约，应与上述源码交叉核对。

## 3. 跟随选定的运行时角色

### Client

1. `ppp/app/ApplicationClientBootstrap.cpp` — 在 proxy stub 和平台 TAP 配置之间选择，并启动 client 运行时。
2. `ppp/app/client/VEthernetNetworkSwitcher.*` — client 级编排。
3. `ppp/app/client/VEthernetExchanger.*` — 连接和虚拟网络状态。
4. `ppp/app/client/route/` 与 `ppp/app/client/dns/` — 平台路由/DNS 协调。

将[客户端架构](../architecture/CLIENT_ARCHITECTURE_CN.md)和[路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)作为辅助地图。

### Server

1. `ppp/app/ApplicationServerBootstrap.cpp` — server 配置和启动。
2. `ppp/app/server/VirtualEthernetSwitcher.*` — server 侧交换和监听。
3. `ppp/app/server/VirtualEthernetExchanger.*` — 每个对端的交换行为。
4. `ppp/app/server/` — peer 路由、映射和 server 专用支持。

更完整图见[服务端架构](../architecture/SERVER_ARCHITECTURE_CN.md)。

## 4. 跟踪字节和协议行为

1. `ppp/transmissions/ITransmission.*` — 面向传输的生命周期和帧处理基础。
2. `ppp/transmissions/ITcpipTransmission.*` 与 `ppp/transmissions/IWebsocketTransmission.*` — TCP/WebSocket 实现。
3. `ppp/app/protocol/` — 虚拟以太网信息和链路层消息。
4. `ppp/app/protocol/VirtualEthernetLinklayer.h` — packet action 定义。
5. `ppp/diagnostics/ErrorCodes.def` 和 `ppp/diagnostics/Error.*` — 错误和格式化诊断输出。

辅助文档：[传输](../architecture/TRANSMISSION_CN.md)、[链路层协议](../reference/LINKLAYER_PROTOCOL_CN.md)和[错误处理](../reference/ERROR_HANDLING_API_CN.md)。

## 5. 将可选界面视为独立调查

| 界面 | 起读位置 |
|---|---|
| 终端 UI | `ppp/app/ConsoleUI.cpp`、`ppp/app/tui/TuiRuntimeAdapter.h` |
| MUX | `ppp/app/mux/` |
| P2P | `ppp/p2p/` 和 `ppp/app/P2PCandidateAdapter.*` |
| Desktop Client | `desktop/client/` 及其 `src-tauri/` 壳 |
| Android 原生桥接 | `android/` 和 `android/CMakeLists.txt` |
| iOS 原生库 | `ios/` 和 `ios/CMakeLists.txt` |
| Go 组件 | `go/` |

每个界面都有自己的成熟度和构建路径。不要推断可选或平台专用界面属于根原生 `ppp` target。

## 6. 修改时同时阅读测试

从[测试](TESTING_CN.md)开始。`tests/cpp` 下的独立 C++ 项目有意不同于由 `ENABLE_TESTS` 启用的根 CMake 测试；请选择覆盖所改代码的套件。
