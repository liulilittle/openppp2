# OPENPPP2

> Status: Current
> Type: Navigation
> Last verified: 2026-07-22
> 文档索引：[按任务查找文档](docs/README_CN.md) · English: [English](README.md)

[English](README.md) | 简体中文

OPENPPP2 是一个 C++ 网络运行时。根目录 CMake 项目构建原生 `ppp` 可执行文件和静态 `openppp2_lib` 库。本页只提供简明的仓库入口；配置、运维和实现细节请从下方当前有效的任务文档进入。

## 按任务开始

| 需求 | 从这里开始 |
|---|---|
| 构建并完成首次运行 | [快速开始](docs/getting-started/README_CN.md) |
| 配置 `ppp` 或查看命令行参数 | [配置参考](docs/reference/CONFIGURATION_CN.md) · [CLI 参考](docs/reference/CLI_REFERENCE_CN.md) |
| 配置路由、DNS、代理行为或平台 | [任务指南](docs/guides/README_CN.md) |
| 部署、观测或排查运行时 | [部署与运维](docs/operations/README_CN.md) |
| 理解运行时结构和生命周期 | [启动与生命周期](docs/architecture/STARTUP_AND_LIFECYCLE_CN.md) |
| 安全地阅读或修改源码 | [源码阅读指南](docs/development/SOURCE_READING_GUIDE_CN.md) |
| 查看哪些接口稳定、实验性、内部或尚未完成 | [项目接口全景图](docs/reference/PROJECT_INTERFACE_MAP_CN.md) |

## `ppp` 启动链

常规运行路径（不含帮助或一次性辅助路径）如下：

```text
main.cpp
  -> ppp::facade::RunApplication()
  -> PppApplication::GetInstance().Run()
  -> PreparedArgumentEnvironment()
  -> Executors::Run()
  -> RunPreparedApplication()
  -> PppApplication::Main()
```

参数准备阶段会加载配置、解析应用模式并准备网络接口上下文。随后常规路径进入 `Main()`，执行宿主预检并启动选定的客户端、服务端或代理运行时。实现级顺序和关闭行为请参阅[启动与生命周期](docs/architecture/STARTUP_AND_LIFECYCLE_CN.md)。

## 核心与配套表面

- **核心原生运行时：**`main.cpp`、`ppp/`、`common/`，以及根 CMake 按 Windows、Linux 或 Darwin 选择的平台源码。
- **测试：**根项目仅在配置 `-DENABLE_TESTS=ON` 时纳入 `tests/`；支持的测试流程见[开发文档](docs/development/README_CN.md)。
- **独立的平台专属表面：**`go/` 和 `go/guardian/` 是 Go 模块；`android/` 包含仓库内的 Flutter 应用与 Android/NDK 构建文件；`ios/` 包含 Swift package target；`desktop/client/` 则有独立的 Svelte/Vite 与 Tauri 清单。根 CMake 不构建这些表面；在将其中任何一项作为生产部署路径前，请先阅读其本地文档和清单。

## 当前文档与历史文档

上方链接的任务页面构成当前有效的导航路径。`docs/archive/`、`docs/adr/` 和 `docs/design/` 下的内容保存历史依据、决策和证据，不能替代当前的配置、CLI 或运维指导。这对导航页面提供英中文配对；使用其他当前页面前，请先核对其状态、语言配对和父级索引元数据。
