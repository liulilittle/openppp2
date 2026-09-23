# 快速开始
> Status: Active
> Type: Index
> Last verified: 2026-07-22
>
> **用途：**为本仓库中的原生运行时和实验性桌面界面选择安全、可追溯的起点。
> **适用对象：**使用者、运维人员和贡献者。
> **上一层索引：**[文档](../README_CN.md) · **English：**[Getting Started](README.md)

## 选择路径

### 运行原生 `ppp` 运行时

先阅读配对的[用户手册](USER_MANUAL_CN.md)。其中说明当前原生命令路径、配置发现顺序、权限边界以及后续应阅读的参考文档。未提供 `--mode` 时，可执行程序默认使用 server 角色。

### 试用 Desktop Client

[桌面客户端](DESKTOP_CLIENT_CN.md)说明 `desktop/client/` 下的 Tauri/Svelte 管理器。它是**实验性**、面向从源码运行的界面；已提交的 Tauri 配置当前不会生成打包安装程序。

### 构建、测试或阅读源码

- [开发文档](../development/README_CN.md) — 原生构建前提和贡献者入口。
- [源码阅读指南](../development/SOURCE_READING_GUIDE_CN.md) — 沿真实应用启动和运行时路径阅读。
- [测试](../development/TESTING_CN.md) — 选择独立测试、根 CMake 测试、覆盖率或组件测试入口。

## 需要详细信息时

| 任务 | 权威页面 |
|---|---|
| JSON 配置和默认值 | [配置参考](../reference/CONFIGURATION_CN.md) |
| 命令行选项 | [CLI 参考](../reference/CLI_REFERENCE_CN.md) |
| 路由和 DNS 行为 | [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md) |
| 平台限制 | [平台说明](../guides/PLATFORMS_CN.md) |
| 部署和运维 | [部署](../operations/DEPLOYMENT_CN.md) · [运维](../operations/OPERATIONS_CN.md) |

## 文档边界

标为 **Active** 的页面描述当前树；Desktop Client 会明确标为 **Experimental**。开发部分中带日期的技术审计用于复核证据，不应作为当前运行指令。
