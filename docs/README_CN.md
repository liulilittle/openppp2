# 按任务查找文档
> Status: Active
> Type: Reference
> Last verified: 63fc030

> **用途：**说明本主题的当前行为、配置或实现边界。
> **适用对象：**OPENPPP2 用户、运维人员与开发者。
> **当前状态：**当前有效。
> **最后核对依据：**当前仓库结构、实现路径与文档链接，2026-07-18。
> **上一层索引：**[返回索引](../README_CN.md) · **English：**[Documentation by Task](README.md)


[English](README.md)

本页是当前有效文档的统一入口。历史设计、计划、审计和状态记录已隔离到 [`archive/`](archive/README_CN.md)。

## 从这里开始

| 任务 | 当前文档 |
|---|---|
| 安装与构建 | [构建与首次运行](getting-started/USER_MANUAL_CN.md#快速开始) |
| 编写最小配置 | [最小客户端与服务端配置](getting-started/USER_MANUAL_CN.md#快速开始) |
| 启动服务端或客户端 | [启动命令](getting-started/USER_MANUAL_CN.md#快速开始) |
| 验证隧道 | [运维检查清单](operations/OPERATIONS_CN.md#运维检查清单) |
| 配置路由与 DNS | [路由与 DNS 指南](guides/ROUTING_AND_DNS_CN.md) |
| 使用纯代理模式 | [纯代理模式](guides/PROXY_MODE_CN.md) |
| 管理订阅和后台 | [管理后端](guides/MANAGEMENT_BACKEND_CN.md) |
| 部署为系统服务 | [部署说明](operations/DEPLOYMENT_CN.md) |
| 排查故障 | [运维与故障排查](operations/OPERATIONS_CN.md#按阶段排障) |
| 查找项目全部接口和已知缺口 | [项目接口全景图](reference/PROJECT_INTERFACE_MAP_CN.md) |

## 按职责浏览

- [快速开始](getting-started/README_CN.md)：安装、最小配置、启动和首次验证。
- [任务指南](guides/README_CN.md)：路由、DNS、代理、订阅、管理后台、IPv6 和平台操作。
- [参考手册](reference/README_CN.md)：完整配置、CLI、错误、协议和数据格式。
- [项目接口全景图](reference/PROJECT_INTERFACE_MAP_CN.md)、[Project Interface Map](reference/PROJECT_INTERFACE_MAP.md)：全仓库稳定、实验、内部、废弃和缺失接口。
- [运行时契约与发布门槛](reference/UI_RUNTIME_CONTRACT_CN.md)、[VMUX 验证](reference/VMUX_VALIDATION_CN.md)：当前平台契约和发布证据。
- [当前架构](architecture/README_CN.md)：当前运行时、协议、传输和子系统模型。
- [开发文档](development/README_CN.md)：源码阅读、构建、测试和兼容性。
- [部署与运维](operations/README_CN.md)：部署、生产运维、安全和故障排查。
- [历史归档](archive/README_CN.md)：历史设计、计划、审计和状态记录。

## 文档规则

当前文档说明现在可以使用的行为；归档文档只保留设计依据和验证记录，不得作为当前配置依据。稳定的中英文文档继续配对，每篇文档都提供上一层索引入口。
