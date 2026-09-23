# 参考手册
> Status: Active
> Type: Reference index
> Last verified: 8c8a888
> Parent index: [文档索引](../README_CN.md)
> Peer link: [English](README.md)

本索引覆盖此 `openppp2/` 树中已由源码核对的当前接口。请先阅读面向任务的页面；协议与原生 C++ 页面描述的是与实现耦合的内部边界，不是第三方 SDK。

## 启动或配置 `ppp`

- [命令行参考](CLI_REFERENCE_CN.md) — 参数、启动顺序、别名和副作用。
- [配置模型](CONFIGURATION_CN.md) — 可接受的 JSON 结构、归一化和安全配置实践。

## 诊断运行中的进程

- [诊断错误系统](DIAGNOSTICS_ERROR_SYSTEM_CN.md) — 错误状态模型和可观测性限制。
- [错误码参考](ERROR_CODES_CN.md) — 错误目录的权威来源和查询规则。
- [错误处理 API](ERROR_HANDLING_API_CN.md) — 内部 C++ 诊断 API。
- [UI Runtime 契约](UI_RUNTIME_CONTRACT_CN.md) — 仓库内 UI 消费的版本化 snapshot。

## 维护与实现耦合的边界

- [项目接口全景图](PROJECT_INTERFACE_MAP_CN.md) — 契约清单、分类和已知缺口。
- [链路层协议指南](LINKLAYER_PROTOCOL_CN.md) — opcode 载荷和分发边界。
- [包格式](PACKET_FORMATS_CN.md) — transport 与 static-echo 包编解码器。
- [会话与控制面模型](TRANSMISSION_PACK_SESSIONID_CN.md) — 握手值和 INFO 信封。
- [VMUX 验证与发布门槛](VMUX_VALIDATION_CN.md) — 实验性调度器所需的证据。

文档与源码不一致时，以各页面列出的源码路径为准。当前页面均有中英文配对；历史材料不属于本索引。