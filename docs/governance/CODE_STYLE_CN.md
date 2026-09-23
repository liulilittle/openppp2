# 代码风格与模块边界

> **用途：**定义当前代码放置、依赖和格式规则。
> **适用对象：**贡献者和评审者。
> **当前状态：**现行治理规则。
> **最后核对依据：**当前仓库检查和 CI 规则，2026-07-22。
> **上一层索引：**[Development](../development/README.md) · **English：**[Code Style and Module Boundaries](CODE_STYLE.md)

> Status: Active
> Type: Governance
> Last verified: 8c8a888

使用 C++17、四个空格、禁止制表符，并遵循相邻代码的 include 和排序约定。格式化只适用于新增和修改的代码；不得对继承文件进行大规模格式化。

| 位置 | 职责 |
|---|---|
| `ppp/app/runtime` | 运行时契约和生命周期发布 |
| `ppp/app/client/dns` | DNS 策略、会话生命周期和可达性投影 |
| `ppp/app/client/route` | 路由状态、事务协调器和不可变计划输入 |
| `ppp/app/mux` | VMUX 协议、调度和运行时状态 |
| `ppp/p2p` | 经认证的直连通道原语 |
| 平台目录 | OS 调用和具体适配器 |
| `android`、`ios` | 展示层和平台桥接 |

`tools/check_repository_layout.py` 会检查以下禁止模式：新增 `.inc` 片段、路由/DNS 公共头中的具体主机名、可变容器指针、反向协议依赖、旧式 service locator，以及保留 Switcher 所有者的路由管理器。
