# 桌面客户端手动节点与启动参数设计
> Status: Active
> Type: Design
> Last verified: 8c8a888

> **用途：**记录桌面 Client 手动节点和启动参数的状态绑定设计。
> **适用对象：**维护桌面 Client 的开发者和评审者。
> **当前状态：**实现对照设计；不是稳定接口或发布承诺。
> **最后核对依据：**`desktop/client/src-tauri/src/{preferences,manual_nodes,launch_options,desktop}.rs`、`ppp/app/ApplicationConfig.cpp` 与桌面 manifest，2026-07-22。
> **上一层索引：**[Design Documents](README.md)

> **核对提示：**本文档只描述当前仓库内的桌面实现与已知限制。字段映射、后端校验和平台打包能力都必须以当前代码和测试为准。

## 目标

Windows/macOS 客户端支持不依赖订阅的单节点新增、编辑、删除和连接，并让“配置”页对齐移动端已有的启动参数语义。仅暴露 C++ 桌面运行时真实支持的字段，不展示 Android 专属能力。

## 数据模型

手动节点沿用订阅 v1 的 `SubscriptionNode` 结构，持久化到桌面端 `preferences.json` 的 `manualNodes` 数组。节点 ID 由后端生成并带 `manual:` 前缀；订阅节点保持原 ID。运行时将两类节点合并展示，但保留 `source: manual | subscription` 供 UI 判断是否可编辑。

手动节点字段分为：

- 基本信息：名称、副标题。
- 服务器：`ppp://` URI、GUID、带宽。
- 加密：`protocol`、`protocol-key`、`transport`、`transport-key`、`kf/kx/kl/kh`、`masked/plaintext/delta-encode/shuffle-data`。
- 本地代理：HTTP/SOCKS bind 与 port。
- 高级：完整 JSON。结构化字段和 JSON 使用同一配置对象，保存前由后端校验。

## 启动参数

全局启动参数持久化为 `launchOptions`。订阅节点或手动节点自带的 `options` 覆盖同名全局值；空值不生成 CLI 参数，以保留 C++ 默认和服务端自动分配行为。

桌面端支持：

| 字段 | C++ 参数 |
|---|---|
| `tunIp` | `--tun-ip` |
| `tunMask` | `--tun-mask` |
| `gateway` | `--tun-gw` |
| `dns1/dns2` | 合并为 `--dns` |
| `mux` | `--tun-mux` |
| `muxMode` | `--mux-mode` |
| `vnet` | `--tun-vnet` |
| `blockQuic` | `--block-quic` |
| `staticMode` | `--tun-static` |

`route/routePrefix/mtu/mark` 属于移动 VPN 平台层，分应用代理是 Android 专属，本轮不在桌面端伪造支持。

## 后端接口

完整命令表见 [项目接口全景图 §9](../reference/PROJECT_INTERFACE_MAP_CN.md)。与手动节点/启动参数直接相关：

- `client_bootstrap` — 合并节点、全局启动参数、设置。
- `client_upsert_manual_node` / `client_delete_manual_node` — 手动节点 CRUD（`manual:` 前缀 ID）。
- `client_update_launch_options` / `client_update_client_config` / `client_update_config` — 启动参数与 JSON。
- `client_connect` — 从合并节点视图查找目标，生成配置并合并启动参数。

所有写入都经过 Rust 后端的结构性校验；前端只做即时提示，不能替代后端校验。

## 界面

节点页工具栏增加带加号图标的“添加节点”按钮。手动节点行显示“本地”来源，并提供编辑、删除图标；订阅节点只读。编辑器使用单层模态窗口，桌面宽度不超过 760px，不嵌套卡片。样式在 `<=640px` 时会切换为全屏滚动，但打包桌面壳当前最小宽度为 720px；该规则不能作为受支持移动端体验的承诺。

配置页改为结构化启动参数表单，按“虚拟网卡、DNS、多路复用、网络策略”分区；原始 appsettings JSON 保留在“高级 JSON”折叠区。

## 验收与已知限制

- 无订阅时可新增一个节点，重启后仍存在并可连接。
- 手动节点可编辑、删除；订阅节点不可编辑。
- 启动参数按全局值加节点覆盖规则生成真实 CLI 参数。
- 当前后端拒绝空或结构性无效的 `ppp://` URI、无效代理端口、空密钥对象及非对象 JSON；服务器端口和密钥内容尚未完成全面语义校验，不能声称所有非法输入都不会落盘。
- 现有订阅刷新、收藏、延迟探测、托盘和 raw JSON 工作流需要回归验证。
- 前端可使用 `npm run build` 验证；Tauri `bundle.active` 仍为 false，正式 Windows 安装包/签名验收未完成。桌面 1120x760 与窄屏布局也仍需在目标平台上验证。
