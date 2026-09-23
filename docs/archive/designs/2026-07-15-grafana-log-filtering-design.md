# Grafana 日志筛选规范化设计
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


**日期：** 2026-07-15
**状态：** 已确认
**范围：** OpenPPP2 OTLP 日志、Loki、Grafana Explore 与 `OpenPPP2 日志` Dashboard

## 1. 背景

当前 Grafana 日志看板无法可靠筛选，主要原因不是 Grafana 本身，而是查询与实际 Loki 数据模型不一致：

- 实际 `service_name` 为 `OpenPPP2`，现有 Dashboard 使用 `openppp2`。
- Loki 当前仅索引 `service_name`、`service_namespace`，现有 Dashboard 却把 `severity_text` 当作索引标签。
- 实际平台字段为 `os_type`，现有 Dashboard 使用不存在的 `platform`。
- 常用字段保存在 structured metadata 中，Explore 无法通过标签选择器快速组合查询。
- 包号、地址、摘要等高基数字段不适合作为 Loki 索引标签。

本设计同时规范 Explore 和固定 Dashboard，不修改客户端日志协议，不重写历史数据。

## 2. 目标

1. 常见日志检索不需要手写复杂 LogQL。
2. Explore 可以使用稳定标签快速缩小日志范围。
3. Dashboard 可以按级别、事件、平台、组件、数据面、方向和链路状态筛选。
4. 设备 ID、关键字等高基数条件仍可精确查询，但不进入 Loki 索引。
5. 现有历史日志继续可查。
6. 标签数量和取值范围受控，不引入 Loki 高基数风险。

## 3. 非目标

- 不修改 iOS、Android 或原生客户端的日志发送格式。
- 不在本次处理逐包 Error 放大或 `writePackets` 失败重试。
- 不迁移或重写 Loki 中已有日志。
- 不建设告警通知链路。

## 4. 字段模型

### 4.1 索引标签

仅将以下稳定、低基数字段提升为 Loki 标签：

| 规范标签 | OTLP 来源 | 用途 |
|---|---|---|
| `service_name` | `service.name` | 服务选择 |
| `service_namespace` | `service.namespace` | 命名空间选择 |
| `severity_text` | 日志 severity | 级别筛选 |
| `event_name` | `event.name` | 事件筛选 |
| `os_type` | `os.type` | 平台筛选 |
| `scope_name` | instrumentation scope | 组件筛选 |
| `openppp2_dataplane` | `openppp2.dataplane` | 数据面筛选 |
| `openppp2_packet_direction` | `openppp2.packet.direction` | 输入/输出筛选 |
| `openppp2_link_state` | `openppp2.link_state` | 链路状态筛选 |

提升逻辑必须在当前 OTel Collector 与 Loki 3.3.2 支持的路径中实现。实施前先读取实际 Collector pipeline 和 Loki 配置，再选择 Loki OTLP `attributes_config` 或 Collector Loki label hint，不同时启用两套重复映射。

### 4.2 Structured metadata

以下字段明确保留为 structured metadata：

- `machine_id`、`device_vendor_id_hash`
- `openppp2_packet_number`
- `openppp2_packet_summary`
- 包长度、输入/输出累计计数
- IP、端口、序列号、校验和等包摘要内容
- 错误正文、配置正文和其他自由文本

这些字段可能接近每条日志唯一，禁止提升为索引标签。

### 4.3 命名规则

- Loki 标签统一使用小写 `snake_case`。
- OTLP 点号在 Loki 中统一转换为下划线。
- `service_name` 的规范值保持客户端实际值 `OpenPPP2`，查询不得依赖错误的小写值。
- Dashboard 展示名称可以使用中文，查询字段必须使用规范标签名。

## 5. Dashboard 设计

保留 UID `openppp2-logs` 和现有文件名，原地升级 provisioning Dashboard，避免链接失效。

### 5.1 筛选器

顶部按以下顺序提供筛选器：

1. 级别 `severity_text`
2. 事件 `event_name`
3. 平台 `os_type`
4. 组件 `scope_name`
5. 数据面 `openppp2_dataplane`
6. 包方向 `openppp2_packet_direction`
7. 链路状态 `openppp2_link_state`
8. 设备 ID，文本输入
9. 关键字，文本输入

标签筛选器支持多选和 All。设备 ID 与关键字通过 pipeline 过滤，不进入标签选择器。

### 5.2 面板

- 当前范围日志总数
- Error 数量与 Error 占比
- 每分钟日志和 Error 趋势
- 事件 Top 10
- 平台/组件分布
- 失败输出包趋势
- 停止原因分布
- 原始日志流

日志流默认倒序、显示时间和日志详情，不默认展开全部 metadata。面板查询统一复用同一组变量条件，避免统计面板与日志流口径不一致。

### 5.3 Explore 入口

Dashboard 提供 Explore 链接，携带当前时间范围和基础 `service_name="OpenPPP2"` 选择器。Datasource 配置中补充示例查询说明，但不配置会泄露动态字段的 derived link。

## 6. 历史兼容

新标签只对配置生效后的新日志可用。为避免历史数据消失：

- 日志流和总量查询以 `{service_name="OpenPPP2"}` 为基础选择器。
- 对历史 structured metadata 使用 LogQL pipeline 字段过滤。
- 新标签用于 Explore 快速检索和 Dashboard 变量枚举，不把标签存在性作为历史日志的必要条件。
- 在筛选变量 description 中注明“选项值来自新日志；历史日志仍可通过时间、设备 ID、关键字查询”，不增加独立说明面板。

## 7. 部署与回滚

1. 备份远端 Collector、Loki 和 Grafana provisioning 文件。
2. 更新标签映射配置并执行配置校验。
3. 仅重启必须重载配置的观测组件。
4. 更新 provisioned Dashboard JSON。
5. 验证后保留备份到同一部署目录的带时间戳文件；不提交凭据。

回滚时恢复备份配置并重启对应容器。Dashboard 保持相同 UID，因此回滚不影响收藏链接。

## 8. 验收标准

1. Grafana、Loki、Collector 健康检查通过，无 OOM 或持续重启。
2. 新发送日志包含预期低基数标签，高基数字段未进入 `/loki/api/v1/labels`。
3. Explore 可按级别、事件、平台和组件组合查询。
4. Dashboard 所有变量可加载，所有面板无查询错误。
5. `service_name="OpenPPP2"` 的历史日志仍能显示。
6. Error 数量与原始 LogQL 计数一致。
7. 设备 ID 和关键字筛选能定位已知 iOS PacketTunnel 日志。
8. 配置重载后 15 分钟内 Collector 与 Loki 不出现新的持续性 error/fatal 日志。

## 9. 风险控制

- 标签白名单之外的字段不得自动提升。
- 如果 `event_name` 或 `scope_name` 实际基数异常，先保留为 metadata，再使用 Dashboard 自定义值筛选。
- 配置修改必须先在容器内执行可用的校验命令；没有校验器时，使用临时容器读取同一配置验证启动。
- 不删除现有 Loki 数据卷，不执行 destructive Docker 或 Git 操作。
