# 桌面客户端
> Status: Experimental
> Type: Guide
> Last verified: 2026-07-22
>
> **用途：**用本仓库的 Tauri/Svelte client 管理器评估本地 `ppp` 可执行程序。
> **适用对象：**桌面开发者和评估人员。
> **上一层索引：**[快速开始](README_CN.md) · **English：**[Desktop Client](DESKTOP_CLIENT.md)

## 状态和边界

Desktop Client 位于 `desktop/client/`，是一个**实验性**的 Tauri 2 + Svelte 界面。已提交的 Tauri 配置关闭了 bundling，因此本文只说明从源码运行的评估路径，不把它描述为受支持的安装程序或发布包。

Client 会根据保存的偏好和所选节点生成运行时配置，然后以以下参数启动 `ppp`：

```text
--mode=client --config=<runtime appsettings.json> --stats-json=<runtime stats.ndjson>
```

生成文件位于应用数据目录中的 runtime 目录；不要把它们当作可长期维护的配置源来编辑。

## 前提

- 前端脚本需要 Node.js/npm。
- Tauri 壳需要 Rust/Cargo 及相应平台依赖。
- 需要由本仓库构建的原生 `ppp` 可执行程序，或显式选择的兼容本地可执行文件。

当 `pppPath` 设置为空时，源码**不会**在 `PATH` 中查找。此时它会在 Desktop Client 可执行程序旁查找 Windows 上的 `ppp.exe` 或其他平台上的 `ppp`。从源码开发时，除非刻意安排这种同级文件布局，否则请在设置中把 `pppPath` 指向实际的可执行文件。

## 前端检查和开发

在 `desktop/client/` 下运行：

```bash
npm ci
npm test
npm run build
```

`npm run dev` 启动 Vite 前端。Tauri 配置把 `http://127.0.0.1:1420` 用作开发 URL，因此评估壳程序时应保持相应的前端开发服务可用。

```bash
npm run dev
```

## Tauri 壳

下面的 package script 直接用 Cargo 启动 `openppp2-client-app` 二进制：

```bash
npm run desktop
```

它需要 Cargo，也不会把当前 Tauri 配置变成打包应用。请将其视为本地开发路径。Rust crate 在有 Cargo 时还可使用自己的测试入口：

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

## 预期运行行为

- 订阅和手动节点数据会先合并到生成的运行时配置，再建立连接。
- 进程管理器会丢弃子进程标准输出，只捕获和分类标准错误；UI 不是完整的进程输出控制台。
- 运行时统计从随 `--stats-json` 提供的生成 NDJSON 路径读取。
- 连接会影响原生 client 进程。在真实主机使用非 proxy 网络模式前，请阅读[用户手册](USER_MANUAL_CN.md)以及平台和运维文档。

仓库主单元测试 workflow 当前不运行 Desktop Client 的 `npm test` 或 Cargo 测试命令。修改此界面时，请运行相应本地检查。

## 相关资料

- [用户手册](USER_MANUAL_CN.md)
- [开发文档](../development/README_CN.md)
- [测试](../development/TESTING_CN.md)
- [Desktop 设计说明（中文）](../design/SUB_CLIENT_DESIGN_CN.md)
- [项目接口全景图](../reference/PROJECT_INTERFACE_MAP_CN.md)
