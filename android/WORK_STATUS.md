# Android 维护状态说明

> [当前中文概览](README_CN.md) · [当前技术指南](debug_CN.md) · [English overview](README.md)

**Status:** 受状态约束；非规范性当前文档

**Type:** 维护边界与核验记录

**Last verified:** 2026-07-22

本文件不再保存一次性的本机构建结果、设备日志或已无法由当前代码复现的故障结论。它们不能替代真实设备验证，也不应被解释为该客户端已适合生产部署。

## 当前可由源码确认的事项

- Android 客户端位于本 OpenPPP2 树的 `android/` 中，使用 Flutter UI、Kotlin `PppVpnService` 和 JNI `libopenppp2.so`。
- VPN 服务在私有 `:vpn` 进程中运行；UI 经由 `MethodChannel` 读取服务写入的快照、心跳、链路状态和最后错误镜像。
- 原生库构建依赖 Android NDK 与 ABI 匹配的 Boost/OpenSSL 库；应用打包的库 ABI 必须与实际 Gradle 构建相匹配。
- GeoIP/GeoSite 回退资源会由服务从 APK assets 复制到应用私有规则目录，具体行为见[规则资源说明](android/app/src/main/assets/rules/README.md)。

## 不应从本文件推断的事项

- 某一次 APK、原生库或远端连接已经通过验证。
- 特定 Android 版本、设备、模拟器或 ABI 一定可用。
- 历史错误码、日志片段或修复说明仍准确对应当前源码。
- 本地脚本中的 SDK、NDK、代理或目录设置适合其他机器。

## 维护时的最小核验

1. 阅读[当前技术指南](debug_CN.md)，确认改动位于 Flutter、服务、状态镜像或 JNI 的哪一层。
2. 对 Dart/Flutter 改动运行适用的 `flutter analyze` 和 `flutter test`。
3. 如涉及原生库、VPN 授权、路由或 DNS，在 ABI 匹配的真实 Android 设备上进行连接与断开验证。
4. 将可复现的测试条件和结果记录在对应的变更说明中；不要把凭据、私有地址、日志中的敏感值或本机绝对路径写入文档。

当前规范入口是 [README_CN.md](README_CN.md) 和 [debug_CN.md](debug_CN.md)。
