# Android 实现与排查指南

> [Android 概览](README_CN.md) · [English](debug.md) · [规则资源](android/app/src/main/assets/rules/README.md)

**Status:** 实验性实现参考

**Type:** 内部平台集成与排查指南

**Last verified:** 2026-07-22

本页只描述 `android/` 下当前代码的实现。它比协议或配置参考更窄，不定义公开的 Android API。

## 组件对应关系

| 表面 | 当前职责 |
|---|---|
| `lib/main.dart`、`lib/app_shell.dart` | 启动 Flutter 应用并提供主页、启动参数、配置文件和设置页面。 |
| `lib/vpn_service.dart` | 调用平台通道；应用可见时每秒轮询运行状态，并从镜像推导 UI 流量/状态。 |
| `MainActivity.kt` | 持有 `MethodChannel("supersocksr.ppp/vpn")`；请求 VPN 授权、启停服务、读取镜像文件，并为应用选择器提供已安装应用元数据。 |
| `PppVpnService.kt` | 在 `:vpn` 中运行；管理前台 VPN 生命周期、创建 TUN、调用 JNI 并镜像原生状态。 |
| `PppStateStore.kt` | 在应用私有存储中原子写入跨进程快照、链路状态、心跳和最后错误。 |
| `c/libopenppp2.kt` | 声明原生方法并接收原生回调；JNI 名称/签名必须与 `libopenppp2.cpp` 一致。 |
| `libopenppp2.cpp` | 共享运行时、TUN 描述符、socket 保护、遥测和运行时快照的 Android 原生胶水层。 |

## 连接生命周期

1. Flutter 以 `configJson` 和 `vpnOptions` 调用 `connect`。
2. `MainActivity` 调用 `VpnService.prepare()`；如果 Android 返回授权 Intent，则等待用户决定，否则直接启动 `PppVpnService`。
3. 服务进入前台，解析选项，把原生根路径设为自己的 `filesDir`，并通过 `set_app_configuration` 传递配置。
4. 服务构建 Android VPN 接口，包括 IPv4 路由、DNS、IPv6 捕获路由，以及平台支持时的按应用/系统 HTTP 代理策略。
5. `Builder.establish()` 成功后，服务用 `detachFd()` 把 TUN 文件描述符所有权交给 JNI，调用 `set_network_interface`，再在工作线程中阻塞运行 `libopenppp2.run(0)`。
6. `start_exec`、`runtime_snapshot`、链路状态轮询和错误处理更新服务状态。`run()` 返回后，线程停止轮询、释放资源，并重放排队的重连或停止前台服务。

`run()` 是阻塞调用。不要将它移到 Activity/UI 线程，也不要假设 UI 进程加载的 JNI 对象与 `:vpn` 进程共享状态。

## 状态投递与存活判定

当前实现没有 EventChannel。独立服务进程改为使用文件镜像：

```text
原生运行时回调或服务轮询
  -> PppStateStore 原子替换文件
  -> MainActivity MethodChannel 响应
  -> Flutter 轮询并由 RuntimeStore 做顺序检查
```

- 原生快照携带 `generation` 和 `monotonic_ms`；`PppVpnService` 会在持久化前拒绝旧值。
- 会话运行期间，链路状态和心跳每秒轮询一次。
- `PppStateStore` 将超过 30 秒的心跳视为过期；当心跳和快照都过期时，`getRuntimeSnapshot` 不再返回当前快照。
- 空镜像结果只表示 UI 无法获得当前原生进程状态，不是协议层断开原因。

这些桥接方法均为实现细节。调用方应使用 Flutter 服务，不应把 `getRuntimeSnapshot`、`getLastError` 或 JNI 方法视为稳定外部接口。

## 有用的诊断阶段

`PppLog` 会记录服务端步骤，便于区分授权、TUN、配置和原生错误。推断原因前，应先查看应用诊断 UI 或平台通道返回的日志。

| 日志/阶段 | 表示的内容 |
|---|---|
| `connect requested` | Flutter 已到达 `MainActivity`。 |
| `startForeground done` | 服务已进入前台模式。 |
| `set_root_path ...` | 已尝试设置原生相对路径根目录。 |
| `set_app_configuration result=...` | 配置交接结果。 |
| `builder.establish result=...` | Android TUN 创建结果。 |
| `set_network_interface result=...` | TUN 描述符交接结果。 |
| `before libopenppp2.run(0)` / `vpnThread started...` | 原生运行线程已经启动。 |
| `onStarted key=...` | 原生启动回调已到达服务。 |
| `libopenppp2.run returned=...` | 原生运行循环已返回；还应查看最后错误文本。 |

Android TUN 创建成功并不代表远端会话成功。同样，服务启动时短暂没有快照并不等于连接失败；应结合有序快照、心跳、最后错误和日志判断。

## JNI 修改规则

- 保持 `supersocksr.ppp.android.c.libopenppp2` 的包名、类名和方法签名与 C++ `Java_...` 导出同步。
- 原生代码调用 `protect(fd)` 使底层 socket 不经 VPN 路由；它依赖存活的 `PppVpnService` 实例。
- 原生快照回调可能来自非 UI 线程；服务在 Flutter 读取前负责排序并写入镜像。
- 修改 TUN 所有权、回调或进程生命周期后，必须同时验证连接和断开。仅能编译不能验证 Android VPN 授权或路由。

## 构建与测试边界

在本目录执行 Dart/Flutter 检查：

```sh
flutter analyze
flutter test
```

Android 包装层还在 `android/app/src/androidTest/` 下包含 instrumentation 测试，但它们需要正确配置的 Android 测试环境。原生库构建与 Flutter 检查分离：

- `CMakeLists.txt` 需要 NDK 和 ABI 匹配的 Boost/OpenSSL 静态库。
- `build.sh` 把 `arm64` 映射为 `aarch64`/`arm64-v8a`，输出 `bin/android/arm64-v8a/libopenppp2.so`。
- 应用只能加载为当前 ABI 打包的库；不要假设仓库内的 arm64 库可让 x86/x86_64 模拟器运行。

安全的原生构建模板见 [Android 概览](README_CN.md)。不要把本地 bootstrap/build 辅助脚本当作通用说明：其中一些会重建项目文件或包含主机特定路径。

## 本地相关文档

- [Android 概览](README_CN.md)
- [English technical guide](debug.md)
- [随应用打包的规则资源](android/app/src/main/assets/rules/README.md)
- [受状态约束的维护说明](WORK_STATUS.md)
