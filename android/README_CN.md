# OpenPPP2 Android 客户端

> [English](README.md) · [技术指南](debug_CN.md) · [规则资源](android/app/src/main/assets/rules/README.md)

**Status:** 实验性

**Type:** Flutter、Android VPN 与 JNI 的平台客户端

**Last verified:** 2026-07-22

本目录包含随本 OpenPPP2 树提供的 Android 客户端。它是由 Flutter UI、Android `VpnService` 和打包的原生 `libopenppp2.so` 组成的应用，不是独立 SDK，也不替代原生命令行运行时。

## 目录内容

- `lib/`：Flutter UI、配置文件与设置代码。
- `android/app/src/main/`：Activity、VPN 服务、跨进程状态镜像和 JNI 声明。
- `android/app/src/main/jniLibs/arm64-v8a/libopenppp2.so`：已打包的原生库。
- 当前目录下的 Android CMake 源码和按 ABI 构建的 `build.sh` 辅助脚本。

当前 UI 包含主页、启动参数、配置文件和设置。此客户端仍是实验性平台表面；在依赖其运行前，应在真实设备上验证连接及 Android VPN 行为。

## 启动与运行链路

```text
Flutter VpnService.connect(configJson, vpnOptions)
  -> MethodChannel "supersocksr.ppp/vpn"
  -> MainActivity 按需请求 Android VPN 授权
  -> 私有 :vpn 进程中的 PppVpnService
  -> VpnService.Builder 创建 TUN 接口
  -> JNI 配置并运行 libopenppp2.so
  -> 原生回调和服务轮询把运行状态镜像到应用文件
  -> Flutter 在应用可见时轮询该镜像
```

`PppVpnService` 被明确放在独立的 `:vpn` 进程中。因此 UI 不直接读取原生状态，而是经由 Activity 获取镜像的运行时快照、链路状态、心跳或最后错误。修改生命周期或 JNI 签名前，请先阅读[技术指南](debug_CN.md)。

## Flutter 应用开发

在本目录中，安装兼容的 Flutter/Android 工具链后运行：

```sh
flutter pub get
flutter test
```

运行或构建还需要与当前 Android Gradle 配置 ABI 匹配的原生库。仓库中的 `jniLibs` 目前包含 `arm64-v8a` 库；这并不表示所有模拟器或构建变体均可使用它。

```sh
flutter run
```

请使用可替换的开发设备和非生产配置。不要把凭据、私有端点、截图中的敏感信息或测试配置提交到文档中。

### 重建原生库（维护者）

`CMakeLists.txt` 从共享 C/C++ 运行时构建 `libopenppp2.so`，输出到 `bin/android/<ABI>/`。`build.sh` 支持 `x86`、`x64`、`arm`、`arm64` 和 `all`，需要 Android NDK 以及 ABI 匹配的预编译 Boost、OpenSSL 库。

下面是与机器路径无关的 arm64 模板：

```sh
cd android
NDK_ROOT=/path/to/android-ndk \
OTHER_ARGS="-DTHIRD_PARTY_LIBRARY_DIR=/path/to/android-third-party" \
./build.sh arm64

cp ../bin/android/arm64-v8a/libopenppp2.so \
  android/app/src/main/jniLibs/arm64-v8a/libopenppp2.so
```

该脚本会删除临时 `build/` 目录。打包前应检查实际生效的 Gradle 脚本，并为每个需要的 ABI 明确提供原生库。本地 bootstrap/WSL 辅助脚本含有覆盖操作或机器特定路径，因此不作为通用入门命令推荐。

## 文档边界

- [技术指南](debug_CN.md) 描述当前 Flutter/Kotlin/JNI 实现和排查信号。
- [规则资源说明](android/app/src/main/assets/rules/README.md) 描述随应用打包的 GeoIP/GeoSite 回退文件。
- [工作状态](WORK_STATUS.md) 是受状态约束的维护说明，不代表当前构建或设备测试已经成功。

配置字段语义、协议行为及跨平台运行保证应以项目的规范文档为准，不由该 Android 包装层承诺。
