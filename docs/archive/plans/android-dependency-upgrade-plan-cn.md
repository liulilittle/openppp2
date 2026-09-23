# Android 依赖分层升级矩阵（方案 B）
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> **状态**: 规划文档 — 本 commit 不升级依赖、不改变构建行为。
> **生成日期**: 2026-05-11
> **适用范围**: `android/` 目录下的 Flutter + Kotlin + C++ native 构建体系

---

## 1. 当前版本清单

### 1.1 Gradle 体系

| 组件 | 当前版本 | 来源文件 | 备注 |
|------|---------|---------|------|
| Gradle Wrapper | **8.14** | `android/android/gradle/wrapper/gradle-wrapper.properties` | `distributionUrl` 中读取 |
| AGP (Groovy) | **8.3.2** | `android/android/settings.gradle` 第 21 行 | `id "com.android.application" version "8.3.2"` |
| AGP (KTS) | **8.11.1** | `android/android/settings.gradle.kts` 第 22 行 | `id("com.android.application") version "8.11.1"` |
| Kotlin (Groovy) | **1.9.24** | `android/android/settings.gradle` 第 22 行 | `id "org.jetbrains.kotlin.android" version "1.9.24"` |
| Kotlin (KTS) | **2.2.20** | `android/android/settings.gradle.kts` 第 23 行 | `id("org.jetbrains.kotlin.android") version "2.2.20"` |
| Flutter Plugin Loader | **1.0.0** | 两个 settings.gradle{.kts} | `dev.flutter.flutter-plugin-loader` |

> **关键发现**: 仓库中存在 **Groovy (`.gradle`) 和 Kotlin DSL (`.gradle.kts`) 两套并行构建文件**，且版本差异显著。KTS 版本明显更新，暗示正在或计划迁移到 Kotlin DSL。升级策略需明确以哪套为基准。

### 1.2 Flutter / Dart 体系

| 组件 | 当前版本 | 来源文件 |
|------|---------|---------|
| Flutter SDK（最低要求） | **>=3.35.0** | `android/pubspec.lock` 第 338 行 |
| Dart SDK（约束） | **>=3.9.0 <4.0.0** | `android/pubspec.lock` 第 337 行 |
| Dart SDK（pubspec.yaml 约束） | **>=3.0.0 <4.0.0** | `android/pubspec.yaml` 第 7 行 |
| `shared_preferences` | **^2.2.0**（锁文件 2.5.5） | `android/pubspec.yaml` 第 12 行 / `pubspec.lock` 第 202 行 |
| `flutter_lints` | **^3.0.0**（锁文件 3.0.2） | `android/pubspec.yaml` 第 17 行 / `pubspec.lock` 第 80 行 |

### 1.3 Android SDK / NDK / Java

| 组件 | 当前版本 | 来源文件 | 备注 |
|------|---------|---------|------|
| Java 兼容性 | **17** | `android/android/app/build.gradle` 第 24-25 行、`build.gradle.kts` 第 14-15 行 | `sourceCompatibility` / `targetCompatibility` |
| `jvmTarget` | **17** | `app/build.gradle` 第 29 行、`build.gradle.kts` 第 19 行 | Kotlin JVM target |
| Android NDK | **25.1.8937393** | `android/WORK_STATUS.md` 第 19 行 | Windows 开发环境记录 |
| NDK min API | **21** | `android/build.sh` 第 32 行 | `ANDROID_NATIVE_API_LEVEL=21` |
| NDK STL | **c++_static** | `android/build.sh` 第 33 行 | `ANDROID_STL=c++_static` |
| `compileSdk` | **flutter.compileSdkVersion** | `app/build.gradle` 第 9 行 | 由 Flutter SDK 决定，非显式声明 |
| `minSdkVersion` | **flutter.minSdkVersion** | `app/build.gradle` 第 13 行 | 由 Flutter SDK 决定 |
| `targetSdk` | **flutter.targetSdkVersion** | `app/build.gradle` 第 14 行 | 由 Flutter SDK 决定 |
| `ndkVersion` | **flutter.ndkVersion** | `app/build.gradle.kts` 第 11 行 | 仅 KTS 版本显式声明 |

### 1.4 Native C++ / 第三方库

| 组件 | 当前版本 | 来源文件 | 备注 |
|------|---------|---------|------|
| CMake 最低要求 | **3.0.0** | `android/CMakeLists.txt` 第 1 行 | `CMAKE_MINIMUM_REQUIRED` |
| C++ 标准 | **C++17** | `android/CMakeLists.txt` 第 76 行 | `SET(CMAKE_CXX_STANDARD 17)` |
| OpenSSL | **需确认**（仓库仅记录 native 参考版本 3.0.13） | `AGENTS.md` 仅记录 Linux/macOS `/root/dev/openssl/` 版本；Android `/root/android/` 未细分版本 | Android 实际预编译库版本需在升级 Phase 0 从构建产物或部署环境确认 |
| Boost | **需确认**（仓库仅记录 native 参考版本 1.86.0） | `AGENTS.md` 仅记录 Linux/macOS `/root/dev/boost/` 版本；Android `/root/android/` 未细分版本 | Android 实际预编译库版本需在升级 Phase 0 从构建产物或部署环境确认 |
| ABI 过滤 | **arm64-v8a** | `app/build.gradle` 第 19 行 | KTS 版本未设 `abiFilters` |

### 1.5 Gradle Properties

| 属性 | 值 | 来源 |
|------|---|------|
| `android.useAndroidX` | `true` | `gradle.properties` 第 2 行 |
| `android.enableJetifier` | `true` | `gradle.properties` 第 3 行 |
| `kotlin.incremental` | `false` | `gradle.properties` 第 4 行 |
| `org.gradle.jvmargs` | `-Xmx4G -XX:MaxMetaspaceSize=2G` | `gradle.properties` 第 1 行 |

### 1.6 AndroidX / Jetifier 状态

- `android.useAndroidX=true`：已启用 AndroidX。
- `android.enableJetifier=true`：仍在自动转换 Support Library → AndroidX。后续可评估关闭 Jetifier（所有直接/间接依赖均已迁移到 AndroidX 后）。

---

## 2. 分层升级矩阵

### 层级总览

| 层级 | 组件 | 升级优先级 | 相互依赖 |
|------|------|-----------|---------|
| L0 | Gradle Wrapper | 最高（其他层的基础设施） | 无 |
| L1 | Android Gradle Plugin (AGP) | 高 | 依赖 L0 |
| L2 | Kotlin | 中 | 依赖 L1 |
| L3 | AndroidX / Jetifier | 中 | 依赖 L1+L2 |
| L4 | NDK / CMake / Java | 中 | 依赖 L1 |
| L5 | Flutter / Dart deps | 中 | 依赖 L0+L1 |
| L6 | Native TLS (OpenSSL) / Boost | 独立 | 无（CMake 独立构建） |

---

### L0: Gradle Wrapper

| 项目 | 内容 |
|------|------|
| **当前版本** | 8.14 |
| **目标版本** | TODO — 依据 AGP 兼容性矩阵确认（AGP 8.x 要求 Gradle 8.x） |
| **升级原因** | Gradle Wrapper 是所有 Gradle 构建的运行时基础，需与 AGP 版本匹配 |
| **破坏性变更风险** | 低风险。Gradle 8.x 之间通常向后兼容。需关注弃用 API 的移除 |
| **验证方式** | `./gradlew --version` 确认版本；`:app:assembleDebug` 构建通过 |
| **回滚方式** | 修改 `gradle-wrapper.properties` 中 `distributionUrl` 回退 |

---

### L1: Android Gradle Plugin (AGP)

| 项目 | 内容 |
|------|------|
| **当前版本** | Groovy: 8.3.2 / KTS: 8.11.1（两套并行） |
| **目标版本** | TODO — 需确定以 Groovy 还是 KTS 为基准，再确认目标版本 |
| **升级原因** | AGP 更新带来构建性能优化、新 API 支持、安全修复 |
| **破坏性变更风险** | **中等**。AGP 大版本升级（如 8→9）可能需要 Gradle Wrapper 同步升级、`build.gradle` DSL 变更、`namespace` 强制要求等。小版本升级（8.3→8.11）风险较低 |
| **验证方式** | `./gradlew :app:assembleDebug` 构建通过；Lint 无新增 error |
| **回滚方式** | `settings.gradle{.kts}` 中回退版本号 |
| **额外决策** | 需先解决 Groovy vs KTS 双轨问题。建议统一到 KTS 后再升级 AGP |

---

### L2: Kotlin

| 项目 | 内容 |
|------|------|
| **当前版本** | Groovy: 1.9.24 / KTS: 2.2.20 |
| **目标版本** | TODO — 如统一到 KTS 基准则为 2.2.20（已是最新）；如保持 Groovy 则需从 1.9.x 升级到 2.x |
| **升级原因** | Kotlin 2.x 带来 K2 编译器（更快编译、更好类型推断）、新语言特性 |
| **破坏性变更风险** | **高**（1.x→2.x 跨大版本）。K2 编译器对部分 Kotlin 代码有语义变化；需逐一排查 `.kt` 源文件的编译警告。KTS 2.2.20 已就绪，风险主要在 Groovy 侧 |
| **验证方式** | `./gradlew :app:compileDebugKotlin` 无错误无新增 warning |
| **回滚方式** | `settings.gradle{.kts}` 中回退 Kotlin 版本号 |

---

### L3: AndroidX / Jetifier

| 项目 | 内容 |
|------|------|
| **当前状态** | AndroidX 已启用，Jetifier 仍在运行 |
| **目标** | 评估关闭 Jetifier（确认所有依赖均已原生支持 AndroidX） |
| **升级原因** | Jetifier 增加构建时间，且长期不再维护。关闭可加速构建 |
| **破坏性变更风险** | **低~中**。如有第三方库仍依赖旧 Support Library，关闭 Jetifier 会导致编译失败 |
| **验证方式** | 设置 `android.enableJetifier=false`，构建通过即安全 |
| **回滚方式** | 重新设置 `android.enableJetifier=true` |
| **当前 AndroidX 依赖** | 仓库可确认已启用 `android.useAndroidX=true`，并包含 `shared_preferences_android` 等 Flutter plugin；是否所有传递依赖均已原生 AndroidX 需通过依赖树确认 |

---

### L4: NDK / CMake / Java

| 项目 | 内容 |
|------|------|
| **当前版本** | NDK 25.1.8937393 / CMake >=3.0.0 / Java 17 |
| **目标版本** | TODO — NDK: 下一步确认（26.x 或 27.x）；CMake: 建议升级最低要求到 3.10+；Java: 保持 17 |
| **升级原因** | NDK 更新带来新 ABI 支持、安全修复、编译器改进 |
| **破坏性变更风险** | **中等**。NDK 升级可能影响 `android.toolchain.cmake` 路径、STL 行为、弃用 API。CMake 最低版本提升对现有 `CMakeLists.txt` 兼容性影响小（当前已满足） |
| **验证方式** | `android/build.sh arm64` 编译 `libopenppp2.so` 通过；APK 包含新编译的 so |
| **回滚方式** | 修改 `ANDROID_NDK` 环境变量或 `local.properties` 中的 `ndk.dir` |
| **备注** | NDK 版本通过环境变量 `$NDK_ROOT` 和 `build.sh` 控制，不锁在 Gradle 配置中。KTS `app/build.gradle.kts` 中 `ndkVersion = flutter.ndkVersion` 由 Flutter SDK 决定 |

---

### L5: Flutter / Dart 依赖

| 项目 | 当前 | 目标 | 风险 |
|------|------|------|------|
| `shared_preferences` | ^2.2.0（锁 2.5.5） | TODO — 确认最新 2.x 稳定版 | 低。API 稳定 |
| `flutter_lints` | ^3.0.0（锁 3.0.2） | TODO — 确认是否迁移到 `flutter_lints` 4.x 或 `lints` 包 | 低。仅影响静态分析 |
| Dart SDK 约束 | >=3.0.0 <4.0.0 | TODO — 可收紧到 >=3.9.0 以匹配锁文件实际约束 | 无风险。收紧约束不影响已有构建 |
| Flutter SDK | >=3.35.0 | TODO — 确认最新 stable 版本 | 低~中。Flutter 升级可能引入 widget 废弃警告 |

**验证方式**: `flutter analyze` 无新增 error/warning；`flutter build apk` 通过。

**回滚方式**: `pubspec.yaml` + `pubspec.lock` git revert。

---

### L6: Native TLS (OpenSSL) / Boost（独立层）

| 项目 | 当前 | 目标 | 风险 |
|------|------|------|------|
| OpenSSL | Android 实际版本需确认（native 参考版本：3.0.13） | TODO — 确认 Android 预编译库当前版本后，再决定是否升级到 3.0.x 最新 patch 或 3.3.x/3.4.x | **低**（patch 级）；**中**（跨 minor） |
| Boost | Android 实际版本需确认（native 参考版本：1.86.0） | TODO — 确认 Android 预编译库当前版本后，再决定是否升级到 1.87.0 | 低~中。参见 `docs/BOOST_187_COMPATIBILITY.md` |

**升级原因**: 安全补丁、性能优化、新特性。

**破坏性变更风险**: OpenSSL 3.0.x 内 patch 升级风险极低；跨到 3.1+ 需检查 provider 行为变化。Boost minor 升级通常兼容，但协程/asio API 可能有微调。

**验证方式**: `android/build.sh arm64` 编译通过；运行时 TLS 握手正常。

**回滚方式**: 替换 `/root/android/openssl/` 和 `/root/android/boost/` 中的库文件重新编译。

---

## 3. 执行顺序（分阶段）

```
Phase 0 ─ 扫描 / 锁版本
  │  · 确认 Groovy vs KTS 基准选择
  │  · 导出完整依赖树（./gradlew :app:dependencies）
  │  · 确认 Android `/root/android/` 下 OpenSSL/Boost 预编译库实际版本
  │  · 记录当前可工作的 commit hash 作为回滚锚点
  │
Phase 1 ─ Gradle Wrapper + AGP
  │  · 升级 gradle-wrapper.properties
  │  · 升级 settings.gradle{.kts} 中 AGP 版本
  │  · 验证: assembleDebug 通过
  │
Phase 2 ─ Kotlin + AndroidX / Jetifier
  │  · 统一 Kotlin 版本
  │  · 评估关闭 Jetifier
  │  · 验证: compileDebugKotlin 通过；assembleDebug 通过
  │
Phase 3 ─ NDK / CMake
  │  · 升级 NDK 版本（环境变量/local.properties）
  │  · 评估 CMake 最低版本要求
  │  · 验证: build.sh arm64 编译通过；APK 包含 so
  │
Phase 4 ─ Flutter / Dart deps
  │  · flutter pub upgrade
  │  · 收紧 Dart SDK 约束
  │  · 验证: flutter analyze + flutter build apk
  │
Phase 5 ─ Native TLS / Boost
     · 替换预编译库
     · 重新编译 libopenppp2.so
     · 验证: 运行时 TLS 握手 + VPN 连接正常
```

**每个 Phase 独立 commit，互不依赖。任一 Phase 失败可独立回滚，不影响其他 Phase。**

---

## 4. 风险评估汇总

| 层级 | 风险等级 | 关键风险点 | 缓解措施 |
|------|---------|-----------|---------|
| L0 Wrapper | 🟢 低 | Gradle 8.x 内部兼容性 | 锁定 AGP 兼容矩阵 |
| L1 AGP | 🟡 中 | Groovy/KTS 双轨不一致 | 先统一构建系统 |
| L2 Kotlin | 🔴 高 | 1.x→2.x K2 编译器语义变化 | 逐文件检查编译 warning |
| L3 AndroidX | 🟢 低 | 个别传递依赖未迁移 | 先开 Jetifier=false 试构建 |
| L4 NDK/CMake | 🟡 中 | toolchain 路径 / STL 行为变化 | 保留旧 NDK 并行安装 |
| L5 Flutter | 🟢 低 | widget 废弃警告 | 锁文件先行验证 |
| L6 Native | 🟢 低 | OpenSSL/Boost API 微调 | 单独编译 + 运行时冒烟测试 |

---

## 5. Groovy vs KTS 双轨问题

当前仓库同时存在：

| 文件 | AGP | Kotlin |
|------|-----|--------|
| `settings.gradle` | 8.3.2 | 1.9.24 |
| `settings.gradle.kts` | 8.11.1 | 2.2.20 |
| `app/build.gradle` | — | — |
| `app/build.gradle.kts` | — | — |
| `build.gradle` | — | — |
| `build.gradle.kts` | — | — |

**建议**：
1. 先确认 Flutter 构建实际使用哪套文件（取决于 Gradle 优先级：KTS > Groovy 同名时）。
2. 如 KTS 已实际生效，则 AGP 8.11.1 + Kotlin 2.2.20 已是较新版本，升级空间有限。
3. 如 Groovy 仍实际生效，则 KTS 文件可能是模板/备用，需在升级计划中明确。
4. 最终目标：移除未使用的那套文件，避免维护负担和版本漂移。

---

## 6. 声明

- **本 commit 不升级任何依赖、不改变任何构建行为。**
- 本文档仅为规划参考，目标版本栏标注 TODO 的条目需在实际执行前逐一确认。
- 表中明确版本均来自仓库静态文件；对仓库未直接记录的 Android OpenSSL/Boost 实际版本，本文档标记为“需确认”，不伪造具体版本。
