# 开发文档
> Status: Active
> Type: Index
> Last verified: 2026-07-22
>
> **用途：**在本仓库中开始可由源码追溯的原生开发。
> **适用对象：**贡献者和维护者。
> **上一层索引：**[文档](../README_CN.md) · **English：**[Development](README.md)

## 从这里开始

| 任务 | 页面 |
|---|---|
| 从入口点跟踪到运行时 | [源码阅读指南](SOURCE_READING_GUIDE_CN.md) |
| 运行合适的测试集合 | [测试](TESTING_CN.md) |
| 审阅带日期的 Boost 审计 | [Boost 兼容性审计](BOOST_187_COMPATIBILITY.md) |
| 遵循仓库约定 | [代码风格](../governance/CODE_STYLE.md) · [文档规范](../governance/DOCUMENTATION_STYLE.md) |

## 原生 `ppp` 构建边界

根 CMake 项目构建原生 `ppp` 可执行程序和 `openppp2_lib` 静态库，需要支持 C++17 的工具链。

Linux 和 macOS 上，根 CMake 期望 `THIRD_PARTY_LIBRARY_DIR` 包含本项目使用的 Boost、OpenSSL 和 jemalloc 目录布局。若检出目录中已准备名为 `third-party` 的依赖目录，基本原生构建形态如下：

```bash
cmake -S . -B build/native \
  -DCMAKE_BUILD_TYPE=Release \
  -DTHIRD_PARTY_LIBRARY_DIR=third-party
cmake --build build/native
```

根配置会把非 Windows 原生输出写到 `bin/ppp`。它不会自动下载或构建该第三方依赖树；需要本地复现时，请先对照 Linux/macOS CI workflow。

Windows 上，根 CMake 需要活动的 vcpkg triplet，并从中查找 Boost、OpenSSL 和 jemalloc。已提交的辅助脚本有可由源码确认的本地 x64 路径：

```bat
build_windows.bat Release x64
```

其解析器当前接受 `x86` 和 `x64` 目标参数。虽然 usage 文本也提到 `arm64`，在解析器修复前请不要依赖该辅助参数；Windows ARM64 由单独的 CI 处理。辅助脚本会在 `bin` 下写入按配置和架构划分的子目录。

Android 和 iOS 有各自的 CMake 项目，输出的是库而不是根原生 `ppp` 可执行程序。应把它们视为平台专用界面，而非根 target 的另一种调用方式。

## 构建和测试入口

- [测试](TESTING_CN.md)区分独立 C++ 测试和根 `ENABLE_TESTS` 构建。
- `scripts/run-cpp-tests.sh` 配置并运行 `tests/cpp` 下的聚焦 C++ 测试。
- `scripts/run-cpp-coverage.sh` 与 `scripts/coverage.sh` 的覆盖率范围和前提不同。
- `scripts/run-lifecycle-sanitizers.sh` 运行独立生命周期 sanitizer targets。

## CI 事实

已提交的 workflows 覆盖原生 Linux、Windows 和 macOS 构建，以及独立的 Android 和平台界面。主单元测试 workflow 运行独立 C++ 检查、生命周期 sanitizer、Guardian/Go 检查、Flutter 测试和 iOS 逻辑测试。当前不运行实验性 Desktop Client 的 npm 或 Cargo 检查。

## 当前文档与带日期材料

本索引中的 English/Chinese 页面是当前配对文档。[`BOOST_187_COMPATIBILITY.md`](BOOST_187_COMPATIBILITY.md)有意仅保留中文，并标记为需要重新验证的带日期源码审计；它不是稳定的支持矩阵。
