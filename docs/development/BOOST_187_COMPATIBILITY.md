# Boost 1.87+ 兼容性源码审计
> Status: Historical — re-verification required
> Type: Technical audit
> Last verified: 2026-07-22
>
> **用途：**保留一次基于当前源码和 CI 配置的兼容性审计，不作为发布支持承诺。
> **适用对象：**维护 Boost 工具链、CI 或相关 Asio 调用的贡献者。
> **上一层索引：**[开发文档](README_CN.md)
> **语言边界：**本文是带日期的中文技术审计，故意不配稳定 English 页面。

## 结论边界

当前源码包含若干针对较新 Boost API 的版本条件，但本审计**不能**证明“全面支持 Boost 1.87+”，也不能替代在目标 triplet/平台上的实际构建和测试。

- Linux amd64 CI 明确设置 `BOOST_VERSION=1.86.0`。
- Windows CI 通过 vcpkg 安装 Boost 组件；工作流没有在仓库中固定一个可作为 Boost 1.87+ 支持证据的 Boost 版本。
- 根 `CMakeLists.txt` 要求若干 Boost 组件，但没有一个 Boost 最低版本检查。
- 下面仍保留 `cancel(ec)` 调用，因此升级 Boost 前必须在目标环境编译验证。

因此，本文状态为 **Historical — re-verification required**，而不是 Active 兼容性矩阵。

## 已观察到的源码适配

| 源码位置 | 当前观察 | 审计含义 |
|---|---|---|
| `ppp/stdafx.cpp` | 以 `BOOST_VERSION >= 108700` 选择 `boost/stacktrace/stacktrace.hpp`，否则使用旧头路径。 | 代码显式处理 stacktrace 头路径差异。 |
| `ppp/auxiliary/StringAuxiliary.cpp` | 以 `BOOST_VERSION >= 108600` 选择 UUID 内存拷贝路径。 | 代码显式处理 UUID API/布局差异。 |
| `common/aggligator/aggligator.cpp` | 以 `BOOST_VERSION >= 108000` 选择较新的 `boost::asio::spawn` 调用形式。 | 代码显式处理部分 Asio 调用差异。 |
| `ppp/tap/ITap.cpp` | 仍存在 `stream->cancel(ec)`。 | 必须在目标 Boost/toolchain 上验证。 |
| `ppp/net/Socket.cpp` | 仍存在 `stream->cancel(ec)`。 | 必须在目标 Boost/toolchain 上验证。 |

这些观察只覆盖列出的路径；不能推导到所有 Boost 或 Asio API。

## CI 和构建证据

`build-linux-amd64.yml` 当前构建 Boost 1.86.0、OpenSSL 3.0.13 和 jemalloc 5.3.0 后，再向根 CMake 提供第三方目录。Windows x64 workflow 则以 vcpkg 的静态 triplet 安装 Boost、OpenSSL 和 jemalloc，然后构建 Windows 项目。

这两条工作流说明当前维护的构建输入不同，不能把 Linux 的 1.86.0 结果等同于任意 vcpkg 快照，更不能自动外推到所有 1.87+ 版本。

## 重新验证建议

升级或更换 Boost 时：

1. 在目标平台准备与根 CMake 所需布局一致的 Boost、OpenSSL 和 jemalloc。
2. 配置并构建目标原生项目；Windows 应使用目标 vcpkg triplet。
3. 运行与改动相关的独立 C++ 套件或根 `ENABLE_TESTS` 套件；入口见[测试](TESTING_CN.md)。
4. 对 Asio 取消、协程、解析器和网络接口路径的编译失败或行为变化建立回归测试，而不是只修改版本条件。
5. 只有在目标平台 CI 和本地复现均通过后，才更新任何面向用户的支持声明。

## 不应从本文推导的结论

- 不应据此声明所有 Boost 1.87+ 版本、所有平台或所有 vcpkg 快照均已支持。
- 不应把仓库中的条件编译视为完整 ABI 或运行时兼容性测试。
- 不应将诊断/实验性构建结果作为生产兼容性承诺。
