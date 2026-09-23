# 测试
> Status: Active
> Type: Development guide
> Last verified: 2026-07-24
>
> **用途：**选择并运行真正覆盖所改界面的测试入口。
> **适用对象：**贡献者和 CI 维护者。
> **上一层索引：**[开发文档](README_CN.md) · **English：**[Testing](TESTING.md)

## 选择正确的 C++ 测试边界

仓库有两条不同的 C++ 测试路径。不要把其中一条描述成另一条的快捷方式。

| 路径 | 构建内容 | 使用时机 |
|---|---|---|
| `tests/cpp` | 由 CTest 注册的聚焦独立可执行文件 | 不配置完整原生运行时时进行快速单元/回归测试。 |
| 根 CMake + `ENABLE_TESTS=ON` | `ppp`、`openppp2_lib`、基于 GTest 的 `openppp2_tests` 和 `openppp2_dns_cache_ttl_tests` | 改动需要根原生依赖图或 root-linked 测试行为时。 |

### 独立 C++ 套件

脚本使用 Ninja 配置 `tests/cpp`、构建并运行 CTest：

```bash
scripts/run-cpp-tests.sh
```

该项目需要 CMake 3.16 或更高版本、支持 C++17 的编译器、OpenSSL 和 Ninja（脚本明确选择它）。构建目录为 `build/test`。

### 根 CMake 测试

先准备根依赖目录布局，再用 `ENABLE_TESTS` 配置根项目：

```bash
cmake -S . -B build/root-tests \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_TESTS=ON \
  -DTHIRD_PARTY_LIBRARY_DIR=third-party
cmake --build build/root-tests
ctest --test-dir build/root-tests --output-on-failure
```

`ENABLE_TESTS` 默认是 `OFF`。启用时，`tests/CMakeLists.txt` 会获取 GoogleTest v1.14.0，因此首次配置除根原生依赖外还可能需要网络访问。这与 `tests/cpp` 是两条独立路径。

## 覆盖率和 sanitizer

### 聚焦 LLVM 覆盖率

```bash
scripts/run-cpp-coverage.sh
```

脚本会为 `tests/cpp` 启用覆盖率，且只构建并运行 `p2p_replay_window_test`、`dns_buffer_test` 和 `base64_test`，随后写入 `build/coverage/summary.txt`。除独立套件前提外，还需要 `llvm-profdata` 和 `llvm-cov`。

### 根运行时覆盖率

```bash
THIRD_PARTY_LIBRARY_DIR=third-party scripts/coverage.sh
```

该脚本用 Clang、`ENABLE_TESTS=ON` 和 `ENABLE_COVERAGE=ON` 配置根项目，因此需要完整的原生依赖目录布局。根覆盖率插桩不支持 MSVC。

### 生命周期 sanitizer targets

```bash
scripts/run-lifecycle-sanitizers.sh
```

该脚本以 `ENABLE_SANITIZERS=ON` 配置独立 C++ 项目，默认使用 `clang++`，并构建/运行五个指定的生命周期、路由和 DNS targets。它适用于生命周期敏感的改动；它不会构建完整原生可执行程序。

### ThreadSanitizer

```bash
CXX=clang++ scripts/run-cpp-tsan-tests.sh
```

该脚本在 `build/test-tsan` 中以 `ENABLE_TSAN=ON` 配置完整独立 C++ 套件，然后构建并运行全部已注册的 CTest targets。TSan 与 `ENABLE_SANITIZERS`（ASan/UBSan）互斥，需要编译器提供可用的 ThreadSanitizer runtime，并且不会构建根原生可执行程序。本地 Clang TSan runtime 不可用时可改用 `CXX=g++`。通过 `openppp2_add_cpp_test()` 注册的每个独立测试都具有 120 秒 watchdog，因此死锁会失败而不是永久挂住 CI。

本批关键的确定性并发测试包括 `yield_context_test`、`spinlock_test`、`asynchronous_write_io_queue_test`、`dns_udp_relay_test`、`client_datagram_port_manager_test`、`protector_network_request_test`、`transmission_qos_concurrency_test`、`vdns_request_lifecycle_test`、`mapping_port_connect_reentrancy_test` 和 `dns_controller_test`。

## Runtime contract 前提

`bash scripts/test-runtime-contract.sh cpp` 假定 `build/test` 已存在。先配置独立项目；该脚本随后在检查共享 fixture hashes 后，只构建并运行 `runtime_snapshot_test`。

```bash
cmake -S tests/cpp -B build/test -G Ninja
bash scripts/test-runtime-contract.sh cpp
```

## 其他已提交组件测试

修改相应组件时，从指定目录运行：

```bash
# Guardian Go package
( cd go/guardian && go test ./... )

# CI 使用的 Go manager/backend package 检查
( cd go && go vet ./ppp/... && go test ./ppp/... )

# Android Flutter 测试
( cd android && flutter pub get && flutter test )

# iOS 逻辑测试
( cd ios/App && ./run-tests.sh )

# 实验性 Desktop Client 前端和 Rust 壳
( cd desktop/client && npm ci && npm test && npm run build \
  && cargo test --manifest-path src-tauri/Cargo.toml )
```

部分命令需要平台 SDK/工具链；本地缺少 SDK 不应被当作运行时失败。

## 根 CMake 的测试相关选项

以下选项默认均为 `OFF`：

| 选项 | 作用 |
|---|---|
| `ENABLE_TESTS` | 启用 CTest，并加入根 GTest/DNS 测试子目录。 |
| `ENABLE_COVERAGE` | 在非 MSVC 工具链上加入 LLVM 覆盖率插桩。 |
| `ENABLE_VMUX_CHURN_TEST` | 构建并注册 root-linked VMUX carrier-churn 集成测试。 |
| `ENABLE_VMUX_RECEIVE_SEMANTICS_TEST` | 构建并注册 root-linked VMUX receive-semantics 测试。 |
| `ENABLE_ASAN`、`ENABLE_UBSAN` | 在根项目中启用诊断 sanitizer flags；不是生产构建模式。 |

## 当前 CI 覆盖

`.github/workflows/test.yml` 是主单元测试 workflow。它运行独立 C++/覆盖率路径、独立的完整套件 ThreadSanitizer job、生命周期 sanitizer、Guardian 和 Go 检查、Flutter 测试以及 iOS 逻辑测试。它**不**运行实验性 Desktop Client 的 npm 或 Cargo 测试命令。

原生构建 workflows 与这个单元测试 workflow 分开。宣称某个平台或特性已由 CI 覆盖前，请阅读对应 workflow。
