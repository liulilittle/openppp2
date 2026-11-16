# 测试

可选协程后端需要分别运行默认/corocc 套件，以及独立 corocc ASan、TSan 构建。
命令与覆盖范围见 [corocc 测试说明](COROCC_BACKEND_CN.md)，
实测见[验证记录](COROCC_VALIDATION_CN.md)。WSL 下 sanitizer 脚本使用
`setarch $(uname -m) -R`。保护页 death test 仅在可选 guard 构建的子进程运行。

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

### 聚焦 P2P v2 隔离验收

在仓库根目录运行固定套件；三种模式使用独立构建目录，并编译真实应用接线：

```sh
sh scripts/run-p2p-v2-isolation.sh normal
sh scripts/run-p2p-v2-isolation.sh asan
sh scripts/run-p2p-v2-isolation.sh tsan
```

需保留已有构建产物时，以 `OPENPPP2_P2P_BUILD_DIR` 指定独立目录；
`CXX` 选择编译器，`OPENPPP2_BUILD_JOBS` 控制编译并发数。

在独立目录配置 `tests/cpp`，构建 `p2p_*` targets。新增 v2 目标包括
`p2p_v2_offer_test`、`p2p_v2_channel_test`、`p2p_v2_noise_test`、
`p2p_v2_integration_test`、`p2p_probe_coordinator_test`、
`p2p_ingress_limiter_test`、`p2p_stun_gatherer_test` 和
`p2p_native_socket_stun_test`。固定套件还包含 `p2p_information_message_test`
与 `p2p_v2_server_coordination_test`；后者测试生产协调 helper 的并发刷新、
双边激活、取消、迟回调和保守 predecessor 恢复。
`p2p_v2_app_wiring_compile` 对真实客户端、
server 和 carrier 接线进行对象编译，不链接或启动 PPP。

ASan/UBSan 使用 `-DENABLE_SANITIZERS=ON`，TSan 使用独立目录及
`-DENABLE_TSAN=ON`，不能混用。native 测试仅使用非特权 loopback UDP；
sandbox 可能要求开放 socket 的执行权限。禁止为该套件启动 PPP 或特权 netns。
集成测试使用真实 offer/channel/codec 和 IPv4 parser，只模拟 NAT、relay 与时钟，
覆盖 180 秒轮换、100 次连接/刷新/停止、迁移、nonce 耗尽与 CommitACK 丢失。
该 integration target 未实例化完整 Exchanger 自动恢复；下文独立的根链接恢复目标
使用真实 Exchanger。上述证据不代表 Android 真机、
真实 NAT 或 Linux SO_MARK 绕过 TUN 已验收，生产 gate 必须保持关闭。

本节描述的 P2P v2 改动及 2026-10-05 测试结果来自相对当时已发布 `main` 的实现。代码推送现已获授权；
v2.1.7 仍待代码推送完成且 CI 全绿后发布。

2026-10-05 普通 P2P 与原有 Noise 回归套件 30 targets 通过，包括因 socket 权限限制
单独运行的非特权 loopback 检查；原有 Noise handshake/exporter 两个目标也通过。
最终 focused 套件 10 targets、80 cases
在 ASan/UBSan/LSan 与独立 TSan 下均通过。integration target 共 16 cases，
包含 180 秒与 100 次循环场景；真实应用接线对象目标编译通过。
最终 channel 用例覆盖认证 RX 序号大幅数值前进，仍禁止回绕、重复交付，
失败 AEAD 不提交接收窗口更新。相关 tooling 套件 46 项通过。
上述 focused 结果覆盖 Linux 隔离检查。后续根项目 Linux Release 完成 283 项
全量编译/链接，并在恢复修复后增量重新链接；最终生产构建无恢复测试宏，gate 关闭。
这不代表 Windows MSBuild、Android SDK/真机或真实网络已验收。

### 根 CMake 测试

验收真实 Exchanger 恢复前，先准备根项目所需的原生依赖目录布局，再运行独立脚本。
依赖根通过 CMake 参数传入；脚本不会安装依赖：

```sh
sh scripts/run-p2p-v2-exchanger-recovery.sh normal -DTHIRD_PARTY_LIBRARY_DIR=/path/to/native-deps
sh scripts/run-p2p-v2-exchanger-recovery.sh asan -DTHIRD_PARTY_LIBRARY_DIR=/path/to/native-deps
sh scripts/run-p2p-v2-exchanger-recovery.sh tsan -DTHIRD_PARTY_LIBRARY_DIR=/path/to/native-deps
```

三种模式在独立目录构建真实 `openppp2_lib`，只运行
`p2p_v2_exchanger_recovery_test`，不启动 PPP。可按需设置
`OPENPPP2_P2P_RECOVERY_BUILD_DIR`、`CC`、`CXX` 和 `OPENPPP2_BUILD_JOBS`。
根选项 `ENABLE_P2P_RECOVERY_TESTS` 默认 OFF；编译隔离的依赖钩子要求显式测试
capability，生产 gate 继续关闭。用例通过真实恢复与 Update 方法覆盖 socket 故障、
退避、登记失败、调度失败、旧回调及挂起协程隔离、认证 v2 重连、v1 拒绝和 FRP 维护。
根项目 ASan/UBSan 和 TSan 构建必须使用不同目录。

2026-10-05 真实 Exchanger 的 9 个用例在完整库普通、ASan/UBSan/LSan 和独立
TSan 构建下全部通过，脚本三种模式也分别复验通过。此 sandbox 中 LSan 需要
隔离进程检查权限。登记、transport 和 relay 输出属于模拟依赖；原生 socket
保护、真实 INFO 交付、NAT 穿透和设备行为仍未验收。恢复失败且无就绪 transport
时，现已按退避安排重试而不发送 renew。

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

Linux 下脚本检查 `ADDR_NO_RANDOMIZE`，必要时通过
`setarch "$(uname -m)" -R` 重启自身。高熵 ASLR（本地 WSL2 的
`vm.mmap_rnd_bits=32`）可能将 PIE 或共享库映射到 TSan 保留地址范围，
导致进入 `main` 前报 `unexpected memory mapping`。仅关闭 PIE 无法控制共享库
地址。该处理只影响测试进程树，不修改系统 sysctl。需要 util-linux 的
`setarch` 及设置该 personality 标志的权限；容器禁止该操作时脚本明确失败。
不能通过反复重试直到启动成功来掩盖问题。

`TSAN_BUILD_DIR` 可指定独立构建目录，`CMAKE_BUILD_PARALLEL_LEVEL` 控制并行度，
额外脚本参数传递给 CMake：

```bash
TSAN_BUILD_DIR=/tmp/cpp-tsan CMAKE_BUILD_PARALLEL_LEVEL=8 CXX=g++ \
  sh scripts/run-cpp-tsan-tests.sh -DENABLE_XTCP_TESTS=ON \
  -DXTCP_SOURCE_DIR=/path/to/prepared/xtcp -DCMAKE_BUILD_TYPE=RelWithDebInfo
```

vendored XTCP 自身测试需要同时插桩库和测试程序：

```bash
cmake -S /path/to/prepared/xtcp -B /tmp/xtcp-tsan -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DXTCP_CHECKSUM_VALIDATE=ON \
  -DXTCP_SANITIZE=OFF -DXTCP_BUILD_TESTS=ON \
  -DCMAKE_CXX_FLAGS='-fsanitize=thread -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread
cmake --build /tmp/xtcp-tsan --parallel 8
TSAN_OPTIONS='halt_on_error=0 exitcode=66' setarch "$(uname -m)" -R \
  ctest --test-dir /tmp/xtcp-tsan --output-on-failure --timeout 120
```

M3 并发覆盖包括 `spsc_handoff_test`、`xtcp_direct_handoff_test`、
`tap_output_lane_test`、`tap_lane_envelope_handoff_test`、
`xtcp_queue_mode_lifecycle_test`、`xtcp_shard_policy_test`；XTCP 侧包括
`test_shard`、`test_thread_data`、
`test_thread_send_abort`、`test_conn_churn_threads`。shard policy 测试只验证选择规则，
不能视为多线程 runtime 验证。TSan 通过只说明实际执行的离线路径，不能证明 VPN
会话工作正常。

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

根生产构建选项另有平台默认值：Linux 构建（包括交叉编译）默认启用
`ENABLE_XTCP`，配置前需要运行 `bash tools/prepare_xtcp.sh`；Android、macOS
和 Windows 默认关闭，发布工作流会显式传入对应值。`ENABLE_SIMD` 在 x86/x64 上默认启用，
ARM/Android 默认关闭；Windows MSBuild 可用 `/p:OpenPPP2EnableSimd=false` 显式移除
`__SIMD__`。

## 当前 CI 覆盖

网络控制面生命周期的合同、Issue 拆分和平台验收边界见[VPN 网络生命周期合同](../architecture/NETWORK_LIFECYCLE_CONTRACT_CN.md)。其中的离线测试和真实系统测试是两种不同证据；通过 CTest 不等于 Windows DNS、路由或代理已在实机恢复。

`.github/workflows/test.yml` 是主单元测试 workflow。它运行独立 C++/覆盖率路径、独立的完整套件 ThreadSanitizer job、生命周期 sanitizer、Guardian 和 Go 检查、Flutter 测试以及 iOS 逻辑测试。它**不**运行实验性 Desktop Client 的 npm 或 Cargo 测试命令。

原生构建 workflows 与这个单元测试 workflow 分开。宣称某个平台或特性已由 CI 覆盖前，请阅读对应 workflow。
