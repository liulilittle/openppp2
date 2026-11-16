# corocc 后端：构建与验证

[English](COROCC_BACKEND.md) | [设计 ADR](../adr/0003-corocc-coroutine-backend_CN.md)

corocc 是默认关闭的可选实验性 L0 后端。默认构建继续使用 Boost fcontext，
不下载或配置 corocc。YieldContext 公开 API 和 Anchor 调用点保持不变。
corocc 构建在运行统计新增 `coroutine_backend: "corocc"`；默认 Boost 构建不输出
此字段以保留原序列化字节，字段缺省时仍表示原有 Boost 行为。

## 构建

```sh
bash tools/prepare_corocc.sh
cmake -S . -B build/corocc -DENABLE_COROCC=ON \
  -DTHIRD_PARTY_LIBRARY_DIR=/path/to/provisioned/dependencies
cmake --build build/corocc --parallel 4
```

按原平台构建说明准备依赖；启用 corocc 不会取消 Boost/OpenSSL 要求。
构建输出必须与运行中的 PPP 安装分开；编译不需要启动客户端或改路由、DNS、驱动。

准备脚本校验固定归档 SHA-256，缓存到 `third-party/.cache`，按文件名顺序应用
`tools/corocc-patches/*.patch` 并写入 revision/patch marker。已有目录与版本或
补丁不一致时拒绝覆盖；检查后移到别处，或用 `COROCC_SOURCE_DIR` 选择新目录。
配置时用 `-DCOROCC_SOURCE_DIR=/path/to/prepared/corocc` 指定源码位置。
依赖源码不纳入版本控制；升级时必须审计借用栈范围字段与 sanitizer 布局等 ABI。

`-DPPP_COROCC_GUARD_STACK=ON` 使用带保护页的栈，默认关闭。
`-DCOROCC_FORCE=ON` 允许白名单外的实验平台，但不能启用 iOS 后端。
独立 MSBuild 工程暂不启用 corocc；Windows 可选构建使用 CMake/MSVC。
macOS 需要原生 SDK，Android 需要 NDK 及目标平台 Boost/OpenSSL。
Linux 编译不能证明 Windows 原生 SEH/TIB 或移动端运行行为。

准备脚本需要 Bash、curl、tar、patch 和 sha256sum；macOS 等缺少 sha256sum
的环境需先配置 coreutils。

Android 独立的 `android/CMakeLists.txt` 接受相同开关，将 PIC corocc 静态库
链接进共享库。iOS 独立入口会警告并关闭该开关，保留现有 Boost 汇编及 shim。

## 离线测试

```sh
bash scripts/run-cpp-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-asan-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-tsan-tests.sh
ENABLE_COROCC=1 bash scripts/run-cpp-tests.sh -DPPP_COROCC_GUARD_STACK=ON
bash tools/check_include_boundaries.sh
bash tools/check_vcxproj_sources.sh
```

`CPP_TEST_BUILD_DIR` 覆盖构建目录，`CPP_TEST_JOBS` 控制构建并行度（默认 4）。
默认、corocc、ASan、TSan 使用独立目录；ASan/UBSan 与 TSan 不能混用。
WSL 下 sanitizer 脚本通过 `setarch $(uname -m) -R` 运行 CTest；若无法设置
personality，属于环境限制，不能算测试通过。ASan 开启 stack-use-after-return
与泄漏检查。这些脚本不运行需要特权的网络 E2E。

切换测试覆盖 100 万次切换、嵌套、三方接力、结束 handoff，以及通过 101 个
依次 join 的不同线程迁移；另一次迁移由四个持续存活的 worker 按序接力。
已有 Anchor 套件覆盖重复、迟到、提前、结束后唤醒及四 worker
竞态。新增测试覆盖标准/未知异常、24 KiB 栈保持、1/4 独立 io_context worker，
以及 POSIX guard 构建下的子进程保护页故障。

XTCP contract 测试需先准备 XTCP，再向脚本传入 `-DENABLE_XTCP_TESTS=ON`。
`tools/run_xtcp_fault_suite.sh` 测试独立上游 XTCP C 库，不调用 YieldContext，
因此本身不能区分协程后端；应与启用 corocc 的集成测试配合运行，不能当作
协程切换覆盖。

用 `nm -g --defined-only` 检查内核链接结果：原 Boost 符号与重命名的
`corocc_asm_*` 可共存，不应出现重复定义；PPP 后端不应引用 corocc
token/runtime/scope API。

## 性能门槛

使用相同源码、编译器、依赖和配置的两个 release 二进制，仅 `ENABLE_COROCC`
不同；测量前固定 SHA-256。只使用实验机批准的测量控制器及锁，不替换活动安装，
不另行启动网络 runner。DL/UL P1/P16/P64 两轮交错，顺序 A1/B1/B2/A2；保留
吞吐、CPU、RSS、重传、控制器/二进制哈希及清理证据。保持至少 20 GB 剩余空间，
结束后删除本任务构建目录。

各单元报告两轮数据、均值相对变化及波动；退化超过 3%、波动大于差值或任何
正确性故障均不能宣称收益。微基准不能代替 A/B。
实际执行范围与限制见[验证记录](COROCC_VALIDATION_CN.md)。
