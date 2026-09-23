# OpenPPP2 Proxy-only 模式完整计划
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


本文档描述 **proxy-only 本地 SOCKS/HTTP 正向代理模式** 的功能实现、测试与 LLVM 覆盖率计划。

**分支：** `feature/proxy-only-mode`
**范围：** Linux / macOS / Windows / Android（不含 iOS）

---

## 1. 结论

OpenPPP2 已有本地 HTTP/SOCKS5 代理实现（`ppp/app/client/proxys/`）。proxy-only 模式新增独立启动路径：**只连远端 + 本机监听**，不改系统路由，桌面端无需 root。

---

## 2. 目标行为

- 启动：`./ppp --mode=proxy --config=./appsettings.json`
- 默认：`127.0.0.1:8080`（HTTP）、`127.0.0.1:1080`（SOCKS5）
- 配置：复用 `client.server`、`client.guid`、`key.*`
- Android：`vpnOptions.proxyOnly=true`，最小 VPN 路由 + socket protect

---

## 3. 功能实现清单

| 模块 | 文件 | 状态 |
|------|------|------|
| ApplicationMode / ResolveApplicationMode | `PppApplication.h`, `ApplicationConfig.cpp` | 已实现 |
| TapStub | `ppp/tap/TapStub.*` | 已实现 |
| proxy_only 配置 | `AppConfiguration.*` | 已实现 |
| Switcher proxy 分支 | `VEthernetNetworkSwitcher.*` | 已实现 |
| Initialize / Main | `ApplicationInitialize.cpp` | 已实现 |
| Android | `libopenppp2.cpp`, `PppVpnService.kt` | 已实现 |
| 文档 | `CLI_REFERENCE.md`, `CONFIGURATION.md` | 已更新 |
| 单元测试 / LLVM-cov | `tests/` | **已实现** |

---

## 4. 使用示例

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://your-server:20000/",
    "proxy-only": true,
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

```bash
./ppp --mode=proxy --config=./appsettings.json
curl -x socks5h://127.0.0.1:1080 https://example.com
```

---

## 5. 测试与 LLVM-cov

### 5.1 基础设施

```cmake
option(ENABLE_TESTS "Build unit tests" OFF)
option(ENABLE_COVERAGE "Enable LLVM source coverage" OFF)
```

目录：`tests/unit/`（GTest），脚本：`scripts/coverage.sh`，CI：`.github/workflows/test-linux-coverage.yml`

### 5.2 用例矩阵（摘要）

| Phase | ID 前缀 | 内容 |
|-------|---------|------|
| 1 | M/C/T | mode 解析、配置默认值、TapStub |
| 2 | S | Switcher proxy_only 分支 |
| 3 | P | HTTP/SOCKS 握手解析 |
| 4 | I | `tools/proxy_mode_smoke.sh` 进程冒烟 |
| 5 | A | Android proxyOnly |

### 5.3 LLVM-cov

```bash
cmake -B build-cov -DENABLE_TESTS=ON -DENABLE_COVERAGE=ON \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
cmake --build build-cov && cd build-cov && ctest
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov report ./tests/openppp2_tests -instr-profile=default.profdata
```

**门槛：** proxy-only 相关文件 line coverage ≥ **70%**

### 5.4 工作量预估

| 工作包 | 人日 |
|--------|------|
| 功能 F1（本分支） | 3–5 |
| 测试基础设施 T0 + Phase1 T1 + CI T4 | 3.5 |
| Phase2–3 + 冒烟 | 4–5 |
| **合计（含测试）** | **12–15** |

---

## 6. 验收标准

- [x] `./ppp --mode=proxy` 无 root 启动，本地代理可 curl
- [x] 默认路由未修改（TapStub / 跳过 AddAllRoute）
- [ ] `--mode=client` 回归通过（需手动验证）
- [x] `ctest` 单元测试 + `scripts/coverage.sh` 覆盖率脚本
- [x] Android `proxyOnly` UI + native 路径

---

## 7. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-06-28 | 初版计划；功能实现合入 feature/proxy-only-mode |
