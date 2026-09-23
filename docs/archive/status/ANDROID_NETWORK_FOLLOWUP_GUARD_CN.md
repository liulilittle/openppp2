# Android 网络 Follow-up Guard 记录
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


## 概述

本文档记录 Android 网络模块中逐步实施的低风险、最小侵入性防御性守卫（guard）项。每项均遵循以下约束：

- 不改变 VPN protect 主流程
- 不改变线程模型或锁粒度
- 不触碰 DNS、`system()`/`popen()`、`atomic_shared_ptr` 相关文件
- 纯诊断日志或空指针/生命周期防御

---

## Guard #1: PostJNI 静默丢弃任务的诊断日志

**日期**: 2026-05-12
**文件**: `android/libopenppp2.cpp`
**函数**: `libopenppp2_application::PostJNI()`

### 问题

`PostJNI()` 通过 `boost::asio::post` 将 JNI 回调任务投递到 ProtectorNetwork 的 io_context。Lambda 中有两个静默失败路径：

1. **protector 生命周期过期**: `protector_weak.lock()` 返回 null，说明 ProtectorNetwork 已在 `VEthernetNetworkSwitcher::Dispose()` 中被析构，`DetachJNI()` 已执行。
2. **JNI 环境不可用**: `protector->GetEnvironment()` 返回 null，说明 JNI 环境指针已被 `DetachJNI()` 清除。

两条路径均静默丢弃任务（如 `StatisticsJNI` 流量统计推送、`PostExecJNI` 序列回调），在 logcat 中完全不可见，增加了 Android 端连接故障的排查难度。

### 修复

在两个失败路径添加 `__android_log_print(ANDROID_LOG_WARN, ...)` 诊断日志：

```cpp
boost::asio::post(*context,
    [context, protector_weak, task]() noexcept {
        std::shared_ptr<ppp::net::ProtectorNetwork> protector = protector_weak.lock();
        if (NULLPTR == protector) {
            __android_log_print(ANDROID_LOG_WARN, "libopenppp2",
                "PostJNI: protector expired, task dropped");
            return;
        }

        JNIEnv* env = protector->GetEnvironment();
        if (NULLPTR == env) {
            __android_log_print(ANDROID_LOG_WARN, "libopenppp2",
                "PostJNI: JNI env unavailable, task dropped");
            return;
        }

        task(env);
    });
```

### 风险评估

| 维度 | 评估 |
|------|------|
| 行为变更 | 无。仅添加日志，不改变控制流 |
| 线程安全 | 无影响。日志调用 `__android_log_print` 本身是线程安全的 |
| 性能影响 | 可忽略。仅在异常路径触发 |
| VPN protect | 不涉及。`PostJNI` 用于统计推送和事件回调 |
| 锁粒度 | 不变 |
| 适用范围 | Android (`_ANDROID` 宏保护下) |

### 可观测性改善

- 断连/重连期间，logcat 将明确显示任务被丢弃的原因
- 可通过 `adb logcat -s libopenppp2 | grep PostJNI` 过滤相关日志
- 辅助判断 ProtectorNetwork 生命周期与 JNI 环境的时序关系

---

## 已知待办项（未实施，记录供后续参考）

### P2: ProtectSocketFd 全局引用 TOCTOU 窗口

**文件**: `android/OpenPPP2VpnProtectBridge.cpp`
**函数**: `ProtectSocketFd()`

**问题**: 在 `clazz`/`protect_method` 从 state 拷贝（锁内）到 `CallStaticBooleanMethod` 调用（锁外）之间，`ShutdownProtectBridge` 可能在另一线程删除全局引用，导致 use-after-free。

**建议修复**: 在 JNI 调用前增加一次锁内一致性校验（比对 `state.clazz == clazz`）。

**风险**: 需要修改 VPN protect 桥接路径的锁获取，需更充分评估。

### P3: libopenppp2_from_tuntap_driver_new 参数防御

**文件**: `android/libopenppp2.cpp`
**函数**: `libopenppp2_from_tuntap_driver_new()`

**问题**: 函数内未对 `context` 和 `network_interface` 参数做空指针检查，完全依赖调用方的前置检查。

**建议修复**: 在函数入口添加 `NULLPTR` 检查并返回 `NULLPTR`。

**风险**: 极低。纯防御性添加，调用方已做检查，正常路径不受影响。

### P4: libopenppp_try_open_ethernet_switcher_new 参数防御

**文件**: `android/libopenppp2.cpp`
**函数**: `libopenppp_try_open_ethernet_switcher_new()`

**问题**: 函数接受 6 个 `shared_ptr` 参数，但未对 `app`、`tap`、`network_interface`、`configuration` 做内部空指针检查。

**建议修复**: 添加入口防御性检查。

**风险**: 极低。调用方 (`libopenppp2_try_open_ethernet_switcher`) 已全部检查。
