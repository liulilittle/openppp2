# PPP_PUBLIC_DNS_SERVER_LIST 维护治理规范
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **用途：**保留设计依据、决策过程或历史验证记录。
> **适用对象：**需要追溯历史背景的维护者。
> **当前状态：**已归档，不作为当前配置依据。
> **最后核对依据：**文档生命周期与 Git 历史，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)

> **归档提示：**本文档仅用于追溯，不得作为当前安装、配置或运行依据。


> 本文档描述 `ppp/stdafx.h` 中 `PPP_PUBLIC_DNS_SERVER_LIST` 数组的维护规则，
> 防止因隐式字符串拼接导致的回归问题（参见 deep-code-audit P2-3）。

## 1. 问题背景

C/C++ 中相邻的字符串字面量会被编译器隐式拼接：

```cpp
"120.53.53.53"       // ← 如果此处漏掉逗号
"8.8.8.8"            // ← 编译器会将其拼接为 "120.53.53.538.8.8.8"
```

这会导致：
- 产生非法 IP 地址
- 数组元素总数减少一个
- 运行时 DNS 解析静默失败

历史上 `PPP_PREFERRED_DNS_SERVER_1`（宏展开为 `"8.8.8.8"`）前曾漏掉逗号，
导致上述隐式拼接。

## 2. 当前防护措施

### 2.1 边界注释

```cpp
// ---- PPP_PUBLIC_DNS_SERVER_LIST begins ----
// Each entry MUST be a separate comma-separated string literal.
// PPP_PREFERRED_DNS_SERVER_1/2 are #define macros (expand to string literals);
// a missing comma before them would cause C/C++ implicit adjacent-string concatenation.
static constexpr const char* PPP_PUBLIC_DNS_SERVER_LIST[] = {
    ...
};
// P2-3 regression guard: pin the expected entry count ...
static_assert(sizeof(PPP_PUBLIC_DNS_SERVER_LIST) / sizeof(PPP_PUBLIC_DNS_SERVER_LIST[0]) == 56,
              "PPP_PUBLIC_DNS_SERVER_LIST entry count changed - did you forget a comma?");
// ---- PPP_PUBLIC_DNS_SERVER_LIST ends ----
```

### 2.2 编译期 `static_assert`

在数组声明之后紧跟一个 `static_assert`，固定元素计数为 **56**。

**效果：**
- 如果任何两个条目因漏逗号而合并，元素数变为 55，编译失败。
- 如果新增条目但忘记更新断言数字，同样编译失败——强制开发者人工核对条目数。

**局限：**
- 不能检测单个条目的 IP 格式是否合法。
- 不能检测是否多了/少了合法条目（只校验总数）。

## 3. 修改规则

### 3.1 新增 DNS 条目

1. 在数组中合适位置添加新条目，确保前后均有逗号。
2. 更新 `static_assert` 中的数字（当前为 56，新增 1 条则改为 57）。
3. 本地编译验证 `static_assert` 通过。

### 3.2 删除 DNS 条目

1. 删除目标条目，确保不留悬空逗号。
2. 更新 `static_assert` 中的数字。
3. 本地编译验证。

### 3.3 修改宏展开项

`PPP_PREFERRED_DNS_SERVER_1` 和 `PPP_PREFERRED_DNS_SERVER_2` 是 `#define` 宏，
展开后为字符串字面量。修改宏定义本身不影响条目数，但修改其在数组中的位置时
需格外注意逗号。

## 4. 可选脚本校验方案（已提供）

以下工具 **不接入 CI、不改构建、不作为 release gate**，仅供开发者在本地修改 DNS 列表后手动运行以提高信心。

### 4.1 `scripts/check-dns-ipv4.py`

**文件位置：** `scripts/check-dns-ipv4.py`

**用途：** 从 `ppp/stdafx.h` 中提取 `PPP_PUBLIC_DNS_SERVER_LIST` 数组的全部条目，
解析两个 `#define` 宏展开值，逐项校验是否为合法 IPv4 地址。

**校验规则：**

| 规则 | 说明 |
|------|------|
| 严格 IPv4 格式 | 四组 0–255 的十进制数，以 `.` 分隔 |
| 禁止前导零 | 如 `01.02.03.04` 判为非法（避免与某些解析器歧义） |
| 禁用保留地址 | `0.0.0.0` 和 `255.255.255.255` 判为非法 |
| 宏解析 | `PPP_PREFERRED_DNS_SERVER_1` → `"8.8.8.8"`，`PPP_PREFERRED_DNS_SERVER_2` → `"8.8.4.4"` |

**运行方式：**

```bash
# 从仓库根目录运行（自动定位 ppp/stdafx.h）
python3 scripts/check-dns-ipv4.py

# 或显式指定文件路径
python3 scripts/check-dns-ipv4.py ppp/stdafx.h
```

**退出码：**

| 退出码 | 含义 |
|--------|------|
| `0` | 全部条目合法 |
| `1` | 存在非法 IPv4 条目（会打印具体行号与原因） |
| `2` | 解析错误（找不到数组边界标记或宏定义） |

**脚本特性：**

- ✅ 只读：仅读取 `ppp/stdafx.h`，不修改任何文件
- ✅ 离线：无网络依赖
- ✅ 独立：仅依赖 Python 3 标准库
- ✅ 非门控：不接入 CI 流水线，不作为发布阻断条件

### 4.2 与 `static_assert` 的互补关系

```
┌─────────────────────────────────────────────────────────┐
│ static_assert(count == 56)                              │
│   └─ 编译期拦截：条目数减少（漏逗号导致拼接）            │
│   └─ 不能校验单条目 IPv4 格式                           │
├─────────────────────────────────────────────────────────┤
│ scripts/check-dns-ipv4.py                               │
│   └─ 手动运行校验：每条目是否为合法 IPv4                 │
│   └─ 可检测格式错误、前导零、保留地址                    │
│   └─ 不阻断构建，不做发布门控                           │
└─────────────────────────────────────────────────────────┘
```

两者覆盖范围不同：
- `static_assert` 捕捉**结构性**问题（条目数减少 = 逗号遗漏），在编译期自动生效。
- 脚本捕捉**语义性**问题（IP 格式非法），需要开发者主动运行。

### 4.3 非 Release Gate 策略

此脚本 **不** 接入 CI 流水线或构建系统，原因如下：

1. **零收益于阻断发布**：`static_assert` 已在编译期拦截最危险的回归（隐式字符串拼接）。
2. **当前条目人工可控**：56 条 DNS 记录不频繁变动，人工审查足以覆盖。
3. **避免构建依赖膨胀**：不引入 Python 运行时作为构建前置条件。

建议的使用时机：
- 修改 `PPP_PUBLIC_DNS_SERVER_LIST` 后、提 PR 前手动运行一次。
- Code review 时可要求作者贴运行结果作为证据（可选，非强制）。

### 4.4 代码审查清单（PR 模板建议）

在 PR 模板中增加一项检查：

> ☑ 如果修改了 `PPP_PUBLIC_DNS_SERVER_LIST`：
> - [ ] 已同步更新 `static_assert` 中的条目计数
> - [ ] （可选）已运行 `python3 scripts/check-dns-ipv4.py` 并确认全部通过

## 5. 编译期 constexpr IPv4 格式校验（未实现，仅供参考）

理论上可以用 C++17 `constexpr` 函数逐字符校验每个字符串是否符合 `d.d.d.d` 格式，
在编译期直接拒绝非法 IP。但存在以下障碍：

- 当前数组包含 `#define` 宏展开项（`PPP_PREFERRED_DNS_SERVER_1/2`），
  `constexpr` 上下文中对宏展开的字符串字面量做逐字符校验需要将宏收敛为
  统一的 `constexpr` 变量，改动面较大。
- 在 `stdafx.h` 这个超级前缀头文件中引入复杂模板逻辑，编译开销不可控。

**替代路径：** 如果未来条目数增长到百级以上，可考虑：
1. 将宏展开项改为 `static constexpr const char*` 变量。
2. 编写 `constexpr bool is_valid_ipv4(const char*)` 工具函数。
3. 在数组声明处添加逐项 `static_assert`（需 C++20 或手动展开）。

当前阶段（56 条）不需要走到这一步，脚本方案已足够。
