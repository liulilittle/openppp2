# 文档规范

> **用途：**定义当前文档的元数据、位置、链接和配对规则。
> **适用对象：**文档作者和评审者。
> **当前状态：**现行治理规则。
> **最后核对依据：**当前文档检查器和目录布局，2026-07-22。
> **上一层索引：**[Development](../development/README.md) · **English：**[Documentation Style](DOCUMENTATION_STYLE.md)

> Status: Active
> Type: Governance
> Last verified: 8c8a888

稳定参考文档归入 `docs/README.md`，通常应提供英文/中文配对。范围较窄的设计、审计、迁移计划和治理决策应放在各自的专门区域。

受治理文档以以下元数据开头：

```markdown
> Status: Draft
> Type: Design
> Last verified: <commit>
```

`tools/check_docs.py` 会检查受治理文档的元数据和相对链接。它只在根 `docs/README.md` 出现英文/中文配对链接时检查该配对；不会检查每一个文档地图中的所有配对。既有元数据债务按准确路径记录在 `METADATA_GRANDFATHERED.txt` 中。旧文档移动后应更新列出的路径；一旦具备受治理元数据，就应删除该例外。新文档不得使用目录级例外。
