# Documentation Style

> **Purpose:** Define current document metadata, placement, link, and pairing rules.
> **Audience:** Documentation authors and reviewers.
> **Status:** Current governance.
> **Last verified against:** Current documentation checker and directory layout, 2026-07-22.
> **Parent index:** [Development](../development/README.md) · **Chinese:** [文档规范](DOCUMENTATION_STYLE_CN.md)

> Status: Active
> Type: Governance
> Last verified: 8c8a888

Stable references belong in `docs/README.md` and normally have an English/Chinese pair. Narrow designs, audits,
migration plans, and governance decisions belong in their specialized sections.

Governed documents start with:

```markdown
> Status: Draft
> Type: Design
> Last verified: <commit>
```

`tools/check_docs.py` validates governed-document metadata and relative links. It checks English/Chinese pairs only
when a paired link appears in root `docs/README.md`; it does not validate pairing throughout every document map.
Existing metadata debt is listed by exact path in `METADATA_GRANDFATHERED.txt`. When a legacy document moves,
update its listed path or remove it once governed metadata is present; new documents cannot use directory-wide
exceptions.
