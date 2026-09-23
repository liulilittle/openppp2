#!/usr/bin/env python3
"""Validate governed Markdown metadata, relative links, and bilingual map entries."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
GOVERNED_NAME_PATTERN = re.compile(
    r"(?:^|[_-])(?:AUDIT|DESIGN|GOVERNANCE|PLAN)(?:[_-]|\.)",
    re.IGNORECASE,
)
METADATA_FIELDS = ("Status", "Type", "Last verified")


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _governed(relative: str) -> bool:
    path = Path(relative)
    if relative.startswith((
        "docs/adr/",
        "docs/design/",
        "docs/governance/",
        "docs/superpowers/plans/",
        "docs/superpowers/specs/",
    )):
        return path.name.lower() != "readme.md"
    return bool(GOVERNED_NAME_PATTERN.search(path.name))


def _grandfathered(root: Path) -> set[str]:
    path = root / "docs/governance/METADATA_GRANDFATHERED.txt"
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def _link_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    if not target or target.startswith(("#", "/", "mailto:")):
        return None
    if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
        return None
    target = unquote(target.split("#", 1)[0])
    return (source.parent / target).resolve()


def check_repository(root: Path) -> list[str]:
    root = root.resolve()
    docs = root / "docs"
    if not docs.exists():
        return []

    violations: list[str] = []
    grandfathered = _grandfathered(root)
    markdown_files = sorted(docs.rglob("*.md"))
    for path in markdown_files:
        relative = _relative(path, root)
        text = path.read_text(encoding="utf-8", errors="replace")
        if _governed(relative) and relative not in grandfathered:
            header_lines: list[str] = []
            in_fence = False
            for line in text.splitlines():
                if line.lstrip().startswith("```"):
                    in_fence = not in_fence
                elif not in_fence:
                    header_lines.append(line)
                if len(header_lines) >= 20:
                    break
            header = "\n".join(header_lines)
            missing = [
                field
                for field in METADATA_FIELDS
                if not re.search(rf"^>\s*{re.escape(field)}\s*:\s*\S", header, re.MULTILINE)
            ]
            if missing:
                violations.append(
                    f"{relative}:1: missing document metadata: {', '.join(missing)}"
                )

        in_fence = False
        for line_number, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            prose = re.sub(r"`[^`]*`", "", line)
            for match in LINK_PATTERN.finditer(prose):
                target = _link_target(path, match.group(1))
                if target is not None and not target.exists():
                    violations.append(
                        f"{relative}:{line_number}: broken relative link: {match.group(1)}"
                    )

    index = docs / "README.md"
    if index.exists():
        for line_number, line in enumerate(
            index.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            targets = [match.group(1).split("#", 1)[0] for match in LINK_PATTERN.finditer(line)]
            if len(targets) != 2:
                continue
            english, chinese = targets
            if not english.endswith(".md") or chinese != english[:-3] + "_CN.md":
                continue
            for target in (english, chinese):
                if not (docs / target).exists():
                    violations.append(
                        f"docs/README.md:{line_number}: missing bilingual document: {target}"
                    )
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    violations = check_repository(root)
    if violations:
        print("Documentation violations:")
        for violation in violations:
            print(violation)
        return 1
    print("PASS: documentation metadata and links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
