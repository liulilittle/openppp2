#!/usr/bin/env python3
"""Build and preview the bilingual docs without changing repository Markdown.

Only tracked documents (plus the explicitly maintained site guide) are published.
All generated inputs, caches, and output live in build/docs-site.
"""
from __future__ import annotations

import argparse
import copy
import html
import importlib.util
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
SITE_URL = "https://miaocchi.github.io/openppp2/"
REPOSITORY = "https://github.com/Miaocchi/openppp2"
LANGUAGES = ("en", "zh")
EXCLUDED = {"untracked", "superpowers", "node_modules", "build", "dist", "__pycache__"}
EXCLUDED_FILES = {"AGENTS.md", "CLAUDE.md", "CRASH_ANALYSIS_CN.md", "PROJECT_CLEANUP_CN.md"}
SECTIONS = (
    ("getting-started", "Getting started", "快速开始"),
    ("guides", "Guides", "指南"),
    ("reference", "Reference", "参考"),
    ("architecture", "Architecture", "架构"),
    ("development", "Development", "开发"),
    ("operations", "Operations", "运维"),
    ("design", "Designs and decisions", "设计与决策"),
    ("archive", "History", "历史归档"),
)
# Reader-facing order inside a section; unlisted pages follow alphabetically.
ORDER = {name: rank for rank, name in enumerate((
    "getting-started/USER_MANUAL.md",
    "getting-started/CONFIGURE.md",
    "getting-started/DESKTOP_CLIENT.md",
    "guides/ROUTING_AND_DNS.md",
    "guides/POLICY_CLI.md",
    "guides/PROXY_MODE.md",
    "guides/IPV6.md",
    "guides/PEER_PREFIX_ROUTING.md",
    "guides/MANAGEMENT_BACKEND.md",
    "guides/REMOTE_SUBSCRIPTION.md",
    "guides/PLATFORMS.md",
))}
# Match inline code before links, so examples remain byte-for-byte intact.
PROSE = re.compile(
    r"(?P<code>`+[^`\n]*`+)"
    r"|(?P<link>!?\[[^\]\n]*\]\()(?P<url><[^>\n]+>|[^\s)]+(?:\([^\n)]*\)[^\s)]*)?)(?P<tail>[^\n)]*\))"
    r"|(?P<ref>^\s*\[[^\]\n]+\]:\s*)(?P<refurl><[^>\n]+>|\S+)"
    r"|(?P<attr>\b(?:href|src)=)(?P<quote>[\"'])(?P<htmlurl>.*?)(?P=quote)",
    re.MULTILINE,
)


def included(path: Path) -> bool:
    return not (set(path.parts) & EXCLUDED) and path.name not in EXCLUDED_FILES


def canonical(path: Path) -> Path:
    """Pairs have one public path, with each README becoming an index."""
    name = path.name.removesuffix(".md").removesuffix("_CN")
    return path.with_name(("index" if name == "README" else name) + ".md")


def chinese(path: Path, text: str = "") -> bool:
    # Some intentionally Chinese-only audits predate the _CN naming convention.
    return path.stem.endswith(("_CN", "-cn")) or bool(re.search(r"[\u3400-\u9fff]", title(text)))


def title(text: str) -> str:
    match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def page_url(path: Path) -> str:
    if path.name == "index.md":
        parent = path.parent.as_posix()
        return "" if parent == "." else quote(parent) + "/"
    return quote(path.with_suffix("").as_posix()) + "/"


def slug(text: str) -> str:
    text = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", text)
    text = html.unescape(re.sub(r"<[^>]+>", "", text))
    text = re.sub(r"[^\w\-\s]", "", text.lower())
    return re.sub(r"\s", "-", text.strip())


def prose_lines(text: str):
    """Fence/indent awareness is shared by heading and link transformations."""
    fence = None
    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s{0,3}(?:>\s*)?(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            yield line, False
        else:
            yield line, fence is None and not line.startswith(("    ", "\t"))


def heading_ids(text: str) -> str:
    """Keep GitHub-style Unicode fragments stable with explicit Markdown IDs."""
    counts: dict[str, int] = {}
    result = []
    for line, prose in prose_lines(text):
        heading = re.match(r"^(#{1,6})\s+(.+?)(?:\s+#+)?\s*$", line) if prose else None
        if heading and not re.search(r"\{[^}]*#[^}]+\}\s*$", line):
            base = slug(heading.group(2)) or "section"
            count = counts.get(base, 0)
            counts[base] = count + 1
            anchor = base + (f"-{count}" if count else "")
            line = f"{heading.group(1)} {heading.group(2)} {{#{anchor}}}\n"
        result.append(line)
    return "".join(result)


class DocsSite:
    def __init__(self, root: Path = ROOT, site_url: str = SITE_URL):
        self.root = root.resolve()
        self.site_url = site_url.rstrip("/") + "/"
        self.base = urlsplit(self.site_url).path
        self.work = self.root / "build/docs-site"
        self.output = self.work / "site"
        self.sources: dict[Path, dict[str, Path]] = {}
        self.texts: dict[Path, str] = {}
        self.assets: set[Path] = set()

    def discover(self, paths: list[Path] | None = None) -> None:
        if paths is None:
            tracked = subprocess.check_output(
                ["git", "ls-files", "-z", "--", "docs"], cwd=self.root
            ).decode().split("\0")
            paths = [Path(p) for p in tracked if p]
            # Include this feature's new guide before its first commit.
            paths += [Path("docs/development/DOCS_SITE.md"), Path("docs/development/DOCS_SITE_CN.md")]
        for repo_path in sorted(set(paths)):
            if not included(repo_path) or not (self.root / repo_path).is_file():
                continue
            path = repo_path.relative_to("docs")
            if path.suffix != ".md":
                self.assets.add(path)
                continue
            text = (self.root / repo_path).read_text(encoding="utf-8")
            self.texts[path] = text
            language = "zh" if chinese(path, text) else "en"
            variants = self.sources.setdefault(canonical(path), {})
            if language in variants:
                raise ValueError(f"Duplicate {language} page: {path} and {variants[language]}")
            variants[language] = path

    def selected(self, page: Path, language: str) -> Path:
        variants = self.sources[page]
        return variants.get(language) or next(iter(variants.values()))

    def historical(self, path: Path) -> bool:
        return path.parts[0] == "archive" or "AUDIT" in path.name.upper() or path.name == "BOOST_187_COMPATIBILITY.md"

    def destination(self, raw: str, source: Path, language: str) -> str:
        wrapped = raw.startswith("<") and raw.endswith(">")
        raw = raw[1:-1] if wrapped else raw
        url = urlsplit(raw)
        if url.scheme or url.netloc or not url.path:
            return raw if not wrapped else f"<{raw}>"
        target = (self.root / "docs" / source.parent / unquote(url.path)).resolve()
        try:
            relative = target.relative_to(self.root / "docs")
        except ValueError:
            relative = None
        if relative is not None:
            if target.is_dir():
                relative /= "README.md"
            page = canonical(relative)
            if page in self.sources and included(relative):
                # Explicit peers cross languages; ordinary links stay in this site.
                target_language = "zh" if relative.stem.endswith("_CN") else language
                if language == "zh" and "en" in self.sources[page] and relative == self.sources[page]["en"]:
                    # A Chinese page's metadata often explicitly links its English peer.
                    if canonical(source) == page:
                        target_language = "en"
                prefix = "zh/" if target_language == "zh" else ""
                path = self.base + prefix + page_url(page)
                return urlunsplit(("", "", path, url.query, url.fragment))
            if relative in self.assets:
                prefix = "zh/" if language == "zh" else ""
                return urlunsplit(("", "", self.base + prefix + quote(relative.as_posix()), url.query, url.fragment))
        try:
            repo_path = target.relative_to(self.root).as_posix()
        except ValueError:
            raise ValueError(f"Link leaves repository: {source}: {raw}") from None
        kind = "tree" if target.is_dir() else "blob"
        return urlunsplit(("https", "github.com", f"/Miaocchi/openppp2/{kind}/main/{quote(repo_path)}", url.query, url.fragment))

    def rewrite(self, text: str, source: Path, language: str) -> str:
        def replace(match: re.Match) -> str:
            if match.group("code"):
                return match.group()
            if match.group("link"):
                return match.group("link") + self.destination(match.group("url"), source, language) + match.group("tail")
            if match.group("ref"):
                return match.group("ref") + self.destination(match.group("refurl"), source, language)
            return match.group("attr") + match.group("quote") + self.destination(match.group("htmlurl"), source, language) + match.group("quote")
        return "".join(PROSE.sub(replace, line) if prose else line for line, prose in prose_lines(text))

    def render(self, page: Path, language: str) -> str:
        import yaml
        source = self.selected(page, language)
        text = self.texts[source]
        metadata = {}
        if text.startswith("---\n"):
            _, front, text = text.split("---\n", 2)
            metadata = yaml.safe_load(front) or {}
        notices = []
        if language not in self.sources[page]:
            original = "Chinese" if chinese(source, text) else "English"
            notice = f"This document is available only in {original}; the original text is shown."
            if language == "zh":
                notice = f"本文仅有{'中文' if original == 'Chinese' else '英文'}版本，以下保留原文。"
            notices.append(f"> {notice}\n\n")
        if self.historical(source):
            metadata.setdefault("search", {})["exclude"] = True
            notice = "Historical material: check its original status and date before relying on it."
            if language == "zh":
                notice = "历史资料：使用前请核对原始状态和日期。"
            notices.append(f"> {notice}\n\n")
        front = "---\n" + yaml.safe_dump(metadata, allow_unicode=True) + "---\n\n" if metadata else ""
        return front + "".join(notices) + heading_ids(self.rewrite(text, source, language))

    def navigation(self, language: str) -> list:
        def pages_under(prefix: str) -> list:
            pages = sorted(p for p in self.sources if p.as_posix().startswith(prefix + "/"))
            pages.sort(key=lambda p: (p.name != "index.md", ORDER.get(p.as_posix(), len(ORDER)), p.as_posix()))
            return [{title(self.texts[self.selected(p, language)]) or p.stem: p.as_posix()} for p in pages]
        nav = [{"Home" if language == "en" else "首页": "index.md"}]
        for directory, english, zh in SECTIONS:
            items = pages_under(directory)
            if directory == "development":
                items += pages_under("testing") + pages_under("governance")
            elif directory == "design":
                items += pages_under("adr")
            elif directory == "archive":
                items += pages_under("vmux")
            if items:
                nav.append({english if language == "en" else zh: items})
        return nav

    def prepare(self) -> None:
        import tomli_w
        if self.work.exists():
            shutil.rmtree(self.work)
        base_config = tomllib.loads((self.root / "zensical.toml").read_text())
        for language in LANGUAGES:
            directory = self.work / language
            docs = directory / "docs"
            for page in self.sources:
                output = docs / page
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(self.render(page, language), encoding="utf-8")
            for asset in self.assets:
                output = docs / asset
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self.root / "docs" / asset, output)
            config = copy.deepcopy(base_config)
            project = config["project"]
            project.update(docs_dir="docs", site_dir="site", site_url=self.site_url + ("zh/" if language == "zh" else ""), nav=self.navigation(language))
            shutil.copytree(self.root / "tools/docs_theme", directory / "theme")
            project["theme"].update(language=language, custom_dir="theme")
            project["extra"] = {"alternate": [
                {"name": "English", "link": self.base, "lang": "en"},
                {"name": "中文", "link": self.base + "zh/", "lang": "zh"},
            ]}
            (directory / "zensical.toml").write_text(tomli_w.dumps(config), encoding="utf-8")

    def build(self) -> None:
        self.discover()
        self.prepare()
        if importlib.util.find_spec("zensical") is None:
            raise RuntimeError("Install requirements-docs.txt in the active Python environment first")
        for language in LANGUAGES:
            directory = self.work / language
            subprocess.run([sys.executable, "-m", "zensical", "build", "--strict", "--clean", "-f", "zensical.toml"], cwd=directory, check=True)
        shutil.copytree(self.work / "en/site", self.output)
        shutil.copytree(self.work / "zh/site", self.output / "zh")
        (self.output / ".nojekyll").touch()
        violations = check_links(self.output, self.base)
        if violations:
            raise RuntimeError("Generated site links failed:\n" + "\n".join(violations))
        print(f"PASS: {len(self.sources)} pages per language; generated links verified: {self.output}")


class PageLinks(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.links: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(attributes["id"])
        for key in ("href", "src"):
            if attributes.get(key):
                self.links.append(attributes[key])


def check_links(directory: Path, base: str) -> list[str]:
    pages = {p: PageLinks(p.read_text(encoding="utf-8")) for p in directory.rglob("*.html")}
    violations = []
    targets: dict[str, tuple[Path, bool]] = {}
    for source, parsed in pages.items():
        source_url = base + source.relative_to(directory).as_posix()
        for raw in parsed.links:
            url = urlsplit(raw)
            if url.scheme or url.netloc:
                continue
            path = unquote(urlsplit(urljoin(source_url, raw)).path)
            if not path.startswith(base):
                violations.append(f"{source.relative_to(directory)}: link outside site base: {raw}")
                continue
            if path not in targets:
                target = directory / path[len(base):]
                if target.is_dir():
                    target /= "index.html"
                targets[path] = (target, target.is_file())
            target, exists = targets[path]
            if not exists:
                violations.append(f"{source.relative_to(directory)}: missing target: {raw}")
            elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
                violations.append(f"{source.relative_to(directory)}: missing anchor: {raw}")
    return sorted(set(violations))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "serve"))
    parser.add_argument("--site-url", default=SITE_URL, help="Published base URL (build only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    site = DocsSite(site_url=args.site_url if args.command == "build" else f"http://{args.host}:{args.port}/")
    site.build()
    if args.command == "serve":
        from functools import partial
        handler = partial(SimpleHTTPRequestHandler, directory=str(site.output))
        print(f"Preview: {site.site_url} (Chinese: {site.site_url}zh/). Re-run after editing docs.", flush=True)
        with ThreadingHTTPServer((args.host, args.port), handler) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
