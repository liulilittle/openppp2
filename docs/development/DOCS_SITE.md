# Documentation site

> Status: Active
> Type: Guide
> Last verified: 2026-10-05
> Parent index: [Development](README.md) · Chinese: [文档站](DOCS_SITE_CN.md)

The site uses Zensical 0.0.67 with English at <https://miaocchi.github.io/openppp2/> and Chinese at <https://miaocchi.github.io/openppp2/zh/>. The language menu keeps the current page path. Search indexes are independent; Chinese content is searchable, but search prompts remain English in this release ([Zensical search documentation](https://zensical.org/docs/setup/search/)).

## Install and preview

Use Python 3.13, matching CI. From the repository root:

```bash
python3 -m venv build/docs-venv
# Windows: build\docs-venv\Scripts\activate
. build/docs-venv/bin/activate
python -m pip install -r requirements-docs.txt
python tools/docs_site.py serve
```

Open <http://127.0.0.1:8000/> or <http://127.0.0.1:8000/zh/>. Both languages are built before serving. After editing a document, stop the server and re-run the command to regenerate both sites. Optional `--host` and `--port` arguments change the listener.

## Build and verify

```bash
python -m unittest tests.tooling.test_check_docs tests.tooling.test_docs_site -v
python tools/check_docs.py
python tools/docs_site.py build
```

`build` runs both Zensical builds in strict mode, then verifies generated internal links and fragments. Output is `build/docs-site/site`; generated inputs and caches also stay under `build/docs-site`. Each run cleans this workspace so removed pages cannot survive. Use `--site-url https://example.com/project/` to test another deployment base path.

Only tracked files under `docs/` are published, along with this guide before its first commit. Add new documents to Git before previewing. `README.md` becomes its directory's homepage; `NAME.md` and `NAME_CN.md` share one page path. Unpaired pages show their original language with a notice. Relative Markdown links are rewritten in generated copies; explicit language peers switch languages. Repository links outside `docs/` point to GitHub. Code examples and original GitHub reading links are preserved.

Archives and historical audits show a history notice and are excluded from search. `archive/untracked/`, local build directories, and agent work records are excluded entirely. Original document status and verification dates are retained. Edit navigation and theme defaults in [zensical.toml](../../zensical.toml); the builder creates localized category navigation from the document tree.

## Publish

[Documentation workflow](../../.github/workflows/docs.yml) checks governance, tests the builder, and builds both languages on documentation PRs. PRs cannot deploy. A matching push to `main`, or a manual run on `main`, uploads the official Pages artifact and deploys through the `github-pages` environment. Before the first deployment, select **Settings → Pages → Build and deployment → Source → GitHub Actions**. Alternatively, provide a repository secret `PAGES_SETUP_TOKEN` with Pages write permission (and administration write permission for a GitHub App token); the workflow then enables Pages through `actions/configure-pages`. The default `GITHUB_TOKEN` can deploy an enabled site but cannot perform first-time enablement ([official action inputs](https://github.com/actions/configure-pages/blob/v5/action.yml)). Remove the setup secret after enablement if no longer needed.

Before merging, preview a paired and an unpaired page, use the language menu from a nested page, search English and Chinese terms, check a Mermaid diagram and code copy, and inspect navigation at a narrow mobile width. Native, Guardian, and mobile build dependencies are unnecessary for the documentation build.
