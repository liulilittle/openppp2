# AGENTS.md

## Cursor Cloud specific instructions

OPENPPP2 is a cross-platform C++ VPN/tunnel engine (the `ppp` binary) plus
management tooling (Go Guardian daemon + Svelte Web UI), and mobile apps
(Android/iOS). The startup update script installs the C++ test toolchain
(`cmake ninja-build clang llvm libboost-all-dev libssl-dev libstdc++-14-dev`).
Go 1.22 and Node 22 are already in the base image.

### What the dev environment covers

| Service | Lint / Test / Build / Run | Notes |
|---------|---------------------------|-------|
| C++ standalone unit tests (`tests/cpp`) | lint: `bash tools/check_include_boundaries.sh`, `bash tools/check_vcxproj_sources.sh`; test/build: `scripts/run-cpp-tests.sh` (cmake+ninja+clang → `ctest`); TSan: `scripts/run-cpp-tsan-tests.sh` (separate `build/test-tsan` dir, `ENABLE_TSAN=ON`, mutually exclusive with ASan/UBSan) | Does **not** need the full native dep tree. See `docs/TESTING.md`. XTCP unit tests are opt-in: configure with `-DENABLE_XTCP_TESTS=ON` (requires `third-party/xtcp`; e.g. the `build/xtcp-lab-tests` dir). |
| XTCP upstream fault suite | `bash tools/run_xtcp_fault_suite.sh` (needs `third-party/xtcp`; prepare via `bash tools/prepare_xtcp.sh`) | Runs the patched upstream lab tests; 20 cases. See `docs/design/XTCP_INTEGRATION_CN.md`. |
| Linux netns E2E (XTCP) | `XTCP_SOAK_SECONDS=3 XTCP_E2E_CHURN=16 bash tests/integration/linux/xtcp_tap_netns_e2e.sh` (defaults SOAK=60/CHURN=512; needs root + `ip netns`) | Full battery incl. netem, soak, stats-json and route/DNS rollback. |
| Go Guardian (`go/guardian`) | test: `go test ./...`; build: `go build .`; run: `./guardian --config=guardian.json` | HTTP API + embedded Web UI on `127.0.0.1:18080`. |

### Non-obvious caveats

- **clang needs `libstdc++-14-dev`.** clang-18 selects the GCC-14 toolchain, but
  the base image only ships `libstdc++-13-dev`, so linking fails with
  `cannot find -lstdc++` until `libstdc++-14-dev` is installed (in the update
  script).
- **Guardian Web UI is pre-built and checked in** at `go/guardian/webui/dist`
  and embedded via `go:embed`, so the Guardian binary builds/runs without Node.
  Only run `npm ci && npm run dev` (or `npm run build`) in `go/guardian/webui`
  if you are changing the frontend.
- **Guardian login password = `auth.jwtSecret`** in the guardian config JSON. On
  first run Guardian generates a random secret and persists it to the config
  file; set a known `jwtSecret` in a `guardian.json` to log into the Web UI. The
  REST API is under the `/api/v1` prefix (e.g. `POST /api/v1/auth/login` with
  body `{"password":"<jwtSecret>"}`).
- **Creating a profile via the Web UI "Add" button** posts empty JSON `{ }`,
  which the backend rejects (`profile.JSON does not contain a known ppp key`).
  Seed profiles with valid content via `PUT /api/v1/profiles/{name}`, then
  edit/validate/save them through the UI.

### Out of scope in this environment

- **The full `ppp` core binary** (top-level `CMakeLists.txt`) is **not** built
  here: it requires third-party libraries (Boost 1.86, OpenSSL 3.0.13, jemalloc)
  under `THIRD_PARTY_LIBRARY_DIR` (default `/root/dev`), which is not provisioned.
  The `tests/cpp` suite covers C++ logic without that tree.
- **Android / iOS** apps need Flutter + Android NDK / Xcode.
- **Go managed backend** (`go/ppp`) needs MySQL + Redis (sentinel).

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **openppp2**. Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

## Environment Setup

GitNexus is installed at `/tmp/gx-169/package/dist/cli/index.js` (not on PATH).
All CLI commands must set these environment variables:

```bash
export GITNEXUS_HOME=/tmp/gitnexus-home
export GITNEXUS_DISABLE_CHECKPOINT=1
export GITNEXUS_LBUG_EXTENSION_INSTALL=never  # use `auto` for analyze (FTS)
export HF_HOME=/tmp/hf-cache
export NODE_OPTIONS="--max-old-space-size=4096 --max-semi-space-size=64"
```

Verify with: `/tmp/gx-169/package/dist/cli/index.js status`

The MCP server is registered as `gitnexus` in Codex config (`codex mcp list`).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Reindexing

Full rebuild (required when the index is stale or corrupted):

```bash
/tmp/gx-169/package/dist/cli/index.js analyze --force \
  --skip-git --skip-agents-md --skip-skills \
  --max-file-size 512 --workers 1 --worker-timeout 300
```

The `--workers 1 --worker-timeout 300` flags are **required** for the large C++ files
in this repo (`VEthernetExchanger.cpp`, `XtcpRuntime.cpp`, `TapLinux.cpp`, `sockets.c`
are 134-223KB). Without them, tree-sitter native workers time out and abort.

FTS-only repair (fast, no full reparse):

```bash
/tmp/gx-169/package/dist/cli/index.js analyze --repair-fts \
  --skip-git --skip-agents-md --max-file-size 512
```

Embedding regeneration (uses local ONNX model cached at `/tmp/hf-cache`):

```bash
/tmp/gx-169/package/dist/cli/index.js analyze --embeddings \
  --skip-git --skip-agents-md --skip-skills \
  --max-file-size 512 --workers 1 --worker-timeout 300
```

## Known Issues and Workarounds

1. **Tree-sitter crash on large files.** Files >32KB crash the direct string
   parser with `Invalid argument` or `Napi::Error`. GitNexus's
   `parseSourceSafe` callback-chunking handles this, but only when the worker
   has enough time. Always use `--workers 1 --worker-timeout 300`.

2. **WAL corruption after interrupted analysis.** If you see
   `Storage exception: Checksum verification failed, the WAL file is corrupted`,
   the index is corrupted. Run `--force` to rebuild. Do NOT use `--repair-fts`
   on a corrupted index — it will fail with the same error.

3. **Sandbox blocks network.** The HuggingFace embedding model is cached at
   `/tmp/hf-cache` (one-time download via proxy `10.1.0.36:2091`). If the cache
   is gone, embeddings cannot regenerate without network access.

4. **`/tmp` is ephemeral.** GitNexus install, index home, and HF cache all live
   under `/tmp`. After a container restart, the GitNexus binary may be gone but
   the index at `/home/openppp2/.gitnexus/` persists.

5. **`GITNEXUS_DISABLE_CHECKPOINT=1` is required.** LadybugDB checkpoint
   segfaults in this sandbox. This env var is already set in the MCP config
   and must also be set for CLI commands.

6. **Corrupted WAL warnings.** `lbug.wal` without `lbug.shadow` is normal
   after a clean shutdown — LadybugDB relies on WAL replay. Only treat it as
   corruption if analyze also fails.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/openppp2/context` | Codebase overview, check index freshness |
| `gitnexus://repo/openppp2/clusters` | All functional areas |
| `gitnexus://repo/openppp2/processes` | All execution flows |
| `gitnexus://repo/openppp2/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
