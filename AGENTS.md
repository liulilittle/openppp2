# AGENTS.md

## Scope

This guide applies to the repository. Follow explicit user instructions and
any applicable instructions in a more specific directory. Verify available
tools and dependencies; do not assume a particular machine or cloud image.

## Project Map

| Location | Purpose |
|----------|---------|
| `ppp/`, `common/`, `main.cpp` | Cross-platform C++ VPN/tunnel engine and supporting libraries |
| `desktop/client/` | Svelte frontend and Rust/Tauri Windows desktop client |
| `go/guardian/` | Guardian daemon, HTTP API, and embedded Svelte management UI |
| `go/ppp/` | Managed backend requiring MySQL and Redis |
| `android/`, `ios/` | Mobile clients and platform integration |
| `windows/`, `linux/`, `darwin/`, `Driver/`, `sln/` | Platform code, drivers, and auxiliary projects |
| `tests/`, `bench/`, `benchmarks/` | Unit, integration, fault, and performance checks |
| `cmake/`, `builds/`, `scripts/`, `tools/`, `.github/` | Build definitions, tooling, deployment, and CI |

## Working Rules

- Read the affected code and its callers before editing. Prefer existing patterns
  and keep changes limited to the requested behavior.
- Inspect Git status before editing. Preserve unrelated user changes.
- Do not treat platform-specific or optional code as unused merely because it is
  not built on the current host.
- Before deleting files, check build, packaging, runtime, and documentation
  references. Inspect generated directories for local configuration and backups.
- Never launch a PPP client, alter routes or DNS, install drivers, change system
  proxy settings, or interrupt an active connection without user authorization.
  If the user requires offline testing, use compilation and isolated unit tests.
- A running process or startup log alone does not prove a working VPN session.
- Report what was checked and any unverified platform or runtime behavior.

## Validation

Run relevant checks from the repository root unless stated otherwise. Select
checks for the affected component; do not run privileged network tests as part
of an ordinary unit-test pass.

| Component | Commands | Prerequisites and limits |
|-----------|----------|--------------------------|
| C++ source layout | `bash tools/check_include_boundaries.sh`; `bash tools/check_vcxproj_sources.sh` | Shell and script dependencies; no PPP startup |
| Standalone C++ tests | `bash scripts/run-cpp-tests.sh` | CMake, Ninja, compatible C++ compiler, Boost/OpenSSL development dependencies; see `docs/development/TESTING_CN.md` |
| C++ thread sanitizer | `bash scripts/run-cpp-tsan-tests.sh` | Supported toolchain; separate build directory; do not combine TSan with ASan/UBSan |
| XTCP fault suite | `bash tools/run_xtcp_fault_suite.sh` | Optional `third-party/xtcp`; prepare with `bash tools/prepare_xtcp.sh` if needed |
| Linux network E2E | `bash tests/integration/linux/xtcp_tap_netns_e2e.sh` | Explicit authorization, Linux, root, and `ip netns`; exercises network state and rollback |
| Guardian | `go test ./...`; `go build .` in `go/guardian` | Compatible Go toolchain; service startup is separate from validation |
| Desktop frontend | `npm ci`; `npm test`; `npm run build` in `desktop/client` | Compatible Node/npm; versions and scripts are defined in `package.json` and its lockfile |
| Desktop Rust backend | `cargo test --manifest-path src-tauri/Cargo.toml` in `desktop/client` | Rust and Tauri platform dependencies; build frontend assets first |

The full C++ kernel needs its native dependency tree. Consult `CMakeLists.txt`
and the relevant platform build configuration instead of assuming a globally
installed dependency version or a fixed `THIRD_PARTY_LIBRARY_DIR`.
Android requires Flutter and the Android SDK/NDK; iOS requires the appropriate
Flutter/Xcode environment. Missing dependencies are environment limits, not
reasons to delete platform code.

### Windows and Desktop

- Build `ppp.vcxproj` from a configured Visual Studio developer environment.
  Prefer the 64-bit host tools to avoid linker memory limits. A typical command
  is `MSBuild ppp.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /p:VcpkgTriplet=x64-windows-static /m:2`.
  Verify that the selected vcpkg triplet is provisioned before building.
- Keep build output separate from binaries currently in use. Building a kernel
  does not authorize launching it or replacing an active installation.
- Driver runtime files are copied by the project build target. Keep `Driver/`
  and verify packaging when changing Windows build behavior.
- Desktop development uses Vite and `npm run desktop`; normal Cargo builds use
  embedded frontend assets. See `desktop/README.md` and
  `docs/testing/DESKTOP_GUI.md` for the workflow and acceptance checks.
- The desktop client uses an external compatible `ppp.exe`. Virtual-adapter
  mode requires elevation; do not invoke it for routine offline testing.

### Guardian

- `go/guardian/webui/dist` is tracked and embedded with `go:embed`. It is a
  required build input, not disposable output. Rebuild it when changing the UI.
- Guardian defaults to a loopback HTTP listener. Use an explicit local config
  to run it; do not expose its management API without authorization.
- The current login password is `auth.jwtSecret`. First startup can generate
  and persist that value. Treat the config as secret; never print or commit it.
  API routes use the `/api/v1` prefix.
- The profile Add workflow submits the current default form as its initial
  profile. Empty request bodies to profile save/validate endpoints return HTTP
  400 with an explicit error; `{}` remains invalid because it has no known PPP
  key.
- The API sends no CORS headers: foreign-Origin POST/PUT/DELETE get 403, and
  loopback listeners reject unknown Host headers (keep Host when proxying).
  Login/password endpoints rate-limit per IP (HTTP 429). Guardian refuses to
  start on a non-loopback `listen` with `auth.enabled=false`. Binaries are only
  executed for version detection when named like ppp and inside `binariesDir`
  or auto-discovered.

## Code Analysis

Use GitNexus when it is available and its repository index is current:

- Before modifying a function, class, or method, run upstream impact analysis
  and inspect its callers and affected execution flows. Explain HIGH/CRITICAL
  findings before proceeding.
- Use query/context tools to trace unfamiliar behavior and the rename tool for
  symbol renames. Run change detection before committing.
- Configure installation paths, storage, model caches, and proxy settings
  locally. Do not put machine-specific values in this file.
- Rebuild stale or corrupted indexes using the installed version's documented
  commands. For large files, use supported worker limits and adequate timeouts.

If GitNexus is unavailable, use `rg`, source inspection, build definitions,
`git diff`, and focused tests to assess the same scope. State the limitation;
do not claim GitNexus checks ran or block routine work solely on its absence.
Before committing, inspect the staged diff and run `git diff --cached --check`.

## Secrets and Local Artifacts

- Never commit real node addresses/configurations, subscription credentials,
  passwords, private keys, access tokens, or internal infrastructure details.
  Use clearly marked test values and documentation placeholders.
- Keep private runtime/deployment material in ignored local locations such as
  `build/private/`. Ignoring a path does not untrack previously committed files.
- Avoid printing full configs or connection URLs. Redact credentials in logs,
  diagnostics, test output, and summaries.
- Treat node exports, application-data files, backups, and crash dumps as
  potentially sensitive; do not delete them as caches without inspecting purpose.
- Before committing, inspect staged filenames and content for sensitive data.
  Distinguish new findings from existing sample credentials or historical files.
  Report existing committed secrets without reproducing their values.
- Removing a secret from the current tree does not remove it from Git history.
  Rotation and history rewriting are separate actions requiring appropriate scope.
