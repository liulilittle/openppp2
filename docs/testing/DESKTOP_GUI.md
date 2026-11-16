# Desktop GUI verification

Offline checks last run: 2026-10-18. All 40 frontend tests, the production frontend build and 59 Windows Rust tests passed after updating the redesign onto main. No desktop application or kernel was launched; `OPENPPP2_POLICY_CLI` was unset, so the optional real-kernel policy test returned early.

Historical native/browser checks: 2026-10-05. Windows development client, external kernel. These acceptance checks were not repeated during the offline validation above.

Recorded result: 13 frontend tests and 34 Rust tests passed. The Windows x64 Release kernel and native GUI rebuilt successfully. Hidden native smoke passed with kernel `2.1.5.0`: actual ordinary-user spawn, HTTP/SOCKS listeners, structured statistics, duplicate-connect rejection, active-node deletion rejection, disconnect releasing both ports, session generation and the administrator guard. No QA processes or listeners remained, and the host system-proxy fingerprint was unchanged. Browser smoke previously passed at all three widths.

The kernel manifest now uses `asInvoker`; server and virtual-adapter privilege checks remain in the runtime. Explicit `/utf-8` fixes MSVC source decoding. Tray menu handles are copied before native UI calls to avoid a worker/main-thread lock deadlock during disconnect.

## Automated checks

From the repository root:

```powershell
npm --prefix desktop/client test
npm --prefix desktop/client run build
cargo test --offline --manifest-path desktop/client/src-tauri/Cargo.toml
cargo build --offline --manifest-path desktop/client/src-tauri/Cargo.toml
```

`tests/policy_workspace.rs` also runs an end-to-end check against a real policy-capable kernel when `OPENPPP2_POLICY_CLI` points to it (offline `policy init/check/explain/migrate` only); without the variable the test returns early.

The Rust suite covers profile merging, missing-section handling, unknown-field preservation, network validation, credential redaction, multi-source cache isolation, preference migration, intentional disconnect, process stop/restart, telemetry precedence and reversible proxy recovery with external changes. The native proxy query test is read-only.

Browser smoke checks require Playwright and Microsoft Edge, plus Vite at port 1420:

```powershell
$env:PLAYWRIGHT_MODULE='build/gui-tools/node_modules/playwright/index.mjs'
node desktop/client/test/gui-smoke.mjs
```

The script checks light/dark layouts at 1120, 720 and 375 pixels, loaded logo, navigation, manual-node and subscription creation, routing template and rule add, DNS save, settings tabs, language changes, keyboard modal dismissal, logs and page errors. Screenshots go to ignored `build/gui-checks`.

## Isolated native commands

Debug builds support `OPENPPP2_CLIENT_DATA_DIR` for test isolation. It is ignored by release builds. The wrapper starts and hides the QA window, configures a disposable directory and local WebView2 debugging, checks the original system-proxy fingerprint and closes the QA client afterward:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File desktop/client/test/native-smoke.ps1
```

The wrapper requires Playwright at `build/gui-tools/node_modules/playwright` and a built debug GUI. It uses the repository's `x64/Release/ppp.exe`, fake local credentials, an unreachable loopback server and disabled automatic system proxy. It checks bootstrap, kernel inspection, persistence, redacted preview, actual spawn, both listeners, structured statistics, disconnect and generation changes. Error 740 and timed-out commands fail the test. Never run the underlying JavaScript directly against normal application data: it deletes manual nodes in the test directory. Logs go to ignored `build/gui-checks/native-smoke*.log`.

## Required live acceptance

- With a trusted test server, verify HTTP and SOCKS traffic in proxy mode, statistics and reconnect behavior.
- With UAC elevation, verify virtual-adapter traffic and original routes/DNS after disconnect and explicit exit.
- Verify Windows proxy/PAC write and exact restoration on disconnect, exit and crash recovery; test an external proxy change during connection.
- Cancel administrator restart, then accept it; confirm one active GUI after successful handoff.
- With policy v2 enabled, verify a template policy connects, `policy check` failures block the connection, Status shows the active version after connecting, and manual update succeeds through the SOCKS listener.
- In virtual-adapter mode, disconnect and confirm the kernel exits through Ctrl+C (log shows cleanup) with routes and DNS restored, rather than the 5-second forced stop.
- Verify tray close/reopen, explicit exit, duplicate launches and autostart after Windows login.

Local automated proxy recovery uses injected settings, not writes to the host. Administrator restart, TUN routing/DNS rollback and traffic through a valid VPN server remain live acceptance work.
