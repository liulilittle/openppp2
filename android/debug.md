# Android implementation and troubleshooting guide

> [Android overview](README.md) · [中文](debug_CN.md) · [Rule assets](android/app/src/main/assets/rules/README.md)

**Status:** Experimental implementation reference

**Type:** Internal platform integration and troubleshooting guide

**Last verified:** 2026-07-22

This page documents the code currently under `android/`. It is intentionally narrower than a protocol/configuration reference and does not define a public Android API.

## Component map

| Surface | Current responsibility |
|---|---|
| `lib/main.dart`, `lib/app_shell.dart` | Starts the Flutter app and exposes Home, launch-options, profiles, and settings pages. |
| `lib/vpn_service.dart` | Calls the platform channel, polls runtime state every second while the application is visible, and derives UI traffic/state from the mirror. |
| `MainActivity.kt` | Owns `MethodChannel("supersocksr.ppp/vpn")`, requests VPN permission, starts/stops the service, reads mirrored files, and supplies installed-app metadata for the picker. |
| `PppVpnService.kt` | Runs in `:vpn`, owns the foreground VPN lifecycle, creates the TUN interface, invokes JNI, and mirrors native status. |
| `PppStateStore.kt` | Atomically writes the cross-process snapshot, link-state, heartbeat, and last-error files in app-private storage. |
| `c/libopenppp2.kt` | Declares native methods and receives native callbacks. JNI names/signatures must match `libopenppp2.cpp`. |
| `libopenppp2.cpp` | Android-native glue around the shared runtime, TUN descriptor, socket protection, telemetry, and runtime snapshots. |

## Connection lifecycle

1. Flutter calls `connect` with `configJson` and a `vpnOptions` map.
2. `MainActivity` calls `VpnService.prepare()`. If Android returns an intent, it waits for the user decision; otherwise it starts `PppVpnService` immediately.
3. The service enters foreground mode, parses options, sets the native root path to its `filesDir`, and passes the configuration to `set_app_configuration`.
4. It builds an Android VPN interface, including IPv4 routing, DNS, an IPv6 capture route, and optional per-app/system HTTP-proxy policy where the platform supports it.
5. After `Builder.establish()`, the service transfers the TUN file-descriptor ownership to JNI with `detachFd()`, calls `set_network_interface`, then runs blocking `libopenppp2.run(0)` on its worker thread.
6. `start_exec`, `runtime_snapshot`, link-state polling, and error handling update the service state. When `run()` returns, the worker stops pollers, releases resources, and either replays a queued reconnect or stops the foreground service.

`run()` is blocking. Do not move it onto the Activity/UI thread or assume that a JNI object loaded by the UI process shares state with the `:vpn` process.

## State delivery and liveness

There is no EventChannel in this implementation. The separate service process instead writes a file-backed mirror:

```text
native runtime callback or service poller
  -> PppStateStore atomic file replacement
  -> MainActivity MethodChannel response
  -> Flutter poll and RuntimeStore ordering check
```

- Native snapshots carry `generation` and `monotonic_ms`; `PppVpnService` rejects older values before persisting them.
- Link state and heartbeat are polled once a second while a session runs.
- `PppStateStore` treats a heartbeat older than 30 seconds as stale. `getRuntimeSnapshot` returns no current snapshot when both heartbeat and snapshot freshness are stale.
- A null mirror result means that the UI must treat the native process as unavailable; it is not a protocol-level disconnect reason.

The bridge methods are implementation details. Callers should use the Flutter service rather than treating `getRuntimeSnapshot`, `getLastError`, or JNI methods as stable external interfaces.

## Useful diagnostic stages

`PppLog` records service-side steps that help separate permission, TUN, configuration, and native failures. Check the app's diagnostic UI or the log returned by the platform channel before inferring a root cause.

| Log/stage | What it shows |
|---|---|
| `connect requested` | Flutter reached `MainActivity`. |
| `startForeground done` | The service entered foreground mode. |
| `set_root_path ...` | Native relative-path root was attempted. |
| `set_app_configuration result=...` | Configuration handoff result. |
| `builder.establish result=...` | Android TUN creation result. |
| `set_network_interface result=...` | TUN descriptor handoff result. |
| `before libopenppp2.run(0)` / `vpnThread started...` | Native run thread was started. |
| `onStarted key=...` | The native start callback reached the service. |
| `libopenppp2.run returned=...` | The native run loop returned; inspect the last-error text too. |

A successful Android TUN establishment does not prove a successful remote session. Conversely, a current snapshot can be unavailable briefly while the service starts; use the ordered snapshot, heartbeat, last error, and logs together.

## JNI change rules

- Keep `supersocksr.ppp.android.c.libopenppp2` package/class names and method signatures synchronized with the C++ `Java_...` exports.
- `protect(fd)` is called by native code to keep an underlying socket outside VPN routing; it depends on a live `PppVpnService` instance.
- Native runtime callbacks can arrive on non-UI threads. The service performs ordering and writes its mirror before Flutter observes the value.
- Test both a connection and teardown after changing TUN ownership, callbacks, or process lifecycle. A compile-only check cannot validate Android VPN permissions or routing.

## Build and test boundary

For Dart/Flutter checks, from this directory:

```sh
flutter analyze
flutter test
```

The Android wrapper also has instrumentation tests under `android/app/src/androidTest/`, but they require an appropriately configured Android test environment. Native library builds are separate from Flutter checks:

- `CMakeLists.txt` needs an NDK plus ABI-matched Boost/OpenSSL static libraries.
- `build.sh` maps `arm64` to `aarch64`/`arm64-v8a` and writes `bin/android/arm64-v8a/libopenppp2.so`.
- The app can only load a library packaged for the active ABI. Do not assume that the checked-in arm64 library makes an x86/x86_64 emulator runnable.

See [the Android overview](README.md) for a safe native-build template. Avoid using local bootstrap/build helpers as general instructions: some recreate project files or contain host-specific paths.

## Related local documentation

- [Android overview](README.md)
- [中文技术指南](debug_CN.md)
- [Bundled rule assets](android/app/src/main/assets/rules/README.md)
- [Status-bound maintenance note](WORK_STATUS.md)
