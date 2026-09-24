# OpenPPP2 iOS platform surface

> [iOS app and Packet Tunnel guide](App/README.md)

**Status:** Experimental

**Type:** iOS native runtime build, XCFramework, and Packet Tunnel integration

**Last verified:** 2026-07-22

This directory contains the iOS-specific native runtime and the support needed by the app/Network Extension in `App/`. It is an internal platform integration surface, not a general-purpose Swift package or a released iOS distribution channel.

## What the iOS build produces

`CMakeLists.txt` builds the static C++ target `openppp2_ios` with:

- iOS deployment target **15.0**;
- `_IPHONE`/`IPHONE` compile definitions instead of the macOS path;
- the callback-based `TapIos` implementation, because an iOS app receives packets through `NEPacketTunnelFlow` rather than a `utun` file descriptor;
- the C bridge declared by `OpenPPP2PacketTunnelBridge.h`.

The target writes archives to:

- `bin/ios/libopenppp2_ios.a` for an iPhoneOS build;
- `bin/ios-simulator/libopenppp2_ios.a` for an iPhoneSimulator build.

A static archive is not a complete app link. The app/extension also needs iOS-compatible OpenSSL libraries and any selected non-header-only runtime dependencies.

## Build the XCFramework

Run this from the repository root on macOS with CMake and Xcode command-line tools available:

```sh
./ios/build-xcframework.sh
```

The script builds an arm64 device archive, builds a simulator archive using the host architecture by default (`arm64` on Apple Silicon, otherwise `x86_64`), then creates:

```text
bin/OpenPPP2.xcframework
```

Use `IOS_DEVICE_ARCHS`, `IOS_SIMULATOR_ARCHS`, and `IOS_DEPLOYMENT_TARGET` only when the matching toolchain and dependencies are available. For example:

```sh
IOS_SIMULATOR_ARCHS=x86_64 ./ios/build-xcframework.sh
```

If an XCFramework already exists, the script preserves it under a timestamped `bin/OpenPPP2.xcframework.previous.*` name before installing the new one.

### Manual CMake configuration

The build script is the reference workflow. A device configuration is equivalent to:

```sh
cmake -S ios -B build/ios-device \
  -G Ninja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0
cmake --build build/ios-device
```

`OPENPPP2_IOS_EXTRA_INCLUDE_DIRS` is available for additional include paths. Do not use macOS headers/libraries as a substitute for iOS SDK artifacts.

## Build OpenSSL for the app targets

`build-openssl.sh` is an optional local helper for the app build. It expects an OpenSSL source tarball and builds static outputs for `iphoneos-arm64` and `iphonesimulator-x86_64` by default.

```sh
OPENSSL_TARBALL=/path/to/openssl-source.tar.gz \
  ./ios/build-openssl.sh
```

The outputs default to `bin/openssl-ios/`. A simulator with a different architecture needs compatible OpenSSL headers/libraries supplied through `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR` to the app build scripts. The helper's source-tarball default is machine-specific, so do not rely on it in portable documentation or CI.

## Packet Tunnel bridge boundary

The `OpenPPP2PacketTunnelBridge.h` API creates and owns an iOS TAP facade, accepts packet input from Swift, emits packet output through callbacks, and exposes start/stop, link-state, runtime-snapshot, diagnostic, telemetry, and optional P2P transport hooks. `TapIos` is driven by `NEPacketTunnelFlow` in a Network Extension.

This bridge is coupled to the checked-in host app and extension. It is not documented as a stable external ABI: changes require coordinated C++, bridge-header, module-map, Swift adapter, and device-tunnel testing.

## App, signing, and packaging

The actual host app and Network Extension live in [App/README.md](App/README.md). In particular:

- a normal device VPN install requires an Apple-signed app/extension with the appropriate Network Extension and App Group entitlements;
- `App/build-unsigned.sh` can build/package an unsigned IPA container, but that does not make it installable as a normal iOS VPN app;
- `package-ipa.sh` and `sign-and-package-ipa.sh` package an existing `.app` bundle; they do not remove the need for correct provisioning;
- `package-ipk.sh` and fake-sign options are custom-install workflows, not normal App Store or device-distribution instructions.

Treat all generated `build/` and `bin/` outputs as local build artifacts. Verify an actual connection, packet flow, and teardown on an entitled device before depending on a build.
