# OpenPPP2 iOS app and Packet Tunnel

> [iOS platform overview](../README.md)

**Status:** Experimental

**Type:** iOS host application and Network Extension integration guide

**Last verified:** 2026-07-22

`App/` contains the Xcode project for the OpenPPP2 host application and its Packet Tunnel Extension. It is part of this repository's iOS surface; it is not a standalone mobile project or a public framework example.

## Targets and responsibilities

| Target | Responsibility |
|---|---|
| `OpenPPP2` | Host app: profiles, tunnel preferences, UI, and communication with the provider. |
| `OpenPPP2PacketTunnel` | `NEPacketTunnelProvider` extension: applies tunnel network settings, bridges `NEPacketTunnelFlow` to native code, and owns the active tunnel lifecycle. |

The project targets iOS 15.0 and references `../../bin/OpenPPP2.xcframework`. Both targets use Network Extension/App Group entitlement files. The extension bundle identifier is derived from the host identifier as `${OPENPPP2_BUNDLE_ID}.PacketTunnel` during the signed build.

## Build prerequisites

Use macOS with Xcode command-line tools, a compatible CMake toolchain, and iOS-targeted OpenSSL artifacts. Do not substitute host/macOS OpenSSL libraries for iOS device or simulator libraries.

From the repository root, build the two native prerequisites:

```sh
OPENSSL_TARBALL=/path/to/openssl-source.tar.gz \
  ./ios/build-openssl.sh

./ios/build-xcframework.sh
```

The app scripts look for these default OpenSSL locations:

```text
bin/openssl-ios/iphoneos-arm64
bin/openssl-ios/iphonesimulator-x86_64
```

Override both `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR` when supplying a different iOS/simulator architecture.

## Build modes

### Unsigned development artifact

```sh
SDK=iphoneos ./ios/App/build-unsigned.sh
```

The script runs Xcode with `CODE_SIGNING_ALLOWED=NO`, then packages the resulting `.app` as an IPA under `bin/ipa/`. This is useful for validating build integration, but an unsigned IPA is not a normally installable device VPN application.

For a simulator product, use the matching SDK and matching OpenSSL artifacts, for example:

```sh
SDK=iphonesimulator CONFIGURATION=Debug ./ios/App/build-unsigned.sh
```

### Apple-signed device build

Provide values owned by the developer account rather than copying any local identity or team value from this checkout:

```sh
DEVELOPMENT_TEAM=YOUR_TEAM_ID \
OPENPPP2_BUNDLE_ID=com.example.openppp2 \
SDK=iphoneos \
CONFIGURATION=Release \
./ios/App/build-signed.sh
```

The script enables automatic Xcode provisioning updates and writes `bin/ipa/OpenPPP2-iphoneos-signed.ipa` after a successful build. The selected profile must authorize both the host app and its Packet Tunnel Extension, including the required Network Extension/App Group capabilities. An app can install while its tunnel still fails to start if the extension entitlement/provisioning is wrong.

`../sign-and-package-ipa.sh` is for signing an already built `.app` bundle. It still needs valid signing inputs and signs embedded extensions/frameworks; it is not a substitute for configuring the Xcode targets correctly.

## Tunnel startup boundary

`PacketTunnelProvider.startTunnel`:

1. reads the stored provider configuration (or a shared last configuration);
2. requires a usable `client.server` host;
3. applies `NEPacketTunnelNetworkSettings`, IPv4 routes, DNS, and exclusions for the server/telemetry hosts;
4. prepares the extension's runtime rules directory;
5. creates `OpenPPP2PacketTunnelAdapter`, which passes packets between `NEPacketTunnelFlow` and the C bridge;
6. persists runtime/diagnostic information for the host app.

The provider disables iOS proxy settings itself; it does not expose the native bridge as a general system proxy API. The adapter has bounded output handling and polls/writes runtime snapshots, but no build-only check can prove that a tunnel can connect or forward traffic on a device.

## Focused logic tests

`Package.swift` defines a small Swift Package test target for selected host-app logic files. It does not build the full app or extension, but it is useful for the listed model/runtime/profile tests:

```sh
cd ios/App
swift test
```

Run full Xcode/device validation after changing entitlements, packet flow, native bridge code, provider configuration, or app-group state.

## Security and support boundary

- Profile and tunnel configuration can contain secrets; do not place real values in documentation, sample commits, or test fixtures.
- Do not treat unsigned/fake-signed/custom-package workflows as a normal distribution method.
- The project has no claim here of App Store readiness, universal device support, or a stable Swift SDK.
- The packet tunnel is platform-specific and must be tested with a real entitled device and the target network configuration.
