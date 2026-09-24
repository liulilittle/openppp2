# OpenPPP2 Android client

> [中文](README_CN.md) · [Technical guide](debug.md) · [Rule assets](android/app/src/main/assets/rules/README.md)

**Status:** Experimental

**Type:** Platform-specific Flutter, Android VPN, and JNI client surface

**Last verified:** 2026-07-22

This directory is the Android client that is shipped with this OpenPPP2 tree. It is a Flutter application backed by an Android `VpnService` and the bundled native `libopenppp2.so`; it is not a standalone SDK or a replacement for the native command-line runtime.

## What is here

- Flutter UI and profile/settings code in `lib/`.
- Android activity, VPN service, state mirror, and JNI declarations in `android/app/src/main/`.
- A packaged native library at `android/app/src/main/jniLibs/arm64-v8a/libopenppp2.so`.
- Native Android CMake sources and the ABI-oriented `build.sh` helper at this directory level.

The UI currently has Home, launch-options, profiles, and settings areas. Treat the client as an experimental platform surface: validate a real connection and the device's VPN behavior before relying on it operationally.

## Startup and runtime path

```text
Flutter VpnService.connect(configJson, vpnOptions)
  -> MethodChannel "supersocksr.ppp/vpn"
  -> MainActivity requests Android VPN permission when needed
  -> PppVpnService in the private :vpn process
  -> VpnService.Builder establishes a TUN interface
  -> JNI configures and runs libopenppp2.so
  -> native callbacks and a service poller mirror runtime state to app files
  -> Flutter polls the mirror while the app is visible
```

`PppVpnService` is deliberately declared in a separate `:vpn` process. The UI therefore does not read native state directly: it asks the activity for a mirrored runtime snapshot, link state, heartbeat, or last error. See [the technical guide](debug.md) before changing that lifecycle or any JNI signature.

## Work on the Flutter application

From this directory, with a compatible Flutter/Android toolchain installed:

```sh
flutter pub get
flutter test
```

A device run/build also needs a native library whose ABI matches the active Android Gradle configuration. The checked-in `jniLibs` directory currently contains an `arm64-v8a` library; do not assume that this also covers every emulator or build variant.

```sh
flutter run
```

Use a disposable development device and a non-production configuration. Do not put credentials or private endpoints in documentation, screenshots, or committed test profiles.

### Rebuild the native library (maintainers)

`CMakeLists.txt` builds `libopenppp2.so` from the shared C/C++ runtime and writes it under `bin/android/<ABI>/`. `build.sh` selects `x86`, `x64`, `arm`, `arm64`, or `all`; it requires an Android NDK plus matching prebuilt Boost and OpenSSL libraries.

A path-independent template for an arm64 build is:

```sh
cd android
NDK_ROOT=/path/to/android-ndk \
OTHER_ARGS="-DTHIRD_PARTY_LIBRARY_DIR=/path/to/android-third-party" \
./build.sh arm64

cp ../bin/android/arm64-v8a/libopenppp2.so \
  android/app/src/main/jniLibs/arm64-v8a/libopenppp2.so
```

The helper removes its temporary `build/` directory. Check the active Gradle scripts and package each required ABI deliberately before using the result. The local bootstrap/WSL helper scripts contain overwrite behavior or machine-specific paths, so they are not general onboarding commands.

## Documentation boundary

- [Technical guide](debug.md) documents the current Flutter/Kotlin/JNI implementation and troubleshooting signals.
- [Rule assets](android/app/src/main/assets/rules/README.md) documents the bundled GeoIP/GeoSite fallback files.
- [Work status](WORK_STATUS.md) is a status-bound maintenance note, not a record of current build or device-test success.

Configuration field semantics, protocol behavior, and cross-platform runtime guarantees belong to the canonical project documentation, not to this platform wrapper.
