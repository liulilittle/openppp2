# Development
> Status: Active
> Type: Index
> Last verified: 2026-07-22
>
> **Purpose:** Start source-backed native development in this repository.
> **Audience:** Contributors and maintainers.
> **Parent index:** [Documentation](../README.md) · **Chinese:** [开发文档](README_CN.md)

## Start here

| Task | Page |
|---|---|
| Follow the executable from entry point to runtime | [Source Reading Guide](SOURCE_READING_GUIDE.md) |
| Run the appropriate test set | [Testing](TESTING.md) |
| Review the dated Boost audit | [Boost compatibility audit (Chinese)](BOOST_187_COMPATIBILITY.md) |
| Follow repository conventions | [Code style](../governance/CODE_STYLE.md) · [Documentation style](../governance/DOCUMENTATION_STYLE.md) |

## Native `ppp` build boundary

The root CMake project builds the native `ppp` executable and the `openppp2_lib` static library. It requires a C++17-capable toolchain.

On Linux and macOS, root CMake expects `THIRD_PARTY_LIBRARY_DIR` to contain the Boost, OpenSSL, and jemalloc layout used by the project. With a prepared dependency directory named `third-party` in the checkout, the basic native shape is:

```bash
cmake -S . -B build/native \
  -DCMAKE_BUILD_TYPE=Release \
  -DTHIRD_PARTY_LIBRARY_DIR=third-party
cmake --build build/native
```

The root configuration writes non-Windows native output to `bin/ppp`. It does not download or build that third-party dependency tree for you; compare the Linux/macOS CI workflows before recreating it locally.

On Windows, root CMake requires an active vcpkg triplet and looks for Boost, OpenSSL, and jemalloc there. The checked-in helper has a source-backed local x64 path:

```bat
build_windows.bat Release x64
```

Its parser currently accepts `x86` and `x64` target arguments. Although the usage text also mentions `arm64`, do not rely on that helper argument until its parser is fixed; Windows ARM64 is handled separately by CI. The helper writes to a configuration/architecture subdirectory under `bin`.

Android and iOS have their own CMake projects that produce libraries rather than the root native `ppp` executable. Treat those as platform-specific surfaces, not as alternate invocations of the root target.

## Build and test entry points

- [Testing](TESTING.md) distinguishes the standalone C++ suite from the root `ENABLE_TESTS` build.
- `scripts/run-cpp-tests.sh` configures and runs the focused C++ suite under `tests/cpp`.
- `scripts/run-cpp-coverage.sh` and `scripts/coverage.sh` have different coverage scopes and prerequisites.
- `scripts/run-lifecycle-sanitizers.sh` runs the standalone lifecycle sanitizer targets.

## CI facts

The checked-in workflows cover native Linux, Windows, and macOS builds, plus separate Android and platform surfaces. The primary unit-test workflow runs standalone C++ checks, lifecycle sanitizers, Guardian/Go checks, Flutter tests, and iOS logic tests. It does not currently run the experimental Desktop Client's npm or Cargo checks.

## Current versus dated material

The English/Chinese pages in this index are current paired documentation. [`BOOST_187_COMPATIBILITY.md`](BOOST_187_COMPATIBILITY.md) is intentionally Chinese-only and marked as a dated source audit requiring re-verification; it is not a stable support matrix.
