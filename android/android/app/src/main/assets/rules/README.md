# Android bundled rule assets

> [Android overview](../../../../../../README.md) · [Technical guide](../../../../../../debug.md)

**Status:** Status-bound maintenance note

**Type:** Bundled binary asset inventory

**Last verified:** 2026-07-22

This directory contains the Android APK assets consumed by `PppVpnService.ensureGeoRulesAssets()`.

## Runtime behavior

When `PppVpnService` is created, it ensures that these bundled assets are available in the application's private files directory:

| APK asset | Runtime destination |
|---|---|
| `rules/geoip.dat` | `files/rules/GeoIP.dat` |
| `rules/geosite.dat` | `files/rules/GeoSite.dat` |

The service creates `files/rules` when needed. If a destination is missing, empty, or is mistakenly a directory, it replaces it with the bundled file. A non-empty regular destination file is retained. Failures are logged by the service; this routine does not establish a network download contract.

The service also sets the native root path to Android `filesDir`, allowing relative runtime configuration paths such as `./rules/GeoIP.dat` and `./rules/GeoSite.dat` to resolve to the extracted files.

## Maintenance rules

- Keep the APK filenames lowercase: `geoip.dat` and `geosite.dat`.
- Preserve the binary format expected by the native runtime; do not replace a data file with a directory, text placeholder, or compressed archive.
- Before refreshing either file, record the source, retrieval date/version or revision when available, and a checksum in the change record. The repository does not currently contain a verified provenance/version manifest for these binaries.
- Review the applicable upstream terms before redistributing changed data. This page does not make a licensing or provenance determination.
- Test an Android startup that reaches `PppVpnService.onCreate()` after a refresh. A file's presence in the APK alone does not validate native parsing, routing, or connection behavior.

For the Android client lifecycle and diagnostics, see the [technical guide](../../../../../../debug.md).
