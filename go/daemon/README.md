# OpenPPP2 local single-instance daemon

> [Go overview](../debug.md) · [中文](README_CN.md)

**Status:** Experimental; local use only

**Type:** Single-child-process HTTP management wrapper

**Last verified:** 2026-07-22

`go/daemon` starts, stops, and observes one configured local `ppp` process. It also serves a minimal browser page and JSON endpoints, and can reverse-proxy a configured management API. It is not an authenticated administration service and must not be exposed directly to untrusted or remote networks.

## What it manages

The daemon configuration has four sections:

| Section | Relevant behavior |
|---|---|
| `listen` | HTTP bind address; defaults to `:18080`. Use an explicit loopback address for local development. |
| `instance` | One child binary, work directory, configuration path, arguments, environment, stop policy, and in-memory log limit. |
| `managedApi` | Optional reverse-proxy target; `/api/managed/` is stripped before forwarding. |
| `ui` | Browser-page title only. |

Defaults point the child at `./openppp2` with client-mode arguments and `./appsettings.json`, but a real deployment must provide valid paths and configuration. Relative `instance.configPath` is resolved against `instance.workDir`.

## Start with an explicit configuration

From `go/`, first run the package tests that do not launch an instance:

```sh
go test ./daemon
```

The daemon requires a readable JSON configuration file. Start it with the source-supported flag:

```sh
go run ./daemon --configuration=./path/to/daemon.json
```

A safe development configuration should use a loopback `listen` value and relative paths within a disposable working directory. Do not put production credentials, tokens, or private endpoints in a sample committed here.

## HTTP surface

The handler registers these paths:

| Path | Behavior |
|---|---|
| `/` | Minimal local HTML control page. |
| `/api/status` | Current child/config/log-buffer status. |
| `/api/config` | Reads configuration with `GET`; accepts JSON/plain configuration writes with `PUT` or `POST`. |
| `/api/start` | Starts the configured child if it is not already running. |
| `/api/stop` | Requests child shutdown. |
| `/api/restart` | Stops, then starts the child. |
| `/api/logs` | Returns the in-memory stdout/stderr log buffer. |
| `/api/managed/…` | Reverse-proxies to `managedApi.baseUrl` when configured. |

There is **no authentication or authorization middleware**. The default `:18080` bind can listen beyond loopback depending on the host. Bind explicitly to loopback or place a reviewed authentication/TLS/reverse-proxy boundary in front of it; this code does not supply one.

## Process and file effects

- The child is run with the configured work directory and environment. Its stdout/stderr are captured in a bounded in-memory buffer.
- Stop requests use the configured interrupt/TERM signal, wait for `stopWaitMs`, then kill the process if it remains alive.
- Configuration writes require JSON syntax but overwrite the configured file directly with mode `0644`; they are not an access-control or secret-storage mechanism.
- `/api/managed/` only forwards requests. It does not add an authentication layer to the downstream service.

Use the [Go overview](../debug.md) for the root control-plane's own security and configuration boundaries. This daemon is intentionally narrower and should not be presented as a replacement for Guardian or a multi-instance supervisor.
