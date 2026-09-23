# Noise/PSK Authenticated Carrier Compatibility

> Status: Implemented, default-off
> Type: Design
> Last verified: working tree
> Parent index: [Design documents](../README.md)

> **Purpose:** Freeze the implemented compatibility contract for authenticated carrier bindings on plain TCP and plain WebSocket while retaining the existing WSS/TLS-exporter path.
> **Audience:** Maintainers of transmission setup, L3 session roaming, configuration, and interoperability tests.
> **Implementation status:** The carrier-binding abstraction, handshake capability/policy bits, strict INFO negotiation, OpenSSL EVP Noise/PSK core, keyring/configuration, client/server plain-carrier wiring, and exact roaming eligibility checks are implemented. Client and server policy defaults remain disabled.

## Scope and current baseline

WSS continues to use its authenticated TLS session exporter. When both peers advertise support and both endpoint policies are enabled, plain TCP and plain WebSocket run `noise-psk-v1` after the existing `ITransmission` handshake and expose a carrier-local authenticated binding to the existing fresh/resume roaming proof layer. With either policy disabled or a legacy peer, the ordinary fresh-session path remains unchanged.

The existing randomized NOP exchange, `ivv`, configured cipher reconstruction, and payload transforms are not the Noise Protocol and are not represented as a formal authenticated key agreement or as providing forward secrecy. `noise-psk-v1` does not replace the application handshake, add a `PacketAction`, reinterpret application payload keys, or add an extra legacy read.

The current roaming state and wire evidence remain documented in [Authenticated L3 session roaming](l3-roaming.md). CDN ingress remains excluded, and the roaming generation/reservation/commit-fence machinery is unchanged.

## Compatibility invariants

The implementation must preserve all of the following:

- WSS continues to use the existing TLS exporter labels and session-bound exporter behavior.
- `transport-auth` negotiation is independent of the existing `session-resume` v1 object. It does not consume a roaming capability bit or relax the current exact-v1 validation.
- Unknown trailing-INFO sibling fields remain ignorable by legacy peers. No fixed `VirtualEthernetInformation` field or packet framing changes.
- Legacy peers and peers with transport authentication disabled continue to establish ordinary fresh sessions.
- A session ID is never an authenticator. An existing live or suspended logical session cannot be replaced only because a candidate presents the same ID.
- Once a resume attempt selects authenticated transport, an authentication failure cannot downgrade that same attempt to unauthenticated roaming.
- The existing roaming actions, canonical proof transcript, retained state boundary, owner-context requirement, generation rules, reservation token, and send-before-publish commit fence remain unchanged.
- CDN ingress is not automatically included. CDN support requires a separate design proving where authentication terminates and which end-to-end carrier is bound.

## Carrier establishment order

The implemented order is:

```text
raw TCP / WebSocket / TLS+WebSocket carrier setup
  -> existing ITransmission handshake
  -> transport-auth capability and method negotiation
  -> selected carrier authentication (TLS exporter already ready, or Noise/PSK)
  -> authenticated carrier binding ready
  -> ordinary fresh or session-resume INFO protocol
  -> data plane
```

For WSS, TLS and WebSocket setup have already completed before the existing `ITransmission` handshake. The TLS exporter is still gated by completion of that application handshake. WSS continues to report `tls-exporter-v1` directly and does not enter the new transport-auth INFO method negotiation or run Noise inside TLS.

For plain TCP and plain WebSocket, both peers must select `noise-psk-v1` and complete Noise authentication before either side treats the carrier as eligible for roaming. The existing application handshake remains a compatibility layer beneath this step and is not used as the Noise PSK source.

## Independent capability negotiation

### Handshake capability and policy bits

Transport-auth support and the endpoint's enabled policy are encoded in the existing client `nmux` and server `ivv` handshake values by `TransportAuthHandshakeCapabilityCodec`. The transport-auth marker, support bit, and policy bit preserve the existing mux bit and the high-64-bit canary. Legacy values and opposite-direction markers decode as unsupported. This adds no packet, round trip, or extra legacy read; peer support/policy state is cleared on disposal and failed handshakes.

The capability/policy bits are independent of `session-resume` v1. Both peers must report support and enabled policy before a plain carrier starts INFO authentication. WSS keeps `tls-exporter-v1` and never enters Noise negotiation.

### Fixed four-step INFO exchange

For plain TCP and plain WebSocket, the exact `transport-auth` sibling exchange is:

1. Client `advertise`: version 1, action `advertise`, `methods=["noise-psk-v1"]`, matching `method`, active `key-id`, sequence 1, Noise message 1, and a per-attempt token.
2. Server `select`: action `select`, the same method/key/token, sequence 2, and Noise message 2.
3. Client `success`: the same method/key/token plus the 32-byte client confirmation proof encoded as 64 lowercase hex characters.
4. Server `success`: exact proofless acknowledgement with the same method/key/token; only then may the client take and install its Noise result. The server result is likewise one-shot.

The attempt token is exactly 16 bytes represented by 32 lowercase hexadecimal characters. It is pre-bound into the Noise prologue extension and must match at every step. Reject controls use the fixed reason `authentication-failed`; a token is echoed only after a canonical token is known. Unknown trailing-INFO siblings remain ignorable, while unknown fields inside `transport-auth`, wrong types, unsupported versions/actions, duplicate methods, noncanonical hex, tuple mismatches, replay, skipped/reordered controls, and post-completion controls fail closed.

Selection is carrier-specific:

| Carrier | Implemented method |
|---|---|
| WSS/TLS | `tls-exporter-v1` |
| plain TCP | `noise-psk-v1`, default-off |
| plain WebSocket | `noise-psk-v1`, default-off |
| CDN ingress | none; not automatically included |

`transport-auth` and `session-resume` remain independent INFO siblings. Advertising or enabling a method is not authentication completion; roaming eligibility requires the exact carrier/method pair, an active binding, and an authoritative successful exporter check.

### Legacy-safe behavior

```text
Legacy peer
  -> existing handshake
  -> no Noise capability
  -> ordinary fresh session

New peer + Noise disabled
  -> existing handshake
  -> capability may be present but policy is disabled
  -> no method selection
  -> ordinary fresh session

New peer + both enabled
  -> existing handshake
  -> negotiate noise-psk-v1
  -> Noise/PSK authentication
  -> export authenticated carrier binding
  -> fresh/resume roaming protocol

Noise failure
  -> reject roaming
  -> never downgrade the same resume attempt to unauthenticated roaming
  -> optionally destroy the candidate and reconnect as an explicit fresh legacy session
```

An explicit fresh reconnect is a new connection and a new intent. It must discard the failed candidate carrier and must not carry forward a resume request, reservation, candidate binding, or authentication transcript from the failed attempt.

## Noise/PSK v1 cryptographic profile

### Implemented profile

The implemented profile is fixed as:

```text
Noise_NNpsk0_25519_ChaChaPoly_SHA256
```

`NoisePsk.cpp` implements SHA-256/HMAC, X25519 generation and DH, ChaCha20-Poly1305 empty-payload authentication, and constant-time proof comparison with OpenSSL EVP/crypto APIs. The client is always the Noise initiator and the server the responder, regardless of the historical `HandshakeClient` / `HandshakeServer` naming. Production generates a fresh EVP X25519 ephemeral key for every attempt; deterministic private keys are exposed only through the test hook.

The canonical binary prologue is length-delimited and binds the `openppp2-noise-handshake` domain, carrier byte (`tcp` or `websocket`), transport-auth version 1, exact `noise-psk-v1` method, binary 16-byte OpenPPP session ID, and non-secret key ID. Negotiation then appends version 1, a big-endian token length, and the canonical 32-hex attempt token before Noise initialization. Roles are fixed by initiator/responder state, not supplied by peer JSON. JSON field order, locale, endpoint text, host byte order, and textual session-ID spelling are not transcript inputs.

### Authenticated binding export

The public handshake hash is never used as secret binding material. Final Noise `Split` uses three HKDF outputs: the two directional outputs are immediately cleansed and the third is retained as a move-only 32-byte exporter secret. Domain-separated HMAC-SHA256 derivation under `openppp2-noise-binding-v1` supports exactly `SessionResumeRetainedRootV1`, `SessionResumeCandidateV1`, and `P2PWrapV1`. Each binding HMAC includes big-endian 64-bit length prefixes for the purpose label, binary exporter context, and handshake hash, followed by each field's exact bytes. The client-success confirmation uses its own `openppp2-noise-client-success-v1` domain plus the handshake hash.

`NoisePskAuthenticatedCarrierBinding` maps only the existing fixed exporter labels to those typed purposes. Resume root/candidate require the binary 16-byte session-ID context; P2P wrap requires the canonical 113-byte `P2PExporterContext`; all outputs are exactly 32 bytes. The binding runs on the owning strand/context and fails after migration or disposal. Temporary PSKs, private keys, chaining/cipher state, directional outputs, proofs, and exporter material are cleansed at ownership transitions and destruction. They are not runtime snapshot or telemetry payloads.

### Frozen limits and ordering

- PSK: exactly 32 bytes, loaded from exactly 64 lowercase hexadecimal file bytes.
- Session ID: exactly 16 binary bytes; attempt token: exactly 32 lowercase hex characters representing 16 bytes.
- Noise exchange: exactly two raw messages, client then server, each exactly 48 bytes and encoded as 96 lowercase hex characters in the strict negotiation.
- INFO parser ceilings: at most 4 methods; method length 32; key ID length 63; decoded message length 128 bytes; reason length 64.
- Keyring: at most 8 metadata entries, at most 2 `verify-only` keys, and exactly one `active` key whenever either endpoint policy is enabled.
- Whole authentication timeout: default 5000 ms, clamped to 1000..30000 ms.
- Duplicate, skipped, reordered, trailing-size, replayed, or post-completion messages are terminal. A result and exporter secret are one-owner/one-shot.

Noise success authenticates only the current carrier. The existing retained-root proof, generation, nonce, reservation, candidate-binding, and publication checks remain mandatory.

## Coexistence with WSS TLS exporter

`tls-exporter-v1` remains the only method for WSS. Its implementation continues to use the existing labels:

```text
EXPORTER-OPENPPP2-L3-ROAMING-ROOT-v1
EXPORTER-OPENPPP2-L3-ROAMING-CANDIDATE-v1
```

The exporter context remains the binary 16-byte session ID. The TLS provider remains unavailable before the TLS/WebSocket/application handshake is complete, during an unsafe scheduler migration, off its required strand, after disposal, or on server-marked loopback proxy ingress. For directly accepted non-loopback WSS, wire behavior, exporter derivation, roaming transcript, and carrier eligibility are unchanged; WSS does not run a Noise round trip.

Noise uses a separate protocol name, key schedule, and exporter domain. TLS and Noise implementations satisfy the same carrier-binding contract, but their cryptographic roots and derivations remain distinct.

## Unified carrier-binding interface

The implemented label-aware carrier-binding contract retains the project integer types and existing exporter call shape:

```cpp
class IAuthenticatedCarrierBinding {
public:
    virtual ~IAuthenticatedCarrierBinding() noexcept = default;

    virtual bool HasAuthenticatedSessionExporter() const noexcept = 0;

    virtual bool ExportAuthenticatedSessionKey(
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept = 0;
};
```

`ITransmission` implements fail-closed defaults and can install an authenticated binding after successful plain-carrier authentication. `ISslWebsocketTransmission` continues to provide the TLS-exporter implementation. Plain TCP and plain WebSocket become eligible only after the existing application handshake, successful `noise-psk-v1` negotiation, installation on the owning strand/context, and an exact carrier/method eligibility check; before that they retain the unavailable default.

The compatibility rules are:

- `ExportAuthenticatedSessionKey(...)` is authoritative. `HasAuthenticatedSessionExporter()` is only a policy hint or fast pre-check; export independently fails closed if the carrier is disposed, migrates schedulers, is called from the wrong owner context, or otherwise loses eligibility.
- Labels and contexts are canonical protocol inputs. Existing consumers continue to supply fixed domain-separated labels and bounded binary contexts.
- WSS passes the existing label and binary context directly to the TLS exporter, so its derivation remains unchanged.
- The Noise binding accepts only the existing fixed labels, maps them to typed versioned purposes under its separate domain, and rejects other labels or invalid context/output lengths.
- The interface does not expose the retained roaming root, PSK, TLS secrets, Noise chaining key, exporter secret, or reusable provider master secret.
- Export runs on the carrier's owner strand/context; cross-context use is not hidden inside the synchronous getter.

## State machine

```text
LegacyOrUnadvertised
  -> ordinary fresh only

Advertised
  -> PolicyDisabled          -> ordinary fresh only
  -> MethodSelected

MethodSelected
  -> Authenticating

Authenticating
  -> BindingReady
  -> Failed

BindingReady
  -> fresh roaming arm, when session-resume is also enabled
  -> authenticated resume request/verification

Failed
  -> reject current authentication or roaming attempt
  -> dispose candidate
  -> fresh requires a separate explicit legacy connection
```

`BindingReady` is carrier-local and monotonic only until disposal. It becomes unavailable immediately when disposal begins or provider lifecycle requirements cease to hold. It is never inherited by a replacement carrier.

The following events enter `Failed`: malformed negotiation, no mutually enabled method after a method was required, unknown selection, carrier/method mismatch, missing or retired key ID, Noise parse failure, authentication-tag failure, transcript mismatch, timeout, replay, duplicate or reordered message, exporter failure, owner-context violation, and disposal during authentication.

## Fresh, resume, and downgrade rules

| Condition | Fresh session | Resume attempt |
|---|---|---|
| No `transport-auth` capability | ordinary legacy fresh | no authenticated roaming |
| Capability advertised, local policy disabled | ordinary fresh | no authenticated roaming |
| No mutually enabled method | ordinary fresh before selection | reject; do not attach existing session |
| `noise-psk-v1` selected and succeeds | may arm fresh roaming | continue existing roaming proof protocol |
| Noise fails after method selection | only through a separate explicit legacy connection | reject and dispose candidate; never downgrade the same connection |
| Noise fails on a resume candidate | only through a separate explicit connection | reject; never downgrade same attempt |
| Existing session ID collides with live/suspended session | must not replace based on ID | authenticate and satisfy recovery state, or reject |
| Stale authenticated generation | not applicable | existing one-shot authenticated `generation-sync` rule |
| Binding unavailable after disposal | new fresh carrier required | reject/preserve suspended state as existing transaction rules require |

Fresh compatibility is not permission to overwrite an existing logical session. Once a transport-auth method is selected, this implementation is fixed fail closed and has no `fresh-fallback` configuration field or same-connection fallback. A higher layer may explicitly create an entirely new legacy connection. Where the server still owns a live or suspended session ID, a candidate without an authenticated binding cannot claim it. Cleanup or grace expiry must remove the old exchanger before an unrelated fresh connection can use that ID.

## PSK management and rotation

### Dedicated keyring

Noise PSKs belong to a dedicated transport-authentication keyring. They must not reuse `protocol_key`, `transport_key`, TLS private keys, session IDs, user passwords, or P2P secrets.

Each entry contains:

- a bounded, non-secret `key-id` suitable for negotiation and telemetry;
- exactly 32 bytes of high-entropy secret material required by the Noise profile;
- lifecycle state: `active`, `verify-only`, or `revoked`;
- optional activation and retirement times interpreted by configuration management, not trusted from the peer.

There is exactly one active emission key per policy scope. A bounded number of verify-only keys may coexist during rotation. A peer-supplied key ID selects only an already configured local entry; it never selects a file path, environment name, KMS query, or unbounded lookup.

On POSIX, PSKs are loaded from permission-restricted `secret-file` entries through one `O_NOFOLLOW` descriptor with `fstat` owner/mode checks and same-descriptor reads. Windows transport-auth PSK secret loading is currently unsupported and returns a stable failure; enabling transport-auth there therefore fails closed until a handle-bound owner/DACL implementation exists. Loaded secrets are validated before publication, held in cleansable memory, and never printed in logs, diagnostics, runtime snapshots, crash annotations, INFO JSON, or metrics. There is no built-in default or weak compatibility PSK. Configuration JSON serializes only transport-auth policy, timeout, key metadata, state, and `secret-file` paths; it never serializes secret bytes or a `transport-auth-keyring` object.

The published runtime keyring is an immutable in-memory `TransportAuthKeyringSnapshot`: each successful build receives a process-wide, thread-safe, monotonically increasing nonzero generation, one active emit key, and bounded verify-only lookup state. Generation exhaustion fails closed. A failed rebuild does not allocate or replace the prior snapshot. This internal keyring snapshot is not the diagnostics runtime-snapshot schema, and neither schema exposes secret bytes, bindings, or confirmation proofs.

### Rotation sequence

Normal rotation is:

1. Add the new PSK to servers as `verify-only` while retaining the old active key.
2. Promote the new server key to `active`; keep the old key `verify-only` for a bounded overlap window.
3. Roll clients to emit the new key ID and retain the old key only as required for rollback.
4. Confirm new-key handshake success and absence of old-key use beyond the expected lag.
5. Remove or revoke the old key on clients and servers.

Emission is single-key; acceptance may be dual-key only during the bounded overlap. The protocol must not trial-decrypt across every configured key when a key ID is unknown, and it must not silently fall back from a selected new key to an old key within the same handshake.

A retained roaming root is not implicitly rotated when the Noise keyring changes. A suspended session may resume only if its new candidate carrier authenticates under an accepted key and then passes the unchanged retained-root proof. A missing or revoked key fails closed. Policy may then require a separate fresh authentication, which creates a new retained root; it must not transform the failed resume into fresh attachment on the same candidate.

Emergency revocation removes the key from both active and verify-only sets, rejects new bindings using it, clears affected in-memory authentication attempts, and relies on existing session disposal/reconnect policy for already established carriers. Whether emergency revocation forcibly terminates active sessions is an operational policy decision and must be explicit rather than an accidental side effect of key reload.

## Support matrix

| Carrier / condition | Binding | Fresh | Roaming |
|---|---|---|---|
| WSS/TLS | TLS exporter | compatible | implemented and enabled as before |
| plain TCP, both peers new and enabled | Noise/PSK | compatible | implemented, default-off |
| plain WebSocket, both peers new and enabled | Noise/PSK | compatible | implemented, default-off |
| plain TCP/WS, either peer legacy | none | compatible | unsupported |
| new peers, policy disabled on either side | none | compatible | unsupported |
| loopback proxy ingress (including current CDN routing) | deliberately unavailable | ordinary fresh only | excluded |
| Noise authentication failure | none | possible only after explicit new connection | forbidden for the failed attempt |
| capability or selected-method mismatch | none | compatible before selection | unsupported/fail closed |
| key ID missing or revoked | none | separate explicit reconnect only | forbidden for the failed attempt |
| binding lost on dispose/migration | none | new carrier required | unsupported on that carrier |

“Compatible” means the existing fresh-session behavior remains available where there is no protected existing-session collision. It does not mean unauthenticated fresh fallback may replace a live or suspended logical session.

## CDN exclusion

The current CDN listeners are transparent SNI/HTTP proxies rather than authenticated `ITransmission` carriers. They do not terminate the external TLS session and cannot export its keying material. HTTP routing may loop traffic to a local plain WS listener, and TLS routing may loop traffic to a local WSS listener, but neither fact proves an end-to-end binding to the external CDN-facing connection.

The current provenance rule is intentionally narrow and fail closed: every server-accepted TCP/WS/WSS transmission whose immediate remote endpoint is loopback, or whose endpoint cannot be classified, is marked as loopback ingress. Such a transmission does not advertise or run transport-auth and cannot expose either a Noise or WSS TLS exporter to recovery or P2P consumers. This excludes current CDN proxy loopback traffic; it also conservatively excludes direct localhost clients and unclassifiable ingress because endpoint provenance cannot distinguish them safely. Classified non-loopback directly accepted TCP/WS/WSS behavior is unchanged. CDN is never automatically included and still requires a separate design covering trust boundaries, TLS termination ownership, proxy authenticity, connection identity across hops, downgrade behavior, and the carrier binding used for roaming.

## Roaming generation and commit fence remain unchanged

Noise only supplies the authenticated carrier-binding prerequisite. It does not alter recovery state semantics:

- A newly armed logical session begins at generation `1`.
- Generation represents the currently published carrier epoch, not a reconnect-attempt counter.
- Suspend, reservation, cancellation, authentication failure, and committed-frame write failure do not increment generation.
- `resume-accept` and `resume-confirm` carry the current generation.
- The server prepares and sends `resume-committed(generation + 1)` before publishing the candidate carrier.
- Only the existing publication fence advances generation exactly once, rebinds retained UDP/statistics/echo state, and makes the replacement carrier active.
- The old-carrier completion fence continues to compare both transmission identity and carrier generation, so a stale completion cannot tear down the replacement.
- The existing exclusive grace deadline, one-shot authenticated generation synchronization, reservation checks, and same-owner-context gate remain mandatory.

No Noise callback may publish a carrier, advance generation, bypass `RunSessionResumeEstablishTransaction`, or weaken the current proof transcript. Noise failure before publication follows the existing cancellation/preserve-suspended behavior.

## Implemented increments

1. The carrier-binding abstraction and WSS adapter preserve the existing TLS exporter labels, binary contexts, strand affinity, lifecycle gates, proof transcript, and WSS behavior.
2. The EVP-backed Noise core, strict INFO codec, client confirmation, one-shot exporter, keyring snapshot, configuration validation, POSIX secret-file loading, and Windows fail-closed boundary implement the frozen `noise-psk-v1` profile.
3. Handshake capability/policy encoding and client/server wiring enable plain TCP only after mutual opt-in and successful authentication.
4. The same post-upgrade path supports plain WebSocket, with exact carrier/method eligibility and failed-attempt downgrade prevention.

All endpoint defaults remain disabled. Implementation completion is not rollout approval: full-product builds, every supported platform, full roaming E2E, and sanitizer configurations are separate validation boundaries.

## Focused tests

The standalone CMake suite registers these transport-auth targets:

```text
transport_auth_information_test
noise_psk_handshake_test
noise_psk_exporter_test
transport_auth_keyring_test
transport_auth_configuration_test
transport_auth_lifecycle_test
transport_auth_handshake_capability_test
transport_auth_negotiation_test
client_transport_auth_wiring_policy_test
```

The production-source WSS regressions remain registered as:

```text
session_resume_production_wss_lifecycle_test
session_resume_establish_transaction_wss_test
```

Together these focused targets cover strict INFO controls, deterministic and production-role Noise handshakes, exporter domain separation, wrong-key/tamper/replay failures, keyring limits and secret loading, default-off JSON behavior, immutable keyring publication, carrier lifecycle and ownership gates, handshake capability preservation, negotiation ordering, client policy, and unchanged WSS lifecycle/transaction behavior. The broader standalone suite remains available through `scripts/run-cpp-tests.sh`; TSan uses `scripts/run-cpp-tsan-tests.sh`.

Focused test success does not imply that full-product builds, cross-platform execution, ASan/UBSan, TSan, CDN ingress, or every end-to-end roaming fault scenario has been validated.

## Rollout and rollback

1. Distribute the default-off implementation and provision permission-restricted PSK files only on POSIX platforms with the supported loader.
2. Enable servers for a small plain-TCP pool, then selected compatible clients.
3. Expand plain TCP only after fresh compatibility, authentication-failure, and downgrade counters are stable.
4. Repeat the process independently for plain WebSocket.

Rollback disables `noise-psk-v1` selection and returns plain carriers to ordinary fresh-session behavior. It does not disable WSS/TLS-exporter roaming. Suspended sessions that require Noise remain protected and expire normally; rollback must not convert them into unauthenticated attachments. Removing a PSK or disabling Noise requires a separate explicit fresh reconnect when a fresh session is desired; this implementation never downgrades the selected connection.

## Remaining rollout boundaries

- CDN ingress remains excluded pending its own end-to-end authentication design.
- Active-carrier termination on emergency key revocation remains an explicit operational policy choice; new authentication attempts already use the newly published immutable keyring snapshot.
- Rollout thresholds and telemetry aggregation belong to deployment policy and must not expose PSKs, proofs, exporter material, or keyring contents.
- Full-product, cross-platform, full roaming E2E, and sanitizer validation must be recorded separately before broad enablement.

These rollout boundaries do not relax the compatibility, downgrade, CDN, or roaming-fence rules above.
