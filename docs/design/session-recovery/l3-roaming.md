# Authenticated L3 Session Roaming
> Status: Implemented
> Type: Design
> Last verified: 93d9cae
> Parent index: [Design documents](../README.md)

## Scope

This design upgrades same-process carrier recovery from session-ID lookup to an authenticated, generation-fenced L3 roaming protocol. It retains only the logical session identity, assigned IP state, NAT ownership, and UDP manager state while a carrier is suspended. It is deliberately limited to a replacement `ISslWebsocketTransmission` for which `HasAuthenticatedSessionExporter()` is true.

Roaming is enabled only when both peers advertise and configure the v1 capability. The `client.session_resume.enabled` and `server.session_resume.enabled` master flags default to false; `server.session_resume.grace_ms` defaults to 60000 milliseconds. Plain TCP, plain WebSocket, CDN transports, WSS without an authenticated exporter, mixed-version peers, malformed controls, and capability mismatches fail closed and use the normal fresh-session path.

## Non-goals

The protocol does not provide raw-IP replay, stream offsets, byte acknowledgements, frame replay, FIN/RST recovery, mailbox or cross-executor handoff, transparent proxy/FRP continuation, or VMUX continuation. Suspending a session still removes FRP mappings and closes VMUX. Existing TCP/proxy/FRP flows are expected to reconnect at their own layer. The retained root is process-local and is not persisted across server restart.

## Support matrix

| Carrier / condition | Fresh negotiation | Resume | Result |
|---|---:|---:|---|
| WSS, authenticated exporter, both flags enabled | yes | yes | authenticated roaming v1 |
| WSS, exporter unavailable | no | no | fail closed; fresh legacy session only |
| plain WebSocket | no | no | fresh legacy session only |
| plain TCP / PPP | no | no | fresh legacy session only |
| CDN transport | no | no | fresh legacy session only |
| either master flag disabled | no | no | existing behavior; no retained roaming secret |
| different process / server restart | fresh offer possible | no | clear stale client retained state and retry fresh on the same carrier |

## Threat model

The attacker may observe, replay, delay, reorder, duplicate, or inject INFO frames and may know a session ID. A session ID is never an authenticator. The attacker is assumed unable to extract TLS exporter output or the retained root from process memory. The protocol must prevent carrier hijack, cross-session substitution, stale-generation attachment, transcript ambiguity, and replay of a prior resume attempt.

Fresh TLS exporter material derives a retained session root. Exporter material from a reconnecting carrier derives only a candidate-carrier binding; it never replaces or reveals the retained root. Every proof is a complete 32-byte HMAC-SHA256 over one canonical, fixed-width binary transcript. Verification uses constant-time comparison. Nonces come from the OpenSSL CSPRNG. Temporary exporter bytes, derived values, proofs, and retained roots are cleansed with `OPENSSL_cleanse` when their owner is destroyed or the value is replaced. Secrets and proofs are never logged.

TLS still authenticates and protects each carrier. The retained HMAC root binds the old logical session to the new TLS carrier. Both are required.

## INFO extension schema

Control messages use the existing trailing JSON object of an INFO frame. No `PacketAction` value and no fixed handshake field is added. Unknown sibling JSON fields remain forward-compatible; the `session-resume` object itself is strict. A malformed present object clears the parsed control and causes the roaming step to reject.

```json
{
  "session-resume": {
    "version": 1,
    "action": "resume-request",
    "capabilities": 1,
    "session-id": "00112233445566778899aabbccddeeff",
    "generation": "7",
    "client-nonce": "<64 lower-case hex characters>",
    "candidate-binding": "<64 lower-case hex characters>",
    "proof": "<64 lower-case hex characters>"
  }
}
```

Actions are `offer`, `accepted`, `resume-request`, `generation-sync`, `resume-accept`, `resume-confirm`, `resume-committed`, and `reject`. Required fields depend on the action; values have exact JSON types. `resume-request` and `generation-sync` omit `server-nonce` and authenticate an all-zero server nonce in the fixed-width transcript; the accept, confirm, and committed actions carry both nonces. `version` is exactly 1, `capabilities` is an unsigned 32-bit mask with only advertised v1 bits accepted, `session-id` is exactly 16 bytes encoded as 32 lowercase hexadecimal characters, `generation` is an unsigned 64-bit integer represented as a decimal string to avoid JSON integer-width ambiguity, each nonce/binding/proof is exactly 32 bytes encoded as 64 lowercase hexadecimal characters, and `reason` is a bounded non-secret token used only by reject controls. Unknown fields inside the object are ignored for additive compatibility, but known fields with the wrong type, length, range, or action combination reject the whole control.

During the pre-data proof phase, the strict single-frame reader accepts only one complete INFO frame. Any ordinary data-plane action, malformed frame, or trailing bytes fails the candidate carrier.

## Canonical transcript

All integers are unsigned big-endian. No text, JSON serialization, delimiters, variable lengths, or host byte order participate in authentication. The transcript is exactly:

```text
byte[24] domain = "openppp2-l3-roaming-v1" plus zero padding
uint8    protocol_version = 1
uint8    action_code
uint32   capabilities
byte[16] normalized_session_id
uint64   generation
byte[32] client_nonce
byte[32] server_nonce
byte[32] candidate_binding
```

The action code is independent of the JSON spelling and has a fixed v1 mapping. Every authenticated action uses its own action code, preventing reflection between request, acceptance, confirmation, commit, and generation-sync messages. HMAC input always includes the complete transcript; fields not yet supplied by the peer are represented by all-zero fixed-width values only where that action explicitly defines them as absent.

The fresh exporter is expanded with a dedicated exporter label and the normalized session ID to derive the 32-byte retained root. A reconnect exporter is expanded with a different label and the same session ID to derive the 32-byte candidate binding. Labels, protocol domain, and version are independent from P2P and other exporter users.

## State machines

### Fresh WSS

```text
client                                  server
  plain INFO capability probe      ->   (unmanaged IPv4-only path)
                                  <- INFO offer(capability, server nonce)
  accepted(client + server nonce,
           proof)                  ->
                                         verify proof; retain root
  ordinary INFO / Run may begin
```

A fresh eligible client sends a legacy-compatible plain INFO probe before waiting for an offer. This prevents a new client from deadlocking with an old or disabled server. An unmanaged IPv4-only server replies to that probe with the `offer`; a managed or IPv6-enabled server may instead attach the offer to its existing initial INFO response. The client returns `accepted` with its proof, and the server verifies that proof before roaming is armed. Both sides derive the same retained root only from the fresh authenticated WSS exporter. If either side cannot export, derive, parse, or verify, roaming is not armed and no retained secret is kept. A fresh session can still proceed through the existing handshake when policy permits.

After a server restart, an armed client sends `resume-request` to a fresh exchanger. When no initial offer is already in flight, the server returns a bare `reject` followed by an offer-bearing INFO; if recovery is unavailable, the second frame is plain INFO. The client clears stale retained state and continues the fresh handshake on that same carrier.

### Resume

```text
client                                      server exchanger owner
  resume-request(generation, client nonce,
                 candidate binding, proof) ->
                                            reserve only
                                        <-  resume-accept(both nonces, proof)
  verify; send resume-confirm(proof)       ->
                                            validate and prepare commit
                                        <-  resume-committed(next generation, proof)
                                            generation := generation + 1
                                            attach/publish carrier
  verify committed generation
  only now publish transmission and start ordinary Run
```

`resume-accept` reserves the suspended exchanger but does not attach or publish the carrier. `VirtualEthernetSwitcher::Establish` delegates the existing-session control sequence to `RunSessionResumeEstablishTransaction`; its narrow adapter invokes exchanger-owned `BeginResume`, commit preparation, `PublishCommittedResume`, and `CancelResume`. Only a matching reservation can commit. The transaction sends the prepared committed control before publication. Only after that send succeeds does `PublishCommittedResume` increment generation exactly once, attach the candidate, publish UDP/echo/statistics state, and invalidate the reservation. Any earlier read/write/verification/deadline failure cancels the reservation and leaves the prior suspended state recoverable until its grace deadline; a committed-frame write failure explicitly preserves the suspended session, and an unpublished prepared commit receives only a bounded publish grace.

A stale generation never attaches. The server returns an authenticated `generation-sync` containing the current generation. The client creates a new nonce and retries at most once. When the session is genuinely missing after a process restart, the newly created exchanger enters the fresh path and first sends an offer-bearing or plain INFO frame; a subsequently arriving `ResumeRequest` probe can be consumed by that fresh path without requiring a bare rejection, so the client clears stale retained state and continues fresh on the same carrier. If an exchanger with that session ID still exists but authentication or resume state validation fails, the candidate fails closed and cannot replace it; cleanup/grace expiry must remove the old exchanger before a fresh connection can claim that ID.

The client completes proof before `EchoLanToRemoteExchanger`, publishing `transmission_`, mapping setup, static echo, or ordinary `Run`. The server never calls resume attachment based only on session ID and never publishes the replacement carrier before the committed control frame has been sent.

## Secret lifecycle

- Retained root: derived once from the accepted fresh WSS exporter; stored only in the logical exchanger; never serialized, logged, or rotated on resume.
- Candidate binding: derived independently for every replacement WSS carrier; binary working copies are scoped to one attempt and cleansed on every exit. Its wire encoding is authenticated protocol data, not a retained secret.
- Nonces: 32 random bytes per attempt; a generation-sync retry always uses a new client nonce.
- Proofs/transcripts: binary stack or attempt-owned working values are cleansed after use. Hex and JSON wire encodings of bindings, nonces, and proofs use ordinary bounded strings; they do not contain the retained root.
- Fresh fallback, terminal expiry, disposal, configuration disablement, or exporter ineligibility clears retained roaming state.
- Server restart intentionally loses roots and reservations, forcing fresh authentication.

## Owner-context limitation

There is no mailbox and no cross-executor handoff in v1. A resumable exchanger can only consume a carrier created on the same `io_context`; the existing `GetContext()` equality gate remains mandatory. When server roaming is enabled, only the WSS listener's `AcceptLoopbackAsync` is pinned to the switcher's `context_`. Other listeners retain their current scheduling.

This is a deliberate performance limitation: enabled WSS roaming concentrates WSS accept and handshake work on the owner context instead of distributing those connections across worker contexts. Operators should measure that context's queueing and CPU saturation before broad rollout. A future cross-executor design requires an explicit ownership/mailbox protocol and is outside v1.

## Telemetry

Emit counters without identifiers, nonces, bindings, or proofs:

- fresh offer accepted/rejected/ineligible;
- resume requested, reserved, committed, cancelled, rejected, expired;
- generation-sync sent and one-shot retry outcome;
- malformed INFO control and non-INFO proof-phase frame;
- exporter unavailable / wrong carrier / context mismatch;
- fresh fallback after missing retained session.

Existing link telemetry continues to distinguish clean close, carrier failure, suspend, and terminal expiry. Logs may include action, bounded reason code, generation, and aggregate latency; they must not include session secrets or authentication byte strings.

## Verification scope

`session_resume_wss_fault_injection_test` runs the production TLS exporter, resume authenticator, INFO-extension JSON codec, and recovery-state commit fence over a real loopback TCP/TLS/WebSocket connection. It covers a successful request/accept/confirm/committed exchange, write-before-publish ordering, exactly-once generation advancement, dropped controls, duplicate requests, old-carrier replay, stale-generation synchronization, concurrent reservations, grace-boundary expiry, and rejection before the application handshake gate. The test intentionally disables client certificate verification: it verifies exporter equality and the post-handshake application gate, not public-key-infrastructure identity validation.

`session_resume_production_wss_lifecycle_test` additionally instantiates a real loopback pair of production `ISslWebsocketTransmission` objects. It verifies that the exporter fails closed before the OpenPPP application handshake, is available on both strands after the complete TLS/WebSocket/application handshake, derives equal retained roots and per-carrier bindings, carries payloads through production application framing and I/O, produces a different binding on a replacement carrier, rejects an old-carrier binding in the new proof transcript, and fails closed again after disposal. Its test configuration intentionally uses plaintext application framing inside authenticated TLS, so this test does not claim coverage of the optional `Ciphertext` payload mode.

`session_resume_establish_transaction_wss_test` executes the same production transaction coordinator called by `VirtualEthernetSwitcher::Establish` over replacement production `ISslWebsocketTransmission` pairs and strict INFO controls. It covers successful carrier publication, one-shot authenticated generation synchronization, bad-confirm cancellation, old-carrier binding rejection, committed-frame write failure that preserves the suspended session, and fatal publish failure. The state adapter uses the production authenticator and `SessionRecoveryState`; it asserts generation `1 -> 2`, write-before-publish ordering, carrier-only replacement, and unchanged logical-session, assigned-IP/NAT, and UDP-manager identity sentinels.

`session_roaming_switcher_e2e_test` instantiates the production `VirtualEthernetSwitcher`/`VirtualEthernetExchanger` graph with two logical sessions, a replacement production WSS/TLS carrier, and the authenticated resume transcript. It verifies that the replacement advances generation `1 -> 2` while preserving exchanger and statistics identity; forwards a raw TCP NAT packet between the two sessions before and after roaming; suspends after abrupt loss of the old carrier; delivers a delayed response from an already-existing UDP relay through the replacement carrier; and reuses that relay's source port for a second post-roam UDP request.

This remains an in-process packet-level E2E test. It does not create a real TUN device or network namespace, switch a physical interface, cross a process boundary, or exercise kernel TCP sequence state. It therefore does not prove transparent continuation of an existing kernel TCP connection, recovery of unseen byte-stream offsets, replay of unacknowledged data, or general connection migration. FRP/proxy, VMUX, and static-echo continuation also remain outside the v1 guarantee and reconnect or close according to their existing behavior.

On the current verified tree, the native roaming E2E passed 100 consecutive runs, and the same E2E completed without ASan or UBSan findings. The focused session recovery/resume regression passed 8/8 tests. The broader CTest regression passed all 91/91 tests in split runs; `spinlock_test` was run separately and completed in 103.11 seconds.

## Rollout and rollback

1. Deploy code with both `client.session_resume.enabled` and `server.session_resume.enabled` false (the default).
2. Enable the server flag on a small WSS-only pool and confirm that legacy clients remain fresh-session only.
3. Enable selected clients, monitor commit/cancel/fallback rates, owner-context saturation, and grace-expiry counts.
4. Increase rollout only when authenticated commits and fresh fallbacks match expectations.

Operational rollback is to disable either master flag and restart the affected process. This immediately prevents new retained roots and causes reconnects to use the ordinary fresh path; existing in-memory roots disappear on disposal/restart. No wire-format migration or persisted-secret cleanup is required. Code rollback removes the `session-resume` INFO object while preserving the existing fixed handshake and PacketAction compatibility.
