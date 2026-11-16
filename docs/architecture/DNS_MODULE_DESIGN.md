# DNS Module Design
> Status: Active
> Type: Architecture
> Last verified: legacy DNS sources and v2.1.7 policy/DNS sources, 2026-10-07
>
> **Purpose:** Describe the native client DNS interception and resolver boundaries.
> **Audience:** Contributors and operators.
> **Parent index:** [Architecture](README.md) · **Chinese:** [DNS 模块设计](DNS_MODULE_DESIGN_CN.md)

## Scope

The client interception entry is UDP/53-specific. `ClientPacketDispatchHandler` recognizes UDP packets whose destination port is 53 and delegates them to `DnsController`. This does not make client TCP DNS, DoH, or DoT traffic a generic interception feature. UDP, TCP, DoH, and DoT describe the resolver’s *upstream* protocols.

## Owner and lifecycle model

```text
UDP/53 client packet
  -> DnsController
  -> DnsInterceptor / DnsRedirectPlan
  -> cache, legacy relay, provider resolver, tunnel fallback, or drop
  -> datagram output or session tunnel send
```

`DnsController` owns the policy wrapper, current session context, query context, and close order. `OpenSession()` installs a session context backed by a weak tunnel transport. `Close()` invalidates the session, clears context, cancels supplied timers, and closes the policy, so later asynchronous work cannot extend exchanger lifetime through that transport.

`DnsInterceptor` owns DNS rules, `DnsResolver`, and fake-IP state. It performs DNS decoding, AAAA suppression when IPv6 is not permitted, cache lookup, routing-plan selection, fake A response generation, and dispatch.

## Resolver paths

The routing plan distinguishes these main paths:

| Input/result | Current dispatch boundary |
|---|---|
| Cached response | Inject response through the datagram-output callback |
| Legacy rule containing an IP | `DnsUdpRelay` |
| Rule containing a provider | `DnsResolver::ResolveAsync()` |
| Unmatched/gateway resolver path | Explicit foreign entries, explicit domestic entries, or foreign → domestic → cloudflare fallback |
| Defer/drop/blocked AAAA | Plan-specific response or no forwarding |

Rules are an input to plan selection; do not document gateway handling as a blanket priority over every rule. Successful legacy UDP relay responses inject through their relay callback, while resolver responses and fallback use the response handler path.

`DnsResolver` currently implements UDP, TCP, DoH, and DoT upstream senders. There is no DoQ or DoH3 protocol enum/implementation. Provider entry order supplies the fallback order; deployment behavior still depends on reachable configured endpoints.

## v2 Policy DNS (v2.1.7 target)

The v2 policy DNS capabilities described here are part of the v2.1.7 code release target; v2.1.6 does not include them. Check the [release page](https://github.com/Miaocchi/openppp2/releases) for v2.1.7 package availability. The established UDP/53 interception boundary above still applies.

With a v2 policy snapshot, `PolicyResolverService` evaluates the DNS rule and uses the selected resolver definition and `via` action. Its in-memory response cache and in-flight coalescing key include the DNS question and selected resolver/transport/bootstrap semantics; in-flight operations are additionally scoped to a session. Cached answers honor TTL; in-flight requests have bounded waiters, operation count, bytes, and a deadline. Each waiter gets an independent cancellation handle. Closing a DNS session invalidates its transport and pending work; cancelling the final waiter closes that operation, while late completions are ignored by the inactive/session checks. This bounds response delivery and ownership; it does not guarantee that every underlying network operation finishes immediately.

The policy fake-IP store is separate from the transient resolver response cache. It binds persisted mappings to a configured identity and IPv4 pool, holds an exclusive store lock, and journals a new hostname-to-address mapping durably before returning it. A compact snapshot can replace the journal. A fresh store creates an empty snapshot and journal. A corrupt or mismatched snapshot, a missing journal for a nonempty or previously advanced snapshot, a lock conflict, or a persistence error makes the store unavailable rather than silently reassigning an existing identity. Allocation is dispatched to a bounded disk worker and its callback returns to the owning event context only while the request remains active. Fake-IP is IPv4/A-only; it does not synthesize AAAA records.

Resolver upstream transport support (UDP, TCP, DoH, DoT) describes how the resolver contacts its configured upstream. It does not mean client TCP/53 is intercepted, nor that encrypted DNS or arbitrary DNS-over-HTTPS traffic is blocked or redirected. The client dispatch entry remains UDP destination port 53.

## Fake IP and DNS reachability

The fake-IP facility is IPv4/A-record only. It can synthesize an A response, resolve the real A answer in the background, and rewrite known fake destinations for both UDP and TCP paths. Desktop route planning can include the fake-IP pool route.

DNS reachability is intentionally split: tunnel DNS routes can use the tunnel gateway, while underlying DNS routes can use the underlying gateway. Provider endpoint IPs and legacy rule IPs are collected according to their route semantics; this is not a universal “all DNS stays on the physical NIC” rule.

## Server DNS is separate

Server UDP/53 handling uses `VirtualEthernetNamespaceCache` when enabled. On a miss, it redirects only if `udp.dns.redirect` is configured; otherwise ordinary UDP forwarding continues. The namespace cache is created only when both DNS cache is enabled and TTL is positive.

## Boundaries to keep explicit

- Upstream TLS verification, endpoint reachability, and resolver interoperability are deployment concerns; do not promise successful resolution solely from configuration.
- Fake IP does not provide IPv6/AAAA synthesis.
- DNS controller/session cleanup is designed to prevent later sends through a closed session, not to guarantee completion of every outstanding upstream operation.
- Configuration fields and safe operator examples belong in [Reference](../reference/README.md) and the routing/DNS guides, not this architecture overview.
- The Linux evidence report records only its named real-host probes and their explicit failure/coverage limits; it does not broaden the DNS interception boundary above.

## Source anchors

- `ppp/app/client/ClientPacketDispatchHandler.cpp`
- `ppp/app/client/dns/DnsController.cpp`
- `ppp/app/client/dns/DnsInterceptor.cpp`
- `ppp/app/client/dns/DnsRedirectPlan.cpp`
- `ppp/dns/DnsResolver.h/.cpp`
- `ppp/app/server/VirtualEthernetExchanger.cpp`
