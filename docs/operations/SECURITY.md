# Security Model

> **Status:** Current hardening boundary; not a formal security assessment
> **Type:** Operations guide
> **Last verified:** Configuration validation, runtime, native manager, and subscription sources, 2026-07-22
> **Parent index:** [Operations](README.md) · **Chinese:** [安全模型](SECURITY_CN.md)

## Scope and non-goals

This page states operational controls visible in this tree. It does not claim perfect forward secrecy, a formal cryptographic proof, a leak-proof kill switch, automatic host-firewall management, or universal TLS.

Treat the tunnel configuration, management credentials, and published subscription documents as sensitive deployment assets.

## Protect configuration material

The `key` configuration contains protocol/transport key material. At minimum:

- use unique secrets for each deployment;
- keep `key.protocol-key`, `key.transport-key`, and related configuration readable only by the intended service account/operator;
- keep `key.plaintext` disabled outside controlled testing;
- do not commit active configuration, keys, subscription documents, or exported manager data to source control;
- review runtime configuration warnings for weak/default/legacy settings, but do not treat warnings as an enforcement policy or a security audit.

Do not publish a copyable “strong key” value in documentation. Generate and distribute keys through the deployment's secret-management process.

## Protect management and subscriptions

| Surface | Required hardening |
|---|---|
| Native manager admin API | Restrict listener address/network, protect bearer token, and use an operator-managed TLS boundary when it is not on a trusted network. |
| C++ managed link | Keep `server.backend-key` and Go `key` secret; require matching `server.node`, URL/path, and manager record. |
| Public subscription URL | Treat `/sub/{token}` as a credential-bearing capability; rotate, disable, or delete it when access must end. |
| `manager-data.json` | Protect it as sensitive local control data in standalone mode. |

The direct Go HTTP server does not provide TLS termination. A `public-base-url` changes returned URLs; it does not secure the listener.

## Host networking is part of the boundary

Normal client/server operation can alter virtual-interface, route, DNS, IPv6, and listener state. A bad route or resolver policy can send traffic somewhere unexpected even if the configured tunnel keys are correct.

- Review bypass lists and DNS rule inputs before each rollout.
- Test normal client route/DNS changes in a controlled environment.
- Keep host firewall policy, port exposure, route persistence, and DNS-service policy under operator control.
- Do not claim default-route protection prevents every traffic/DNS leak; it is host-dependent route management, not a universal kill switch.
- Treat Linux server GUA/NAT66/NDP setup as privileged host integration with separate upstream/firewall requirements.

## Transport and TLS boundary

The source has configured protocol/transport key material and session runtime behavior, but this page does not turn that into claims about a complete adversary model. Use a trusted transport/network boundary for control services, and supply TLS termination where a service is exposed beyond a trusted network.

For WSS or other TLS-bearing deployment paths, validate certificates, names, and reverse-proxy behavior in the actual deployment. Do not infer TLS from a URL field alone.

## Operational hardening checklist

1. Store client/server configuration, manager data, and logs under least-privilege access control.
2. Use different tunnel and manager keys per environment; plan a documented rotation procedure.
3. Bind listeners only to intended interfaces and use host firewall policy to constrain exposure.
4. Put public management/subscription surfaces behind HTTPS/TLS termination and monitor access logs.
5. Review subscription documents before publication because they can carry node key material.
6. Revalidate route, DNS, IPv6, and peer-prefix policy after upgrades or topology changes.
7. If credentials may have leaked, rotate affected keys/tokens, restrict the listener, redeploy affected configuration, and verify new clients cannot use the old capability.

## Related pages

- [Deployment model](DEPLOYMENT.md)
- [Operations and troubleshooting](OPERATIONS.md)
- [Management backend](../guides/MANAGEMENT_BACKEND.md)
- [Remote subscription format](../guides/REMOTE_SUBSCRIPTION.md)
- [Routing and DNS](../guides/ROUTING_AND_DNS.md)