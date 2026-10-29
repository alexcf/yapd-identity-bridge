# Proposed upstream boundary

This repository separates two responsibilities:

1. A source-neutral YAPD identity provider that enriches existing client/query views from a validated private snapshot.
2. A separately scheduled adapter/reconciler with registered collection providers and one DNS authority, writing owned local DNS through YAPD's authenticated API.

The small YAPD patch introduces no MikroTik credentials, router requests, new public routes, database schema changes, or extra infrastructure into the dashboard. Provider-specific discovery stays in the worker. Built-ins support MikroTik, JSON snapshots, optional Prometheus observations and a separate passive DHCPv4 collector; installed Python entry points can add other trusted providers. UniFi remains a future adapter. See [PROVIDERS.md](PROVIDERS.md) for capabilities, precedence, failure behavior and the SDK.

Suggested upstream work is to formalize the snapshot/provider interface in a NestJS module, expose source freshness/provenance explicitly in the client API/UI, and add supported IP-based policy controls for routed clients. The current patch uses the existing frontend fields and tags, preserving manual aliases and reporting uncorrelated activity/policy rather than fabricating observations.

The supported source baseline is `df9633ed6ee1941e22eec7a3faaa4b0817dd4459` (YAPD 1.0.0). Apply `yapd-patch/identity-provider.patch` to that revision and run the backend tests/build. Upstream acceptance or a native third-party plugin loader is not assumed. This repository does not automatically open upstream issues or pull requests.

The same source patch is published for review on [alexcf/yadp, branch feat/external-identity-provider-20261029](https://github.com/alexcf/yadp/tree/feat/external-identity-provider-20261029). It is based on the tested release revision rather than assuming compatibility with newer upstream changes. No pull request has been submitted to the upstream maintainers.

Optional Loki notifications use configurable LogQL and a separate change-notifier protocol. They trigger the existing reconciliation path and retain scheduled synchronization during notifier outages. The passive collector drops capture privileges before decoding packets; the regular worker and YAPD require none. Expiring observations are pruned by both reconciliation and the YAPD reader, including cached snapshots. See [PASSIVE-DHCP.md](PASSIVE-DHCP.md) and [TRIGGERS.md](TRIGGERS.md).

The optional worker webhook accepts authenticated refresh hints from Grafana/Loki, Prometheus Alertmanager or other publishers. Passive snapshots can refresh observations without router API reads; authority is retained with its original timestamps. Common scoped event keys coalesce normalized duplicate LAN/log/webhook hints. Neither notification path assigns filtering groups. See [WEBHOOKS.md](WEBHOOKS.md).
