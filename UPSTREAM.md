# Proposed upstream boundary

This repository separates two responsibilities:

1. A source-neutral YAPD identity provider that enriches existing client/query views from a validated private snapshot.
2. A separately scheduled adapter/reconciler that reads RouterOS REST and writes owned local DNS through YAPD's authenticated API.

The small YAPD patch introduces no MikroTik credentials, router requests, new public routes, database schema changes, or extra infrastructure into the dashboard. MikroTik-specific discovery stays in the worker. An external collector can supply the same JSON format for another vendor.

Suggested upstream work is to formalize the snapshot/provider interface in a NestJS module, expose source freshness/provenance explicitly in the client API/UI, and add supported IP-based policy controls for routed clients. The current patch uses the existing frontend fields and tags, preserving manual aliases and reporting uncorrelated activity/policy rather than fabricating observations.

The supported source baseline is `df9633ed6ee1941e22eec7a3faaa4b0817dd4459` (YAPD 1.0.0). Apply `yapd-patch/identity-provider.patch` to that revision and run the backend tests/build. Upstream acceptance or a native third-party plugin loader is not assumed. This repository does not automatically open upstream issues or pull requests.
