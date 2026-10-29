# Generic reconciliation webhooks

An optional authenticated `POST /reconcile` endpoint accepts refresh hints from Grafana/Loki alerting, Prometheus Alertmanager or another platform. Standard JSON alert payloads are accepted. Request contents never become authoritative identity, DNS or policy state.

## Enable

Generate a random bearer token of at least 32 characters in private `secrets/reconcile-token`, mode 0600 and owned by the worker UID. Copy [webhook.example.json](webhook.example.json) to `secrets/webhook.json` and set `IDENTITY_WEBHOOK_FILE=/run/secrets/webhook.json` in the worker environment. The existing secret mount keeps credentials server-side. Restart the worker after token changes.

The example binds to port 8092 inside the container. [compose.webhook.example.yaml](compose.webhook.example.yaml) publishes it on host loopback only. A trusted same-network container can use the identity service address directly. For remote publishers, explicitly configure a private route or a TLS reverse proxy and retain bearer authentication. No public endpoint or proxy route is created automatically.

Send an `Authorization: Bearer <token>` header and a JSON object. HTTP 202 means queued or coalesced, not successfully applied. Missing/incorrect tokens return 401; payloads exceeding 16 KiB return 413. The handler reads no browser cookies and offers no arbitrary command/configuration API. Credentials are never returned to a browser or logged.

Grafana contact points support webhook bearer authentication. Prometheus generally sends notifications through Alertmanager; its webhook receiver supports `http_config.authorization` with a credentials file. Loki log alerts normally reach a webhook through Grafana or Loki ruler/Alertmanager. Those alert-rule/contact-point configurations are outside the bridge itself. Choose lease-change signals carefully: alerting commonly notifies on state transitions rather than on every log entry or sample. Scheduled sync remains necessary even when publishers are healthy.

## Three update paths and deduplication

1. **Passive LAN:** the collector updates its snapshot. A local watcher refreshes observational inventory using retained authoritative caches; it makes no RouterOS or Pi-hole API calls. Conflicting observed assignments and visible revocations of known bindings request authoritative confirmation.
2. **Notifications:** a webhook or optional direct Loki notifier requests a debounced full reconciliation. Duplicate hints coalesce. Unknown events retain the safe full-refresh behavior.
3. **Polling:** startup and periodic full synchronization refresh authoritative providers regardless of event delivery, deduplication or notifier availability. Neither local updates nor event cooldown postpones that schedule.

For cross-source semantic deduplication, publishers can supply this normalized shape:

```json
{
  "network": "site-a/users",
  "mac": "AA:BB:CC:DD:EE:01",
  "ip": "192.168.50.20",
  "action": "ack"
}
```

The network label must match the collector's configured network scope. MACs are normalized and IPs validated. Supported actions are `ack`, `release`, `decline` and `nak`. The shared key includes network, MAC, IP and action. It coalesces matching hints within 15 seconds and has a bounded in-memory cache. Different networks/actions remain separate, and a later renewal becomes a new event. A LAN observation arriving first can suppress a matching redundant notification; a notification arriving first may already have requested one authoritative read.

For direct Loki queries, extract `mac`, `ip`, `action` and optionally `network` as stream labels using LogQL. `event_network` can supply a configured scope, and `action_map` can normalize vendor action labels. No vendor message parser is built into the bridge. Missing fields trigger a full refresh rather than guessing equivalence.

For generic alert bodies without those fields, exact payloads are deduplicated. Publishers can also supply an `Idempotency-Key` of up to 256 characters. Distinct payloads without common identity fields cannot be reliably identified as the same underlying DHCP event; global debounce and minimum refresh intervals still coalesce bursts.

Deduplication is an optimization, not proof of device identity or guaranteed event delivery. Local observations retain their expiry deadlines and lower precedence; matching a log or webhook does not promote them to authoritative bindings. Time-ranged historical attribution and automatic migration of Pi-hole group assignments remain separate unfinished work.

## Operation and tests

Incoming webhook handling is separate from Loki HTTP polling, so a slow/hung Loki request cannot block webhook ingestion or periodic synchronization. A missing or invalid optional webhook configuration disables only that receiver. Omit both notification environment settings for passive observations plus scheduled synchronization alone.

Local-only runs write `state/local-status.json`; full sync retains `state/status.json` and DNS ownership state. Retained authority timestamps are preserved, not freshened by local packets. Logs distinguish `scheduled`, `notification` and `local` refreshes.

Tests cover authentication, request-size limits, idempotent responses, LAN/Loki/Prometheus normalized deduplication, network/action separation, later renewals, passive-only updates without router/API calls, conflicts requiring confirmation, and periodic sync independent of local activity.
