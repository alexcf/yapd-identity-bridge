# Optional change notifications

Scheduled synchronization is the default: full sync at startup and every `SYNC_INTERVAL_SECONDS` (default 300, minimum 60). Notifications request additional reconciliations. Providers remain responsible for authoritative inventory.

## Portable Loki notifier

The notifier uses Loki's standard [query-range API](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-logs-within-a-range-of-time) and a configurable LogQL query. It does not parse MikroTik message formats or depend on a router vendor, DHCP server, label convention or collector such as Alloy.

Queries can select messages from MikroTik, dnsmasq, UniFi, Windows DHCP or another system already shipping logs to Loki. An event only means “refresh the configured providers.” It never edits a lease, transfers group membership or grants a permission.

1. Copy [trigger.example.json](trigger.example.json) to private `secrets/trigger.json`.
2. Set the Loki URL and a query returning **log streams**, not a metric expression. The sample labels/text are placeholders.
3. Set `IDENTITY_TRIGGER_FILE=/run/secrets/trigger.json`; the existing secrets mount is read-only.
4. Restart the worker after reviewing its provider/DNS preview.

Omitting that environment variable retains scheduled-only behavior. Invalid or missing optional configuration disables the notifier with a bounded error log; regular sync continues. Runtime Loki failures back off polling and leave scheduled sync running.

HTTPS verification is required unless explicitly opting into private-network HTTP using `allow_http: true`. Bearer authentication uses `token_file` and always requires HTTPS. Optional `ca_file` and `tenant_id` support private CAs and tenancy. Redirects are refused and system proxies ignored. Restart the worker after rotating notifier credentials.

Polling defaults to five seconds, debounce to two seconds and the minimum between notification syncs to ten seconds. One background polling thread keeps slow HTTP or DNS outside the reconciliation scheduler; a hung notifier cannot spawn more pollers or stop periodic sync. Scheduled sync is never postponed by notification cooldown. Requests have bounded timeouts, response sizes, entry counts, overlap and duplicate caches. Identical events coalesce; different messages at one timestamp remain distinct. A ten-second overlap catches limited delayed ingestion.

This is a best-effort hint channel. Limits may coalesce/drop events, older delayed events may be missed, and the cursor is in memory. Startup always performs a full sync. Periodic synchronization recovers from missed notifications, regardless of log delivery or Loki availability.

## Other notification sources

Implement `ChangeNotifier.poll() -> bool` from [triggers/__init__.py](triggers/__init__.py). Collection and reconciliation remain unchanged. Loki is the configured implementation today; other types need an explicit factory entry in `daemon.optional_trigger`. There is no arbitrary module loader or unauthenticated incoming webhook.

Tests cover duplicate/late events, generic vendor messages, the HTTP contract, configuration errors, outages, debounce, minimum intervals and continued periodic sync during trigger failure. No Loki deployment is required with notifications disabled.

## Webhooks and passive refreshes

An optional [authenticated webhook receiver](WEBHOOKS.md) accepts platform-neutral JSON refresh hints alongside or instead of Loki polling. Passive snapshot changes also refresh local observations without reading router APIs. Full authoritative reads still occur on schedule, on uncorrelated notifications, and when a captured assignment conflicts with known authority. Local refreshes never rewrite DNS arrays or filtering groups.

To correlate direct Loki hints with passive observations or webhook publishers, extract `mac`, `ip`, `action` and optionally `network` as stream labels in LogQL. Set `event_network` for a static scope and `action_map` for vendor action names. Missing fields retain full-refresh behavior. The shared deduper keys network, MAC, IP and action over a short window; see [WEBHOOKS.md](WEBHOOKS.md).
