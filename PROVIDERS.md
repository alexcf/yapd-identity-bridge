# Identity providers

The worker separates collection, validation, identity merging, and DNS reconciliation. YAPD reads a versioned snapshot, not a router-specific API. Its existing aliases remain authoritative display names. This is a source patch to a pinned YAPD revision, not a native upstream plugin system.

## Available providers

| Type | Identity source | DNS publishing | Binding authority |
| --- | --- | --- | --- |
| `mikrotik` | RouterOS HTTPS REST, DHCP leases and static DNS | Yes | Yes |
| `json` | Validated v1 snapshot from another collector | Configurable, default yes | Configurable, default yes |
| `prometheus` | Instant query with explicit device labels | Never | Never |
| `dhcp` | Private snapshot from the passive DHCPv4 collector | Never | Never |
| `arp` | Private snapshot from the same collector's optional ARP observer | Never | Never |

UniFi is an extension point, not an implemented or tested integration. A future adapter should use its documented inventory API and declare only the capabilities its data supports. Alternatively, an external collector can write the JSON format described in the README. Do not fabricate a MAC from an exporter target, router address, IP, or device name.

## Configuration and precedence

Existing environment-only MikroTik configuration continues to work. For multiple sources, mount a private configuration file read-only and set `IDENTITY_PROVIDERS_FILE` to its container path. [providers.example.json](providers.example.json) illustrates MikroTik plus optional Prometheus. Replace the example endpoints/query with verified local values before using it. Credentials are read from secret files; do not put passwords or bearer tokens in this JSON.

- Source IDs are stable lowercase names, unique within one worker. Changing configuration invalidates that source's cache.
- At most one configured provider can declare `dns_records`. This enforces one authority for the shared DNS arrays. A metadata-only configuration makes no YAPD DNS calls and does not remove previously deployed records.
- Binding authorities outrank observations. Within the same class, larger `priority` wins. Equal-priority MAC claims for one address are omitted as ambiguous. Known expired authoritative leases cannot be resurrected by telemetry. Conflicting equal-priority names are left blank and reported.
- Multiple sources for one MAC retain their provenance and retrieval times. IP-only observations may fill a missing name for a uniquely known binding, but never create a device, MAC or DNS entry.
- Each source has a configuration-bound last-good cache. Partial source failure retains that source's original timestamps and marks affected identities stale. The worker reports degraded health and retries. An authoritative source with no compatible cache aborts publication. Total source failure leaves the published snapshot and deployed DNS unchanged.
- Retained cached bindings can become outdated during an outage; stale labels explicitly flag this limitation. Identity enrichment is not authorization or proof of device ownership.

The configuration and adapter code are trusted operator inputs. A provider can access its configured API; this is not a sandbox for untrusted plugins. Do not expose provider configuration as an ordinary-user API.

## Prometheus

The adapter uses the documented [Prometheus instant-query endpoint](https://prometheus.io/docs/prometheus/latest/querying/api/#instant-queries), `GET /api/v1/query`. It accepts successful instant vectors only, limits response size/series count, validates TLS, refuses redirects and reads an optional bearer token from `token_file`. Private-network plain HTTP requires an explicit `allow_http: true`; bearer tokens always require HTTPS. System HTTP proxy environment variables are ignored.

An exporter must already expose the identity labels you need. Generic `up`, node-exporter, or an `instance` label is not a DHCP table. Defaults are `mac`, `ip`, `name`, and `network`; `labels` maps these fields to your exporter's label names. A labelled MAC/IP can create an **observed identity**, visibly distinguished from a DHCP lease in YAPD. Without a valid MAC, a sample is retained as an IP-only observation and cannot create a client row. Metrics never publish local DNS or become a lease authority.

The illustrative `timestamp(network_device_info)` query is not a bundled metric. Replace it with your actual exporter series. With `value_is_timestamp: true`, the adapter reads the scrape sample time from the returned value; this avoids mistaking an instant query's evaluation timestamp for the original sample time. Samples older than `max_sample_age_seconds` (default 300, maximum 900), excessively future-dated samples, and NaN values are rejected. With ordinary numeric results, the returned vector timestamp is used; its freshness may reflect query evaluation instead of scraping, so use the timestamp form for info metrics.

Info metric value `1` does not mean online. `active` remains unknown unless `active_from_value: true` is explicitly configured for a boolean status metric. That option has no effect when values are timestamps. Prometheus exporter accuracy, scrape latency and label cardinality still limit attribution. No live Prometheus connection or UniFi connection is claimed by the fixture tests.

## Implementing another adapter

Implement `IdentityProvider` from [providers/base.py](providers/base.py):

```python
from providers.base import Capabilities, ProviderResult

class MyProvider:
    capabilities = Capabilities(identity=True, binding_authority=True)

    def __init__(self, config):
        self.config = config

    def collect(self) -> ProviderResult:
        # Fetch a complete, validated inventory. Raise on incomplete collection.
        # Do not return an empty snapshot to represent an API failure.
        return ProviderResult(inventory=fetch_complete_inventory(self.config))
```

Inventory v1 uses uppercase MACs, canonical IPv4/IPv6 strings, a timezone-aware `retrievedAt`, and `devices`. Each device has `mac`, `ips`, `name`, `network`, `active`, and `isStatic`; unknown states can be null. A provider must remove expired bindings and duplicate address ownership before returning, listing ambiguous addresses in `ambiguous_ips` so another observation cannot reclaim them. The core validates each result independently before merging.

Register a built-in factory with `registry.register("myprovider", MyProvider)`, or install a trusted Python distribution in a custom worker image with this package entry point:

```toml
[project.entry-points."yapd_identity.providers"]
myprovider = "my_package.provider:MyProvider"
```

The factory receives only that source's `config`; reconciliation needs no provider-specific branch. Installed entry points load at startup. Arbitrary module paths from JSON configuration are deliberately unsupported. Capabilities are validated: emitting DNS or observations without declaring them fails collection. Add adapter fixture tests, failure tests and a source-neutral merge test before deployment.

## Passive DHCP and change notifications

See [PASSIVE-DHCP.md](PASSIVE-DHCP.md) for the optional Linux collector and `dhcp` file provider. It emits observations with explicit identity/IP expiration deadlines; cached files do not extend these deadlines. The regular bridge has no capture privileges. The protocol is DHCPv4 over directly visible Ethernet; DHCPv6 and relayed DHCP are outside the initial implementation.

The optional `arp` file provider reads `/var/lib/yapd-dhcp/arp-observations.json` by default (override `source_file`). Enable ARP capture with explicit local IPv4 CIDRs as documented in [PASSIVE-ARP.md](PASSIVE-ARP.md). ARP is observational and can be spoofed. Separate files prevent an ARP sighting from extending DHCP evidence. Providers may include `protocols: ["dhcp", "arp"]` on a device to preserve visible evidence through merging; these labels grant no authority or policy membership.

Optional [Loki change notifications](TRIGGERS.md) have a separate `ChangeNotifier` protocol. Their configurable LogQL selectors are vendor-independent. They trigger full collection/reconciliation and keep periodic sync as fallback; they are not identity providers or policy writers.

Local-only observation refreshes mark reused authoritative snapshots `retained` and preserve their retrieval times. They do not query remote providers or reconcile DNS. The daemon requests full confirmation for conflicting or revoked known bindings; scheduled full sync is independent. [WEBHOOKS.md](WEBHOOKS.md) documents optional authenticated hints and cross-source deduplication.
