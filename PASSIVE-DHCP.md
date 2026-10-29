# Passive DHCPv4 observations

The optional DHCP provider learns from packets visible on a chosen Linux LAN interface. It uses no router API credentials, sends no DHCP packets, binds no DHCP service ports, and does not configure bridges, VLANs or promiscuous mode.

The separate collector writes a private observation snapshot. The unprivileged `dhcp` provider reads that file and feeds the normal merge and YAPD integration.

The same process can optionally observe ARP for devices that do not use DHCP. See [PASSIVE-ARP.md](PASSIVE-ARP.md); it writes a separate snapshot and requires an additional `arp` provider.

## What it learns

- DISCOVER, REQUEST and INFORM: Ethernet client MAC and optional hostname. Requested IPs never establish an assigned IP.
- ACK: a temporary observed IP, only when packet source and server identifier match the configured server allowlist, with a positive lease duration.
- Visible RELEASE/DECLINE: revoke only that observed client's relevant IP. An allowlisted NAK revokes that observed client's IP.
- Overlapping IP claims are omitted as ambiguous. Private MACs remain separate identities.

Allowlisting reduces accidental ingestion; DHCP identifiers, MACs and hostnames can still be spoofed. These are observations, never authoritative bindings, DNS records, group assignments or permissions. Authoritative providers keep precedence regardless of observation priority.

An IP expires after the smaller of its captured lease duration and `--binding-ttl` (default 900 seconds). Requests cannot extend that deadline. A device expires after `--device-ttl` (default 3600 seconds) without another accepted packet. The collector writes a heartbeat every five seconds without changing actual observation times. Both the bridge and YAPD patch enforce deadlines, including cached snapshots after collection or reconciliation stops.

The provider rejects a collector heartbeat older than 60 seconds, allowing the core to report a cached/unavailable source. Caches retain original timestamps and finite observation deadlines. The collector has its own heartbeat health check. A quiet LAN remains healthy; missing broadcasts do not establish that a device is offline.

## Deployment

Use a Linux host in the same broadcast domain and an existing VLAN access interface or VLAN subinterface. The kernel filter expects Ethernet IPv4 on an access interface, not an arbitrary tagged trunk. Broadcasts need no promiscuous mode. Other hosts' switched unicast renewals/releases normally require a mirror/SPAN feed. IPv6/DHCPv6, relayed DHCP, option overload, FQDN option 81 and fragmented packets are outside this first implementation. Unsupported or malformed packets are ignored.

The separate collector starts with only `NET_RAW`, `SETUID` and `SETGID`. It binds a packet socket to the selected interface, attaches and locks a DHCP-port filter, then drops to a non-root UID/GID before parsing. It requests neither `NET_ADMIN` nor privileged mode. The regular worker retains its dropped capabilities. Only decoded identity metadata is persisted; no raw PCAP or packet payloads are stored.

1. Create `dhcp-state/`, mode 0700, owned by `PUID`/`PGID` (defaults 1000).
2. Set `DHCP_INTERFACE`, `DHCP_SERVER` and optionally `DHCP_NETWORK` in the Compose environment. These select existing network settings.
3. Merge [compose.dhcp.example.yaml](compose.dhcp.example.yaml) into the bridge deployment. Host networking applies only to the collector.
4. Adapt [providers.dhcp.example.json](providers.dhcp.example.json) into private `secrets/providers.json`; set `IDENTITY_PROVIDERS_FILE=/run/secrets/providers.json`. Retain existing source IDs when changing configuration to preserve compatible caches.
5. Start only the collector, review its output, and run the normal bridge preview before applying the provider configuration.

For DHCP observations alone, remove the router entry from the provider file. The `dhcp` provider cannot write DNS, so its worker needs no router or YAPD API credentials. Dashboard authentication still applies. Keep other configured providers when they maintain DNS you intend to retain.

A bounded capture is available with `python -m collectors.dhcp_listener --interface <interface> --server <server-ip> --duration 45`. It requires capture privileges and an output directory writable by the target UID. Use the supplied container configuration for ongoing collection. Repeat `--server` for multiple servers; CLI help lists TTL, network-label and UID/GID options.

The versioned snapshot can also be securely transferred to a bridge on another host. Only the Linux probe needs capture access. Synchronize clocks and preserve source timestamps and deadlines during transport.

## Recovery and verification

Compatible snapshots resume after restart without extending observation lifetimes. Interface, server allowlist, network label and TTL settings are recorded; changing them starts clean observation state. Stopping the collector lets observations expire. Native Pi-hole history and other providers' authoritative bindings are preserved.

Packet fixtures cover requests versus ACKs, server allowlists, malformed/truncated packets, fragments, duplicate/overloaded options, lease caps, releases, NAKs, private MAC changes, conflicts and expiry. TypeScript tests cover expiry while the collector or bridge is stopped. Live verification should not force DHCP renewals or change DHCP configuration.

References: [DHCP](https://www.rfc-editor.org/rfc/rfc2131), [options](https://www.rfc-editor.org/rfc/rfc2132), [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html).

## Local refreshes and correlated notifications

The daemon watches semantic changes to configured passive snapshots. Heartbeat-only writes do not request a reconciliation. Observational updates reuse compatible authoritative caches and preserve their original timestamps; this path makes no RouterOS or Pi-hole API calls. A captured conflicting assignment or revocation of a known binding requests authoritative confirmation. Full polling remains independent. A bounded recent-event ledger supports cross-source deduplication described in [WEBHOOKS.md](WEBHOOKS.md).
