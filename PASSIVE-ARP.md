# Passive ARP observations

ARP is an optional input to the existing Linux DHCP collector. It learns from packets already visible on an existing LAN access interface. It sends no probes, enables no promiscuous mode, creates no bridge/VLAN, and needs no router credentials. The regular identity worker remains unprivileged.

## Evidence and limits

Only the ARP **sender** IPv4/MAC is learned, never the address being queried. Ethernet source and sender hardware address must agree; malformed packets and non-Ethernet/IPv4 ARP are ignored. A probe with sender IP `0.0.0.0` supplies only a MAC sighting. Explicit `--arp-cidr` scopes exclude off-subnet, network and broadcast addresses. Gratuitous ARP is supported.

An address observation expires after `--arp-ttl` (default 300 seconds). The MAC sighting expires after `--device-ttl` (default 3600). Heartbeats, cached reads and restarts do not extend either deadline. DHCP and ARP use separate files so one protocol cannot renew the other's evidence. The core and YAPD reader independently prune expired observations. Authoritative bindings retain precedence, including protection against resurrecting expired leases.

ARP can discover devices absent from DHCP, including potential static-IP devices, but cannot prove an address was manually configured. It supplies no hostname, DHCP lease, online/offline certainty, filtering-group membership or DNS record. A quiet or sleeping device eventually disappears from observational inventory. Private/random MACs remain distinct identities. ARP is spoofable and must never authorize access.

Use `--arp-ignore-mac` for gateways/proxies/virtual routers: their MAC sightings remain visible but their address claims are suppressed. An unknown MAC claiming more than eight simultaneous addresses is treated as a possible concentrator; its address claims are cleared and reported. This heuristic cannot reliably detect every proxy. IP conflicts are omitted and reported, not arbitrarily assigned.

Broadcast requests are normally visible throughout one VLAN without promiscuous mode. Other devices' unicast replies require a mirror/SPAN feed. One Users VLAN probe does not observe an IoT VLAN. Deploy a probe on each desired broadcast domain, with separate state directories and network labels. This implementation handles IPv4 ARP only, not IPv6 NDP, DHCPv6 or arbitrary tagged trunk capture. The decoder accepts VLAN headers in fixtures, but the live kernel filter expects an access interface or VLAN subinterface.

## Deployment

1. Follow [PASSIVE-DHCP.md](PASSIVE-DHCP.md) for the collector's private state directory, capabilities and worker mount.
2. Add `--arp --arp-cidr 192.0.2.0/24` to the collector command, substituting the interface's actual local subnet. Repeat `--arp-cidr` for additional local subnets. Add `--arp-ignore-mac` for each known gateway/proxy. Do not use a default route as a capture scope.
3. Add an `arp` entry from [providers.arp.example.json](providers.arp.example.json) to the private provider configuration. Retain existing IDs and DHCP settings. The existing shared directory mount covers both files.
4. Start the collector first. Review `arp-observations.json` and a normal worker preview before enabling publication. No DNS policy change is needed.

For ARP without DHCP, omit `--server` and remove the `dhcp` provider; DHCP requests may still be decoded but ACK addresses are not trusted without an allowlist. The ARP provider never writes DNS, even when another configured source does.

With ARP enabled, the locked kernel socket filter admits ARP plus DHCP traffic only. The socket opens with `NET_RAW`, then the collector drops to a non-root UID/GID with no effective capabilities before decoding. `NET_ADMIN` and privileged mode are unnecessary. Only bounded decoded metadata is persisted, not raw packets or PCAP files. The collector health check covers both file heartbeats.

The daemon watches semantic snapshot changes and refreshes observations locally using retained authoritative caches, without RouterOS/Pi-hole API reads. A conflict with a known authoritative address requests full confirmation; scheduled polling and optional Loki/webhook triggers remain active. Scoped ARP events use the common bounded dedupe ledger and do not masquerade as DHCP ACKs.

## Verification

Packet fixtures cover sender-versus-target attribution, probes, gratuitous ARP, invalid hardware/source mismatches, subnet boundaries, proxy exclusions/concentrators, conflicts and expiry. Integration fixtures cover local refresh without router polling and authoritative precedence. YAPD fixtures verify visible provenance without manufactured query activity. A bounded live capture can use `--duration 45`; do not force renewals or transmit ARP for verification.

References: [ARP (RFC 826)](https://www.rfc-editor.org/rfc/rfc826), [IPv4 address conflict detection (RFC 5227)](https://www.rfc-editor.org/rfc/rfc5227).
