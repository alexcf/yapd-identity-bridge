import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import type { ClientListItem, ClientsMutationInstanceSource } from "../clients/clients.types";

export type IdentityDevice = {
  mac: string;
  ips: string[];
  name: string;
  network: string;
  isStatic: boolean;
  active: boolean;
};
type Snapshot = { version: number; retrievedAt: string; provider: string; devices: IdentityDevice[] };
type Support = { alias: string | null; tags: string[] };
let lastGood: Snapshot = { version: 1, retrievedAt: "1970-01-01T00:00:00Z", provider: "External DHCP", devices: [] };

export function readExternalIdentity(): Snapshot & { stale: boolean } {
  const path = process.env.YAPD_IDENTITY_FILE;
  if (!path) return { ...lastGood, devices: [], stale: true };
  try {
    const raw = readFileSync(path, "utf8");
    if (raw.length > 2_000_000) throw new Error("Identity snapshot too large");
    const value = JSON.parse(raw) as Snapshot;
    if (value.version !== 1 || typeof value.provider !== "string" || value.provider.length > 64 || !Array.isArray(value.devices) || value.devices.length > 10000 ||
        !Number.isFinite(Date.parse(value.retrievedAt))) throw new Error("Invalid identity snapshot");
    const macs = new Set<string>();
    const ips = new Set<string>();
    for (const device of value.devices) {
      if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(device.mac) || macs.has(device.mac) ||
          typeof device.name !== "string" || device.name.length > 191 ||
          typeof device.network !== "string" || !Array.isArray(device.ips) ||
          device.ips.some(ip => !isIP(ip) || ips.has(ip))) throw new Error("Ambiguous identity snapshot");
      macs.add(device.mac);
      device.ips.forEach(ip => ips.add(ip));
    }
    lastGood = value;
  } catch {
    // Atomic writer retains its previous snapshot on source failure. Keep the
    // last validated in-process copy too; never make DNS availability depend on it.
  }
  return { ...lastGood, stale: Date.now() - Date.parse(lastGood.retrievedAt) > 15 * 60_000 };
}

export function mergeExternalClients(
  observed: ClientListItem[], devices: IdentityDevice[], support: Map<string, Support>,
  baseline: ClientsMutationInstanceSource, stale: boolean, provider = "External DHCP",
): ClientListItem[] {
  const owners = new Map(devices.flatMap(device => device.ips.map(ip => [ip, device.mac] as const)));
  const rows = new Map(observed.map(item => [item.hwaddr, {
    ...item,
    // A routed IP seen under the gateway's MAC must not also be attributed to
    // that gateway when DHCP provides the actual device binding.
    ips: item.ips.filter(ip => !owners.has(ip) || owners.get(ip) === item.hwaddr),
  }]));
  for (const device of devices) {
    const native = rows.get(device.mac);
    const manual = support.get(device.mac);
    const tags = [...new Set([...(manual?.tags ?? native?.tags ?? []), provider,
      device.isStatic ? "DHCP reservation" : "Dynamic lease",
      ...(!native ? ["Activity not correlated", "Policy not correlated"] : []), ...(stale ? ["DHCP data stale"] : [])])];
    rows.set(device.mac, {
      hwaddr: device.mac,
      alias: manual?.alias || native?.alias || device.name || null,
      macVendor: native?.macVendor ?? null,
      ips: [...new Set([...device.ips, ...(native?.ips ?? [])])],
      tags,
      instance: native?.instance ?? { ...baseline, instanceName: provider + " inventory" },
      visibleInInstances: native?.visibleInInstances ?? [],
      instanceDetails: native?.instanceDetails ?? [],
      firstSeen: native?.firstSeen ?? null,
      lastQuery: native?.lastQuery ?? null,
      numQueries: native?.numQueries ?? 0,
      comment: native?.comment ?? `DHCP server: ${device.network}; ${device.active ? "bound" : "not bound"}`,
      groupIds: native?.groupIds ?? [],
      groupNames: native?.groupNames ?? [],
    });
  }
  return [...rows.values()];
}

export function mergeExternalAliases(
  aliases: Map<string, string>, devices: IdentityDevice[], manual: Map<string, string>,
): Map<string, string> {
  for (const device of devices) {
    const name = manual.get(device.mac) || device.name;
    if (name) device.ips.forEach(ip => aliases.set(ip, name));
  }
  return aliases;
}
