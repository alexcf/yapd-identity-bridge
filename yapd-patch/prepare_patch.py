from pathlib import Path
ROOT=Path(__file__).resolve().parent
import os
BASE=Path(os.environ['YAPD_SOURCE'])/'apps/api/src'
def replace(s,a,b):
 assert s.count(a)==1, 'Pinned upstream source changed: '+a[:90]
 return s.replace(a,b,1)
s=(BASE/'clients/clients.service.ts').read_text()
s=replace(s,'import type { Request } from "express";','import type { Request } from "express";\nimport { readExternalIdentity, mergeExternalClients } from "../integrations/identity-provider";')
s=replace(s,'    const allHwaddrs = [...new Set(snapshots.flatMap((snapshot) => [...snapshot.devicesByHwaddr.keys()]))];','    const identity = readExternalIdentity();\n    const allHwaddrs = [...new Set([...snapshots.flatMap((snapshot) => [...snapshot.devicesByHwaddr.keys()]), ...identity.devices.map(device => device.mac)])];')
s=replace(s,'    const availableTags = await this.loadAvailableTags();\n    const items = this.buildListedClients(snapshots, baseline.id, baselineMetadata.clientsByHwaddr, supportEntries);','    let availableTags = await this.loadAvailableTags();\n    const nativeItems = this.buildListedClients(snapshots, baseline.id, baselineMetadata.clientsByHwaddr, supportEntries);\n    const items = mergeExternalClients(nativeItems, identity.devices, supportEntries, this.toSourceSummary(baseline), identity.stale, identity.provider);\n    availableTags = [...new Set([...availableTags, ...items.flatMap(item => item.tags)])].sort();')
s=replace(s,'    await this.persistSupportEntries(items, supportEntries);','    await this.persistSupportEntries(nativeItems, supportEntries);')
s=replace(s,'      const targetInstances = this.resolveSaveTargets(instances, dto.targetInstanceIds, locale);','      const targetInstances = this.resolveSaveTargets(instances, dto.targetInstanceIds, locale);\n      if (dto.groups !== undefined || dto.comment !== undefined) await this.guardDHCPPolicyTargets(clients, targetInstances, locale);')
start=s.index('  async updateClient(');end=s.index('\n  async syncClients(',start)
part=s[start:end]
part=replace(part,'      const instances = await this.loadManagedInstances(locale);','      const instances = await this.loadManagedInstances(locale);\n      if (dto.groups !== undefined) await this.guardDHCPPolicyTargets([client], instances, locale);')
s=s[:start]+part+s[end:]
helper='''  private async guardDHCPPolicyTargets(clients: string[], instances: ManagedInstanceRecord[], locale: ReturnType<typeof getRequestLocale>) {
    const imported = new Set(readExternalIdentity().devices.map(device => device.mac));
    const selected = clients.filter(client => imported.has(client));
    if (selected.length === 0) return;
    const { snapshots } = await this.prepareDeviceSnapshotsForList(instances, locale);
    const observed = new Set(snapshots.flatMap(snapshot => [...snapshot.devicesByHwaddr.keys()]));
    if (selected.some(client => !observed.has(client))) {
      throw new BadRequestException("This device is known from an external DHCP inventory, not a Pi-hole-observed MAC. Use an IP-based client policy for routed/VLAN devices; a MAC rule cannot reliably match their DNS traffic. This identity import does not assign policies.");
    }
  }

'''
s=replace(s,'  private async loadManagedInstances(',helper+'  private async loadManagedInstances(')
(ROOT/'patched/clients.service.ts').write_text(s)
s=(BASE/'queries/queries.service.ts').read_text()
s=replace(s,'import type { Request } from "express";','import type { Request } from "express";\nimport { readExternalIdentity, mergeExternalAliases } from "../integrations/identity-provider";')
a='''    return new Map(
      [...aliasByIp.entries()].filter((entry): entry is [string, string] => {
        const [, alias] = entry;
        return alias !== null;
      }),
    );'''
b='''    const devices = readExternalIdentity().devices.filter(device => device.ips.some(ip => requestedIps.has(ip)));
    const manual = devices.length ? await this.prisma.clientDevice.findMany({
      where: { hwaddr: { in: devices.map(device => device.mac) }, alias: { not: null } },
      select: { hwaddr: true, alias: true },
    }) : [];
    return mergeExternalAliases(new Map(
      [...aliasByIp.entries()].filter((entry): entry is [string, string] => entry[1] !== null),
    ), devices, new Map(manual.filter(item => Boolean(item.alias)).map(item => [item.hwaddr, item.alias as string])));'''
s=replace(s,a,b)
(ROOT/'patched/queries.service.ts').write_text(s)
print('Prepared version-pinned backend source patches (no runtime monkey patching)')
