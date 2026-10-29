"""Capability-aware collection and deterministic identity merging."""
import dataclasses
import datetime
import hashlib
import json
from . import registry
from .common import empty_dns, timestamp, validate_inventory, validate_dns
from .base import ProviderResult

def collect(data, atomic, specs=None):
    specs = specs if specs is not None else registry.configured_providers()
    sources, statuses, failures = [], [], []
    dns_sources = 0
    for spec in specs:
        adapter = registry.create(spec)
        caps = adapter.capabilities
        dns_sources += int(caps.dns_records)
        if dns_sources > 1:
            raise ValueError('Configure at most one DNS-writing provider')
        fingerprint = hashlib.sha256(json.dumps({'type':spec.type, 'config':spec.config,
            'capabilities':dataclasses.asdict(caps)}, sort_keys=True).encode()).hexdigest()
        cache_path = data / 'providers' / (spec.id + '.json')
        status = {'id':spec.id, 'type':spec.type, 'capabilities':dataclasses.asdict(caps)}
        try:
            result = adapter.collect().validate(caps)
            atomic(cache_path, {'fingerprint':fingerprint, 'result':result.to_dict()})
            status['status'] = 'fresh'
        except Exception as error:
            failures.append(error)
            status.update(status='cached', error_type=type(error).__name__)
            try:
                cached = json.loads(cache_path.read_text())
                if cached['fingerprint'] != fingerprint:
                    raise ValueError('Provider configuration changed')
                result = ProviderResult.from_dict(cached['result']).validate(caps, allow_stale=True)
            except Exception:
                if caps.binding_authority or caps.dns_records:
                    raise error  # Preserve deployed state when an authority has no cache.
                status['status'] = 'unavailable'
                statuses.append(status)
                continue
        status['retrievedAt'] = result.inventory['retrievedAt']
        statuses.append(status)
        sources.append((spec, caps, result, status))
    # Do not re-publish or freshen the last good inventory on total source loss.
    if failures and not any(s['status'] == 'fresh' for s in statuses):
        raise failures[0]
    inventory, warnings = merge(sources)
    desired = next((r.dns for _, caps, r, _ in sources if caps.dns_records), empty_dns())
    validate_inventory(inventory, allow_stale=True)
    validate_dns(desired)
    return ProviderResult(inventory=inventory, dns=desired, warnings=warnings,
        stats={key:sum(r.stats.get(key, 0) for _,_,r,_ in sources) for key in ('leases','static_dns_records')}), statuses, bool(dns_sources)

def merge(sources):
    by_mac, warnings = {}, []
    ambiguous_authority_ips = {ip for _, caps, result, _ in sources if caps.binding_authority for ip in result.ambiguous_ips}
    for spec, caps, result, status in sources:
        warnings.extend({**w, 'source':spec.id} for w in result.warnings)
        for device in result.inventory['devices']:
            by_mac.setdefault(device['mac'], []).append((spec, caps, device, status))
    devices, ip_claims = [], {}
    for mac, candidates in sorted(by_mac.items()):
        authoritative = [c for c in candidates if c[1].binding_authority]
        ranked = sorted(authoritative or candidates, key=lambda c:(-c[0].priority, c[0].id))
        preferred = ranked[0]
        spec, caps, base, status = preferred
        top = [c for c in ranked if c[0].priority == spec.priority]
        device = {**base, 'ips':sorted({ip for c in top for ip in c[2]['ips']}),
            'identityKind':'binding' if authoritative else 'observation',
            'retrievedAt':min((c[3]['retrievedAt'] for c in top), key=timestamp),
            'stale':any(c[3]['status'] != 'fresh' for c in top),
            'sources':[{'id':c[0].id, 'type':c[0].type, 'retrievedAt':c[3]['retrievedAt'],
                        'status':c[3]['status']} for c in sorted(candidates,key=lambda c:c[0].id)]}
        for field in ('name', 'network'):
            values = {c[2][field] for c in top if c[2][field]}
            device[field] = next(iter(values)) if len(values) == 1 else ''
            if len(values) > 1:
                warnings.append({'kind':'conflicting-identity-label','mac':mac,'field':field})
        if not authoritative:
            device['isStatic'] = None
        devices.append(device)
        for ip in device['ips']:
            # Binding authority always outranks metric observations, regardless of priority.
            ip_claims.setdefault(ip, []).append((bool(authoritative), spec.priority, mac))
    owners = {}
    for ip, claims in ip_claims.items():
        if ip in ambiguous_authority_ips:
            continue
        rank = max((authority, priority) for authority, priority, _ in claims)
        winners = {mac for authority, priority, mac in claims if (authority, priority) == rank}
        if len(winners) == 1:
            owners[ip] = winners.pop()
        else:
            warnings.append({'kind':'ambiguous-provider-ip','ip':ip})
    for device in devices:
        device['ips'] = [ip for ip in device['ips'] if owners.get(ip) == device['mac']]
    # IP-only telemetry may fill a missing display name for an existing binding.
    # It cannot create a MAC, new binding, or DNS record.
    by_owner = {d['mac']:d for d in devices}
    observed_names = {}
    for spec, _, result, _ in sources:
        for observation in result.observations:
            for ip in observation.get('ips', []):
                owner = owners.get(ip)
                if owner and observation.get('name'):
                    observed_names.setdefault(owner, set()).add(observation['name'])
    for mac, names in observed_names.items():
        if not by_owner[mac]['name'] and len(names) == 1:
            by_owner[mac]['name'] = next(iter(names))
    now = datetime.datetime.now(datetime.timezone.utc)
    labels = sorted({r.inventory['provider'] for _,_,r,_ in sources})
    dates = [r.inventory['retrievedAt'] for _,caps,r,_ in sources if caps.binding_authority]
    retrieved = min(dates or [r.inventory['retrievedAt'] for _,_,r,_ in sources] or [now.isoformat()], key=timestamp)
    return {'version':1, 'provider':labels[0] if len(labels)==1 else 'External identity',
            'retrievedAt':retrieved, 'devices':devices}, warnings
