"""MikroTik RouterOS REST source provider. GET-only, TLS validation required."""
import base64, collections, datetime, ipaddress, json, os, re, ssl, urllib.request
from client import secret
MAC = re.compile(r'^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$')
NAME = re.compile(r'^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$')
FIELDS = ('hosts', 'cnameRecords', 'revServers')
SUFFIX = os.environ.get('LOCAL_DNS_SUFFIX', 'home.arpa').strip('.')
SELF = set(os.environ.get('DNS_SELF_ADDRESSES', '127.0.0.1,::1').split(','))

def router_snapshot():
    base = os.environ['MIKROTIK_BASE_URL'].rstrip('/')
    if not base.startswith('https://'):
        raise ValueError('RouterOS HTTPS is required')
    context = ssl.create_default_context(cafile=os.environ.get('MIKROTIK_CA_FILE') or None)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    token = base64.b64encode((os.environ['MIKROTIK_USERNAME'] + ':' + secret('MIKROTIK_PASSWORD')).encode()).decode()
    data = {}
    for name, path in [('leases', 'ip/dhcp-server/lease'), ('dns', 'ip/dns/static')]:
        request = urllib.request.Request(base + '/' + path,
                                         headers={'Authorization': 'Basic ' + token}, method='GET')
        with opener.open(request, timeout=15) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('Router snapshot exceeds size limit')
        data[name] = json.loads(raw)
        if not isinstance(data[name], list) or len(data[name]) > 10000:
            raise ValueError('Invalid router inventory')
    return data

def valid_name(value):
    value = value.rstrip('.').lower()
    if not NAME.fullmatch(value) or '..' in value or any(len(x) > 63 for x in value.split('.')):
        return None
    return value

def compile_snapshot(source):
    desired = {field: [] for field in FIELDS}
    warnings = []
    static = collections.defaultdict(set)
    for record in source['dns']:
        if record.get('disabled') == 'true':
            continue
        name = valid_name(record.get('name', ''))
        kind = record.get('type', 'A')
        if not name or record.get('regexp'):
            warnings.append({'kind': 'unsupported-static-record', 'id': record.get('.id')})
            continue
        if kind in ('A', 'AAAA'):
            address = ipaddress.ip_address(record['address'])
            if (kind == 'A') != (address.version == 4):
                raise ValueError('Static DNS record family mismatch')
            entry = f'{address} {name}'
            desired['hosts'].append(entry)
            static[name].add(str(address))
        elif kind == 'CNAME':
            target = valid_name(record.get('cname', ''))
            if not target or target == name:
                raise ValueError('Invalid/cyclic CNAME')
            desired['cnameRecords'].append(f'{name},{target}')
        elif kind == 'FWD' and record.get('match-subdomain') == 'true':
            target = record.get('forward-to', '')
            # Router forward-to uses IP[#port]. Avoid hostname resolution and
            # reject direct forwarding loops into this Pi-hole cluster.
            parts = target.split('#')
            address = str(ipaddress.ip_address(parts[0]))
            if address in SELF or len(parts) > 2:
                raise ValueError('DNS forwarding loop or invalid destination')
            if len(parts) == 2 and not 1 <= int(parts[1]) <= 65535:
                raise ValueError('Invalid DNS forwarding port')
            prefixes = json.loads(os.environ.get('FORWARD_REVERSE_CIDRS', '{}'))
            if name not in prefixes:
                warnings.append({'kind': 'forwarder-needs-reverse-cidr', 'name': name})
                continue
            prefix = str(ipaddress.ip_network(prefixes[name], strict=True))
            if prefix in ('0.0.0.0/0', '::/0'):
                raise ValueError('Catch-all reverse forwarding is not allowed')
            desired['revServers'].append(f'true,{prefix},{target},{name}')
        else:
            warnings.append({'kind': 'unsupported-static-type', 'type': kind, 'name': name})

    devices = {}
    for lease in source['leases']:
        if lease.get('disabled') == 'true':
            continue
        mac = (lease.get('active-mac-address') or lease.get('mac-address', '')).upper()
        if not MAC.fullmatch(mac) or mac in ('00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'):
            warnings.append({'kind': 'invalid-lease-mac'})
            continue
        active = lease.get('status') == 'bound'
        static_lease = lease.get('dynamic') == 'false'
        address = lease.get('active-address') if active else lease.get('address')
        address = address or lease.get('address')
        ips = [str(ipaddress.ip_address(address))] if address and (active or static_lease) else []
        name = (lease.get('host-name') or lease.get('comment') or '').strip()
        name = ''.join(c for c in name if c.isprintable())[:191]
        device = devices.setdefault(mac, {'mac': mac, 'ips': [], 'name': name,
            'network': lease.get('server', ''), 'isStatic': static_lease, 'active': active})
        device['ips'] = sorted(set(device['ips'] + ips))
        device['active'] |= active
        device['isStatic'] &= static_lease
        if not device['name']:
            device['name'] = name

    # Never attribute a reused/conflicting IP to two devices.
    ip_owners = collections.defaultdict(set)
    for mac, device in devices.items():
        for ip in device['ips']:
            ip_owners[ip].add(mac)
    ambiguous_ips = {ip for ip, owners in ip_owners.items() if len(owners) > 1}
    for device in devices.values():
        device['ips'] = [ip for ip in device['ips'] if ip not in ambiguous_ips]
    warnings.extend({'kind': 'ambiguous-lease-ip', 'ip': ip} for ip in sorted(ambiguous_ips))

    dhcp_names = collections.defaultdict(set)
    for device in devices.values():
        name = valid_name(device['name'])
        # DHCP names are untrusted. Only short names or this site's suffix may
        # become DNS records; a lease must never shadow arbitrary public names.
        if not name or ('.' in name and not name.endswith('.' + SUFFIX)):
            continue
        names = [name, name + '.' + SUFFIX] if '.' not in name else [name]
        for hostname in names:
            for ip in device['ips']:
                dhcp_names[hostname].add(ip)
    for name, addresses in dhcp_names.items():
        if name in static:
            continue  # Explicit router DNS wins over a DHCP-supplied hostname.
        if len(addresses) != 1:
            warnings.append({'kind': 'ambiguous-dhcp-name', 'name': name})
            continue
        desired['hosts'].append(f'{next(iter(addresses))} {name}')

    aliases = {line.split(',')[0]: line.split(',')[1] for line in desired['cnameRecords']}
    for alias in aliases:
        seen = set()
        target = alias
        while target in aliases:
            if target in seen:
                raise ValueError('CNAME cycle')
            seen.add(target)
            target = aliases[target]
    desired = {key: sorted(set(values)) for key, values in desired.items()}
    snapshot = {'version': 1, 'retrievedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'provider': 'MikroTik DHCP', 'devices': sorted(devices.values(), key=lambda item: item['mac'])}
    return desired, snapshot, warnings
