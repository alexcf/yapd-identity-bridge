"""Source-independent validation and configuration helpers."""
import datetime
import ipaddress
import os
import re
import urllib.request

FIELDS = ('hosts', 'cnameRecords', 'revServers')
MAC = re.compile(r'^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$')
NAME = re.compile(r'^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not forward source credentials to a redirected endpoint."""
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None

def valid_name(value):
    if not isinstance(value, str):
        return None
    value = value.rstrip('.').lower()
    if not NAME.fullmatch(value) or '..' in value or any(len(x) > 63 for x in value.split('.')):
        return None
    return value

def empty_dns():
    return {field: [] for field in FIELDS}

def timestamp(value):
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Provider timestamp must include its timezone')
    return result

def validate_inventory(inventory, allow_stale=False):
    if inventory.get('version') != 1 or not isinstance(inventory.get('provider'), str) or len(inventory['provider']) > 64:
        raise ValueError('Invalid inventory version/provider')
    age = (datetime.datetime.now(datetime.timezone.utc) - timestamp(inventory['retrievedAt'])).total_seconds()
    if age < -300 or (not allow_stale and age > 900):
        raise ValueError('Stale or future-dated inventory')
    devices = inventory.get('devices')
    if not isinstance(devices, list) or len(devices) > 10000:
        raise ValueError('Invalid inventory device list')
    macs, ips = set(), set()
    for device in devices:
        if not isinstance(device, dict) or not MAC.fullmatch(device.get('mac', '')) or device['mac'] in macs:
            raise ValueError('Invalid/duplicate device MAC')
        macs.add(device['mac'])
        if not isinstance(device.get('name'), str) or len(device['name']) > 191 or not isinstance(device.get('network'), str) or len(device['network']) > 191:
            raise ValueError('Invalid identity name/network')
        if not isinstance(device.get('ips'), list) or len(device['ips']) > 100:
            raise ValueError('Invalid identity IP list')
        for ip in device['ips']:
            if str(ipaddress.ip_address(ip)) != ip:
                raise ValueError('Identity addresses must use canonical form')
            if ip in ips:
                raise ValueError('Conflicting IP ownership in source inventory')
            ips.add(ip)
        for field in ('active', 'isStatic'):
            if device.get(field) is not None and type(device[field]) is not bool:
                raise ValueError('Invalid identity state')
        if 'expiresAt' in device:
            timestamp(device['expiresAt'])
        deadlines = device.get('ipExpiresAt', {})
        if not isinstance(deadlines, dict) or len(deadlines) > 100 or set(deadlines)-set(device['ips']):
            raise ValueError('Invalid observation IP expiry')
        for deadline in deadlines.values():
            timestamp(deadline)

def live_device(device, now=None):
    """Observation deadlines survive cached snapshots and collector outages."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if device.get('expiresAt') and timestamp(device['expiresAt']) <= now:
        return None
    deadlines = device.get('ipExpiresAt', {})
    ips = [ip for ip in device['ips'] if ip not in deadlines or timestamp(deadlines[ip]) > now]
    result = {**device, 'ips':ips}
    if 'ipExpiresAt' in device:
        result['ipExpiresAt'] = {ip:deadlines[ip] for ip in ips if ip in deadlines}
    return result

def validate_dns(desired, self_addresses=None):
    if not isinstance(desired, dict) or set(desired) != set(FIELDS):
        raise ValueError('Unsupported DNS fields')
    own = set(self_addresses or os.environ.get('DNS_SELF_ADDRESSES', '127.0.0.1,::1').split(','))
    for field in FIELDS:
        if not isinstance(desired[field], list) or len(desired[field]) > 30000:
            raise ValueError('Invalid DNS entry list')
        if any(not isinstance(x, str) or len(x) > 1024 for x in desired[field]):
            raise ValueError('Invalid DNS entry')
    for line in desired['hosts']:
        address, name = line.split()
        ipaddress.ip_address(address)
        if not valid_name(name):
            raise ValueError('Invalid DNS hostname')
    aliases = {}
    for line in desired['cnameRecords']:
        alias, target = line.split(',')
        if not valid_name(alias) or not valid_name(target):
            raise ValueError('Invalid CNAME')
        aliases[alias] = target
    for alias in aliases:
        seen, target = set(), alias
        while target in aliases:
            if target in seen:
                raise ValueError('CNAME cycle')
            seen.add(target)
            target = aliases[target]
    for line in desired['revServers']:
        enabled, prefix, server, domain = line.split(',')
        target, *ports = server.split('#')
        ip = ipaddress.ip_address(target)
        if enabled != 'true' or not valid_name(domain) or str(ipaddress.ip_network(prefix)) in ('0.0.0.0/0', '::/0'):
            raise ValueError('Invalid conditional forwarder')
        if target in own or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError('Unsafe forwarding destination')
        if len(ports) > 1 or (ports and not 1 <= int(ports[0]) <= 65535):
            raise ValueError('Invalid forwarding port')
