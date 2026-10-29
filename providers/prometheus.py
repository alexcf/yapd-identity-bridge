"""Optional observational provider using Prometheus instant-query results.

Requires an exporter/query with explicit device labels. Never derives a MAC from
an instance label, never treats an info metric's value as online status, and
never emits DNS records or authoritative lease bindings.
"""
import datetime
import ipaddress
import json
import math
import os
import pathlib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from .base import Capabilities, ProviderResult
from .common import MAC, NoRedirect

class PrometheusProvider:
    capabilities = Capabilities(identity=True, observations=True)

    def __init__(self, config=None):
        self.config = config or {}

    def collect(self):
        base = (self.config.get('url') or os.environ['PROMETHEUS_BASE_URL']).rstrip('/')
        parsed = urllib.parse.urlsplit(base)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.scheme not in ('http', 'https'):
            raise ValueError('Invalid Prometheus URL')
        if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1') and not self.config.get('allow_http', False):
            raise ValueError('Prometheus HTTPS required; explicitly opt in to private-network HTTP')
        expression = self.config.get('query') or os.environ['PROMETHEUS_QUERY']
        headers = {'Accept': 'application/json'}
        if self.config.get('token_file'):
            if parsed.scheme != 'https':
                raise ValueError('Bearer credentials require HTTPS')
            token = pathlib.Path(self.config['token_file']).read_text().rstrip('\r\n')
            headers['Authorization'] = 'Bearer ' + token
        context = ssl.create_default_context(cafile=self.config.get('ca_file'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
        request = urllib.request.Request(base + '/api/v1/query?' + urllib.parse.urlencode({'query':expression, 'timeout':'10s'}), headers=headers)
        try:
            with opener.open(request, timeout=15) as response:
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as error:
            raise RuntimeError('Prometheus query failed: HTTP ' + str(error.code)) from None
        if len(raw) > 2_000_000:
            raise ValueError('Prometheus response too large')
        return self.parse(json.loads(raw))

    def parse(self, response, now=None):
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if response.get('status') != 'success' or response.get('data', {}).get('resultType') != 'vector':
            raise ValueError('Prometheus query must return a successful instant vector')
        rows = response['data']['result']
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError('Prometheus series limit exceeded')
        label_map = {'mac':'mac', 'ip':'ip', 'name':'name', 'network':'network', **self.config.get('labels', {})}
        devices, observations, warnings = {}, [], []
        max_age = float(self.config.get('max_sample_age_seconds', 300))
        if not 1 <= max_age <= 900:
            raise ValueError('Invalid maximum sample age')
        for row in rows:
            labels = row.get('metric', {})
            sample = row.get('value', [])
            if len(sample) != 2:
                warnings.append({'kind':'invalid-metric-sample'}); continue
            try:
                value = float(sample[1])
                observed = float(sample[1] if self.config.get('value_is_timestamp', False) else sample[0])
            except (ValueError, TypeError):
                warnings.append({'kind':'invalid-metric-sample'}); continue
            if not math.isfinite(value) or not math.isfinite(observed) or not -60 <= now.timestamp()-observed <= max_age:
                warnings.append({'kind':'stale-or-invalid-metric-sample'}); continue
            address = labels.get(label_map['ip'], '')
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError:
                warnings.append({'kind':'missing-or-invalid-device-ip'}); continue
            mac = labels.get(label_map['mac'], '').upper()
            name = ''.join(c for c in labels.get(label_map['name'], '') if c.isprintable())[:191]
            network = labels.get(label_map['network'], '')[:191]
            active = None
            if self.config.get('active_from_value', False) and not self.config.get('value_is_timestamp', False) and value in (0,1):
                active = value == 1
            observation = {'ips':[address], 'name':name, 'network':network, 'active':active,
                'observedAt':datetime.datetime.fromtimestamp(observed, datetime.timezone.utc).isoformat()}
            if not MAC.fullmatch(mac) or mac in ('00:00:00:00:00:00','FF:FF:FF:FF:FF:FF'):
                observations.append(observation)
                warnings.append({'kind':'metric-without-device-mac'})
                continue
            device = devices.setdefault(mac, {'mac':mac,'ips':[], 'name':name, 'network':network,
                'isStatic':None, 'active':active, 'identityKind':'observation', 'observedAt':observation['observedAt']})
            device['ips'] = sorted(set(device['ips']+[address]))
            if device['name'] != name or device['network'] != network:
                warnings.append({'kind':'conflicting-metric-labels','mac':mac})
                # Do not arbitrarily choose between different metric identities.
                device['name'], device['network'] = '', ''
        owners = {}
        for mac, device in devices.items():
            for ip in device['ips']:
                owners.setdefault(ip, set()).add(mac)
        ambiguous = {ip for ip, macs in owners.items() if len(macs)>1}
        for device in devices.values():
            device['ips'] = [ip for ip in device['ips'] if ip not in ambiguous]
        warnings.extend({'kind':'conflicting-metric-ip','ip':ip} for ip in sorted(ambiguous))
        inventory = {'version':1, 'provider':'Prometheus', 'retrievedAt':now.isoformat(),
                     'devices':sorted(devices.values(),key=lambda x:x['mac'])}
        return ProviderResult(inventory=inventory, observations=observations, warnings=warnings,
                              ambiguous_ips=sorted(ambiguous),
                              stats={'series':len(rows), 'observations_without_mac':len(observations)})
