"""Provider-neutral file interface for collectors outside this project.

Input: the same {inventory, dns, warnings} shape written by bridge previews.
Collectors must supply fresh retrievedAt timestamps from a successful source read.
"""
import ipaddress
import json
import os
import pathlib
import re
import datetime
from .mikrotik import valid_name, MAC, SELF

def load():
    raw = pathlib.Path(os.environ['IDENTITY_SOURCE_FILE']).read_text()
    if len(raw) > 2_000_000:
        raise ValueError('Identity snapshot too large')
    value = json.loads(raw)
    inventory = value['inventory']
    desired = value['dns']
    assert inventory['version'] == 1 and isinstance(inventory['provider'], str) and len(inventory['provider']) <= 64
    age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(inventory['retrievedAt'])).total_seconds()
    if age > 900 or age < -300:
        raise ValueError('Stale or future-dated identity snapshot')
    assert isinstance(inventory['devices'], list) and len(inventory['devices']) <= 10000
    macs, ips = set(), set()
    for item in inventory['devices']:
        assert MAC.fullmatch(item['mac']) and len(item['name']) <= 191
        assert item['mac'] not in macs and isinstance(item['network'], str)
        macs.add(item['mac'])
        for ip in item['ips']:
            ipaddress.ip_address(ip)
            assert ip not in ips
            ips.add(ip)
    for line in desired['hosts']:
        address, name = line.split()
        ipaddress.ip_address(address)
        assert valid_name(name)
    for line in desired['cnameRecords']:
        alias, target = line.split(',')
        assert valid_name(alias) and valid_name(target) and alias != target
    for line in desired['revServers']:
        enabled, prefix, server, domain = line.split(',')
        assert enabled == 'true' and valid_name(domain)
        assert str(ipaddress.ip_network(prefix)) not in ('0.0.0.0/0','::/0')
        assert str(ipaddress.ip_address(server.split('#')[0])) not in SELF
    return desired, inventory, value.get('warnings', [])
