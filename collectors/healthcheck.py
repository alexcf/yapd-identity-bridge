"""Collector heartbeat health; quiet DHCP networks remain healthy."""
import datetime
import json
import os
import pathlib
import sys

try:
    if os.geteuid()==0:
        os.setgroups([])
        os.setgid(int(os.environ.get('DHCP_GID','1000')))
        os.setuid(int(os.environ.get('DHCP_UID','1000')))
    path=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/var/lib/yapd-dhcp/observations.json')
    value=json.loads(path.read_text())
    at=datetime.datetime.fromisoformat(value['inventory']['retrievedAt'])
    age=(datetime.datetime.now(datetime.timezone.utc)-at).total_seconds()
    healthy=0<=age<20 and value['stats']['uid']!=0 and 'collector_config' in value
    if value['stats'].get('arp_enabled'):
        arp=json.loads(path.with_name('arp-observations.json').read_text())
        at=datetime.datetime.fromisoformat(arp['inventory']['retrievedAt'])
        age=(datetime.datetime.now(datetime.timezone.utc)-at).total_seconds()
        healthy=healthy and 0<=age<20 and arp['stats']['uid']!=0
except Exception:
    healthy=False
sys.exit(0 if healthy else 1)
