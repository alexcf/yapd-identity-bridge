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
except Exception:
    healthy=False
sys.exit(0 if healthy else 1)
