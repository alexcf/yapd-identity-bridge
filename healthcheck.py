"""Report source freshness and replication completeness without printing data."""
import datetime
import json
import os
import pathlib
import sys

try:
    data = json.loads((pathlib.Path(os.environ.get('IDENTITY_DATA', '/var/lib/yapd-identity')) / 'status.json').read_text())
    age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(data['at'])).total_seconds()
    limit = max(600, 3 * int(os.environ.get('SYNC_INTERVAL_SECONDS', '300')))
    nodes_ok = all(n['status']=='applied' for n in data['nodes']) and (bool(data['nodes']) or data.get('dns_enabled') is False)
    providers_ok = all(p['status']=='fresh' for p in data.get('providers', []))
    healthy = data['mode'] == 'apply' and nodes_ok and providers_ok and 0 <= age < limit
except Exception:
    healthy = False
sys.exit(0 if healthy else 1)
