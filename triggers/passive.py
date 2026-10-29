"""Watch local observations without polling authoritative network providers."""
import datetime
import hashlib
import json
import pathlib
from providers import registry
from providers.common import timestamp
from providers.dhcp import DHCPProvider
from .webhook import ChangeDeduper

class PassiveWatcher:
    def __init__(self,data,deduper):
        self.data=data
        self.deduper=deduper
        self.sources=[s for s in registry.configured_providers() if s.type=='dhcp']
        self.signatures={}
        self.event_ids={}

    def scan(self):
        local,confirm=False,False
        authority={}
        if (self.data/'inventory.json').exists():
            current=json.loads((self.data/'inventory.json').read_text())
            authority={d['mac']:d['ips'] for d in current['devices'] if d.get('identityKind')=='binding'}
        now=datetime.datetime.now(datetime.timezone.utc)
        for spec in self.sources:
            try:
                value=DHCPProvider(spec.config).collect()
                signature=hashlib.sha256(json.dumps(value.inventory['devices'],sort_keys=True).encode()).hexdigest()
                if self.signatures.get(spec.id)==signature:
                    continue
                self.signatures[spec.id]=signature;local=True
                path=pathlib.Path(spec.config.get('source_file','/var/lib/yapd-dhcp/observations.json'))
                with path.open('rb') as stream:raw=stream.read(2_000_001)
                if len(raw)>2_000_000:raise ValueError('Oversized DHCP source')
                payload=json.loads(raw)
                for event in payload.get('recent_events',[])[-64:]:
                    key=ChangeDeduper.key(event)
                    if key is None or not 0<=(now-timestamp(event['at'])).total_seconds()<15:
                        continue
                    event_id=key+event['at']
                    if self.event_ids.get(key)==event_id:
                        continue
                    self.event_ids[key]=event_id
                    duplicate=self.deduper.duplicate(key)
                    mac,ip,action=event['mac'],event['ip'],event['action']
                    known=authority.get(mac)
                    conflict=(action=='ack' and ((known is not None and ip not in known) or
                        any(ip in ips and owner!=mac for owner,ips in authority.items())))
                    revoked=(action in ('release','decline','nak') and known and (ip in known or action=='nak'))
                    if not duplicate and (conflict or revoked):
                        confirm=True
                if len(self.event_ids)>2048:self.event_ids.clear()
            except (OSError,ValueError,KeyError,TypeError):
                # Full sync reports source failures; YAPD independently expires observations.
                continue
        return local,confirm
