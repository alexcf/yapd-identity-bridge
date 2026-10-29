"""Portable LogQL change notifier, independent of DHCP vendor/message syntax."""
import collections
import hashlib
import json
import pathlib
import ssl
import time
import urllib.parse
import urllib.request
from providers.common import NoRedirect
from .webhook import ChangeDeduper

class LokiTrigger:
    def __init__(self, config, deduper=None):
        self.config = config
        self.deduper=deduper or ChangeDeduper()
        self.url = config['url'].rstrip('/')
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid Loki URL')
        if parsed.scheme=='http' and parsed.hostname not in ('localhost','127.0.0.1','::1') and config.get('allow_http') is not True:
            raise ValueError('Loki HTTPS required; private HTTP needs explicit opt-in')
        self.query = config['query']
        if not isinstance(self.query,str) or not 1 <= len(self.query) <= 4096:
            raise ValueError('An explicit LogQL selector is required')
        self.headers={'Accept':'application/json'}
        if config.get('token_file'):
            if parsed.scheme!='https':
                raise ValueError('Loki bearer credentials require HTTPS')
            self.headers['Authorization']='Bearer '+pathlib.Path(config['token_file']).read_text().rstrip('\r\n')
        if config.get('tenant_id'):
            tenant=config['tenant_id']
            if not isinstance(tenant,str) or not tenant or len(tenant)>150 or not tenant.isprintable():
                raise ValueError('Invalid Loki tenant')
            self.headers['X-Scope-OrgID']=tenant
        ctx=ssl.create_default_context(cafile=config.get('ca_file'))
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),NoRedirect())
        # A full sync runs at startup; avoid replaying old events as new changes.
        self.cursor=time.time_ns()
        self.seen=collections.OrderedDict()

    def poll(self):
        end=time.time_ns()
        start=max(0,self.cursor-10_000_000_000)
        params=urllib.parse.urlencode({'query':self.query,'start':start,'end':end,'direction':'forward','limit':1000})
        request=urllib.request.Request(self.url+'/loki/api/v1/query_range?'+params,headers=self.headers)
        with self.opener.open(request,timeout=5) as response:
            raw=response.read(2_000_001)
        if len(raw)>2_000_000:
            raise ValueError('Loki response exceeds limit')
        return self.consume(json.loads(raw),start,end)

    def consume(self, payload, start, end):
        if payload.get('status')!='success' or payload.get('data',{}).get('resultType')!='streams':
            raise ValueError('Loki trigger requires log streams, not metric results')
        streams=payload['data']['result']
        if not isinstance(streams,list) or len(streams)>1000:
            raise ValueError('Invalid Loki streams')
        keys=[];events={};rows=0
        for stream in streams:
            labels=json.dumps(stream.get('stream',{}),sort_keys=True)
            for entry in stream['values']:
                rows+=1
                if rows>1000 or not isinstance(entry,list) or len(entry)<2 or not isinstance(entry[1],str) or len(entry[1])>65536:
                    raise ValueError('Invalid Loki log entries')
                instant=int(entry[0])
                if not start<=instant<=end:
                    raise ValueError('Loki returned an out-of-window event')
                key=hashlib.sha256((str(instant)+'\0'+labels+'\0'+entry[1]).encode()).hexdigest()
                keys.append(key)
                fields=stream.get('stream',{})
                action=fields.get('action')
                events[key]=ChangeDeduper.key({'network':fields.get('network',self.config.get('event_network')),
                    'mac':fields.get('mac'),'ip':fields.get('ip'),
                    'action':self.config.get('action_map',{}).get(action,action)})
        changed=False
        for key in keys:
            if key not in self.seen:
                event=events[key]
                if event is None or not self.deduper.duplicate(event):
                    changed=True
        for key in keys:
            self.seen[key]=None
        while len(self.seen)>4096:
            self.seen.popitem(last=False)
        # Limit overflow is harmless for refresh hints: one event causes a full sync.
        self.cursor=end
        return changed
