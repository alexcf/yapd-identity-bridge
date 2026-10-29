import datetime
import json
import pathlib
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import bridge
import client
from daemon import SyncSchedule
from providers import registry
from providers.base import Capabilities,ProviderResult,ProviderSpec
from providers.dhcp import DHCPProvider,ObservationStore
from triggers.passive import PassiveWatcher
from triggers.webhook import ChangeDeduper,WebhookTrigger
from test_dhcp import NOW,MAC,IP,SERVER,frame
from providers.dhcp import decode_frame

class RefreshTests(unittest.TestCase):
    def test_local_refresh_retains_authority_without_router_or_pihole_api_calls(self):
        counts={'router':0,'lan':0}
        inventory={'version':1,'provider':'Router','retrievedAt':NOW.isoformat(),'devices':[]}
        class Router:
            capabilities=Capabilities(dns_records=True,binding_authority=True)
            def collect(self):
                counts['router']+=1
                return ProviderResult(inventory=inventory)
        class LAN:
            capabilities=DHCPProvider.capabilities
            def collect(self):
                counts['lan']+=1
                return ProviderResult(inventory={**inventory,'provider':'LAN'})
        specs=[ProviderSpec('router','mikrotik'),ProviderSpec('lan','dhcp')]
        with tempfile.TemporaryDirectory() as tmp,patch.object(bridge,'DATA',pathlib.Path(tmp)), \
             patch.object(registry,'configured_providers',return_value=specs), \
             patch.object(registry,'create',side_effect=lambda spec:Router() if spec.id=='router' else LAN()), \
             patch.object(client,'login') as login,patch.object(client,'api') as api:
            bridge.manager.collect(pathlib.Path(tmp),bridge.atomic)
            bridge.run_local(True)
            self.assertEqual(counts,{'router':1,'lan':2})
            result=json.loads((pathlib.Path(tmp)/'local-status.json').read_text())
            self.assertEqual(result['providers'][0]['status'],'retained')
            self.assertEqual(result['providers'][0]['retrievedAt'],NOW.isoformat())
            self.assertFalse(result['dns_reconciled'])
            login.assert_not_called();api.assert_not_called()

    def test_local_changes_cannot_postpone_pending_authority_or_periodic_sync(self):
        schedule=SyncSchedule(60,debounce=0,minimum=10)
        schedule.synced(0,'scheduled');schedule.notify(1)
        for instant in range(1,10):
            schedule.notify_local(instant)
            self.assertEqual(schedule.due(instant),'local')
            schedule.synced(instant,'local')
        self.assertEqual(schedule.due(10),'notification')
        schedule.synced(10,'notification')
        self.assertEqual(schedule.due(60),'scheduled')

    def test_passive_duplicate_known_ack_does_not_require_router_pull(self):
        self.watch_case([IP],False)

    def test_changed_passive_binding_requires_authority_confirmation(self):
        self.watch_case(['192.168.50.99'],True)

    def watch_case(self,known,confirm):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);source=root/'observations.json'
            store=ObservationStore([SERVER],network='users')
            store.ingest(decode_frame(frame(5,ip=IP)),datetime.datetime.now(datetime.timezone.utc))
            result=store.result(datetime.datetime.now(datetime.timezone.utc)).to_dict()
            result['recent_events']=store.events
            bridge.atomic(source,result)
            bridge.atomic(root/'inventory.json',{'devices':[{'mac':MAC,'ips':known,'identityKind':'binding'}]})
            spec=ProviderSpec('lan','dhcp',config={'source_file':str(source)})
            deduper=ChangeDeduper()
            with patch.object(registry,'configured_providers',return_value=[spec]):
                watcher=PassiveWatcher(root,deduper)
            self.assertEqual(watcher.scan(),(True,confirm))
            self.assertEqual(watcher.scan(),(False,False))
            self.assertTrue(deduper.duplicate(ChangeDeduper.key(store.events[0])))

class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.token='test-bearer-token-which-is-long-enough-123'
        path=pathlib.Path(self.tmp.name)/'token';path.write_text(self.token)
        self.deduper=ChangeDeduper()
        self.receiver=WebhookTrigger({'token_file':str(path),'port':0},self.deduper)
        self.url='http://127.0.0.1:'+str(self.receiver.server.server_port)+'/reconcile'
    def tearDown(self):
        self.receiver.close();self.tmp.cleanup()
    def request(self,value,token=None,headers=None):
        data=json.dumps(value).encode()
        request=urllib.request.Request(self.url,data=data,headers={'Authorization':'Bearer '+(token or self.token),'Content-Type':'application/json',**(headers or {})})
        with urllib.request.urlopen(request,timeout=4) as response:return response.status,json.load(response)
    def test_authorized_hint_returns_202_and_is_idempotent(self):
        self.assertEqual(self.request({'publisher':'generic'})[0],202)
        self.assertTrue(self.receiver.poll());self.assertFalse(self.receiver.poll())
        self.assertEqual(self.request({'publisher':'generic'})[1]['status'],'coalesced')
        self.assertFalse(self.receiver.poll())
    def test_unauthorized_and_oversized_requests_are_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as failure:self.request({},token='incorrect')
        self.assertEqual(failure.exception.code,401)
        with self.assertRaises(urllib.error.HTTPError) as failure:self.request({'big':'x'*20000})
        self.assertEqual(failure.exception.code,413)
        self.assertFalse(self.receiver.poll())
    def test_normalized_event_dedupes_across_lan_loki_and_prometheus_publishers(self):
        event={'network':'users','mac':MAC,'ip':IP,'action':'ack'}
        self.assertFalse(self.deduper.duplicate(ChangeDeduper.key(event)))
        for publisher in ('Loki','Prometheus'):
            self.assertEqual(self.request({**event,'publisher':publisher})[1]['status'],'coalesced')
        self.assertFalse(self.receiver.poll())
    def test_loki_extracted_labels_share_the_passive_event_deduper(self):
        from triggers.loki import LokiTrigger
        event={'network':'users','mac':MAC,'ip':IP,'action':'ack'}
        self.deduper.duplicate(ChangeDeduper.key(event))
        trigger=LokiTrigger({'url':'http://127.0.0.1:3100','query':'{job="any-vendor"}'},self.deduper)
        payload={'status':'success','data':{'resultType':'streams','result':[{'stream':event,'values':[['100','lease confirmed']]}]}}
        self.assertFalse(trigger.consume(payload,0,200))

    def test_dedupe_does_not_merge_networks_actions_or_later_renewals(self):
        event={'network':'users','mac':MAC,'ip':IP,'action':'ack'}
        key=ChangeDeduper.key(event)
        self.assertFalse(self.deduper.duplicate(key,now=1))
        self.assertTrue(self.deduper.duplicate(key,now=2))
        self.assertFalse(self.deduper.duplicate(key,now=30))
        self.assertNotEqual(key,ChangeDeduper.key({**event,'network':'another-site/users'}))
        self.assertNotEqual(key,ChangeDeduper.key({**event,'action':'release'}))

if __name__=='__main__':unittest.main()
