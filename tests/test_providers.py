import datetime
import json
import os
import pathlib
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import bridge
import client
from providers import manager, registry
from providers.base import Capabilities, ProviderResult, ProviderSpec
from providers.prometheus import PrometheusProvider

NOW = datetime.datetime.now(datetime.timezone.utc)
MAC = 'AA:BB:CC:DD:EE:01'
IP = '192.168.50.20'

def result(mac=MAC, ips=None, name='laptop'):
    return ProviderResult(inventory={'version':1, 'provider':'Fixture', 'retrievedAt':NOW.isoformat(),
        'devices':[{'mac':mac,'ips':[IP] if ips is None else ips, 'name':name,'network':'lan','active':True,'isStatic':False}]})

def source(identity, value=None, authority=True, priority=50, status='fresh'):
    value = value or result()
    return (ProviderSpec(identity,'json',priority), Capabilities(binding_authority=authority), value,
            {'status':status,'retrievedAt':value.inventory['retrievedAt']})

def vector(rows):
    return {'status':'success','data':{'resultType':'vector','result':rows}}

def metric(**labels):
    return {'metric':{'ip':IP,'mac':MAC, **labels}, 'value':[NOW.timestamp(),'1']}

class MergeTests(unittest.TestCase):
    def test_authority_beats_higher_priority_telemetry(self):
        inventory, _ = manager.merge([source('router'), source('metrics',result(mac='AA:BB:CC:DD:EE:02'),False,999)])
        self.assertEqual(inventory['devices'][0]['ips'],[IP])
        self.assertEqual(inventory['devices'][1]['ips'],[])

    def test_expired_lease_cannot_be_resurrected_by_metric(self):
        inventory, _ = manager.merge([source('router',result(ips=[])),source('metrics',authority=False)])
        self.assertEqual(inventory['devices'][0]['ips'],[])
        self.assertEqual(inventory['devices'][0]['identityKind'],'binding')

    def test_equal_priority_conflict_drops_ip_and_priority_resolves_it(self):
        a, b = source('one'), source('two',result(mac='AA:BB:CC:DD:EE:02'))
        inventory, warnings = manager.merge([a,b])
        self.assertTrue(all(not d['ips'] for d in inventory['devices']))
        self.assertIn('ambiguous-provider-ip',[w['kind'] for w in warnings])
        b = source('two',result(mac='AA:BB:CC:DD:EE:02'),priority=60)
        inventory, _ = manager.merge([a,b])
        self.assertEqual(inventory['devices'][1]['ips'],[IP])

    def test_ambiguous_lease_is_not_claimed_by_other_observer(self):
        a = result(ips=[]); a.ambiguous_ips=[IP]
        inventory, _ = manager.merge([source('router',a),source('metrics',result(mac='AA:BB:CC:DD:EE:02'),False)])
        self.assertTrue(all(not d['ips'] for d in inventory['devices']))

    def test_ip_only_metric_can_fill_missing_name_without_creating_identity(self):
        metrics = result(ips=[]); metrics.inventory['devices']=[]
        metrics.observations=[{'ips':[IP],'name':'observed-name'}]
        inventory, _ = manager.merge([source('router',result(name='')),source('metrics',metrics,False)])
        self.assertEqual(len(inventory['devices']),1)
        self.assertEqual(inventory['devices'][0]['name'],'observed-name')

    def test_conflicting_names_do_not_depend_on_source_order(self):
        a,b=source('one',result(name='one')),source('two',result(name='two'))
        self.assertEqual(manager.merge([a,b])[0],manager.merge([b,a])[0])
        self.assertEqual(manager.merge([a,b])[0]['devices'][0]['name'],'')

class CollectionTests(unittest.TestCase):
    def test_undeclared_dns_and_observations_are_rejected(self):
        value=result();value.dns['hosts']=['192.168.50.2 server.home.arpa']
        with self.assertRaises(ValueError):value.validate(Capabilities())
        value=result();value.observations=[{'ips':[IP]}]
        with self.assertRaises(ValueError):value.validate(Capabilities())

    def test_installed_entry_point_uses_the_same_provider_contract(self):
        class Example:
            capabilities=Capabilities()
            def __init__(self,config):pass
            def collect(self):return result()
        class Entry:
            name='futurevendor'
            def load(self):return Example
        with patch.dict(registry._factories,{},clear=True),patch.object(registry,'_plugins_loaded',False), \
             patch.object(registry.importlib.metadata,'entry_points',return_value=[Entry()]) as entries:
            adapter=registry.create(ProviderSpec('future','futurevendor'))
            self.assertEqual(adapter.collect().inventory['devices'][0]['mac'],MAC)
            entries.assert_called_once_with(group='yapd_identity.providers')

    def test_new_registered_provider_needs_no_bridge_changes(self):
        class Example:
            capabilities=Capabilities()
            def __init__(self,config): self.config=config
            def collect(self): return result(name=self.config['name'])
        with patch.dict(registry._factories,{'example':Example}), tempfile.TemporaryDirectory() as tmp:
            value, statuses, dns = manager.collect(pathlib.Path(tmp),bridge.atomic,[ProviderSpec('future','example',config={'name':'future'})])
            self.assertEqual(value.inventory['devices'][0]['name'],'future')
            self.assertFalse(dns);self.assertEqual(statuses[0]['status'],'fresh')

    def test_partial_failure_retains_original_source_timestamp_and_provenance(self):
        one,two=ProviderSpec('one','json'),ProviderSpec('two','json')
        class Adapter:
            capabilities=Capabilities(binding_authority=True)
            def collect(self):return result()
        with tempfile.TemporaryDirectory() as tmp, patch.object(registry,'create',return_value=Adapter()):
            root=pathlib.Path(tmp)
            manager.collect(root,bridge.atomic,[one,two])
            class Offline(Adapter):
                def collect(self): raise ConnectionError()
            with patch.object(registry,'create',side_effect=lambda spec:Offline() if spec.id=='one' else Adapter()):
                value,statuses,_=manager.collect(root,bridge.atomic,[one,two])
            self.assertEqual(statuses[0]['status'],'cached')
            self.assertEqual(statuses[0]['retrievedAt'],NOW.isoformat())
            self.assertTrue(value.inventory['devices'][0]['stale'])
            with patch.object(registry,'create',return_value=Offline()):
                with self.assertRaises(ConnectionError):manager.collect(root,bridge.atomic,[one,two])
            # A changed configuration must never reuse another source's cache.
            with patch.object(registry,'create',side_effect=lambda spec:Offline() if spec.id=='one' else Adapter()):
                with self.assertRaises(ConnectionError):manager.collect(root,bridge.atomic,[ProviderSpec('one','json',config={'source_file':'other'}),two])

    def test_second_dns_writer_is_rejected(self):
        class Adapter:
            capabilities=Capabilities(dns_records=True)
            def collect(self):return result()
        with tempfile.TemporaryDirectory() as tmp,patch.object(registry,'create',return_value=Adapter()):
            with self.assertRaises(ValueError):manager.collect(pathlib.Path(tmp),bridge.atomic,[ProviderSpec('one','json'),ProviderSpec('two','json')])

    def test_metadata_only_provider_cannot_remove_previously_owned_dns(self):
        class Adapter:
            capabilities=Capabilities()
            def collect(self):return result()
        with tempfile.TemporaryDirectory() as tmp,patch.object(bridge,'DATA',pathlib.Path(tmp)), \
             patch.object(registry,'create',return_value=Adapter()),patch.object(client,'login') as login,patch.object(client,'api') as api:
            ownership=pathlib.Path(tmp)/'ownership.json'
            ownership.write_text('{"nodes":{"one":{"hosts":["192.168.50.2 existing"]}}}')
            before=ownership.read_bytes()
            self.assertEqual(bridge.run(True),0)
            self.assertEqual(ownership.read_bytes(),before)
            login.assert_not_called();api.assert_not_called()

    def test_configuration_rejects_unsafe_ids_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'providers.json'
            for providers in ([{'id':'../escape','type':'json'}],[{'id':'one','type':'json'}]*2):
                path.write_text(json.dumps({'version':1,'providers':providers}))
                with patch.dict(os.environ,{'IDENTITY_PROVIDERS_FILE':str(path)}):
                    with self.assertRaises(ValueError):registry.configured_providers()

class PrometheusTests(unittest.TestCase):
    def test_metric_is_observation_not_dhcp_or_dns(self):
        provider=PrometheusProvider()
        value=provider.parse(vector([metric(name='laptop')]),NOW).validate(provider.capabilities)
        device=value.inventory['devices'][0]
        self.assertIsNone(device['isStatic']);self.assertIsNone(device['active'])
        self.assertEqual(device['identityKind'],'observation');self.assertFalse(any(value.dns.values()))
        self.assertFalse(provider.capabilities.binding_authority)

    def test_instance_label_is_not_a_device_identity(self):
        value=PrometheusProvider().parse(vector([metric(mac='',instance='192.168.50.2:9100')]),NOW)
        self.assertEqual(value.inventory['devices'],[])
        self.assertEqual(value.observations[0]['ips'],[IP])

    def test_stale_future_and_nan_samples_are_rejected(self):
        rows=[metric() for _ in range(3)]
        rows[0]['value']=[NOW.timestamp()-1000,'1']
        rows[1]['value']=[NOW.timestamp()+1000,'1']
        rows[2]['value']=[NOW.timestamp(),'NaN']
        self.assertEqual(PrometheusProvider().parse(vector(rows),NOW).inventory['devices'],[])

    def test_timestamp_value_uses_scrape_time_not_evaluation_time(self):
        row=metric();row['value']=[NOW.timestamp(),str(NOW.timestamp()-1000)]
        provider=PrometheusProvider({'value_is_timestamp':True})
        self.assertEqual(provider.parse(vector([row]),NOW).inventory['devices'],[])

    def test_duplicate_mac_ip_ownership_is_not_attributed(self):
        value=PrometheusProvider().parse(vector([metric(),metric(mac='AA:BB:CC:DD:EE:02')]),NOW)
        self.assertTrue(all(not d['ips'] for d in value.inventory['devices']))

    def test_label_mapping_and_explicit_boolean_value(self):
        provider=PrometheusProvider({'labels':{'mac':'device_mac','ip':'address'},'active_from_value':True})
        value=provider.parse(vector([metric(device_mac=MAC,address='2001:db8::1')]),NOW)
        self.assertEqual(value.inventory['devices'][0]['ips'],['2001:db8::1'])
        self.assertTrue(value.inventory['devices'][0]['active'])

    def test_official_instant_query_contract_with_http_fixture(self):
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps(vector([metric()])).encode())
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            provider=PrometheusProvider({'url':'http://127.0.0.1:'+str(server.server_port),'query':'device_info{job="router"}'})
            self.assertEqual(len(provider.collect().inventory['devices']),1)
            request=urllib.parse.urlsplit(requests[0])
            self.assertEqual(request.path,'/api/v1/query')
            self.assertEqual(urllib.parse.parse_qs(request.query)['query'],['device_info{job="router"}'])
        finally:
            server.shutdown();thread.join();server.server_close()

    def test_credentials_cannot_be_sent_over_http(self):
        with self.assertRaises(ValueError):
            PrometheusProvider({'url':'http://127.0.0.1:9090','query':'up','token_file':'unused'}).collect()

    def test_redirect_is_not_followed(self):
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302);self.send_header('Location','/unexpected');self.end_headers()
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with self.assertRaises(RuntimeError):
                PrometheusProvider({'url':'http://127.0.0.1:'+str(server.server_port),'query':'up'}).collect()
            self.assertEqual(len(requests),1)
        finally:
            server.shutdown();thread.join();server.server_close()

if __name__=='__main__':unittest.main()
