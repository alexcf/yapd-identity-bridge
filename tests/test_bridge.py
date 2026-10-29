import json
import os
import pathlib
import tempfile
import unittest
import datetime
from unittest.mock import patch

from bridge import reconcile_array
import bridge
import client
from providers.mikrotik import compile_snapshot

def lease(mac='AA:BB:CC:DD:EE:01', address='192.168.50.20', name='laptop', **extra):
    return {'mac-address': mac, 'address': address, 'host-name': name,
            'server': 'lan', 'status': 'bound', 'dynamic': 'true', **extra}

class SourceTests(unittest.TestCase):
    def test_static_dns_wins_over_untrusted_dhcp_name(self):
        d, _, _ = compile_snapshot({'leases': [lease(name='server')], 'dns': [
            {'name': 'server', 'type': 'A', 'address': '192.168.50.99'}]})
        self.assertIn('192.168.50.99 server', d['hosts'])
        self.assertNotIn('192.168.50.20 server', d['hosts'])

    def test_dhcp_cannot_shadow_public_domain(self):
        d, _, _ = compile_snapshot({'leases': [lease(name='accounts.example.com')], 'dns': []})
        self.assertEqual(d['hosts'], [])

    def test_expired_dynamic_address_is_not_attributed(self):
        d, inv, _ = compile_snapshot({'leases': [lease(status='waiting')], 'dns': []})
        self.assertEqual(inv['devices'][0]['ips'], [])
        self.assertEqual(d['hosts'], [])

    def test_conflicting_ip_bindings_are_removed_from_inventory(self):
        _, inv, warnings = compile_snapshot({'leases': [lease(), lease(mac='AA:BB:CC:DD:EE:02')], 'dns': []})
        self.assertTrue(all(not x['ips'] for x in inv['devices']))
        self.assertTrue(any(x['kind']=='ambiguous-lease-ip' for x in warnings))

    def test_forwarding_to_loopback_is_rejected(self):
        with self.assertRaises(ValueError):
            compile_snapshot({'leases': [], 'dns': [{'name':'example.test', 'type':'FWD',
                'match-subdomain':'true', 'forward-to':'127.0.0.1'}]})

    def test_malformed_address_rejects_whole_snapshot(self):
        with self.assertRaises(ValueError):
            compile_snapshot({'leases': [], 'dns': [{'name':'server','address':'not-an-ip'}]})

    def test_cname_cycle_rejects_snapshot(self):
        with self.assertRaises(ValueError):
            compile_snapshot({'leases': [], 'dns': [{'name':'one.test','type':'CNAME','cname':'two.test'},
                                                   {'name':'two.test','type':'CNAME','cname':'one.test'}]})

class OwnershipTests(unittest.TestCase):
    def test_existing_identical_record_is_borrowed(self):
        result, owned, _ = reconcile_array('hosts', ['192.168.50.20 laptop'], ['192.168.50.20 laptop'], [])
        self.assertEqual(owned, [])
        result, _, _ = reconcile_array('hosts', result, [], owned)
        self.assertEqual(result, ['192.168.50.20 laptop'])

    def test_stale_owned_record_is_removed_and_manual_record_retained(self):
        result, owned, _ = reconcile_array('hosts', ['192.168.50.20 old','192.168.50.21 manual'], [], ['192.168.50.20 old'])
        self.assertEqual(result, ['192.168.50.21 manual'])
        self.assertEqual(owned, [])

    def test_manual_conflict_wins(self):
        result, owned, conflicts = reconcile_array('hosts', ['192.168.50.21 laptop'], ['192.168.50.20 laptop'], [])
        self.assertEqual(result, ['192.168.50.21 laptop'])
        self.assertTrue(conflicts)
        self.assertEqual(owned, [])

    def test_reconnect_finishes_partially_applied_owned_intent(self):
        # Intent is persisted as old|new before a write. A failed deletion can
        # leave old plus new; retry must still know it owns the old entry.
        old, new = '192.168.50.20 laptop', '192.168.50.22 laptop'
        result, owned, conflicts = reconcile_array('hosts', [old,new], [new], [old,new])
        self.assertEqual(result,[new]); self.assertEqual(owned,[new]); self.assertEqual(conflicts,[])

    def test_multiple_forwarders_for_same_zone_are_retained(self):
        values=['true,192.168.50.0/24,192.168.50.2,example.test','true,192.168.50.0/24,192.168.50.3,example.test']
        result, _, conflicts=reconcile_array('revServers',values,values,[])
        self.assertEqual(result,values);self.assertEqual(conflicts,[])

class ReconciliationTests(unittest.TestCase):
    def test_offline_replica_is_pending_then_converges(self):
        source={'leases':[], 'dns':[{'name':'server.home.arpa','address':'192.168.50.20'}]}
        values={key:{'dns':{'hosts':[],'cnameRecords':[],'upstreams':['192.0.2.53']},
                     'misc':{'revServers':[]}} for key in ('one','two')}
        offline={'two'}
        def api(path, body=None, method=None):
            if path=='/session': return {}
            node=body['sourceInstanceId'] if body else path.split('sourceInstanceId=')[1]
            if node in offline:raise ConnectionError('offline')
            topic=path.split('/')[2].split('?')[0]
            if body:values[node][topic].update(body['config']['config'][topic])
            return {'topic':{'value':dict(values[node][topic])}}
        nodes=[{'id':key,'name':key,'isBaseline':key=='one'} for key in ('one','two')]
        with tempfile.TemporaryDirectory() as tmp, patch.object(bridge,'DATA',pathlib.Path(tmp)), \
             patch.object(bridge.mikrotik,'router_snapshot',return_value=source), \
             patch.object(client,'login'), patch.object(client,'instances',return_value=nodes), patch.object(client,'api',side_effect=api):
            self.assertEqual(bridge.run(True),1)
            status=json.loads((pathlib.Path(tmp)/'status.json').read_text())
            self.assertIn('pending',[n['status'] for n in status['nodes']])
            offline.clear()
            self.assertEqual(bridge.run(True),0)
            self.assertEqual(values['one']['dns']['hosts'],values['two']['dns']['hosts'])
            self.assertEqual(values['one']['dns']['upstreams'],['192.0.2.53'])
            before=(pathlib.Path(tmp)/'inventory.json').read_bytes()
            with patch.object(bridge.mikrotik,'router_snapshot',side_effect=ConnectionError):
                with self.assertRaises(ConnectionError):bridge.run(True)
            self.assertEqual((pathlib.Path(tmp)/'inventory.json').read_bytes(),before)

class JsonProviderTests(unittest.TestCase):
    def test_generic_provider_accepts_current_snapshot(self):
        from providers.jsonfile import load
        value={'inventory':{'version':1,'provider':'Other DHCP','retrievedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'devices':[]},
               'dns':{'hosts':['192.168.50.2 server.home.arpa'],'cnameRecords':[],'revServers':[]}}
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'snapshot.json';p.write_text(json.dumps(value))
            with patch.dict(os.environ,{'IDENTITY_SOURCE_FILE':str(p)}):
                self.assertEqual(load()[1]['provider'],'Other DHCP')

    def test_generic_provider_rejects_stale_snapshot(self):
        from providers.jsonfile import load
        value={'inventory':{'version':1,'provider':'Other DHCP','retrievedAt':'2000-01-01T00:00:00+00:00','devices':[]},
               'dns':{'hosts':[],'cnameRecords':[],'revServers':[]}}
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'snapshot.json';p.write_text(json.dumps(value))
            with patch.dict(os.environ,{'IDENTITY_SOURCE_FILE':str(p)}):
                with self.assertRaises(ValueError):load()

if __name__ == '__main__':
    unittest.main()
