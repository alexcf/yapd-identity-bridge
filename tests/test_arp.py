import datetime
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch
from providers.arp import decode_arp,ARPObservationStore,ARPProvider
from providers.common import live_device
from providers.base import ProviderSpec
from providers import manager,registry
from bridge import atomic
from triggers.passive import PassiveWatcher
from triggers.webhook import ChangeDeduper

NOW=datetime.datetime.now(datetime.timezone.utc)
MAC='02:11:22:33:44:55'
IP='192.168.50.20'

def frame(ip=IP,mac=MAC,target='192.168.50.1',operation=1,vlan=False):
    sender=bytes.fromhex(mac.replace(':',''))
    header=b'\xff'*6+sender+(b'\x81\x00\x00\x65\x08\x06' if vlan else b'\x08\x06')
    return header+struct.pack('!HHBBH',1,0x0800,6,4,operation)+sender+bytes(map(int,ip.split('.')))+bytes(6)+bytes(map(int,target.split('.')))

class ARPTests(unittest.TestCase):
    def store(self,**options):return ARPObservationStore(['192.168.50.0/24'],network='users',**options)
    def test_request_learns_sender_and_never_requested_target(self):
        store=self.store();store.ingest(decode_arp(frame()),NOW)
        result=store.result(NOW)
        self.assertEqual(result.inventory['devices'][0]['ips'],[IP])
        self.assertNotIn('192.168.50.1',result.inventory['devices'][0]['ips'])
        self.assertIsNone(result.inventory['devices'][0]['active'])
        self.assertIsNone(result.inventory['devices'][0]['isStatic'])
        self.assertFalse(any(result.dns.values()))
    def test_probes_record_only_mac_and_replies_from_zero_are_rejected(self):
        store=self.store();store.ingest(decode_arp(frame(ip='0.0.0.0',target=IP)),NOW)
        self.assertEqual(store.result(NOW).inventory['devices'][0]['ips'],[])
        self.assertIsNone(decode_arp(frame(ip='0.0.0.0',operation=2)))
    def test_gratuitous_reply_and_tagged_frame(self):
        event=decode_arp(frame(target=IP,operation=2,vlan=True))
        self.assertEqual(event['ip'],IP);self.assertNotIn('target',event)
    def test_malformed_hardware_mac_mismatch_and_bad_ips_are_ignored(self):
        for packet in (frame()[:20],frame()[:41],frame(mac='01:11:22:33:44:55'),frame(ip='127.0.0.1'),frame(ip='224.0.0.1')):
            self.assertIsNone(decode_arp(packet))
        packet=bytearray(frame());packet[6]=4
        self.assertIsNone(decode_arp(packet))
        packet=bytearray(frame());packet[14:16]=b'\x00\x06'
        self.assertIsNone(decode_arp(packet))
    def test_only_configured_local_addresses_are_learned(self):
        store=self.store()
        for ip in ('198.51.100.1','192.168.50.0','192.168.50.255'):
            self.assertFalse(store.ingest(decode_arp(frame(ip=ip)),NOW))
        with self.assertRaises(ValueError):ARPObservationStore([])
        with self.assertRaises(ValueError):ARPObservationStore(['0.0.0.0/0'])
    def test_proxy_exclusion_and_multi_ip_concentrator_guard(self):
        store=self.store(ignore_macs=[MAC])
        store.ingest(decode_arp(frame()),NOW)
        self.assertEqual(store.result(NOW).inventory['devices'][0]['ips'],[])
        store=self.store(max_addresses=2)
        for ip in (IP,'192.168.50.21','192.168.50.22'):
            store.ingest(decode_arp(frame(ip=ip)),NOW)
        result=store.result(NOW)
        self.assertEqual(result.inventory['devices'][0]['ips'],[])
        self.assertTrue(result.warnings)
    def test_conflicts_and_expiry_do_not_assert_online_or_static(self):
        store=self.store(binding_ttl=10,device_ttl=30)
        store.ingest(decode_arp(frame()),NOW)
        store.ingest(decode_arp(frame(mac='02:11:22:33:44:66')),NOW)
        result=store.result(NOW)
        self.assertEqual(result.ambiguous_ips,[IP])
        self.assertTrue(all(not d['ips'] for d in result.inventory['devices']))
        self.assertTrue(all(not d['ips'] for d in store.result(NOW+datetime.timedelta(seconds=11)).inventory['devices']))
        self.assertEqual(store.result(NOW+datetime.timedelta(seconds=31)).inventory['devices'],[])
    def test_provider_and_passive_watch_accept_arp_without_router_pull_for_new_device(self):
        store=self.store();store.ingest(decode_arp(frame()),datetime.datetime.now(datetime.timezone.utc))
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);source=root/'arp.json'
            result=store.result(datetime.datetime.now(datetime.timezone.utc)).to_dict();result['recent_events']=store.events
            atomic(source,result)
            provider=ARPProvider({'source_file':str(source)})
            loaded=provider.collect().validate(provider.capabilities)
            self.assertEqual(loaded.inventory['devices'][0]['protocols'],['arp'])
            spec=ProviderSpec('arp','arp',config={'source_file':str(source)})
            with patch.object(registry,'configured_providers',return_value=[spec]):
                watcher=PassiveWatcher(root,ChangeDeduper())
            self.assertEqual(watcher.scan(),(True,False))
    def test_authoritative_binding_wins_and_protocol_provenance_is_preserved(self):
        store=self.store();store.ingest(decode_arp(frame()),NOW);arp=store.result(NOW)
        from providers.base import ProviderResult,Capabilities
        authority=ProviderResult(inventory={**arp.inventory,'provider':'Router','devices':[{**arp.inventory['devices'][0],'ips':['192.168.50.99'],'ipExpiresAt':{'192.168.50.99':(NOW+datetime.timedelta(seconds=300)).isoformat()},'protocols':[]}]})
        status={'status':'fresh','retrievedAt':NOW.isoformat()}
        value,_=manager.merge([(ProviderSpec('router','mikrotik'),Capabilities(binding_authority=True),authority,status),(ProviderSpec('arp','arp'),ARPProvider.capabilities,arp,status)])
        self.assertEqual(value['devices'][0]['ips'],['192.168.50.99'])
        self.assertEqual(value['devices'][0]['protocols'],['arp'])

if __name__=='__main__':unittest.main()
