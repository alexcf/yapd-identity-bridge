import datetime
import json
import os
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch

from bridge import atomic
from providers.base import ProviderSpec
from providers.common import live_device
from providers.dhcp import DHCPProvider,ObservationStore,decode_frame
from providers import manager

NOW=datetime.datetime.now(datetime.timezone.utc)
MAC='02:11:22:33:44:55'
IP='192.168.50.20'
SERVER='192.168.50.1'

def address(ip):
    return bytes(map(int,ip.split('.')))

def frame(message=3,mac=MAC,ip='0.0.0.0',name='laptop',lease=300,server=SERVER,extra=b'',vlan=False):
    hardware=bytes.fromhex(mac.replace(':',''))
    reply=message in (2,5,6)
    boot=bytearray(240)
    boot[0:4]=bytes([2 if reply else 1,1,6,0])
    boot[4:8]=b'\x00\x00\x00\x01'
    boot[12:16]=address(ip if message==7 else '0.0.0.0')
    boot[16:20]=address(ip if reply else '0.0.0.0')
    boot[28:34]=hardware
    boot[236:240]=b'\x63\x82\x53\x63'
    options=bytes([53,1,message,12,len(name)])+name.encode()
    if reply:
        options+=bytes([54,4])+address(server)+bytes([51,4])+lease.to_bytes(4,'big')
    if message in (3,4):
        options+=bytes([50,4])+address(IP)
    payload=bytes(boot)+options+extra+b'\xff'
    udp=struct.pack('!HHHH',67 if reply else 68,68 if reply else 67,8+len(payload),0)+payload
    ipv4=bytearray(20)
    ipv4[0]=0x45;ipv4[2:4]=struct.pack('!H',20+len(udp));ipv4[8:10]=bytes([64,17])
    ipv4[12:16]=address(server if reply else '0.0.0.0')
    ipv4[16:20]=address('255.255.255.255')
    ethernet=b'\xff'*6+(bytes.fromhex('021122334499') if reply else hardware)
    ethernet+=b'\x81\x00\x00\x65\x08\x00' if vlan else b'\x08\x00'
    return ethernet+bytes(ipv4)+udp

class PacketTests(unittest.TestCase):
    def test_request_extracts_name_and_mac_but_not_an_assigned_address(self):
        event=decode_frame(frame())
        self.assertEqual(event['mac'],MAC);self.assertEqual(event['name'],'laptop')
        store=ObservationStore([SERVER]);store.ingest(event,NOW)
        self.assertEqual(store.result(NOW).inventory['devices'][0]['ips'],[])

    def test_ack_has_lease_and_vlan_frame_can_be_decoded(self):
        event=decode_frame(frame(5,ip=IP,vlan=True))
        self.assertEqual(event['assignedIP'],IP);self.assertEqual(event['leaseSeconds'],300)

    def test_truncation_options_fragments_and_duplicate_types_are_ignored(self):
        packet=frame()
        for short in (packet[:10],packet[:200],packet[:-2]):
            self.assertIsNone(decode_frame(short))
        fragment=bytearray(packet);fragment[20:22]=b'\x20\x00'
        self.assertIsNone(decode_frame(fragment))
        self.assertIsNone(decode_frame(frame(extra=b'\x35\x01\x03')))
        self.assertIsNone(decode_frame(frame(extra=b'\x34\x01\x01')))
        bad=bytearray(packet);bad[-1:]=b'\x32\xff'
        self.assertIsNone(decode_frame(bad))

    def test_non_dhcp_wrong_mac_and_unsupported_hardware_are_ignored(self):
        packet=bytearray(frame());packet[23]=6
        self.assertIsNone(decode_frame(packet))
        packet=bytearray(frame());packet[6]=4
        self.assertIsNone(decode_frame(packet))
        packet=bytearray(frame());packet[42+1]=6
        self.assertIsNone(decode_frame(packet))

class LifetimeTests(unittest.TestCase):
    def store(self,**options):
        return ObservationStore([SERVER],**options)

    def ack(self,store,mac=MAC,now=NOW,lease=300):
        store.ingest(decode_frame(frame(5,mac=mac,ip=IP,lease=lease)),now)

    def test_ack_only_from_allowlisted_server_and_offers_do_not_assign(self):
        store=self.store()
        self.assertFalse(store.ingest(decode_frame(frame(5,ip=IP,server='192.168.50.99')),NOW))
        store.ingest(decode_frame(frame(2,ip=IP)),NOW)
        self.assertEqual(store.result(NOW).inventory['devices'][0]['ips'],[])
        self.ack(store)
        self.assertEqual(store.result(NOW).inventory['devices'][0]['ips'],[IP])
        self.assertIsNone(store.result(NOW).inventory['devices'][0]['active'])

    def test_requested_ip_and_client_name_do_not_extend_observed_lease(self):
        store=self.store();self.ack(store,lease=20)
        store.ingest(decode_frame(frame()),NOW+datetime.timedelta(seconds=15))
        self.assertEqual(store.result(NOW+datetime.timedelta(seconds=21)).inventory['devices'][0]['ips'],[])

    def test_binding_ttl_caps_large_leases_and_device_eventually_expires(self):
        store=self.store(binding_ttl=10,device_ttl=30);self.ack(store,lease=999999)
        self.assertEqual(store.result(NOW+datetime.timedelta(seconds=11)).inventory['devices'][0]['ips'],[])
        self.assertEqual(store.result(NOW+datetime.timedelta(seconds=31)).inventory['devices'],[])

    def test_release_and_trusted_nak_revoke_only_that_mac(self):
        for message in (4,6,7):
            store=self.store();self.ack(store)
            store.ingest(decode_frame(frame(message,ip=IP)),NOW+datetime.timedelta(seconds=1))
            self.assertEqual(store.result(NOW+datetime.timedelta(seconds=2)).inventory['devices'][0]['ips'],[])

    def test_conflicting_ack_and_rotating_macs_are_separate_and_ambiguous(self):
        store=self.store();self.ack(store);self.ack(store,mac='02:11:22:33:44:66')
        result=store.result(NOW)
        self.assertEqual(len(result.inventory['devices']),2)
        self.assertTrue(all(not d['ips'] for d in result.inventory['devices']))
        self.assertEqual(result.ambiguous_ips,[IP])

    def test_cached_snapshot_keeps_original_expiry_during_partial_failure(self):
        store=self.store(binding_ttl=1);self.ack(store)
        result=store.result(NOW)
        old=result.inventory['devices'][0]
        self.assertEqual(live_device(old,NOW+datetime.timedelta(seconds=2))['ips'],[])

    def test_capture_deadlines_are_preserved_in_core_merge(self):
        store=self.store();self.ack(store)
        value=store.result(NOW)
        spec=ProviderSpec('lan','dhcp')
        merged,_=manager.merge([(spec,DHCPProvider.capabilities,value,{'status':'fresh','retrievedAt':NOW.isoformat()})])
        self.assertEqual(merged['devices'][0]['ipExpiresAt'],value.inventory['devices'][0]['ipExpiresAt'])
        self.assertEqual(merged['devices'][0]['identityKind'],'observation')

    def test_provider_never_emits_dns_and_prunes_stale_file_at_read_time(self):
        store=self.store();self.ack(store)
        old=NOW-datetime.timedelta(hours=2)
        value=store.result(NOW).to_dict()
        for device in value['inventory']['devices']:
            device['expiresAt']=old.isoformat()
        value['collector_config']={'interface':'lan0'}
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'snapshot.json';atomic(path,value)
            result=DHCPProvider({'source_file':str(path)}).collect()
        self.assertEqual(result.inventory['devices'],[])
        self.assertFalse(any(result.dns.values()))

    def test_provider_rejects_missing_deadlines(self):
        store=self.store();self.ack(store)
        value=store.result(NOW).to_dict()
        del value['inventory']['devices'][0]['ipExpiresAt']
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'snapshot.json';atomic(path,value)
            with self.assertRaises(ValueError):DHCPProvider({'source_file':str(path)}).collect()

    def test_merging_two_observers_preserves_each_ips_expiry(self):
        store=self.store();self.ack(store)
        first=store.result(NOW)
        second=store.result(NOW)
        other='192.168.50.21'
        later=NOW+datetime.timedelta(seconds=600)
        second.inventory['devices'][0]['ips']=[other]
        second.inventory['devices'][0]['ipExpiresAt']={other:later.isoformat()}
        sources=[(ProviderSpec(name,'dhcp'),DHCPProvider.capabilities,value,
                  {'status':'fresh','retrievedAt':NOW.isoformat()}) for name,value in [('one',first),('two',second)]]
        merged,_=manager.merge(sources)
        device=merged['devices'][0]
        self.assertEqual(set(device['ipExpiresAt']),{IP,other})
        self.assertEqual(live_device(device,NOW+datetime.timedelta(seconds=400))['ips'],[other])

    def test_no_server_configuration_learns_only_client_observations(self):
        store=ObservationStore()
        self.assertFalse(store.ingest(decode_frame(frame(5,ip=IP)),NOW))
        store.ingest(decode_frame(frame()),NOW)
        self.assertEqual(store.result(NOW).inventory['devices'][0]['ips'],[])

    def test_stopped_collector_cannot_freshen_an_old_snapshot(self):
        store=self.store();self.ack(store)
        value=store.result(NOW).to_dict()
        value['inventory']['retrievedAt']=(NOW-datetime.timedelta(seconds=61)).isoformat()
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'snapshot.json';atomic(path,value)
            with self.assertRaises(ValueError):DHCPProvider({'source_file':str(path)}).collect()

if __name__=='__main__':unittest.main()
