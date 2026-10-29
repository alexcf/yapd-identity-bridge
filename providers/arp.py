"""Passive Ethernet ARP sender observations. No probing, DNS or policy writes."""
import datetime
import ipaddress
import struct
from .common import MAC
from .dhcp import ObservationStore, DHCPProvider

def decode_arp(frame):
    try:
        if len(frame)<14:
            return None
        offset,kind=14,struct.unpack_from('!H',frame,12)[0]
        for _ in range(2):
            if kind not in (0x8100,0x88a8):
                break
            kind=struct.unpack_from('!H',frame,offset+2)[0];offset+=4
        if kind!=0x0806 or len(frame)<offset+28:
            return None
        hardware,protocol,hlen,plen,operation=struct.unpack_from('!HHBBH',frame,offset)
        if (hardware,protocol,hlen,plen)!=(1,0x0800,6,4) or operation not in (1,2):
            return None
        sender=frame[offset+8:offset+14]
        if sender!=frame[6:12] or sender==bytes(6) or sender[0]&1:
            return None
        ip=ipaddress.IPv4Address(frame[offset+14:offset+18])
        if ip.is_multicast or ip.is_loopback or str(ip)=='255.255.255.255' or (operation==2 and ip.is_unspecified):
            return None
        return {'mac':':'.join(f'{x:02X}' for x in sender),'ip':None if ip.is_unspecified else str(ip),
                'operation':operation}
    except (ValueError,IndexError,struct.error):
        return None

class ARPObservationStore(ObservationStore):
    def __init__(self,cidrs,network='LAN',device_ttl=3600,binding_ttl=300,ignore_macs=(),max_addresses=8):
        super().__init__(network=network,device_ttl=device_ttl,binding_ttl=binding_ttl)
        self.cidrs=[ipaddress.IPv4Network(cidr,strict=True) for cidr in cidrs]
        if not 1<=len(self.cidrs)<=32 or any(n.prefixlen==0 for n in self.cidrs):
            raise ValueError('Explicit local IPv4 CIDRs are required for ARP')
        self.ignore_macs={m.upper() for m in ignore_macs}
        if any(not MAC.fullmatch(m) for m in self.ignore_macs) or not 1<=max_addresses<=32:
            raise ValueError('Invalid ARP attribution limits')
        self.max_addresses=max_addresses

    def ingest(self,event,now):
        if event is None:
            return False
        ip=ipaddress.IPv4Address(event['ip']) if event['ip'] else None
        if ip is not None and not any(ip in n and (n.prefixlen>=31 or ip not in (n.network_address,n.broadcast_address)) for n in self.cidrs):
            return False
        self.expire(now)
        mac=event['mac']
        if mac not in self.devices and len(self.devices)>=self.max_devices:
            return False
        device=self.devices.setdefault(mac,{'mac':mac,'name':'','network':self.network,'ips':[],
            'ipExpiresAt':{},'isStatic':None,'active':None,'identityKind':'observation','protocols':['arp']})
        device['observedAt']=now.isoformat()
        device['expiresAt']=(now+datetime.timedelta(seconds=self.device_ttl)).isoformat()
        suppressed=mac in self.ignore_macs or device.get('arpProxySuspected',False)
        if ip is not None and not suppressed:
            address=str(ip)
            if address not in device['ips'] and len(device['ips'])>=self.max_addresses:
                device['ips'],device['ipExpiresAt']=[],{}
                device['arpProxySuspected']=True
            else:
                device['ips']=sorted(set(device['ips'])|{address})
                device['ipExpiresAt'][address]=(now+datetime.timedelta(seconds=self.binding_ttl)).isoformat()
                self.events.append({'network':self.network,'mac':mac,'ip':address,'action':'arp','at':now.isoformat()})
                self.events=self.events[-64:]
        self.accepted+=1
        return True

    def result(self,now):
        result=super().result(now)
        result.inventory['provider']='Passive ARP'
        result.warnings=[{**w,'kind':'ambiguous-arp-observation'} for w in result.warnings]
        result.warnings.extend({'kind':'arp-concentrator-addresses-suppressed','mac':d['mac']}
            for d in self.devices.values() if d.get('arpProxySuspected'))
        return result

class ARPProvider(DHCPProvider):
    def __init__(self,config):
        super().__init__({'source_file':'/var/lib/yapd-dhcp/arp-observations.json',**config})
