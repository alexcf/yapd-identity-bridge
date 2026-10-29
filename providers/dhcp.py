"""Observational DHCPv4 provider and bounded packet decoder; no DNS writes."""
import datetime
import ipaddress
import json
import pathlib
import struct

from .base import Capabilities, ProviderResult
from .common import live_device, timestamp

def decode_frame(frame):
    """Decode Ethernet/IPv4/UDP/BOOTP; ignore unsupported or malformed traffic."""
    try:
        if len(frame) < 14:
            return None
        offset, kind = 14, struct.unpack_from('!H', frame, 12)[0]
        for _ in range(2):
            if kind not in (0x8100, 0x88a8):
                break
            kind = struct.unpack_from('!H', frame, offset+2)[0]
            offset += 4
        if kind != 0x0800 or len(frame) < offset+20:
            return None
        header = (frame[offset] & 15)*4
        size = struct.unpack_from('!H', frame, offset+2)[0]
        fragment = struct.unpack_from('!H', frame, offset+6)[0]
        if frame[offset] >> 4 != 4 or header < 20 or fragment & 0x3fff or frame[offset+9] != 17:
            return None
        if size < header+8 or offset+size > len(frame):
            return None
        udp = offset+header
        source_port, target_port, udp_size = struct.unpack_from('!HHH', frame, udp)
        if (source_port, target_port) not in ((67,68),(68,67)) or udp_size < 248 or udp_size != size-header:
            return None
        data = frame[udp+8:udp+udp_size]
        if data[0] not in (1,2) or data[1:3] != b'\x01\x06' or data[236:240] != b'\x63\x82\x53\x63':
            return None
        if (source_port == 68) != (data[0] == 1):
            return None
        hardware = data[28:34]
        if hardware == bytes(6) or hardware[0] & 1:
            return None
        # Direct Ethernet clients only. Relayed DHCP is outside the first slice.
        if data[24:28] != bytes(4) or (data[0] == 1 and frame[6:12] != hardware):
            return None
        options, cursor, ended = {}, 240, False
        while cursor < len(data):
            code = data[cursor]; cursor += 1
            if code == 0:
                continue
            if code == 255:
                ended = True; break
            if cursor >= len(data):
                return None
            length = data[cursor]; cursor += 1
            if cursor+length > len(data) or code in options:
                return None
            options[code] = data[cursor:cursor+length]; cursor += length
        if not ended or 52 in options or len(options.get(53,b'')) != 1:
            return None
        for code, length in ((50,4),(51,4),(54,4)):
            if code in options and len(options[code]) != length:
                return None
        message = options[53][0]
        if message not in (1,2,3,4,5,6,7,8) or ((message in (2,5,6)) != (data[0] == 2)):
            return None
        name = options.get(12,b'').decode('ascii',errors='ignore').strip()
        if len(name) > 191 or not name.isprintable():
            name = ''
        return {
            'mac':':'.join(f'{part:02X}' for part in hardware), 'message':message, 'name':name,
            'source':str(ipaddress.IPv4Address(frame[offset+12:offset+16])),
            'server':str(ipaddress.IPv4Address(options[54])) if 54 in options else None,
            'assignedIP':str(ipaddress.IPv4Address(data[16:20])),
            'clientIP':str(ipaddress.IPv4Address(data[12:16])),
            'requestedIP':str(ipaddress.IPv4Address(options[50])) if 50 in options else None,
            'leaseSeconds':int.from_bytes(options[51],'big') if 51 in options else None,
        }
    except (ValueError, IndexError, struct.error):
        return None

class ObservationStore:
    def __init__(self, servers=(), network='LAN', device_ttl=3600, binding_ttl=900, max_devices=2048):
        self.servers = {str(ipaddress.IPv4Address(ip)) for ip in servers}
        if not 1 <= binding_ttl <= 86400 or not 1 <= device_ttl <= 86400 or not 1 <= max_devices <= 10000:
            raise ValueError('Invalid DHCP observation limits')
        if not isinstance(network,str) or len(network)>191:
            raise ValueError('Invalid network label')
        self.network, self.device_ttl, self.binding_ttl = network, device_ttl, binding_ttl
        self.max_devices, self.devices, self.accepted = max_devices, {}, 0
        self.events = []

    def ingest(self, event, now):
        if event is None:
            return False
        reply = event['message'] in (2,5,6)
        if reply and (event['source'] not in self.servers or event['server'] not in self.servers):
            return False
        self.expire(now)
        mac = event['mac']
        if mac not in self.devices and len(self.devices) >= self.max_devices:
            return False
        device = self.devices.setdefault(mac, {'mac':mac,'name':'','ips':[],'ipExpiresAt':{},
            'network':self.network,'isStatic':None,'active':None,'identityKind':'observation'})
        if event['name']:
            device['name'] = event['name']
        device['observedAt'] = now.isoformat()
        device['expiresAt'] = (now+datetime.timedelta(seconds=self.device_ttl)).isoformat()
        if event['message'] == 5 and event['leaseSeconds'] and event['assignedIP'] != '0.0.0.0':
            ip = ipaddress.IPv4Address(event['assignedIP'])
            if not (ip.is_multicast or ip.is_unspecified or ip.is_loopback or str(ip)=='255.255.255.255'):
                device['ips'] = [str(ip)]
                device['ipExpiresAt'] = {str(ip):(now+datetime.timedelta(
                    seconds=min(event['leaseSeconds'],self.binding_ttl))).isoformat()}
        elif event['message'] == 6:
            device['ips'], device['ipExpiresAt'] = [], {}
        elif event['message'] in (4,7):
            address = event['clientIP'] if event['message']==7 else event['requestedIP']
            device['ips'] = [ip for ip in device['ips'] if ip != address]
            device['ipExpiresAt'] = {ip:t for ip,t in device['ipExpiresAt'].items() if ip in device['ips']}
        # DISCOVER/REQUEST/INFORM names never establish an IP or extend its TTL.
        kinds={5:'ack',6:'nak',7:'release',4:'decline'}
        if event['message'] in kinds:
            ip=(event['assignedIP'] if event['message']==5 else
                event['requestedIP'] if event['message']==4 else event['clientIP'])
            if ip is not None:
                self.events.append({'network':self.network,'mac':mac,'ip':ip,
                    'action':kinds[event['message']],'at':now.isoformat()})
                self.events=self.events[-64:]
        self.accepted += 1
        return True

    def expire(self, now):
        self.devices = {mac:live for mac,d in self.devices.items() if (live:=live_device(d,now)) is not None}
        self.events=[e for e in self.events if 0<=(now-timestamp(e['at'])).total_seconds()<60]

    def result(self, now):
        self.expire(now)
        owners = {}
        for device in self.devices.values():
            for ip in device['ips']:
                owners.setdefault(ip,set()).add(device['mac'])
        ambiguous = sorted(ip for ip,macs in owners.items() if len(macs)>1)
        devices = []
        for original in self.devices.values():
            device = {**original, 'ips':[ip for ip in original['ips'] if ip not in ambiguous]}
            device.setdefault('protocols',['dhcp'])
            device['ipExpiresAt'] = {ip:t for ip,t in original['ipExpiresAt'].items() if ip in device['ips']}
            devices.append(device)
        return ProviderResult(inventory={'version':1,'provider':'Passive DHCP',
            'retrievedAt':now.isoformat(),'devices':sorted(devices,key=lambda d:d['mac'])},
            ambiguous_ips=ambiguous, stats={'accepted_packets':self.accepted},
            warnings=[{'kind':'ambiguous-dhcp-observation','ip':ip} for ip in ambiguous])

class DHCPProvider:
    capabilities = Capabilities(identity=True, observations=True)

    def __init__(self, config):
        self.config = config

    def collect(self):
        path = pathlib.Path(self.config.get('source_file','/var/lib/yapd-dhcp/observations.json'))
        with path.open('rb') as stream:
            raw = stream.read(2_000_001)
        if len(raw)>2_000_000:
            raise ValueError('DHCP snapshot too large')
        value = json.loads(raw)
        value.pop('collector_config', None)
        value.pop('recent_events', None)
        # Validate even stale files, then prune per-device and IP deadlines.
        result = ProviderResult.from_dict(value).validate(self.capabilities, allow_stale=True)
        for device in result.inventory['devices']:
            if 'expiresAt' not in device or set(device.get('ipExpiresAt',{})) != set(device['ips']):
                raise ValueError('DHCP observations require finite identity and IP deadlines')
        now = datetime.datetime.now(datetime.timezone.utc)
        devices = [live for d in result.inventory['devices'] if (live:=live_device(d,now)) is not None]
        if (now-timestamp(result.inventory['retrievedAt'])).total_seconds()>60:
            raise ValueError('DHCP collector heartbeat is stale')
        result.inventory = {**result.inventory,'devices':devices}
        return result
