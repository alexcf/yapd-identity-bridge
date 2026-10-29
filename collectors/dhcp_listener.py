"""Linux DHCPv4 observer. Receives packets; never binds DHCP ports or sends."""
import argparse
import ctypes
import datetime
import json
import os
import pathlib
import signal
import socket
import time
from bridge import atomic
from providers.dhcp import ObservationStore, decode_frame, DHCPProvider
from providers.base import ProviderResult

def capture_socket(interface):
    # ETH_P_IP on an access/VLAN interface; no promiscuous membership request.
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        capture.bind((interface,0))
        # Classic BPF: IPv4 UDP, no fragments, port pair 67/68 in either direction.
        class Filter(ctypes.Structure):
            _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
        class Program(ctypes.Structure):
            _fields_=[('length',ctypes.c_ushort),('instructions',ctypes.POINTER(Filter))]
        instructions=[
            (0x28,0,0,12), (0x15,0,12,0x0800), (0x30,0,0,23), (0x15,0,10,17),
            (0x28,0,0,20), (0x45,8,0,0x3fff), (0xb1,0,0,14), (0x48,0,0,14),
            (0x15,0,2,67), (0x48,0,0,16), (0x15,4,3,68),
            (0x15,0,2,68), (0x48,0,0,16), (0x15,1,0,67),
            (0x06,0,0,0), (0x06,0,0,4096)]
        array=(Filter*len(instructions))(*(Filter(*entry) for entry in instructions))
        capture.setsockopt(socket.SOL_SOCKET,26,bytes(Program(len(instructions),array)))
        capture.setsockopt(socket.SOL_SOCKET,44,1)  # SO_LOCK_FILTER before dropping capture privileges.
        # Ignore irrelevant traffic in the kernel; retain only bounded DHCP frames.
        capture.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,131072)
        capture.settimeout(1)
        return capture
    except Exception:
        capture.close()
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface',required=True)
    parser.add_argument('--output',default='/var/lib/yapd-dhcp/observations.json')
    parser.add_argument('--server',action='append',default=[],help='IPv4 server allowlist; repeat for multiple servers')
    parser.add_argument('--network',default='LAN')
    parser.add_argument('--device-ttl',type=int,default=3600)
    parser.add_argument('--binding-ttl',type=int,default=900)
    parser.add_argument('--duration',type=float,default=0,help='Stop after N seconds; default runs continuously')
    parser.add_argument('--uid',type=int,default=1000)
    parser.add_argument('--gid',type=int,default=1000)
    args=parser.parse_args()
    if not 0<=args.duration<=86400 or args.uid<=0 or args.gid<=0:
        parser.error('Invalid duration or non-root UID/GID')
    store=ObservationStore(args.server,args.network,args.device_ttl,args.binding_ttl)
    path=pathlib.Path(args.output)
    with capture_socket(args.interface) as capture:
        if os.geteuid()==0:
            os.setgroups([]);os.setgid(args.gid);os.setuid(args.uid)
        if os.geteuid()==0:
            raise RuntimeError('Collector must not remain root')
        # Resume only this same interface/server configuration, with original TTLs.
        identity={'interface':args.interface,'servers':sorted(store.servers),'network':args.network,
                  'device_ttl':args.device_ttl,'binding_ttl':args.binding_ttl}
        if path.exists():
            previous=json.loads(path.read_text())
            if previous.get('collector_config')==identity:
                clean={k:v for k,v in previous.items() if k not in ('collector_config','recent_events')}
                value=ProviderResult.from_dict(clean)
                value.validate(DHCPProvider.capabilities,allow_stale=True)
                store.devices={d['mac']:d for d in value.inventory['devices']}
        running=True
        def stop(*_):
            nonlocal running
            running=False
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        started=time.monotonic();last_write=0;received=0
        def publish():
            now=datetime.datetime.now(datetime.timezone.utc)
            value=store.result(now).to_dict()
            value['stats'].update(received_packets=received,uid=os.geteuid())
            value['collector_config']=identity
            value['recent_events']=store.events
            atomic(path,value)
        publish()
        while running and (not args.duration or time.monotonic()-started<args.duration):
            try:
                frame,_=capture.recvfrom(4096)
                received+=1
                store.ingest(decode_frame(frame),datetime.datetime.now(datetime.timezone.utc))
            except socket.timeout:
                pass
            if time.monotonic()-last_write>=5:
                publish();last_write=time.monotonic()
        publish()
        print(json.dumps({'collector':'dhcp','received_packets':received,
            'accepted_packets':store.accepted,'devices':len(store.devices),'uid':os.geteuid()}),flush=True)

if __name__=='__main__':
    main()
