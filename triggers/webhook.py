"""Authenticated generic refresh hints. Request data never becomes inventory."""
import collections
import hashlib
import hmac
import http.server
import ipaddress
import json
import pathlib
import threading
import time

class ChangeDeduper:
    def __init__(self,window=15):
        self.window=window
        self.seen=collections.OrderedDict()
        self.lock=threading.Lock()

    @staticmethod
    def key(value):
        try:
            network=value['network'];mac=value['mac'].upper();action=value['action']
            from providers.common import MAC
            if not isinstance(network,str) or not network or len(network)>191 or not MAC.fullmatch(mac):
                return None
            if action not in ('ack','release','decline','nak'):
                return None
            ip=str(ipaddress.IPv4Address(value['ip']))
            return json.dumps([network,mac,ip,action])
        except (KeyError,ValueError,TypeError,AttributeError):
            return None

    def duplicate(self,key,now=None):
        now=time.monotonic() if now is None else now
        with self.lock:
            previous=self.seen.pop(key,None)
            self.seen[key]=now
            while len(self.seen)>2048:
                self.seen.popitem(last=False)
            return previous is not None and now-previous<self.window

class WebhookTrigger:
    def __init__(self,config,deduper=None):
        self.config=config
        self.deduper=deduper or ChangeDeduper()
        self.pending=threading.Event()
        self.pending_lock=threading.Lock()
        token=pathlib.Path(config['token_file']).read_text().rstrip('\r\n')
        if len(token)<32 or not token.isascii() or not token.isprintable():
            raise ValueError('Webhook token must contain at least 32 printable ASCII characters')
        outer=self
        class Handler(http.server.BaseHTTPRequestHandler):
            server_version='IdentityBridge'
            def setup(self):
                super().setup()
                self.connection.settimeout(3)
            def log_message(self,*_):
                pass
            def reply(self,status,value):
                raw=json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)))
                self.send_header('Cache-Control','no-store')
                self.end_headers();self.wfile.write(raw)
            def do_POST(self):
                if self.path!='/reconcile':
                    self.reply(404,{'error':'not_found'});return
                supplied=self.headers.get('Authorization','').encode()
                if not hmac.compare_digest(supplied,('Bearer '+token).encode()):
                    self.reply(401,{'error':'unauthorized'});return
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if self.headers.get('Transfer-Encoding') or not 0<=size<=16384:
                        self.reply(413,{'error':'request_too_large'});return
                    raw=self.rfile.read(size)
                    if len(raw)!=size:
                        self.reply(400,{'error':'incomplete_request'});return
                    value=json.loads(raw) if raw else {}
                    if not isinstance(value,dict):
                        raise ValueError()
                except (ValueError,UnicodeDecodeError):
                    self.reply(400,{'error':'invalid_json'});return
                identifier=self.headers.get('Idempotency-Key','')
                if len(identifier)>256:
                    self.reply(400,{'error':'invalid_idempotency_key'});return
                # Explicit normalized events can dedupe across LAN and publishers.
                key=ChangeDeduper.key(value)
                if key is None:
                    key='request:'+identifier if identifier else 'body:'+hashlib.sha256(
                        json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                duplicate=outer.deduper.duplicate(key)
                if not duplicate:
                    with outer.pending_lock:
                        outer.pending.set()
                self.reply(202,{'status':'coalesced' if duplicate else 'queued'})
        host=config.get('host','127.0.0.1')
        port=config.get('port',8092)
        if type(port) is not int or not 0<=port<=65535:
            raise ValueError('Invalid webhook port')
        self.server=http.server.HTTPServer((host,port),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def poll(self):
        with self.pending_lock:
            changed=self.pending.is_set()
            self.pending.clear()
            return changed

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=4)
