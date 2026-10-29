"""Periodic reconciliation with optional, replaceable change notifications."""
import json
import os
import pathlib
import queue
import threading
import time

class SyncSchedule:
    def __init__(self, interval=300, debounce=2, minimum=10):
        self.interval,self.debounce,self.minimum=interval,debounce,minimum
        self.next_periodic=0
        self.last_sync=float('-inf')
        self.pending=None
        self.pending_local=None
        self.last_local=float('-inf')

    def notify(self,now):
        if self.pending is None:
            self.pending=now+self.debounce

    def due(self,now):
        if now>=self.next_periodic:
            return 'scheduled'
        if self.pending is not None and now>=max(self.pending,self.last_sync+self.minimum):
            return 'notification'
        if self.pending_local is not None and now>=max(self.pending_local,self.last_local+1):
            return 'local'
        return None

    def notify_local(self,now):
        if self.pending_local is None:
            self.pending_local=now+self.debounce

    def synced(self,now,reason):
        self.pending_local=None
        self.last_local=now
        if reason=='local':
            return
        self.last_sync=now
        self.pending=None
        if reason=='scheduled':
            self.next_periodic=now+self.interval

def optional_trigger(deduper=None):
    path=os.environ.get('IDENTITY_TRIGGER_FILE')
    if not path:
        return None,{}
    with pathlib.Path(path).open('rb') as stream:
        raw=stream.read(100001)
    if len(raw)>100000:
        raise ValueError('Trigger configuration exceeds limit')
    value=json.loads(raw)
    if value.get('version')!=1 or value.get('type')!='loki' or not isinstance(value.get('config'),dict):
        raise ValueError('Invalid trigger configuration')
    from triggers.loki import LokiTrigger
    config=value['config']
    for field,default,lower,upper in [('poll_seconds',5,1,60),('debounce_seconds',2,0,60),('min_sync_interval_seconds',10,1,300)]:
        item=config.get(field,default)
        if type(item) not in (int,float) or not lower<=item<=upper:
            raise ValueError('Invalid trigger scheduling option')
    return LokiTrigger(config,deduper),config

def optional_webhook(deduper):
    path=os.environ.get('IDENTITY_WEBHOOK_FILE')
    if not path:
        return None
    with pathlib.Path(path).open('rb') as stream:raw=stream.read(100001)
    if len(raw)>100000:raise ValueError('Webhook configuration exceeds limit')
    value=json.loads(raw)
    if value.get('version')!=1 or value.get('type')!='webhook':
        raise ValueError('Invalid webhook configuration')
    from triggers.webhook import WebhookTrigger
    return WebhookTrigger(value['config'],deduper)

def run_forever(sync,interval=300,local_sync=None,data=None):
    from triggers.webhook import ChangeDeduper
    deduper=ChangeDeduper()
    webhook=None;watcher=None
    try:
        webhook=optional_webhook(deduper)
    except Exception as error:
        print(json.dumps({'event':'webhook_disabled','error_type':type(error).__name__}),flush=True)
    if data is not None and local_sync is not None:
        try:
            from triggers.passive import PassiveWatcher
            watcher=PassiveWatcher(data,deduper)
        except Exception as error:
            print(json.dumps({'event':'passive_watch_disabled','error_type':type(error).__name__}),flush=True)
    notifier=None;config={}
    try:
        notifier,config=optional_trigger(deduper)
    except Exception as error:
        print(json.dumps({'event':'trigger_disabled','error_type':type(error).__name__,'fallback':'scheduled_sync'}),flush=True)
    schedule=SyncSchedule(max(60,interval),config.get('debounce_seconds',2),config.get('min_sync_interval_seconds',10))
    next_poll=0
    next_local=0
    poller=None
    results=queue.Queue(maxsize=1)
    def poll():
        try:
            results.put((notifier.poll(),None))
        except Exception as error:
            results.put((False,type(error).__name__))
    while True:
        now=time.monotonic()
        reason=schedule.due(now)
        if reason:
            print(json.dumps({'event':'sync_started','reason':reason}),flush=True)
            try:
                (local_sync if reason=='local' else sync)()
            except Exception as error:
                print(json.dumps({'event':'sync_failed','error_type':type(error).__name__}),flush=True)
                if reason=='local':schedule.notify(time.monotonic())
            schedule.synced(time.monotonic(),reason)
        if webhook and webhook.poll():
            schedule.notify(time.monotonic())
        if watcher and time.monotonic()>=next_local:
            try:
                changed,confirm=watcher.scan()
                if changed:schedule.notify_local(time.monotonic())
                if confirm:schedule.notify(time.monotonic())
            except Exception as error:
                print(json.dumps({'event':'passive_watch_failed','error_type':type(error).__name__}),flush=True)
            next_local=time.monotonic()+2
        # One daemon thread keeps slow HTTP/DNS outside the sync scheduler.
        if poller is not None and not poller.is_alive():
            changed,error_type=results.get_nowait()
            poller=None
            if error_type:
                print(json.dumps({'event':'trigger_unavailable','error_type':error_type,'fallback':'scheduled_sync'}),flush=True)
                next_poll=time.monotonic()+max(30,config.get('poll_seconds',5))
            else:
                if changed:
                    schedule.notify(time.monotonic())
                next_poll=time.monotonic()+config.get('poll_seconds',5)
        if notifier and poller is None and time.monotonic()>=next_poll:
            poller=threading.Thread(target=poll,daemon=True)
            poller.start()
        time.sleep(0.5)
