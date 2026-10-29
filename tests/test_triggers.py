import datetime
import json
import os
import pathlib
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler,HTTPServer
from unittest.mock import patch
from daemon import SyncSchedule,optional_trigger,run_forever
from triggers.loki import LokiTrigger

def stream(message='vendor-independent DHCP event',instant=100):
    return {'status':'success','data':{'resultType':'streams','result':[
        {'stream':{'job':'router-logs'},'values':[[str(instant),message]]}]}}

class ScheduleTests(unittest.TestCase):
    def test_notifications_are_optional_and_periodic_sync_remains_due(self):
        schedule=SyncSchedule(interval=60)
        self.assertEqual(schedule.due(0),'scheduled')
        schedule.synced(0,'scheduled')
        self.assertIsNone(schedule.due(59))
        self.assertEqual(schedule.due(60),'scheduled')

    def test_bursts_are_debounced_and_minimum_interval_does_not_delay_periodic_sync(self):
        schedule=SyncSchedule(interval=60,debounce=2,minimum=10)
        schedule.synced(0,'scheduled')
        for instant in (1,2,3):schedule.notify(instant)
        self.assertIsNone(schedule.due(9))
        self.assertEqual(schedule.due(10),'notification')
        schedule.synced(10,'notification')
        self.assertEqual(schedule.due(60),'scheduled')
        schedule.notify(59)
        self.assertEqual(schedule.due(60),'scheduled')

    def test_invalid_optional_configuration_falls_back_to_sync(self):
        with patch('daemon.optional_trigger',side_effect=ValueError),patch('daemon.time.monotonic',return_value=0), \
             patch('daemon.time.sleep',side_effect=KeyboardInterrupt):
            from unittest.mock import Mock
            sync=Mock()
            with self.assertRaises(KeyboardInterrupt):run_forever(sync,60)
            sync.assert_called_once()

    def test_trigger_runtime_failure_does_not_stop_scheduled_sync(self):
        class Offline:
            def poll(self):raise ConnectionError()
        clock=[0]
        calls=[]
        def advance(_):
            clock[0]+=60
            if clock[0]>120:raise KeyboardInterrupt()
        with patch('daemon.optional_trigger',return_value=(Offline(),{})), \
             patch('daemon.time.monotonic',side_effect=lambda:clock[0]),patch('daemon.time.sleep',side_effect=advance):
            with self.assertRaises(KeyboardInterrupt):run_forever(lambda:calls.append(clock[0]),60)
        self.assertEqual(calls,[0,60,120])

    def test_no_config_means_no_loki_dependency(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(optional_trigger(),(None,{}))

    def test_hung_notifier_cannot_block_periodic_sync_or_spawn_more_pollers(self):
        release=threading.Event()
        class Hung:
            def poll(self):release.wait(5);return False
        clock=[0];calls=[]
        def advance(_):
            clock[0]+=60
            if clock[0]>120:raise KeyboardInterrupt()
        try:
            with patch('daemon.optional_trigger',return_value=(Hung(),{})), \
                 patch('daemon.time.monotonic',side_effect=lambda:clock[0]),patch('daemon.time.sleep',side_effect=advance):
                with self.assertRaises(KeyboardInterrupt):run_forever(lambda:calls.append(clock[0]),60)
            self.assertEqual(calls,[0,60,120])
        finally:release.set()

class LokiTests(unittest.TestCase):
    def trigger(self):
        return LokiTrigger({'url':'http://127.0.0.1:3100','query':'{job="router-logs"}'})

    def test_vendor_messages_are_only_generic_change_hints(self):
        for text in ('routeros users-dhcp assigned address','dnsmasq-dhcp DHCPACK','unifi lease assigned','Windows DHCP lease event'):
            trigger=self.trigger()
            self.assertTrue(trigger.consume(stream(text),0,200))
            self.assertFalse(trigger.consume(stream(text),0,200))

    def test_late_arrivals_and_same_timestamp_new_messages_are_detected(self):
        trigger=self.trigger()
        trigger.consume(stream('one'),0,200)
        self.assertTrue(trigger.consume(stream('two'),0,200))
        self.assertTrue(trigger.consume(stream('late',90),0,200))

    def test_metric_or_out_of_window_results_are_rejected(self):
        trigger=self.trigger()
        with self.assertRaises(ValueError):trigger.consume({'status':'success','data':{'resultType':'vector','result':[]}},0,200)
        with self.assertRaises(ValueError):trigger.consume(stream(instant=999),0,200)

    def test_http_fixture_matches_loki_query_contract(self):
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200);self.end_headers()
                instant=int(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)['end'][0])-1
                self.wfile.write(json.dumps(stream(instant=instant)).encode())
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            trigger=LokiTrigger({'url':'http://127.0.0.1:'+str(server.server_port),'query':'{job="different-vendor"}'})
            self.assertTrue(trigger.poll())
            parsed=urllib.parse.urlsplit(requests[0])
            self.assertEqual(parsed.path,'/loki/api/v1/query_range')
            self.assertEqual(urllib.parse.parse_qs(parsed.query)['query'],['{job="different-vendor"}'])
        finally:server.shutdown();thread.join();server.server_close()

    def test_private_http_and_bearer_secrets_require_explicit_security_settings(self):
        with self.assertRaises(ValueError):LokiTrigger({'url':'http://192.168.50.2:3100','query':'{job="logs"}'})
        with self.assertRaises(ValueError):LokiTrigger({'url':'http://127.0.0.1:3100','query':'{job="logs"}','token_file':'unused'})

if __name__=='__main__':unittest.main()
