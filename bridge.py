#!/usr/bin/env python3
"""One-way external identity and owned DNS reconciliation for YAPD."""
import argparse, datetime, fcntl, json, os, pathlib, sys, time
from providers import manager
DATA = pathlib.Path(os.environ.get('IDENTITY_DATA', '/var/lib/yapd-identity'))
FIELDS = ('hosts', 'cnameRecords', 'revServers')

def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + '.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    os.replace(temporary, path)

def keys(field, entry):
    if field == 'hosts':
        return set(entry.split()[1:])
    if field == 'cnameRecords':
        return {entry.split(',')[0]}
    return {entry.split(',')[-1]} if field == 'revServers' else {entry}

def reconcile_array(field, current, desired, owned):
    current, desired, owned = list(current), set(desired), set(owned)
    manual = [entry for entry in current if entry not in owned]
    conflicts, accepted = [], set()
    for entry in desired:
        collision = [item for item in manual if keys(field, item) & keys(field, entry) and item != entry]
        # Multiple desired addresses for a static name/forward zone are valid;
        # pre-existing matching members may be borrowed without being owned.
        collision = [item for item in collision if item not in desired]
        if collision:
            conflicts.append({'field': field, 'desired': entry, 'existing': collision})
        else:
            accepted.add(entry)
    result = [entry for entry in current if entry not in owned or entry in accepted]
    added = sorted(accepted - set(result))
    result.extend(added)
    next_owned = (owned & accepted & set(result)) | set(added)
    return result, sorted(next_owned), conflicts

def run(apply=False):
    DATA.mkdir(mode=0o700, exist_ok=True)
    with (DATA / 'bridge.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result, providers, publish_dns = manager.collect(DATA, atomic)
        desired, snapshot, warnings = result.dns, result.inventory, result.warnings
        atomic(DATA / 'preview.json', {'dns': desired, 'inventory': snapshot, 'warnings': warnings})
        import client as manage
        state_path = DATA / 'ownership.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {'nodes': {}}
        report = {'at': snapshot['retrievedAt'], 'mode': 'apply' if apply else 'preview',
            'leases': result.stats.get('leases', 0), 'devices': len(snapshot['devices']), 'provider': snapshot['provider'],
            'static_dns_records': result.stats.get('static_dns_records', 0), 'desired_dns_entries': {k: len(v) for k,v in desired.items()},
            'warnings': warnings, 'providers': providers, 'dns_enabled': publish_dns, 'nodes': []}
        if apply:
            atomic(DATA / 'inventory.json', snapshot)
        if not publish_dns:
            atomic(DATA / 'status.json', report)
            print(json.dumps({'mode':report['mode'], 'devices':report['devices'], 'dns_enabled':False}))
            return 1 if any(p['status'] != 'fresh' for p in providers) else 0
        manage.login()
        try:
            for node in sorted((item for item in manage.instances() if item.get('syncEnabled', True)),
                               key=lambda item: item.get('isBaseline', False)):
                node_state = state['nodes'].setdefault(node['id'], {field: [] for field in FIELDS})
                node_report = {'id': node['id'], 'name': node['name'], 'changes': {}, 'conflicts': []}
                try:
                    for topic, fields in [('dns', ('hosts','cnameRecords','revServers'))]:
                        current = manage.api('/config/' + topic + '?sourceInstanceId=' + node['id'])['topic']['value']
                        next_value = dict(current)
                        next_owned = {}
                        for field in fields:
                            values, owned, conflicts = reconcile_array(field, current.get(field, []), desired[field], node_state.get(field, []))
                            next_value[field] = values
                            next_owned[field] = owned
                            node_report['conflicts'].extend(conflicts)
                            node_report['changes'][field] = {'add': len(set(values)-set(current.get(field,[]))),
                                'remove': len(set(current.get(field,[]))-set(values))}
                        if apply and next_value != current:
                            # Record intent before mutation so a partially completed API
                            # write is recoverable and newly added entries remain owned.
                            node_state.update({k: sorted(set(node_state.get(k, [])) | set(v)) for k, v in next_owned.items()})
                            atomic(state_path, state)
                            atomic(DATA / ('before-' + node['id'] + '-' + topic + '.json'), current)
                            manage.api('/config/' + topic, {'sourceInstanceId': node['id'],
                                'config': {'config': {topic: {field: next_value[field] for field in fields}}}}, method='PATCH')
                            actual = manage.api('/config/' + topic + '?sourceInstanceId=' + node['id'])['topic']['value']
                            if any(set(actual.get(field,[])) != set(next_value[field]) for field in fields):
                                raise RuntimeError('DNS read-back verification failed')
                        if apply:
                            node_state.update(next_owned)
                            atomic(state_path, state)
                    node_report['status'] = 'applied' if apply else 'preview'
                except Exception as error:
                    node_report['status'] = 'pending'
                    node_report['error_type'] = type(error).__name__
                report['nodes'].append(node_report)
        finally:
            manage.api('/session', method='DELETE')
        atomic(DATA / 'status.json', report)
        print(json.dumps({key: report[key] for key in ['mode','leases','devices','static_dns_records','desired_dns_entries']}))
        print(json.dumps({'nodes': [{k:v for k,v in item.items() if k not in ('conflicts',)} for item in report['nodes']],
                          'warnings': len(warnings), 'conflicts': sum(len(x['conflicts']) for x in report['nodes'])}))
        return 1 if any(item['status']=='pending' for item in report['nodes']) or any(p['status'] != 'fresh' for p in providers) else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--daemon', action='store_true')
    args = parser.parse_args()
    while True:
        try:
            code = run(args.apply)
        except Exception as error:
            print('Sync failed safely; last good state retained:', type(error).__name__, flush=True)
            code = 1
        if not args.daemon:
            sys.exit(code)
        time.sleep(max(60, int(os.environ.get('SYNC_INTERVAL_SECONDS', '300'))))
