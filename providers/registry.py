"""Built-in providers and trusted installed Python entry-point extensions."""
import importlib.metadata
import json
import os
import pathlib
import re
from .base import ProviderSpec

_factories = {}
_plugins_loaded = False

def register(name, factory):
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name) or name in _factories:
        raise ValueError('Invalid or duplicate provider type')
    _factories[name] = factory

def _builtins():
    from .mikrotik import MikroTikProvider
    from .jsonfile import JsonFileProvider
    from .prometheus import PrometheusProvider
    from .dhcp import DHCPProvider
    from .arp import ARPProvider
    for name, provider in [('mikrotik', MikroTikProvider), ('json', JsonFileProvider), ('prometheus', PrometheusProvider), ('dhcp', DHCPProvider), ('arp', ARPProvider)]:
        if name not in _factories:
            register(name, provider)

def create(spec):
    global _plugins_loaded
    _builtins()
    if not _plugins_loaded:
        for entry in importlib.metadata.entry_points(group='yapd_identity.providers'):
            register(entry.name, entry.load())
        _plugins_loaded = True
    if spec.type not in _factories:
        raise ValueError('Unknown provider type: ' + spec.type)
    return _factories[spec.type](spec.config)

def configured_providers():
    path = os.environ.get('IDENTITY_PROVIDERS_FILE')
    if not path:
        name = os.environ.get('IDENTITY_PROVIDER', 'mikrotik')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name):
            raise ValueError('Invalid provider type')
        return [ProviderSpec(id=name, type=name, priority=100)]
    raw = pathlib.Path(path).read_text()
    if len(raw) > 100000:
        raise ValueError('Provider configuration too large')
    value = json.loads(raw)
    if value.get('version') != 1 or not isinstance(value.get('providers'), list) or not 1 <= len(value['providers']) <= 16:
        raise ValueError('Invalid provider configuration')
    result, seen = [], set()
    for item in value['providers']:
        identity, kind = item.get('id', ''), item.get('type', '')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', identity) or identity in seen:
            raise ValueError('Invalid or duplicate provider ID')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', kind):
            raise ValueError('Invalid provider type')
        config = item.get('config', {})
        priority = item.get('priority', 50)
        if not isinstance(config, dict) or type(priority) is not int or not 0 <= priority <= 1000:
            raise ValueError('Invalid provider settings')
        seen.add(identity)
        result.append(ProviderSpec(identity, kind, priority, config))
    return result
