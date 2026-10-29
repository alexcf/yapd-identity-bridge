"""Versioned file provider for collectors outside this project."""
import json
import os
import pathlib
from .base import Capabilities, ProviderResult
from .common import empty_dns, validate_dns, validate_inventory

def load(config=None):
    config = config or {}
    path = config.get('source_file') or os.environ['IDENTITY_SOURCE_FILE']
    raw = pathlib.Path(path).read_text()
    if len(raw) > 2_000_000:
        raise ValueError('Identity snapshot too large')
    value = json.loads(raw)
    inventory, desired = value['inventory'], value.get('dns', empty_dns())
    validate_inventory(inventory)
    validate_dns(desired, config.get('dns_self_addresses'))
    return desired, inventory, value.get('warnings', [])

class JsonFileProvider:
    def __init__(self, config=None):
        self.config = config or {}
        if any(type(self.config.get(k, True)) is not bool for k in ('publish_dns', 'binding_authority')):
            raise ValueError('Provider capabilities must be boolean')
        self.capabilities = Capabilities(identity=True, dns_records=self.config.get('publish_dns', True),
                                         binding_authority=self.config.get('binding_authority', True))

    def collect(self):
        desired, inventory, warnings = load(self.config)
        if not self.capabilities.dns_records:
            desired = empty_dns()
        return ProviderResult(inventory=inventory, dns=desired, warnings=warnings,
                              stats={'leases': len(inventory['devices']), 'static_dns_records': sum(map(len, desired.values()))})
