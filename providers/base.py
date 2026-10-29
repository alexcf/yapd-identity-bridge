"""Stable provider SDK. Adapters collect; reconciliation remains in the core."""
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol
from .common import empty_dns, validate_dns, validate_inventory

@dataclass(frozen=True)
class Capabilities:
    identity: bool = True
    dns_records: bool = False
    observations: bool = False
    binding_authority: bool = False

@dataclass(frozen=True)
class ProviderSpec:
    id: str
    type: str
    priority: int = 50
    config: dict[str, Any] = field(default_factory=dict, repr=False)

@dataclass
class ProviderResult:
    inventory: dict
    dns: dict = field(default_factory=empty_dns)
    warnings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    observations: list = field(default_factory=list)
    ambiguous_ips: list = field(default_factory=list)

    def validate(self, capabilities: Capabilities, allow_stale=False):
        validate_inventory(self.inventory, allow_stale=allow_stale)
        validate_dns(self.dns)
        if not capabilities.dns_records and any(self.dns.values()):
            raise ValueError('Provider emitted DNS without the DNS capability')
        if self.observations and not capabilities.observations:
            raise ValueError('Provider emitted undeclared observations')
        if not capabilities.identity and self.inventory['devices']:
            raise ValueError('Provider emitted undeclared identities')
        if len(self.observations) > 10000 or len(self.warnings) > 30000 or len(self.ambiguous_ips) > 10000:
            raise ValueError('Provider result exceeds limits')
        # Observations are not identities, but still validate addresses and names.
        import ipaddress
        for ip in self.ambiguous_ips:
            ipaddress.ip_address(ip)
        for item in self.observations:
            if not isinstance(item.get('name', ''), str) or len(item.get('name', '')) > 191 or len(item.get('ips', [])) > 100:
                raise ValueError('Invalid observation name')
            for ip in item.get('ips', []):
                ipaddress.ip_address(ip)
        if any(not isinstance(w, dict) for w in self.warnings):
            raise ValueError('Invalid provider warnings')
        return self

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        return cls(**value)

class IdentityProvider(Protocol):
    capabilities: Capabilities

    def collect(self) -> ProviderResult:
        """Return a complete snapshot; raise on failed/incomplete collection."""
        ...
