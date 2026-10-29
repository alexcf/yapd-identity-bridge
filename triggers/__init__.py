"""Optional change notifications; providers remain the authority for state."""
from typing import Protocol

class ChangeNotifier(Protocol):
    def poll(self) -> bool:
        """Return a refresh hint. Never mutate identities or policy here."""
        ...
