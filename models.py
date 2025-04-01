from dataclasses import dataclass
from typing import List

@dataclass
class DiscoveredHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostnames: List[str] | None = None

