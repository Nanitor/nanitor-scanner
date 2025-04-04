from dataclasses import dataclass


@dataclass
class DiscoveredHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostnames: list[str] | None = None
