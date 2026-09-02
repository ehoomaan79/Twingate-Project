from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class NetworkRoute:
    destination: str
    via: str
    metric: int = 10
    direct: bool = False


@dataclass
class VirtualNetworkTopology:
    routes: Dict[str, NetworkRoute] = field(default_factory=dict)

    def add_route(self, destination: str, via: str, *, metric: int = 10, direct: bool = False) -> NetworkRoute:
        route = NetworkRoute(destination=destination, via=via, metric=metric, direct=direct)
        self.routes[destination] = route
        return route


class VirtualNetworkController:
    """Keeps a simple route table and service map for private virtual addresses."""

    def __init__(self):
        self.topology = VirtualNetworkTopology()
        self.addresses: Dict[str, str] = {}

    def assign_private_address(self, device_id: str, private_ip: str) -> str:
        self.addresses[device_id] = private_ip
        return private_ip

    def resolve_private_address(self, device_id: str) -> Optional[str]:
        return self.addresses.get(device_id)

    def add_route(self, destination: str, via: str, *, metric: int = 10, direct: bool = False) -> NetworkRoute:
        return self.topology.add_route(destination, via, metric=metric, direct=direct)
