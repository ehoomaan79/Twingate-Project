import ipaddress
from typing import Dict, Optional


class VirtualNetwork:
    """Manage private virtual addresses for authenticated devices."""

    def __init__(self, cidr: str = "10.240.0.0/24"):
        self.network = ipaddress.ip_network(cidr, strict=False)
        self._device_to_ip: Dict[str, str] = {}
        self._ip_to_device: Dict[str, str] = {}
        self._next_offset = 1

    def register_device(self, device_id: str) -> str:
        if device_id in self._device_to_ip:
            return self._device_to_ip[device_id]

        if self._next_offset >= self.network.num_addresses - 1:
            raise OverflowError("No available private addresses left in the virtual network")

        address = str(self.network.network_address + self._next_offset)
        self._device_to_ip[device_id] = address
        self._ip_to_device[address] = device_id
        self._next_offset += 1
        return address

    def resolve_private_ip(self, device_id: str) -> Optional[str]:
        return self._device_to_ip.get(device_id)

    def resolve_device(self, private_ip: str) -> Optional[str]:
        return self._ip_to_device.get(private_ip)

    def route(self, source_device: str, target_device: str, relay_host: str, relay_port: int) -> Dict[str, object]:
        if source_device not in self._device_to_ip:
            self.register_device(source_device)
        if target_device not in self._device_to_ip:
            self.register_device(target_device)

        return {
            "mode": "relay",
            "relay_host": relay_host,
            "relay_port": relay_port,
            "source_virtual_ip": self._device_to_ip[source_device],
            "target_virtual_ip": self._device_to_ip[target_device],
            "natted": True,
        }


class VirtualInterface:
    """Network interface abstraction for a client behind NAT."""

    def __init__(self, device_id: str, virtual_ip: str, nat_mode: str = "relay"):
        self.device_id = device_id
        self.virtual_ip = virtual_ip
        self.nat_mode = nat_mode
        self.routes: Dict[str, Dict[str, object]] = {}

    def add_route(self, peer_id: str, peer_virtual_ip: str, relay_host: str, relay_port: int, mode: str = "relay") -> Dict[str, object]:
        route = {
            "peer_id": peer_id,
            "peer_virtual_ip": peer_virtual_ip,
            "relay_host": relay_host,
            "relay_port": relay_port,
            "mode": mode,
            "natted": True,
        }
        self.routes[peer_id] = route
        return route
