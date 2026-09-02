from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from .network import VirtualNetwork


@dataclass
class ConnectorEndpoint:
    connector_id: str
    host: str
    port: int = 443
    tags: Set[str] = field(default_factory=set)
    private_network: str = "10.240.1.0/24"


class ConnectorManager:
    """Registers relay-like access connectors and link them to private network segments."""

    def __init__(self, virtual_network: Optional[VirtualNetwork] = None):
        self.virtual_network = virtual_network or VirtualNetwork("10.240.1.0/24")
        self.connectors: Dict[str, ConnectorEndpoint] = {}

    def register_connector(self, connector_id: str, host: str, port: int = 443, tags: Optional[Set[str]] = None, private_network: str = "10.240.1.0/24") -> ConnectorEndpoint:
        endpoint = ConnectorEndpoint(
            connector_id=connector_id,
            host=host,
            port=port,
            tags=tags or set(),
            private_network=private_network,
        )
        self.connectors[connector_id] = endpoint
        return endpoint

    def resolve_connector(self, connector_id: str) -> ConnectorEndpoint:
        if connector_id not in self.connectors:
            raise KeyError(f"Unknown connector '{connector_id}'")
        return self.connectors[connector_id]

    def expose_private_network(self, connector_id: str, cidr: str) -> str:
        connector = self.resolve_connector(connector_id)
        connector.private_network = cidr
        return cidr
