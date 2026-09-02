from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class Resource:
    resource_id: str
    name: str
    address: str
    protocols: Dict[str, object] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    connector_id: str | None = None
    private_ip: str | None = None


class ResourceCatalog:
    """Tracks protected services and their private endpoints."""

    def __init__(self):
        self.resources: Dict[str, Resource] = {}

    def register_resource(self, resource: Resource) -> Resource:
        self.resources[resource.resource_id] = resource
        return resource

    def resolve_resource(self, resource_id: str) -> Resource:
        if resource_id not in self.resources:
            raise KeyError(f"Unknown resource '{resource_id}'")
        return self.resources[resource_id]
