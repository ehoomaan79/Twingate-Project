from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class ResourcePolicy:
    resource_id: str
    allowed_groups: Set[str] = field(default_factory=set)
    allowed_users: Set[str] = field(default_factory=set)
    allowed_ports: Set[int] = field(default_factory=set)
    require_mfa: bool = False


@dataclass
class AccessRequest:
    user_id: str
    groups: Set[str]
    device_id: str
    resource_id: str
    port: int
    mfa_verified: bool = False
    device_trusted: bool = False
    device_compliant: bool = False


class PolicyEngine:
    """Least-privilege access control with device and user context."""

    def __init__(self):
        self.resources: Dict[str, ResourcePolicy] = {}

    def add_resource(self, resource_id: str, *, allowed_groups: Set[str] | None = None, allowed_users: Set[str] | None = None, allowed_ports: Set[int] | None = None, require_mfa: bool = False) -> ResourcePolicy:
        policy = ResourcePolicy(
            resource_id=resource_id,
            allowed_groups=allowed_groups or set(),
            allowed_users=allowed_users or set(),
            allowed_ports=allowed_ports or {443},
            require_mfa=require_mfa,
        )
        self.resources[resource_id] = policy
        return policy

    def can_access(self, user_id: str, groups: Set[str], resource_id: str, port: int, mfa_verified: bool = False) -> bool:
        policy = self.resources.get(resource_id)
        if policy is None:
            return False
        if user_id in policy.allowed_users:
            return port in policy.allowed_ports and (not policy.require_mfa or mfa_verified)
        if groups & policy.allowed_groups:
            return port in policy.allowed_ports and (not policy.require_mfa or mfa_verified)
        return False

    def evaluate_access(self, request: AccessRequest) -> bool:
        policy = self.resources.get(request.resource_id)
        if policy is None:
            return False
        if not request.device_trusted or not request.device_compliant:
            return False
        if request.user_id in policy.allowed_users:
            if request.port not in policy.allowed_ports:
                return False
            return (not policy.require_mfa) or request.mfa_verified
        if request.groups & policy.allowed_groups:
            if request.port not in policy.allowed_ports:
                return False
            return (not policy.require_mfa) or request.mfa_verified
        return False
