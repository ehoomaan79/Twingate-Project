"""Zero-trust backbone package."""

from .auth import AuthManager, DeviceInfo
from .encryption import SessionCipher
from .dns import address_matches, find_resource, resolve_with_local_dns
from .tunnel import EncryptedEnvelope
from .kernel_routing import LinuxRouteManager
from .network import VirtualInterface, VirtualNetwork
from .policy import AccessRequest, PolicyEngine
from .protocol import ZeroTrustClient
from .relay import RelayServer

__all__ = [
    "AuthManager",
    "DeviceInfo",
    "ZeroTrustClient",
    "RelayServer",
    "VirtualNetwork",
    "VirtualInterface",
    "SessionCipher",
    "address_matches",
    "find_resource",
    "resolve_with_local_dns",
    "EncryptedEnvelope",
    "LinuxRouteManager",
    "AccessRequest",
    "PolicyEngine",
]
