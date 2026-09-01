import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class DeviceInfo:
    device_id: str
    secret: str
    allowed_peers: Set[str] = field(default_factory=set)


class AuthManager:
    """Minimal identity and authorization layer for the demo."""

    def __init__(self, devices: Dict[str, DeviceInfo], server_secret: str = "zero-trust-demo-server-secret"):
        self.devices = devices
        self.server_secret = server_secret
        self._challenges: Dict[str, str] = {}

    def challenge_for(self, device_id: str) -> str:
        if device_id not in self.devices:
            raise KeyError(f"Unknown device '{device_id}'")
        nonce = secrets.token_hex(16)
        self._challenges[device_id] = nonce
        return nonce

    def authenticate(self, device_id: str, nonce: str, signature: str) -> str:
        if device_id not in self.devices:
            raise PermissionError(f"Unknown device '{device_id}'")
        device = self.devices[device_id]
        expected = hmac.new(device.secret.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise PermissionError("Invalid signature for device authentication")
        payload = {
            "device_id": device_id,
            "exp": int(time.time()) + 600,
            "scope": "peer-connect",
        }
        return self._encode_token(payload)

    def verify_token(self, token: str) -> Dict[str, object]:
        try:
            payload_segment, signature = token.split(".")
        except ValueError as exc:
            raise PermissionError("Malformed token") from exc

        expected = hmac.new(self.server_secret.encode("utf-8"), payload_segment.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise PermissionError("Token signature mismatch")

        padded = payload_segment + "=" * ((4 - len(payload_segment) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if int(payload["exp"]) < time.time():
            raise PermissionError("Token expired")
        return payload

    def is_allowed(self, device_id: str, peer_id: str) -> bool:
        device = self.devices.get(device_id)
        if device is None:
            return False
        if device_id == peer_id:
            return False
        return peer_id in device.allowed_peers

    def _encode_token(self, payload: Dict[str, object]) -> str:
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_segment = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
        signature = hmac.new(self.server_secret.encode("utf-8"), payload_segment.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload_segment}.{signature}"
