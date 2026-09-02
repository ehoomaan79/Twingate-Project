from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set


@dataclass
class SecurityPolicy:
    name: str
    mode: str = "allow"
    conditions: Dict[str, Any] = field(default_factory=dict)


class ControllerDatabase:
    """Persistent controller state backed by SQLite."""

    def __init__(self, database_path: str | Path = ":memory:"):
        self.database_path = str(database_path)
        self._lock = threading.RLock()
        self.users: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.resources: Dict[str, Dict[str, Any]] = {}
        self.relays: Dict[str, Dict[str, Any]] = {}
        self.connectors: Dict[str, Dict[str, Any]] = {}
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.security_policies: Dict[str, SecurityPolicy] = {}
        self.connector_tokens: Dict[str, Dict[str, Any]] = {}
        self.client_credentials: Dict[str, Dict[str, str]] = {}
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.execute("CREATE TABLE IF NOT EXISTS controller_state (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL)")
        self._load()

    def close(self):
        with self._lock:
            self._connection.close()

    def __del__(self):
        connection = getattr(self, "_connection", None)
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    def _load(self):
        row = self._connection.execute("SELECT payload FROM controller_state WHERE id = 1").fetchone()
        if not row:
            return
        payload = json.loads(row[0])
        self.users = self._restore_mapping(payload.get("users", {}))
        self.groups = self._restore_mapping(payload.get("groups", {}))
        self.resources = self._restore_mapping(payload.get("resources", {}))
        self.relays = self._restore_mapping(payload.get("relays", {}))
        self.connectors = self._restore_mapping(payload.get("connectors", {}))
        self.clients = self._restore_mapping(payload.get("clients", {}))
        self.security_policies = {
            name: SecurityPolicy(name, item.get("mode", "allow"), item.get("conditions", {}))
            for name, item in payload.get("security_policies", {}).items()
        }
        self.connector_tokens = payload.get("connector_tokens", {})
        self.client_credentials = payload.get("client_credentials", {})

    def _save(self):
        payload = {
            "users": self.users,
            "groups": self.groups,
            "resources": self.resources,
            "relays": self.relays,
            "connectors": self.connectors,
            "clients": self.clients,
            "security_policies": {
                name: {"mode": policy.mode, "conditions": policy.conditions}
                for name, policy in self.security_policies.items()
            },
            "connector_tokens": self.connector_tokens,
            "client_credentials": self.client_credentials,
        }
        encoded = json.dumps(payload, default=self._json_default)
        self._connection.execute("INSERT INTO controller_state(id, payload) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (encoded,))
        self._connection.commit()

    @staticmethod
    def _json_default(value):
        if isinstance(value, set):
            return {"__controller_set__": sorted(value)}
        raise TypeError(f"Unsupported controller state value: {type(value).__name__}")

    @classmethod
    def _restore_mapping(cls, value):
        if isinstance(value, dict):
            if set(value) == {"__controller_set__"}:
                return set(value["__controller_set__"])
            return {key: cls._restore_mapping(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._restore_mapping(item) for item in value]
        return value

    def create_group(self, group_name: str, *, description: str = "") -> Dict[str, Any]:
        with self._lock:
            self.groups[group_name] = {"name": group_name, "description": description, "members": set()}
            self._save()
            return self.groups[group_name]

    def register_user(self, user_id: str, *, groups: Set[str] | None = None, roles: Set[str] | None = None, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            user_groups = set(groups or set())
            self.users[user_id] = {"user_id": user_id, "groups": user_groups, "roles": set(roles or set()), "metadata": metadata or {}}
            for group_name in user_groups:
                if group_name not in self.groups:
                    self.groups[group_name] = {"name": group_name, "description": "", "members": set()}
                self.groups[group_name]["members"].add(user_id)
            self._save()
            return self.users[user_id]

    def register_resource(self, resource_id: str, *, address: str = "", allowed_groups: Set[str] | None = None, allowed_users: Set[str] | None = None, allowed_ports: Set[int] | None = None, allowed_protocols: Set[str] | None = None, aliases: Set[str] | None = None, dns_servers: List[str] | None = None, visible: bool = True, require_mfa: bool = False, description: str = "", connector_id: str | None = None, relay_id: str | None = None) -> Dict[str, Any]:
        item = {
            "resource_id": resource_id,
                "address": address,
            "allowed_groups": set(allowed_groups or set()),
            "allowed_users": set(allowed_users or set()),
            "allowed_ports": set(allowed_ports or {443}),
                "allowed_protocols": set(allowed_protocols or {"tcp", "udp"}),
                "aliases": set(aliases or set()),
                "dns_servers": list(dns_servers or []),
                "visible": visible,
            "require_mfa": require_mfa,
            "description": description,
            "connector_id": connector_id,
            "relay_id": relay_id,
        }
        with self._lock:
            self.resources[resource_id] = item
            self._save()
            return item

    def register_relay(self, relay_id: str, host: str, port: int, *, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            self.relays[relay_id] = {"relay_id": relay_id, "host": host, "port": port, "metadata": metadata or {}}
            self._save()
            return self.relays[relay_id]

    def register_connector(self, connector_id: str, host: str, port: int, resource_ip: str, *, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            self.connectors[connector_id] = {"connector_id": connector_id, "host": host, "port": port, "resource_ip": resource_ip, "metadata": metadata or {}}
            self._save()
            return self.connectors[connector_id]

    def register_client(self, device_id: str, host: str, port: int, virtual_ip: str | None = None, *, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            self.clients[device_id] = {"device_id": device_id, "host": host, "port": port, "virtual_ip": virtual_ip, "metadata": metadata or {}}
            self._save()
            return self.clients[device_id]

    def issue_client_token(self, device_id: str, secret: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self.client_credentials[token] = {
                "device_id": device_id,
                "secret_hash": hashlib.sha256(f"{device_id}:{secret}".encode()).hexdigest(),
            }
            self._save()
        return token

    def verify_client_token(self, token: str, device_id: str) -> bool:
        record = self.client_credentials.get(token)
        return record is not None and record.get("device_id") == device_id

    def add_security_policy(self, name: str, *, mode: str = "allow", conditions: Dict[str, Any] | None = None) -> SecurityPolicy:
        with self._lock:
            policy = SecurityPolicy(name=name, mode=mode, conditions=conditions or {})
            self.security_policies[name] = policy
            self._save()
            return policy

    def create_connector_token(self, connector_id: str, *, expires_at: int | None = None) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self.connector_tokens[token] = {"connector_id": connector_id, "expires_at": expires_at, "used": False}
            self._save()
        return token

    def consume_connector_token(self, token: str, connector_id: str) -> bool:
        with self._lock:
            record = self.connector_tokens.get(token)
            if record is None or record["used"] or record["connector_id"] != connector_id:
                return False
            if record.get("expires_at") is not None and int(record["expires_at"]) < time.time():
                return False
            record["used"] = True
            self._save()
            return True

    def can_access(self, user_id: str, resource_id: str, port: int, *, mfa_verified: bool = False, device_trusted: bool = False, device_compliant: bool = False) -> bool:
        resource = self.resources.get(resource_id)
        user = self.users.get(user_id)
        if resource is None or user is None or not device_trusted or not device_compliant:
            return False
        if port not in resource["allowed_ports"]:
            return False
        if resource["require_mfa"] and not mfa_verified:
            return False

        if user_id in resource["allowed_users"]:
            return True

        user_groups = user.get("groups", set())
        if user_groups & resource["allowed_groups"]:
            return True

        return False

    def resolve_access(self, user_id: str, resource_id: str, port: int, *, mfa_verified: bool = False, device_trusted: bool = False, device_compliant: bool = False) -> Dict[str, Any]:
        authorized = self.can_access(user_id, resource_id, port, mfa_verified=mfa_verified, device_trusted=device_trusted, device_compliant=device_compliant)
        if not authorized:
            return {"authorized": False, "reason": "access_denied"}

        resource = self.resources.get(resource_id)
        if resource is None:
            return {"authorized": False, "reason": "unknown_resource"}

        relay = None
        if resource.get("relay_id"):
            relay = self.relays.get(resource["relay_id"])
        if relay is None:
            relay = next(iter(self.relays.values()), None)

        connector = None
        if resource.get("connector_id"):
            connector = self.connectors.get(resource["connector_id"])
        if connector is None:
            connector = next(iter(self.connectors.values()), None)

        if relay is None or connector is None:
            return {"authorized": False, "reason": "route_unavailable"}

        return {
            "authorized": True,
            "resource_id": resource_id,
            "relay": relay,
            "connector": connector,
            "access_policy": {
                "require_mfa": resource.get("require_mfa", False),
                "allowed_ports": sorted(resource.get("allowed_ports", set())),
            },
        }

    def list_accessible_resources(self, user_id: str, *, device_trusted: bool = False, device_compliant: bool = False) -> List[Dict[str, Any]]:
        resources = []
        for resource in self.resources.values():
            if resource.get("visible", True) and self.can_access(user_id, resource["resource_id"], next(iter(resource["allowed_ports"]), 443), device_trusted=device_trusted, device_compliant=device_compliant):
                resources.append(resource)
        return resources

    def topology(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "users": list(self.users.values()),
            "groups": list(self.groups.values()),
            "resources": list(self.resources.values()),
            "relays": list(self.relays.values()),
            "connectors": list(self.connectors.values()),
            "clients": list(self.clients.values()),
        }
