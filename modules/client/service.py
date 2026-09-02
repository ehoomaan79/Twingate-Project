import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import threading
import time
import tomllib
import urllib.request
import uuid
from collections import deque
from typing import Deque
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zero_trust_core.network import VirtualInterface, VirtualNetwork
from zero_trust_core.dns import find_resource
from zero_trust_core.tunnel import EncryptedEnvelope
from zero_trust_core.tunnel import certificate_fingerprint, client_tls_context


def load_config(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "rb") as handle:
        return tomllib.load(handle)


class ClientService:
    def __init__(self, device_id: str, secret: str, relay_host: str = "127.0.0.1", relay_port: int = 9000,
                 controller_url: str | None = None, user_id: str | None = None):
        self.device_id = device_id
        self.secret = secret
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.controller_url = controller_url
        self.user_id = user_id or device_id
        self.controller_token = None
        self.tunnel_socket = None
        self.token = None
        self.virtual_ip = None
        self.channel_id = None
        self.sock = None
        self._reader_thread = None
        self._incoming: Deque[dict] = deque()
        self._lock = threading.Lock()
        self.network = VirtualNetwork()
        self.interface = VirtualInterface(device_id, "10.240.0.0")

    def connect(self):
        self.sock = socket.create_connection((self.relay_host, self.relay_port), timeout=5)
        self.sock.settimeout(2)
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()
        return self

    def login(self):
        challenge = self._send_command({"type": "auth_request", "device_id": self.device_id})
        if challenge.get("type") != "challenge":
            raise RuntimeError(f"Unexpected auth challenge: {challenge}")

        signature = hmac.new(self.secret.encode("utf-8"), challenge["nonce"].encode("utf-8"), hashlib.sha256).hexdigest()
        response = self._send_command({
            "type": "auth_response",
            "device_id": self.device_id,
            "user_id": self.user_id,
            "nonce": challenge["nonce"],
            "signature": signature,
        })
        if response.get("type") != "auth_ok":
            raise RuntimeError(f"Authentication failed: {response}")

        self.token = response["token"]
        self.virtual_ip = response.get("virtual_ip") or self.network.register_device(self.device_id)
        self.interface.virtual_ip = self.virtual_ip
        self.register_with_controller()
        return response

    def register_with_controller(self):
        if not self.controller_url:
            return None
        payload = json.dumps({
            "device_id": self.device_id,
            "host": self.relay_host,
            "port": self.relay_port,
            "virtual_ip": self.virtual_ip,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.controller_url.rstrip('/')}/register/client",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
        self.controller_token = result.get("client_token")
        return result

    def request_resource(self, user_id: str, resource_id: str, port: int, *, mfa_verified: bool = False,
                         device_trusted: bool = True, device_compliant: bool = True) -> dict:
        if not self.controller_url:
            raise RuntimeError("Controller URL is required for resource access")
        payload = json.dumps({
            "user_id": user_id,
            "resource_id": resource_id,
            "port": port,
            "mfa_verified": mfa_verified,
            "device_trusted": device_trusted,
            "device_compliant": device_compliant,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.controller_url.rstrip('/')}/resolve/access",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.controller_token}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not result.get("authorized"):
            raise PermissionError(result.get("reason", "access_denied"))
        return result

    def list_resources(self, user_id: str, *, device_trusted: bool = True, device_compliant: bool = True) -> list[dict]:
        if not self.controller_url:
            raise RuntimeError("Controller URL is required for resource discovery")
        payload = json.dumps({"user_id": user_id, "device_trusted": device_trusted, "device_compliant": device_compliant}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.controller_url.rstrip('/')}/client/resources",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.controller_token}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("status") != "ok":
            raise PermissionError(result.get("reason", "resource_discovery_denied"))
        return result["resources"]

    @staticmethod
    def match_resource(resources: list[dict], destination: str) -> dict | None:
        """Resolve a local alias, private FQDN, IP, or CIDR destination to a catalog entry."""
        return find_resource(resources, destination)

    def connect_to_peer(self, peer_id: str, *, tunnel_metadata: dict | None = None):
        if self.token is None:
            raise RuntimeError("Client must authenticate before requesting a peer connection")

        response = self._send_command({
            "type": "connect_request",
            "device_id": self.device_id,
            "peer_id": peer_id,
            "token": self.token,
            "tunnel_metadata": tunnel_metadata or {},
        })
        if response.get("type") != "connect_ok":
            raise RuntimeError(f"Peer connection failed: {response}")

        self.channel_id = response["channel_id"]
        self.interface.add_route(peer_id, response.get("peer_virtual_ip") or "10.240.0.0", self.relay_host, self.relay_port)
        return response

    def send_message(self, recipient_id: str, payload: str):
        if self.channel_id is None:
            raise RuntimeError("No active channel to peer")
        response = self._send_command({
            "type": "peer_message",
            "channel_id": self.channel_id,
            "sender": self.device_id,
            "recipient": recipient_id,
            "payload": payload,
        })
        if response.get("type") != "delivery_ack":
            raise RuntimeError(f"Delivery failed: {response}")
        return response

    def send_encrypted(self, recipient_id: str, payload: bytes, shared_secret: str):
        if self.channel_id is None:
            raise RuntimeError("No active channel to peer")
        envelope = EncryptedEnvelope.seal(payload, shared_secret, self.channel_id.encode("utf-8"))
        return self.send_message(recipient_id, envelope.ciphertext)

    def decrypt_message(self, message: dict, shared_secret: str) -> bytes:
        return EncryptedEnvelope(message["payload"]).open(shared_secret, message["channel_id"].encode("utf-8"))

    def close(self):
        for connection in (self.tunnel_socket, self.sock):
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
        self.tunnel_socket = None
        self.sock = None

    def open_tls_tunnel(self, peer_id: str, server_fingerprint: str):
        route = self.connect_to_peer(peer_id)
        tunnel = socket.create_connection((self.relay_host, route["data_port"]), timeout=5)
        tunnel.sendall((json.dumps({"channel_id": route["channel_id"], "tunnel_token": route["tunnel_token"]}) + "\n").encode("utf-8"))
        tls_socket = client_tls_context().wrap_socket(tunnel, server_hostname=peer_id)
        if certificate_fingerprint(tls_socket.getpeercert(binary_form=True)) != server_fingerprint:
            tls_socket.close()
            raise ssl.SSLError("Connector certificate fingerprint mismatch")
        self.tunnel_socket = tls_socket
        return tls_socket

    def open_resource_tunnel(self, resource: dict, port: int, server_fingerprint: str):
        """Authorize a catalog resource, then open TLS to its connector."""
        if self.controller_url:
            self.request_resource(self.user_id, resource["resource_id"], port)
        connector = resource.get("connector_id") or resource.get("connector", {}).get("connector_id")
        if not connector:
            raise RuntimeError("Resource has no connector assignment")
        return self.open_tls_tunnel_with_metadata(
            connector,
            server_fingerprint,
            {"resource_address": resource.get("address", ""), "resource_port": port},
        )

    def open_tls_tunnel_with_metadata(self, peer_id: str, server_fingerprint: str, metadata: dict):
        route = self.connect_to_peer(peer_id, tunnel_metadata=metadata)
        tunnel = socket.create_connection((self.relay_host, route["data_port"]), timeout=5)
        tunnel.sendall((json.dumps({"channel_id": route["channel_id"], "tunnel_token": route["tunnel_token"]}) + "\n").encode("utf-8"))
        tls_socket = client_tls_context().wrap_socket(tunnel, server_hostname=peer_id)
        if certificate_fingerprint(tls_socket.getpeercert(binary_form=True)) != server_fingerprint:
            tls_socket.close()
            raise ssl.SSLError("Connector certificate fingerprint mismatch")
        self.tunnel_socket = tls_socket
        return tls_socket

    def _reader_loop(self):
        reader = self.sock.makefile("r")
        while self.sock is not None:
            try:
                line = reader.readline()
            except socket.timeout:
                continue
            except (OSError, ValueError):
                break
            if not line:
                break
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._incoming.append(item)

    def _send_command(self, payload: dict) -> dict:
        if self.sock is None:
            raise RuntimeError("Client is not connected to the relay")

        request_id = str(uuid.uuid4())
        payload["request_id"] = request_id
        request = (json.dumps(payload) + "\n").encode("utf-8")

        with self._lock:
            self.sock.sendall(request)

        deadline = time.time() + 5
        while time.time() < deadline:
            if not self._incoming:
                time.sleep(0.05)
                continue
            item = self._incoming.popleft()
            if item.get("request_id") == request_id:
                return item
            self._incoming.append(item)
            time.sleep(0.05)
        raise TimeoutError(f"Timed out waiting for server response for request {request_id}")


def main():
    parser = argparse.ArgumentParser(description="Start client service")
    parser.add_argument("--config", default=None, help="Optional TOML config file path")
    parser.add_argument("--device-id", default="client-1")
    parser.add_argument("--secret", default="client-secret")
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--controller-url", default=None)
    parser.add_argument("--user-id", default=None)
    args = parser.parse_args()

    config = load_config(args.config) if args.config else {}
    service_cfg = config.get("service", {})
    controller_cfg = config.get("controller", {})
    device_id = service_cfg.get("device_id", args.device_id)
    secret = service_cfg.get("secret", args.secret)
    relay_host = service_cfg.get("relay_host", args.relay_host)
    relay_port = int(service_cfg.get("relay_port", args.relay_port))
    controller_url = controller_cfg.get("url", args.controller_url)
    user_id = service_cfg.get("user_id", args.user_id)

    client = ClientService(device_id=device_id, secret=secret, relay_host=relay_host, relay_port=relay_port,
                          controller_url=controller_url, user_id=user_id)
    client.connect()
    client.login()
    print(f"Client {client.device_id} connected with virtual IP {client.virtual_ip}")
    if client.controller_url:
        for resource in client.list_resources(client.user_id):
            print(f"Authorized resource: {resource['resource_id']} -> {resource.get('address', '')}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        if client.sock is not None:
            client.sock.close()


if __name__ == "__main__":
    main()
