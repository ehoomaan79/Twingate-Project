import argparse
import json
import socket
import socketserver
import threading
import urllib.request
import uuid
import os
import tomllib
import sys
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zero_trust_core.auth import AuthManager, DeviceInfo
from zero_trust_core.network import VirtualNetwork


def load_config(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def auth_manager_from_config(config: dict) -> AuthManager:
    devices = {
        item["device_id"]: DeviceInfo(
            item["device_id"],
            item["secret"],
            set(item.get("allowed_peers", [])),
        )
        for item in config.get("devices", [])
    }
    return AuthManager(devices)


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class RelayService:
    def __init__(self, host: str = "0.0.0.0", port: int = 9000, auth_manager: AuthManager | None = None,
                 controller_url: str | None = None, relay_id: str = "relay-1", data_port: int | None = None):
        self.host = host
        self.port = port
        self.auth_manager = auth_manager or AuthManager({})
        self.controller_url = controller_url
        self.relay_id = relay_id
        self.data_port = data_port or port + 1
        self.network = VirtualNetwork("10.240.0.0/24")
        self.sessions: Dict[str, socket.socket] = {}
        self.pending_connects: Dict[str, str] = {}
        self._server = None
        self._closing = False
        self._lock = threading.Lock()
        self._tunnel_waiting: Dict[str, socket.socket] = {}
        self._tunnel_tokens: Dict[str, str] = {}
        self._tunnel_done: Dict[str, threading.Event] = {}
        self._tunnel_connections = set()

    def start(self):
        if self._server is not None:
            return self
        self._server = ReusableTCPServer((self.host, self.port), RelayTCPHandler)
        self._server.relay = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._data_server = ReusableTCPServer((self.host, self.data_port), RelayDataHandler)
        self._data_server.relay = self
        self._data_thread = threading.Thread(target=self._data_server.serve_forever, daemon=True)
        self._data_thread.start()
        if self.controller_url:
            self.register_with_controller()
        print(f"Relay service listening on {self.host}:{self.port}")
        return self

    def register_with_controller(self):
        if not self.controller_url:
            return None
        payload = json.dumps({"relay_id": self.relay_id, "host": self.host, "port": self.port}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.controller_url.rstrip('/')}/register/relay",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            print(f"Warning: failed to register relay with controller: {exc}")
            return None

    def shutdown(self):
        if self._server is not None:
            self._closing = True
            for connection in list(self.sessions.values()):
                try:
                    connection.close()
                except OSError:
                    pass
            self.sessions.clear()
            for connection in list(self._tunnel_connections) + list(self._tunnel_waiting.values()):
                try:
                    connection.close()
                except OSError:
                    pass
            for event in self._tunnel_done.values():
                event.set()
            self._server.shutdown()
            self._server.server_close()
            self._data_server.shutdown()
            self._data_server.server_close()
            self._server = None
            self._closing = False

    def dispatch(self, connection, message: dict) -> dict:
        msg_type = message.get("type")
        request_id = message.get("request_id")

        if msg_type == "auth_request":
            device_id = message.get("device_id")
            try:
                nonce = self.auth_manager.challenge_for(device_id)
            except KeyError:
                return {"type": "error", "reason": "unknown_device", "request_id": request_id}
            return {"type": "challenge", "device_id": device_id, "nonce": nonce, "request_id": request_id}

        if msg_type == "auth_response":
            device_id = message.get("device_id")
            nonce = message.get("nonce")
            signature = message.get("signature")
            try:
                token = self.auth_manager.authenticate(device_id, nonce, signature)
            except PermissionError as exc:
                return {"type": "error", "reason": str(exc), "request_id": request_id}
            virtual_ip = self.network.register_device(device_id)
            with self._lock:
                self.sessions[device_id] = connection
            return {"type": "auth_ok", "device_id": device_id, "token": token, "virtual_ip": virtual_ip, "request_id": request_id}

        if msg_type == "connect_request":
            device_id = message.get("device_id")
            peer_id = message.get("peer_id")
            token = message.get("token")
            try:
                payload = self.auth_manager.verify_token(token)
                if payload.get("device_id") != device_id:
                    raise PermissionError("Token does not belong to the sender")
                if not self.auth_manager.is_allowed(device_id, peer_id):
                    raise PermissionError(f"{device_id} is not allowed to reach {peer_id}")
                channel_id = self._pair_channel(device_id, peer_id)
                tunnel_token = uuid.uuid4().hex
                with self._lock:
                    self._tunnel_tokens[channel_id] = tunnel_token
                peer_connection = self.sessions.get(peer_id)
                if peer_connection is not None:
                    peer_connection.sendall((json.dumps({
                        "type": "peer_data",
                        "from": device_id,
                        "channel_id": channel_id,
                        "payload": json.dumps({"type": "tunnel_offer", "tunnel_token": tunnel_token, "data_port": self.data_port}),
                    }) + "\n").encode("utf-8"))
                nat_route = self.network.route(device_id, peer_id, self.host, self.port)
                peer_virtual_ip = self.network.resolve_private_ip(peer_id)
                device_virtual_ip = self.network.resolve_private_ip(device_id)
            except Exception as exc:
                return {"type": "error", "reason": str(exc), "request_id": request_id}
            return {
                "type": "connect_ok",
                "device_id": device_id,
                "peer_id": peer_id,
                "channel_id": channel_id,
                "virtual_ip": device_virtual_ip,
                "peer_virtual_ip": peer_virtual_ip,
                "nat_route": nat_route,
                "request_id": request_id,
                "data_port": self.data_port,
                "tunnel_token": tunnel_token,
            }

        if msg_type == "peer_message":
            sender = message.get("sender")
            recipient = message.get("recipient")
            payload = message.get("payload")
            channel_id = message.get("channel_id")
            if sender not in self.sessions or recipient not in self.sessions:
                return {"type": "error", "reason": "peer_unreachable", "request_id": request_id}
            self.sessions[recipient].sendall((json.dumps({"type": "peer_data", "from": sender, "channel_id": channel_id, "payload": payload}) + "\n").encode("utf-8"))
            return {"type": "delivery_ack", "channel_id": channel_id, "request_id": request_id}

        return {"type": "error", "reason": "unknown_message_type", "request_id": request_id}

    def _pair_channel(self, device_id: str, peer_id: str) -> str:
        with self._lock:
            key = tuple(sorted((device_id, peer_id)))
            if key in self.pending_connects:
                return self.pending_connects[key]
            channel_id = str(uuid.uuid4())
            self.pending_connects[key] = channel_id
            return channel_id

    def _accept_tunnel(self, connection, request):
        self._tunnel_connections.add(connection)
        channel_id = request["channel_id"]
        token = request["tunnel_token"]
        with self._lock:
            if self._tunnel_tokens.get(channel_id) != token:
                connection.close()
                return
            waiting = self._tunnel_waiting.pop(channel_id, None)
            if waiting is None:
                self._tunnel_waiting[channel_id] = connection
                self._tunnel_done[channel_id] = threading.Event()
                return self._tunnel_done[channel_id]
            done = self._tunnel_done[channel_id]
        threading.Thread(target=self._bridge, args=(waiting, connection, channel_id), daemon=True).start()
        return done

    def _bridge(self, left, right, channel_id):
        def copy(source, destination):
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    destination.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threading.Thread(target=copy, args=(left, right), daemon=True).start()
        copy(right, left)
        left.close()
        right.close()
        self._tunnel_connections.discard(left)
        self._tunnel_connections.discard(right)
        done = self._tunnel_done.get(channel_id)
        if done is not None:
            done.set()


class RelayTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        connection = self.connection
        while not self.server.relay._closing:
            try:
                raw = self.rfile.readline()
            except socket.timeout:
                continue
            if not raw:
                break
            message = json.loads(raw.decode("utf-8").strip())
            response = self.server.relay.dispatch(connection, message)
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
            self.wfile.flush()
        connection.close()


class RelayDataHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        handshake = self.request.makefile("r").readline()
        request = json.loads(handshake)
        channel_id = request["channel_id"]
        event = self.server.relay._accept_tunnel(self.request, request)
        while event is not None and not self.server.relay._closing:
            if event.wait(0.5):
                break


def main():
    parser = argparse.ArgumentParser(description="Start relay service")
    parser.add_argument("--config", default=None, help="Optional TOML config file path")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--data-port", type=int, default=None)
    parser.add_argument("--relay-id", default="relay-1")
    parser.add_argument("--controller-url", default=None)
    args = parser.parse_args()

    config = load_config(args.config) if args.config else {}
    service_cfg = config.get("service", {})
    controller_cfg = config.get("controller", {})
    host = service_cfg.get("host", args.host)
    port = int(service_cfg.get("port", args.port))
    data_port = int(service_cfg.get("data_port", args.data_port or port + 1))
    relay_id = service_cfg.get("relay_id", controller_cfg.get("relay_id", args.relay_id))
    controller_url = controller_cfg.get("url", args.controller_url)

    relay = RelayService(
        host=host,
        port=port,
        auth_manager=auth_manager_from_config(config),
        controller_url=controller_url,
        relay_id=relay_id,
        data_port=data_port,
    )
    relay.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        relay.shutdown()


if __name__ == "__main__":
    main()
