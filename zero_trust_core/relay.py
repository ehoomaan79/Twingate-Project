import json
import socket
import socketserver
import threading
import uuid
from typing import Dict, Optional

from .auth import AuthManager


class RelayServer:
    """A minimal relay that lets clients behind NAT rendezvous and exchange messages."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9000, auth_manager: Optional[AuthManager] = None):
        self.host = host
        self.port = port
        self.auth_manager = auth_manager or AuthManager({})
        self.sessions: Dict[str, socket.socket] = {}
        self.pending_connects: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._server = None
        self._closing = False

    def start(self):
        if self._server is not None:
            return self
        self._closing = False
        self._server = socketserver.ThreadingTCPServer((self.host, self.port), RelayTCPHandler)
        self._server.relay = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def shutdown(self):
        if self._server is not None:
            self._closing = True
            for connection in list(self.sessions.values()):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    pass
            self.sessions.clear()
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._closing = False

    def serve_forever(self):
        if self._server is None:
            self.start()
        self._server.serve_forever()

    def dispatch(self, connection, message: dict) -> dict:
        message_type = message.get("type")
        request_id = message.get("request_id")

        if message_type == "auth_request":
            device_id = message.get("device_id")
            try:
                nonce = self.auth_manager.challenge_for(device_id)
            except KeyError:
                return {"type": "error", "reason": "unknown_device", "request_id": request_id}
            return {"type": "challenge", "device_id": device_id, "nonce": nonce, "request_id": request_id}

        if message_type == "auth_response":
            device_id = message.get("device_id")
            nonce = message.get("nonce")
            signature = message.get("signature")
            try:
                token = self.auth_manager.authenticate(device_id, nonce, signature)
            except PermissionError as exc:
                return {"type": "error", "reason": str(exc), "request_id": request_id}

            with self._lock:
                self.sessions[device_id] = connection
            return {"type": "auth_ok", "device_id": device_id, "token": token, "request_id": request_id}

        if message_type == "connect_request":
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
            except Exception as exc:  # pragma: no cover - defensive path
                return {"type": "error", "reason": str(exc), "request_id": request_id}
            return {"type": "connect_ok", "device_id": device_id, "peer_id": peer_id, "channel_id": channel_id, "request_id": request_id}

        if message_type == "peer_message":
            sender = message.get("sender")
            recipient = message.get("recipient")
            payload = message.get("payload")
            channel_id = message.get("channel_id")
            if sender not in self.sessions or recipient not in self.sessions:
                return {"type": "error", "reason": "peer_unreachable", "request_id": request_id}

            forwarded = {
                "type": "peer_data",
                "from": sender,
                "channel_id": channel_id,
                "payload": payload,
            }
            peer_connection = self.sessions[recipient]
            peer_connection.sendall((json.dumps(forwarded) + "\n").encode("utf-8"))
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
