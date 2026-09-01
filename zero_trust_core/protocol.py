import hashlib
import hmac
import json
import socket
import threading
import time
import uuid
from collections import deque
from typing import Any, Deque, Dict, Optional


class ZeroTrustClient:
    """Client-side class used to authenticate and connect to peers through the relay."""

    def __init__(self, device_id: str, secret: str, host: str = "127.0.0.1", port: int = 9000):
        self.device_id = device_id
        self.secret = secret
        self.host = host
        self.port = port
        self.token: Optional[str] = None
        self.channel_id: Optional[str] = None
        self.sock: Optional[socket.socket] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._incoming: Deque[dict] = deque()
        self._lock = threading.Lock()
        self._connected = False

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=5)
        self.sock.settimeout(2)
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()
        self._connected = True
        return self

    def login(self):
        challenge = self._send_command({"type": "auth_request", "device_id": self.device_id})
        if challenge.get("type") != "challenge":
            raise RuntimeError(f"Unexpected auth challenge: {challenge}")

        signature = hmac.new(self.secret.encode("utf-8"), challenge["nonce"].encode("utf-8"), hashlib.sha256).hexdigest()
        response = self._send_command({
            "type": "auth_response",
            "device_id": self.device_id,
            "nonce": challenge["nonce"],
            "signature": signature,
        })
        if response.get("type") != "auth_ok":
            raise RuntimeError(f"Authentication failed: {response}")

        self.token = response["token"]
        return response

    def connect_to_peer(self, peer_id: str):
        if self.token is None:
            raise RuntimeError("Client must authenticate before requesting a peer connection")

        response = self._send_command({
            "type": "connect_request",
            "device_id": self.device_id,
            "peer_id": peer_id,
            "token": self.token,
        })
        if response.get("type") != "connect_ok":
            raise RuntimeError(f"Peer connection failed: {response}")
        self.channel_id = response["channel_id"]
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

    def receive_message(self, timeout: float = 2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._incoming:
                item = self._incoming.popleft()
                if item.get("type") == "peer_data":
                    return item
            time.sleep(0.05)
        raise TimeoutError("No peer message received within timeout")

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def _reader_loop(self):
        while self.sock is not None:
            try:
                line = self.sock.makefile("r").readline()
            except (OSError, ValueError):
                break
            if not line:
                break
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("type") == "peer_data":
                self._incoming.append(item)
            else:
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
