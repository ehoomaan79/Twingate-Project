import argparse
import json
import os
import socket
import ssl
import threading
import tomllib
import urllib.request
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zero_trust_core.dns import resolve_with_local_dns
from zero_trust_core.protocol import ZeroTrustClient
from zero_trust_core.tunnel import server_tls_context


class ConnectorService:
    def __init__(self, host: str = "0.0.0.0", port: int = 9100, resource_ip: str = "10.240.1.10",
                 controller_url: str | None = None, connector_id: str = "connector-1", enrollment_token: str | None = None,
                 relay_host: str | None = None, relay_port: int = 9000, secret: str | None = None,
                 tls_cert: str | None = None, tls_key: str | None = None):
        self.host = host
        self.port = port
        self.resource_ip = resource_ip
        self.controller_url = controller_url
        self.connector_id = connector_id
        self.enrollment_token = enrollment_token
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.secret = secret
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.relay_client = None
        self._server = None
        self._closing = False

    def start(self):
        if self._server is not None:
            return self
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        if self.controller_url:
            self.register_with_controller()
        if self.relay_host and self.secret:
            self.relay_client = ZeroTrustClient(self.connector_id, self.secret, self.relay_host, self.relay_port)
            self.relay_client.connect().login()
            self._relay_thread = threading.Thread(target=self._relay_events, daemon=True)
            self._relay_thread.start()
            print(f"Connector {self.connector_id} authenticated to relay")
        print(f"Connector service listening on {self.host}:{self.port}")
        return self

    def register_with_controller(self):
        if not self.controller_url:
            return None
        payload = json.dumps({
            "connector_id": self.connector_id,
            "host": self.host,
            "port": self.port,
            "resource_ip": self.resource_ip,
            "enrollment_token": self.enrollment_token,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.controller_url.rstrip('/')}/register/connector",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            print(f"Warning: failed to register connector with controller: {exc}")
            return None

    def shutdown(self):
        self._closing = True
        if self._server is not None:
            self._server.close()
            self._server = None

    def _accept_loop(self):
        while not self._closing:
            try:
                conn, _ = self._server.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn):
        try:
            data = conn.recv(4096)
            request = json.loads(data.decode("utf-8"))
            if request.get("type") == "resource_request":
                conn.sendall(json.dumps({"type": "resource_ok", "resource_ip": self.resource_ip, "status": "reachable-via-connector"}).encode("utf-8"))
            elif request.get("type") == "dns_resolve":
                addresses = resolve_with_local_dns(request["hostname"])
                conn.sendall(json.dumps({"type": "dns_result", "hostname": request["hostname"], "addresses": addresses}).encode("utf-8"))
            else:
                conn.sendall(json.dumps({"type": "error", "reason": "unsupported_request"}).encode("utf-8"))
        except Exception as exc:
            conn.sendall(json.dumps({"type": "error", "reason": str(exc)}).encode("utf-8"))
        finally:
            conn.close()

    def accept_tls_offer(self, message: dict, certfile: str, keyfile: str):
        tunnel = socket.create_connection((self.relay_host, message["data_port"]), timeout=5)
        tunnel.sendall((json.dumps({"channel_id": message["channel_id"], "tunnel_token": message["tunnel_token"]}) + "\n").encode("utf-8"))
        return server_tls_context(certfile, keyfile).wrap_socket(tunnel, server_side=True)

    def _relay_events(self):
        while not self._closing and self.relay_client is not None:
            try:
                event = self.relay_client.receive_event(timeout=1)
            except TimeoutError:
                continue
            if event.get("type") != "peer_data":
                continue
            try:
                offer = json.loads(event.get("payload", "{}"))
                if offer.get("type") == "tunnel_offer" and self.tls_cert and self.tls_key:
                    secure = self.accept_tls_offer({**event, **offer}, self.tls_cert, self.tls_key)
                    secure.close()
            except (OSError, ValueError, ssl.SSLError):
                continue


def load_config(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def main():
    parser = argparse.ArgumentParser(description="Start connector service")
    parser.add_argument("--config", default=None, help="Optional TOML config file path")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--resource-ip", default="10.240.1.10")
    parser.add_argument("--connector-id", default="connector-1")
    parser.add_argument("--controller-url", default=None)
    parser.add_argument("--enrollment-token", default=None)
    parser.add_argument("--relay-host", default=None)
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--secret", default=None)
    args = parser.parse_args()

    config = load_config(args.config) if args.config else {}
    service_cfg = config.get("service", {})
    controller_cfg = config.get("controller", {})
    host = service_cfg.get("host", args.host)
    port = int(service_cfg.get("port", args.port))
    resource_ip = service_cfg.get("resource_ip", args.resource_ip)
    connector_id = service_cfg.get("connector_id", controller_cfg.get("connector_id", args.connector_id))
    controller_url = controller_cfg.get("url", args.controller_url)
    enrollment_token = service_cfg.get("enrollment_token", args.enrollment_token)
    relay_host = service_cfg.get("relay_host", args.relay_host)
    relay_port = int(service_cfg.get("relay_port", args.relay_port))
    secret = service_cfg.get("secret", args.secret)
    tls_cert = service_cfg.get("tls_cert")
    tls_key = service_cfg.get("tls_key")

    connector = ConnectorService(host=host, port=port, resource_ip=resource_ip,
                                controller_url=controller_url, connector_id=connector_id,
                                enrollment_token=enrollment_token, relay_host=relay_host,
                                relay_port=relay_port, secret=secret, tls_cert=tls_cert,
                                tls_key=tls_key)
    connector.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        connector.shutdown()


if __name__ == "__main__":
    main()
