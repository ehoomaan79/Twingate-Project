import argparse
import json
import os
import secrets
import ssl
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .database import ControllerDatabase

WEB_ROOT = Path(__file__).resolve().parents[1] / "web"


class ControllerService:
    """Central control-plane service for users, groups, relays, connectors, and clients."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9001, database_path: str = "controller.db", admin_token: str | None = None, tls_cert: str | None = None, tls_key: str | None = None):
        self.host = host
        self.port = port
        self.db = ControllerDatabase(database_path)
        self.admin_token = admin_token or secrets.token_urlsafe(32)
        self.tls_cert = tls_cert
        self.tls_key = tls_key

    def register_user(self, user_id: str, *, groups=None, roles=None, metadata=None):
        return self.db.register_user(user_id, groups=groups, roles=roles, metadata=metadata)

    def create_group(self, group_name: str, *, description: str = ""):
        return self.db.create_group(group_name, description=description)

    def register_resource(self, resource_id: str, *, address: str = "", allowed_groups=None, allowed_users=None, allowed_ports=None, allowed_protocols=None, aliases=None, dns_servers=None, visible=True, require_mfa=False, description: str = "", connector_id: str | None = None, relay_id: str | None = None):
        return self.db.register_resource(resource_id, address=address, allowed_groups=allowed_groups, allowed_users=allowed_users, allowed_ports=allowed_ports, allowed_protocols=allowed_protocols, aliases=aliases, dns_servers=dns_servers, visible=visible, require_mfa=require_mfa, description=description, connector_id=connector_id, relay_id=relay_id)

    def list_resources(self, user_id: str, *, device_trusted=False, device_compliant=False):
        return self.db.list_accessible_resources(user_id, device_trusted=device_trusted, device_compliant=device_compliant)

    def register_relay(self, relay_id: str, host: str, port: int, *, metadata=None):
        return self.db.register_relay(relay_id, host, port, metadata=metadata)

    def register_connector(self, connector_id: str, host: str, port: int, resource_ip: str, *, metadata=None):
        return self.db.register_connector(connector_id, host, port, resource_ip, metadata=metadata)

    def create_connector_token(self, connector_id: str, *, expires_at=None):
        return self.db.create_connector_token(connector_id, expires_at=expires_at)

    def register_client(self, device_id: str, host: str, port: int, virtual_ip: str | None = None, *, metadata=None):
        return self.db.register_client(device_id, host, port, virtual_ip, metadata=metadata)

    def issue_client_token(self, device_id: str, secret: str):
        return self.db.issue_client_token(device_id, secret)

    def add_security_policy(self, name: str, *, mode: str = "allow", conditions=None):
        return self.db.add_security_policy(name, mode=mode, conditions=conditions)

    def resolve_access(self, user_id: str, resource_id: str, port: int, *, mfa_verified: bool = False, device_trusted: bool = False, device_compliant: bool = False):
        return self.db.resolve_access(user_id, resource_id, port, mfa_verified=mfa_verified, device_trusted=device_trusted, device_compliant=device_compliant)

    def topology(self):
        return self.db.topology()

    def start(self):
        server = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        server.controller = self
        if self.tls_cert and self.tls_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.tls_cert, self.tls_key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"Controller service listening on {self.host}:{self.port}")
        server.serve_forever()

    def _make_handler(self):
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/admin":
                    self._send_file("admin.html", "text/html; charset=utf-8")
                    return
                if self.path == "/client":
                    self._send_file("client.html", "text/html; charset=utf-8")
                    return
                if self.path.startswith("/static/"):
                    filename = self.path.removeprefix("/static/")
                    if filename in {"styles.css", "admin.js", "client.js"}:
                        content_type = "text/css" if filename.endswith(".css") else "application/javascript"
                        self._send_file(filename, content_type)
                        return
                if self.path == "/health":
                    self._send_json({"status": "ok", "topology": controller.topology()})
                    return
                if self.path == "/topology":
                    if not self._is_admin():
                        self._send_json({"status": "unauthorized"}, status=401)
                        return
                    self._send_json({"topology": controller.topology()})
                    return
                self._send_json({"status": "not_found"}, status=404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send_json({"status": "invalid_json"}, status=400)
                    return

                admin_paths = {"/register/user", "/register/group", "/register/resource", "/register/security-policy", "/admin/connector-token"}
                if self.path in admin_paths and not self._is_admin():
                    self._send_json({"status": "unauthorized"}, status=401)
                    return

                if self.path == "/register/user":
                    item = controller.register_user(data["user_id"], groups=data.get("groups"), roles=data.get("roles"), metadata=data.get("metadata"))
                    self._send_json({"status": "ok", "user": item})
                    return
                if self.path == "/register/group":
                    item = controller.create_group(data["group_name"], description=data.get("description", ""))
                    self._send_json({"status": "ok", "group": item})
                    return
                if self.path == "/register/resource":
                    item = controller.register_resource(
                        data["resource_id"],
                        address=data.get("address", ""),
                        allowed_groups=data.get("allowed_groups"),
                        allowed_users=data.get("allowed_users"),
                        allowed_ports=set(data.get("allowed_ports", {443})),
                        allowed_protocols=set(data.get("allowed_protocols", {"tcp", "udp"})),
                        aliases=set(data.get("aliases", [])),
                        dns_servers=data.get("dns_servers", []),
                        visible=data.get("visible", True),
                        require_mfa=data.get("require_mfa", False),
                        description=data.get("description", ""),
                        connector_id=data.get("connector_id"),
                        relay_id=data.get("relay_id"),
                    )
                    self._send_json({"status": "ok", "resource": item})
                    return
                if self.path == "/client/resources":
                    user_id = data.get("user_id", "")
                    if not controller.db.verify_client_token(self._bearer_token(), user_id):
                        self._send_json({"status": "unauthorized"}, status=401)
                        return
                    resources = controller.list_resources(user_id, device_trusted=data.get("device_trusted", False), device_compliant=data.get("device_compliant", False))
                    self._send_json({"status": "ok", "resources": resources})
                    return
                if self.path == "/register/relay":
                    item = controller.register_relay(data["relay_id"], data["host"], int(data["port"]), metadata=data.get("metadata"))
                    self._send_json({"status": "ok", "relay": item})
                    return
                if self.path == "/register/connector":
                    token = data.get("enrollment_token")
                    if token is None or not controller.db.consume_connector_token(token, data["connector_id"]):
                        self._send_json({"status": "denied", "reason": "invalid_or_used_enrollment_token"}, status=403)
                        return
                    item = controller.register_connector(data["connector_id"], data["host"], int(data["port"]), data.get("resource_ip", "10.240.1.10"), metadata=data.get("metadata"))
                    self._send_json({"status": "ok", "connector": item})
                    return
                if self.path == "/admin/connector-token":
                    token = controller.create_connector_token(data["connector_id"], expires_at=data.get("expires_at"))
                    self._send_json({"status": "ok", "connector_id": data["connector_id"], "enrollment_token": token})
                    return
                if self.path == "/register/client":
                    item = controller.register_client(data["device_id"], data["host"], int(data["port"]), data.get("virtual_ip"), metadata=data.get("metadata"))
                    token = controller.issue_client_token(data.get("user_id", data["device_id"]), data.get("secret", ""))
                    self._send_json({"status": "ok", "client": item, "client_token": token})
                    return
                if self.path == "/register/security-policy":
                    item = controller.add_security_policy(data["name"], mode=data.get("mode", "allow"), conditions=data.get("conditions", {}))
                    self._send_json({"status": "ok", "policy": {"name": item.name, "mode": item.mode, "conditions": item.conditions}})
                    return
                if self.path == "/resolve/access":
                    if not self._is_admin() and not controller.db.verify_client_token(self._bearer_token(), data.get("user_id", "")):
                        self._send_json({"status": "unauthorized"}, status=401)
                        return
                    item = controller.resolve_access(
                        data["user_id"],
                        data["resource_id"],
                        int(data["port"]),
                        mfa_verified=data.get("mfa_verified", False),
                        device_trusted=data.get("device_trusted", False),
                        device_compliant=data.get("device_compliant", False),
                    )
                    self._send_json({"status": "ok" if item.get("authorized") else "denied", **item})
                    return

                self._send_json({"status": "unknown_endpoint"}, status=404)

            def log_message(self, format, *args):
                return

            def _send_json(self, payload, status=200):
                encoded = json.dumps(payload, default=str).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _send_html(self, content):
                encoded = content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _send_file(self, filename, content_type):
                path = (WEB_ROOT / filename).resolve()
                if WEB_ROOT not in path.parents:
                    self._send_json({"status": "not_found"}, status=404)
                    return
                try:
                    encoded = path.read_bytes()
                except OSError:
                    self._send_json({"status": "not_found"}, status=404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _is_admin(self):
                return self.headers.get("Authorization", "") == f"Bearer {controller.admin_token}"

            def _bearer_token(self):
                value = self.headers.get("Authorization", "")
                return value.removeprefix("Bearer ")

        return Handler


def main():
    parser = argparse.ArgumentParser(description="Start the controller service")
    parser.add_argument("--config", default=None, help="Optional TOML config file")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9001)
    parser.add_argument("--database-path", default="controller.db")
    parser.add_argument("--admin-token", default=None)
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    args = parser.parse_args()

    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "rb") as handle:
            config = tomllib.load(handle)
    service = config.get("service", {})
    ControllerService(
        host=service.get("host", args.host),
        port=int(service.get("port", args.port)),
        database_path=service.get("database_path", args.database_path),
        admin_token=service.get("admin_token", args.admin_token),
        tls_cert=service.get("tls_cert", args.tls_cert),
        tls_key=service.get("tls_key", args.tls_key),
    ).start()


ADMIN_HTML = """<!doctype html>
    <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Zero Trust Controller</title><style>
    body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#f4f6f8}h1{color:#0b5d4f}section{background:white;padding:1rem;margin:1rem 0;border:1px solid #d9e1e5;border-radius:6px}input,textarea,button{padding:.55rem;margin:.25rem;font:inherit}button{background:#0b5d4f;color:white;border:0;border-radius:4px;cursor:pointer}pre{white-space:pre-wrap;background:#17202a;color:#e8f1ee;padding:1rem;overflow:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}.muted{color:#5e6b73}
    </style></head><body><h1>Zero Trust Controller</h1>
    <p class="muted">Manage policy state and inspect registered network components. Use HTTPS in any non-local deployment.</p>
    <section><label>Admin token <input id="token" type="password" autocomplete="off"></label><button onclick="loadTopology()">Connect</button><span id="status"></span></section>
    <div class="grid"><section><h2>User</h2><input id="user" placeholder="user id"><input id="groups" placeholder="groups, comma separated"><button onclick="createUser()">Create user</button></section>
    <section><h2>Group</h2><input id="group" placeholder="group name"><button onclick="createGroup()">Create group</button></section>
    <section><h2>Resource</h2><input id="resource" placeholder="resource id"><input id="address" placeholder="private FQDN, IP or CIDR"><input id="resourceGroups" placeholder="allowed groups"><input id="ports" placeholder="ports, e.g. 443,22"><input id="dns" placeholder="connector DNS servers"><button onclick="createResource()">Create resource</button></section></div>
    <section><h2>Controller state</h2><pre id="topology">Connect to load state.</pre></section>
    <script>
    const api=(path,body)=>fetch(path,{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+document.querySelector('#token').value},body:JSON.stringify(body)}).then(async r=>{const x=await r.json();if(!r.ok)throw Error(x.reason||x.status);return x});
    const csv=id=>document.querySelector(id).value.split(',').map(x=>x.trim()).filter(Boolean);
    async function loadTopology(){const r=await fetch('/topology',{headers:{'Authorization':'Bearer '+document.querySelector('#token').value}});const x=await r.json();if(!r.ok)throw Error(x.status);document.querySelector('#topology').textContent=JSON.stringify(x,null,2);document.querySelector('#status').textContent=' connected';}
    async function createUser(){await api('/register/user',{user_id:user.value,groups:csv('#groups')});await loadTopology()}
    async function createGroup(){await api('/register/group',{group_name:group.value});await loadTopology()}
    async function createResource(){await api('/register/resource',{resource_id:resource.value,address:address.value,allowed_groups:csv('#resourceGroups'),allowed_ports:csv('#ports').map(Number),dns_servers:csv('#dns')});await loadTopology()}
</script></body></html>"""


if __name__ == "__main__":
    main()
