# Connector module

The connector is the private-resource bridge. It is installed on a machine that can reach the internal application or service, and it exposes that service to the zero-trust backbone without opening public ports on the private device.

## Install

```bash
cd modules/connector
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp config.example.toml config.toml
nano config.toml
```

## Run

```bash
python service.py --config config.toml
```

## Config

```toml
[service]
host = "0.0.0.0"
port = 9100
resource_ip = "10.240.1.10"
connector_id = "connector-1"
enrollment_token = "paste-one-time-token-here"
relay_host = "relay.example.com"
relay_port = 9000
secret = "connector-bootstrap-secret"

[controller]
url = "http://127.0.0.1:9001"
```

Create the token from the controller before starting the connector:

```bash
curl -X POST http://controller.example.com:9001/admin/connector-token \
	-H 'Content-Type: application/json' \
	-d '{"connector_id":"connector-1"}'
```

Copy the returned one-time `enrollment_token` into the connector configuration. The controller consumes it on successful registration; never commit it to Git.

The connector also authenticates outbound to the relay using its device secret. The relay must have a matching connector identity in its bootstrap configuration.

Generate a connector certificate for the client to pin:

```bash
openssl req -x509 -newkey rsa:3072 -nodes \
	-keyout connector.key -out connector.crt -days 365 \
	-subj '/CN=connector-1'
openssl x509 -in connector.crt -outform DER | sha256sum
```

Configure `tls_cert` and `tls_key` on the connector, and give the resulting SHA-256 fingerprint to the client. The relay does not receive or inspect the certificate handshake.

For a resource tunnel, the connector receives the authorized resource address and port in the paired offer, resolves the address with its local resolver, opens the private TCP connection, and forwards bytes between that connection and the client TLS stream.

## Role

- registers into the controller
- exposes an internal resource IP or private service endpoint
- accepts requests from authorized clients through the relay backbone
- acts as the private-side bridge for resource access

Use this for a private app server, internal admin portal, database host, or internal subnetwork behind NAT.
