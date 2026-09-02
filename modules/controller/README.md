# Controller module

The controller is the policy and topology brain of the network. It is the server that receives relay, connector, and client registration and decides which client is allowed to reach which resource.

## Install

```bash
cd modules/controller
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

Open `http://controller-host:9001/admin` for the administrator console and enter the configured `admin_token`. The console manages users, groups, and resources; changes are persisted in SQLite. Protect a public deployment with TLS by configuring `tls_cert` and `tls_key`, then use an `https://` controller URL.

## Config

Edit the generated `config.toml` file to set:

```toml
[service]
host = "0.0.0.0"
port = 9001
database_path = "controller.db"
```

## What it manages

- relay registration
- connector registration
- client registration
- authorized access resolution
- user/group/resource policy records

## Important endpoints

- GET /health
- GET /topology
- POST /register/relay
- POST /register/connector
- POST /register/client

Administrative mutation endpoints require `Authorization: Bearer <admin_token>`. Connector enrollment uses its own one-time token and is not an admin bearer token.

This service should be hosted on a stable VPS or private server so relays and connectors can reach it over a fixed hostname or IP.
