# Twingate-inspired Zero-Trust Backbone

This repository is a Linux-first, open-source backbone inspired by Twingate. The goal is to provide a deployable zero-trust access model where users, groups, relays, connectors, and clients are connected through a controller that decides who can access which resource without exposing local services to the public internet.

## What this project is

This repo is designed around a real deployment model, not a single demo script:

- controller: central policy and topology brain
- relay: NAT-safe message broker and virtual network coordinator
- connector: private resource bridge for internal services
- client: device agent that authenticates and receives authorized routes

The architecture is intentionally simple and understandable for a final-year project, while still matching the main Twingate ideas:

- no inbound ports on protected devices
- relay-based connectivity over a trusted backbone
- user and group authorization checks
- private virtual addressing for protected resources
- easy per-module deployment and configuration

## Repository layout

- root docs and project overview: `README.md`
- reusable networking/security logic: `zero_trust_core/`
- controller service: `modules/controller/`
- relay service: `modules/relay/`
- connector service: `modules/connector/`
- client service: `modules/client/`
- tests: `tests/`

## GitHub-friendly module structure

Anyone opening the GitHub page should be able to see the whole architecture without extra hidden logic:

```text
modules/
	controller/
		README.md
		requirements.txt
		service.py
		config.example.toml
	relay/
		README.md
		requirements.txt
		service.py
		config.example.toml
	connector/
		README.md
		requirements.txt
		service.py
		config.example.toml
	client/
		README.md
		requirements.txt
		service.py
		config.example.toml
```

Each module is designed to be installed and run independently on its own Linux host, VM, or VPS.

## Quick install flow

### Root project setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

### Controller deployment

```bash
cd modules/controller
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
nano config.toml
python service.py --config config.toml
```

### Relay deployment

```bash
cd modules/relay
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
nano config.toml
python service.py --config config.toml
```

### Connector deployment

```bash
cd modules/connector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
nano config.toml
python service.py --config config.toml
```

### Client deployment

```bash
cd modules/client
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
nano config.toml
python service.py --config config.toml
```

## Deployment workflow

1. Start the controller on a VPS or server.
2. Configure the relay to point to the controller URL and to expose a relay ID and listening port.
3. Configure the connector with its controller URL, connector ID, resource IP, and private resource address.
4. Launch the client with the relay host information and device secret.
5. The client authenticates to the relay, registers with the controller, and receives its authorized resource catalog.
6. A resource request is resolved by the controller and can proceed only when user, group, device, port, relay, and connector checks succeed.

This makes the controller the main brain for access decisions, while the relay and connector simply provide the runtime path for traffic and session routing.

## What the user configures

The project is designed so a practical deployment can be customized by editing only the module config files:

- controller: host, port, database path
- relay: relay ID, controller URL, open relay port, NAT-safe network range
- connector: connector ID, controller URL, resource IP, local private service address
- client: device ID, secret, relay host, relay port, optional controller URL

Resources can be represented by private FQDNs, IP addresses, or CIDR ranges. Resource configuration also supports aliases, DNS server metadata, visibility, protocols, and port restrictions.

## Production status

This is a solid foundational zero-trust backbone and a practical final-year project, but it is not yet a full commercial Twingate replacement. The next engineering steps are:

- persistent database backend for controller state
- real end-to-end encrypted tunnel traffic
- better NAT traversal and relay failover
- real Linux kernel route installation and policy enforcement

## Documentation

- [modules/README.md](modules/README.md)
- [docs/architecture.md](docs/architecture.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

## Git workflow

Configuration files containing tokens, SQLite databases, private keys, virtual environments, and build output are ignored by `.gitignore`. Before publishing changes:

```bash
git status
git diff --check
git add README.md docs modules controller zero_trust_core tests Makefile
git commit -m "Describe the change"
git push origin main
```

Do not add `config.toml`, enrollment tokens, admin tokens, database files, or TLS private keys to GitHub. The `config.example.toml` files are the shareable templates.
