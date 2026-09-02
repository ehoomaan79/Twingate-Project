# Relay module

The relay is the NAT-safe session broker for the network. It authenticates clients and provides the virtual network path without needing the protected device to accept inbound ports from the internet.

## Install

```bash
cd modules/relay
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
port = 9000
relay_id = "relay-1"

[controller]
url = "http://127.0.0.1:9001"

[[devices]]
device_id = "client-1"
secret = "change-me"
allowed_peers = ["connector-1"]
```

## Behavior

- authenticates clients using challenge-response flow
- validates token trust
- assigns virtual private IPs
- checks whether a device is allowed to reach another peer
- returns NAT-safe route metadata for authorized sessions

The `devices` entries are the relay's bootstrap identity registry. In the next security stage these credentials will be replaced with controller-issued device credentials; never commit real secrets to a public repository.

This is the module that should run on a public or internet-reachable server so devices can connect without opening inbound local ports.
