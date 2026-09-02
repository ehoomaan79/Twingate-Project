# Client module

The client is the endpoint agent installed on the user device. It authenticates to the relay, receives a virtual address, and uses the zero-trust backbone to reach authorized resources.

## Install

```bash
cd modules/client
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
device_id = "client-1"
user_id = "alice"
secret = "change-me"
relay_host = "relay.example.com"
relay_port = 9000

[controller]
url = "http://controller.example.com:9001"
```

## Role

- authenticates to the zero-trust relay
- registers its live endpoint with the controller
- receives virtual private IP information
- requests access decisions from the controller
- receives the authorized resource catalog, including private FQDN/IP addresses and DNS servers
- uses the tunnel path defined by the relay and controller policy

Private resource names are not published to public DNS. The controller sends authorized resource metadata to the client, and the connector resolves configured private names inside the remote network. Transparent DNS interception and encrypted packet forwarding are separate data-plane implementation stages.

This module is the user-facing client for a Linux workstation or device that needs protected access without direct inbound exposure.
