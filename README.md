# Zero-Trust Relay Prototype

This repository is a lightweight, open-source prototype inspired by Twingate-style zero-trust networking. The goal is to model the core ideas behind a private backbone for secure device-to-device connectivity without opening inbound ports on local machines.

## Main idea

The prototype focuses on three core concepts:

1. Device identity and authentication
2. Policy-based authorization for peer access
3. Relay-based NAT traversal for traffic forwarding

This is not a production-grade VPN or private access gateway. It is deliberately small and readable so it can be used as a university project and extended into a more mature system later.

## Project phases

### Phase 1: Zero-trust identity and access model

- device registry with secret-based identity
- challenge-response authentication
- signed session tokens
- simple authorization policy (allowed peer list)

### Phase 2: Relay-based connectivity

- central relay server that acts as a rendezvous broker
- clients can authenticate and request peer connections
- forwarded messages pass through the relay instead of direct inbound ports

### Phase 3: Secure channel concept

- issue signed connection tokens
- derive a session key for encryption in future versions
- support message integrity checks

### Phase 4: Simulation and validation

- local end-to-end simulation of two clients behind NAT-like conditions
- test suite for successful peer connection and blocked access
- documentation of architecture, risks, and extension roadmap

## Project structure

- `zero_trust_core/auth.py` — challenge-response auth and signed tokens
- `zero_trust_core/relay.py` — relay server and TCP message dispatch
- `zero_trust_core/protocol.py` — client class used to authenticate and connect peers
- `zero_trust_core/simulator.py` — local demo runner
- `relay_server.py` — standalone relay server entry point
- `run_simulation.py` — one-command demo
- `tests/test_relay_simulation.py` — validation tests

## Quick start

Create the local virtual environment once:

```bash
python3 -m venv .venv
```

Then activate it using the shell you are currently using. For bash/zsh/sh:

```bash
source .venv/bin/activate
```

For Fish:

```fish
source .venv/bin/activate.fish
```

Run the demo simulation:

```bash
python run_simulation.py
```

Start the relay server:

```bash
python relay_server.py --host 127.0.0.1 --port 9000
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Step-by-step final-project plan

This project is best executed in incremental phases so the core functionality remains understandable and defensible in a final-year presentation.

### Phase 1: Identity and trust base

- define the device registry and shared-secret model
- implement challenge-response authentication
- issue signed session tokens for authorized clients
- verify that only known devices can authenticate

This gives the project the first zero-trust property: no device is trusted by default; every client must prove identity before it is allowed to use the backbone.

### Phase 2: Access control and policy

- implement peer allow-lists such as `alice -> bob`
- reject unauthorized connection attempts
- validate token ownership before a device can request peer access
- document the trust boundary between authentication and authorization

At this stage, the prototype already demonstrates a real zero-trust concept: authentication answers "who are you?" while authorization answers "what are you allowed to do?".

### Phase 3: NAT traversal via relay

- maintain authenticated client sockets in a central relay
- allow clients behind NAT to rendezvous through a public relay endpoint
- assign a connection channel identifier for a permitted peer relationship
- forward messages between clients without exposing local ports

This is the core Twingate-inspired idea: clients do not need inbound port forwarding, because all traffic is brokered through a central relay.

### Phase 4: secure channel foundation

- derive or prepare a session key for future encrypted traffic
- add message integrity protection and replay checks
- store connection metadata for auditing and debugging
- prepare a migration path toward TLS or Noise-based encryption

This phase is where the project moves from a conceptual zero-trust backbone into a realistic secure communications model.

### Phase 5: simulation, testing, and defense

- run local end-to-end simulation between two devices
- verify success path and denied access path using unit tests
- document attack scenarios and trust assumptions
- prepare a final defense presentation around architecture and limitations

## How the simulation works

The repository includes a minimal end-to-end simulation of two devices behind NAT-like conditions:

1. both devices connect to the relay server
2. each client performs challenge-response authentication
3. each client requests a peer connection using a signed token
4. the relay checks authorization policy and relays the message
5. the receiving side reads the forwarded payload and confirms delivery

This keeps the project simple, testable, and suitable for a bachelor defense while still showing the real zero-trust backbone model.

## GitHub workflow

This project is already prepared for a normal GitHub repository workflow:

```bash
git init
git add .
git commit -m "Initial zero-trust relay prototype"
git branch -M main
git remote add origin git@github.com:YOUR_USERNAME/zero-trust-relay-demo.git
git push -u origin main
```

The repository includes:

- `README.md`
- `LICENSE`
- `pyproject.toml`
- `.github/workflows/ci.yml`
- `CONTRIBUTING.md`
- `SECURITY.md`

These files make the project suitable for public or private GitHub hosting and CI validation.

## How the prototype works

1. A device connects to the relay server.
2. The relay issues a challenge nonce.
3. The device signs the nonce using its shared secret.
4. The server validates the signature and issues a signed session token.
5. The device requests access to a peer using this token.
6. The server checks the peer policy and authorizes the connection.
7. Messages are relayed between both clients without opening local inbound ports.

## Security notes

This project is intentionally a learning prototype. It does not yet provide:

- end-to-end encryption with modern primitives
- certificate-based identity
- mTLS or mutual TLS
- robust NAT traversal via UDP hole punching or STUN/TURN integration
- production deployment hardening

It is best understood as the skeletal zero-trust backbone and a demonstrator for a final-year project.

## Next extension ideas

- replace demo HMAC logic with TLS or Noise protocol
- add identity and session persistence in a database
- implement UDP relay and port mapping for lower latency
- add policy engine and RBAC
- create a CLI-based admin panel for device registration and authorization
- turn the prototype into a full remote-access platform
