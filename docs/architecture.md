# Architecture Overview

## Goals

This project models a minimal zero-trust backbone inspired by Twingate-style access control, but without dependency on external vendors or cloud services.

The project is intentionally designed as a step-by-step final-year prototype. The goal is not to build a production-grade private access platform, but to demonstrate the central backbone logic behind a zero-trust network in a way that is understandable, testable, and extensible.

The prototype focuses on four core ideas:

1. Device identity
2. Authorization policy
3. Relay-based connectivity
4. Simple peer-to-peer message forwarding

## Components

### 1. Authentication layer

The `AuthManager` in `zero_trust_core/auth.py` validates device identity using a challenge-response flow. Each device knows a shared secret and signs a nonce issued by the server.

Once valid, a signed bearer token is issued. The token includes:

- device identifier
- expiration time
- authorization scope

### 2. Relay broker

The `RelayServer` in `zero_trust_core/relay.py` acts as the rendezvous point. Clients connect to it even when they are behind NAT.

The relay:

- tracks authenticated client sessions
- verifies token signatures
- checks access policies
- assigns a channel identity for a permitted peer relationship
- forwards messages between authorized peers

### 3. Client protocol

The `ZeroTrustClient` in `zero_trust_core/protocol.py` performs:

- relay connection
- challenge-response authentication
- peer connection request
- data exchange over the relay

This is intentionally minimal and easy to extend.

## Trust model

The prototype uses a server-side trust anchor. In a more mature version, this could evolve into:

- certificate-based device identity
- mutual TLS
- policy engine with RBAC
- dynamic device registration
- signed session records

## Security concerns

This is a learning prototype, not a hardened deployment. Important limitations include:

- no end-to-end encryption yet
- no certificate rotation or revocation
- no protection against relay compromise
- no strong client attestation

## Future evolution

Planned upgrades include:

- Noise or TLS-based encrypted transport
- message integrity checks and replay protection
- packet-level tunneling using UDP or QUIC
- policy evaluation from explicit rules and identity providers
- support for remote device groups and service policies
