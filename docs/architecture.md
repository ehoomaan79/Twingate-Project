# Architecture Overview

## Goals

This project implements a Linux-first, Twingate-inspired zero-trust backbone using independently deployable services. It prioritizes a complete, inspectable control/data-plane foundation over pretending to provide every commercial feature.

The design focuses on five layers:

1. device identity and authentication
2. authorization and policy enforcement
3. relay-based NAT-safe connectivity
4. connector-based private service exposure
5. Linux-friendly route and tunnel integration

## Components

### 1. Authentication layer

The `AuthManager` validates device identity using challenge-response logic and signed tokens. The token includes expiry and scope metadata so each request can be verified independently.

### 2. Relay broker

The relay tracks authenticated sessions and brokers access between peers without requiring local machine port forwarding. It assigns private virtual addresses and manages route metadata for each allowed connection.

The relay is not the policy database and should not contain the complete network configuration. Its production role is to help a client and connector establish a session; authorization is supplied by controller claims and independently checked by the connector.

### 3. Connector layer

The connector runs on the private side of a deployment, registers with the controller, and exposes configured resource metadata without requiring the resource itself to accept public inbound connections.

Connector deployment is enrollment-token based: an administrator creates a one-time token in the controller, installs it on the private host, and the controller consumes it during registration. The connector resolves private DNS names locally before forwarding traffic.

### 4. Policy engine

The policy engine evaluates user, device, and resource context. It supports allow-lists, resource ports, MFA enforcement, and trust/compliance checks.

### 5. Tunnel and routing primitives

The project includes AES-GCM session primitives and Linux route command generation. The relay service has a separate tunnel data listener: after authorization, client and connector make outbound connections to it, the relay pairs the channel and copies bytes, and TLS 1.3 is established directly between endpoints with certificate fingerprint pinning. Kernel interface installation and encrypted packet forwarding remain separate implementation stages.

The client resource catalog is control-plane functionality. It is not a tunnel and does not expose private DNS records publicly.

## Trust model

The controller is the trust and policy authority. Relays and connectors register their reachable endpoints, clients authenticate, and an access decision must resolve to an available relay and connector before a route is returned.

## Security concerns

This is not yet a production-grade platform. Important known limitations include:

- the controller HTTP API needs administrator authentication and TLS termination before internet exposure
- transparent TCP/UDP proxying and kernel interception are still being expanded beyond the current TLS stream API
- interface routing is Linux-oriented and not generalized across every OS
- scalability and enterprise policy federation are still limited

## Future evolution

Planned upgrades include:

- full encrypted tunnel transport with robust session key rotation
- dynamic route management for real kernel interface provisioning
- production NAT traversal strategies beyond centralized relay mediation
- enterprise IAM and device compliance integration
- distributed controller and multi-relay topology
