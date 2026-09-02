# Security Policy

## Supported status

This project is a research prototype for zero-trust backbone concepts. It is not a hardened production deployment system.

## Current security model

The current implementation includes:

- challenge-response authentication with shared-secrets
- signed bearer tokens for session authorization
- allow-list and policy-based access control
- virtual address assignment and NAT-safe forwarding
- AES-GCM session encryption primitives for tunnel protection
- Linux route specification helpers for interface-based routing

## Reporting a vulnerability

Please report vulnerabilities privately through the repository maintainer or a private security channel. Do not open public issues for sensitive security findings until a patch is ready.

## Security limitations

This codebase is not yet intended for production use because it does not include:

- full E2E encrypted tunnel transport
- mature NAT traversal beyond central relay mediation
- strong device attestation and certificate lifecycle management
- production-ready hardening for public internet exposure
- enterprise IAM and policy federation integration
