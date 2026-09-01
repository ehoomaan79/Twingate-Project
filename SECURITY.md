# Security Policy

## Supported versions

This project is currently a research and learning prototype. It is not intended for production deployment.

## Reporting a vulnerability

Please report security issues privately by emailing the maintainer or by creating a private security advisory in GitHub if available.

Please do not open public issues for sensitive vulnerabilities until a fix is available.

## Current security model

The current implementation demonstrates:

- challenge-response authentication using shared secrets
- signed bearer tokens for session authorization
- allow-list policy checks between peers
- relay-based traffic forwarding without direct inbound device ports

This prototype should be treated as an educational foundation, not a hardened production-grade network security system.
