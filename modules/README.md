# Deployable modules

This project is organized around four independently deployable services. The `modules/` tree is the public installation boundary; `zero_trust_core/` and `controller/` contain shared implementation used by those services.

## Modules

- controller: persistent control plane for identity, policy, resources, and topology
- relay: authenticated NAT-safe transport broker
- connector: private-side resource bridge
- client: endpoint agent for authenticated resource access

## Deployment boundary

Each module has its own runtime context, requirements, example TOML configuration, and setup instructions. The same service can run on a VPS, Docker container, VM, or separate Linux host. Modules communicate over configured hostnames and ports; they do not depend on a local demo runner.

## Install a module

Choose a module directory, create its virtual environment, copy its example configuration, and run its `service.py`. The module README contains the exact commands and configuration fields.

The controller should be started first. Relays and connectors then register with its URL. Clients connect to the configured relay and request resources according to controller policy.
