from __future__ import annotations

import fnmatch
import ipaddress
import socket
from typing import Any, Iterable


def address_matches(address: str, query: str) -> bool:
    """Match a resource IP/CIDR/FQDN or wildcard against a requested address."""
    try:
        requested_ip = ipaddress.ip_address(query)
        resource_network = ipaddress.ip_network(address, strict=False)
        return requested_ip in resource_network
    except ValueError:
        return fnmatch.fnmatchcase(query.rstrip("."), address.rstrip("."))


def find_resource(resources: Iterable[dict[str, Any]], query: str) -> dict[str, Any] | None:
    """Return the most specific resource matching an IP, FQDN, or alias."""
    matches = []
    for resource in resources:
        addresses = [resource.get("address", ""), *resource.get("aliases", [])]
        if any(address and address_matches(address, query) for address in addresses):
            matches.append(resource)
    return max(matches, key=lambda item: max(len(item.get("address", "")), *(len(alias) for alias in item.get("aliases", [])))) if matches else None


def resolve_with_local_dns(hostname: str) -> list[str]:
    """Resolve using the host resolver, which is the connector's private DNS path."""
    results = {item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    return sorted(results)
