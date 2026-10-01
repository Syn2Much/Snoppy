"""Resolve hostnames to unique IPv4 and IPv6 addresses."""

import socket
from urllib.parse import urlsplit


def resolve_host(target):
    parsed = urlsplit(target if "://" in target else f"//{target}")
    hostname = parsed.hostname or target
    try:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        return {"target": target, "hostname": hostname, "addresses": [], "error": str(error)}

    addresses = {}
    for family, _, _, _, sockaddr in records:
        version = "IPv4" if family == socket.AF_INET else "IPv6"
        addresses[(version, sockaddr[0])] = {"family": version, "address": sockaddr[0]}
    return {
        "target": target,
        "hostname": hostname,
        "addresses": list(addresses.values()),
    }


def resolve_hosts(targets):
    return [resolve_host(target) for target in targets]