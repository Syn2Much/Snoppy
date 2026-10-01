"""Resolve host addresses and summarize their RDAP and ASN registration data."""

import ipaddress
import socket
from urllib.parse import urlsplit


def _target_addresses(target):
    parsed = urlsplit(target if "://" in target else f"//{target}")
    hostname = parsed.hostname or target
    try:
        address = ipaddress.ip_address(hostname)
        return hostname, [str(address)]
    except ValueError:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        addresses = sorted({record[4][0] for record in records})
        return hostname, addresses


def _summarize_contacts(objects):
    contacts = []
    for role, item in (objects or {}).items():
        contact = item.get("contact") or {}
        emails = sorted({
            address.get("value")
            for address in contact.get("email", [])
            if address.get("value")
        })
        if emails or contact.get("name"):
            contacts.append({
                "role": role,
                "name": contact.get("name"),
                "emails": emails,
            })
    return contacts


def lookup_rdap(target):
    from ipwhois import IPWhois

    try:
        hostname, addresses = _target_addresses(target)
    except (socket.gaierror, ValueError) as error:
        return {"target": target, "error": str(error), "addresses": []}

    lookups = []
    for address in addresses:
        try:
            data = IPWhois(address).lookup_rdap(depth=1)
            network = data.get("network") or {}
            events = network.get("events") or []
            lookups.append({
                "address": address,
                "asn": data.get("asn"),
                "asn_cidr": data.get("asn_cidr"),
                "asn_country_code": data.get("asn_country_code"),
                "asn_description": data.get("asn_description"),
                "asn_date": data.get("asn_date"),
                "network": {
                    "name": network.get("name"),
                    "handle": network.get("handle"),
                    "cidr": network.get("cidr"),
                    "country": network.get("country"),
                    "events": [
                        event for event in events
                        if event.get("action") in {"registration", "last changed"}
                    ],
                },
                "contacts": _summarize_contacts(data.get("objects")),
            })
        except Exception as error:
            lookups.append({"address": address, "error": str(error)})

    return {"target": target, "hostname": hostname, "addresses": addresses, "rdap": lookups}