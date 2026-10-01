"""Inspect email, nameserver, and certificate-authority DNS records."""

from urllib.parse import urlsplit


DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "s1", "s2", "mail", "dkim",
)


def _domain_name(target):
    parsed = urlsplit(target if "://" in target else f"//{target}")
    if not parsed.hostname:
        raise ValueError(f"Invalid domain: {target}")
    return parsed.hostname.rstrip(".").lower()


def audit_dns_posture(target, timeout=3):
    import dns.exception
    import dns.resolver

    domain = _domain_name(target)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    def query(name, record_type):
        try:
            return [str(record) for record in resolver.resolve(
                name, record_type, lifetime=timeout
            )]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException as error:
            return {"error": str(error)}

    txt_records = query(domain, "TXT")
    if isinstance(txt_records, dict):
        spf_records = txt_records
    else:
        spf_records = [record for record in txt_records if record.lower().startswith('"v=spf1')]

    dmarc_records = query(f"_dmarc.{domain}", "TXT")
    if not isinstance(dmarc_records, dict):
        dmarc_records = [record for record in dmarc_records if "v=dmarc1" in record.lower()]

    dkim_records = {}
    for selector in DKIM_SELECTORS:
        records = query(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            dkim_records[selector] = records

    return {
        "domain": domain,
        "records": {
            "MX": query(domain, "MX"),
            "TXT": txt_records,
            "SPF": spf_records,
            "DMARC": dmarc_records,
            "DKIM": dkim_records,
            "CAA": query(domain, "CAA"),
            "NS": query(domain, "NS"),
        },
    }