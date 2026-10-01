"""SSL/TLS certificate inspection helpers for Snoopy. Requires cryptography."""
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlsplit
 
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
 
TIMEOUT = 5
EXPIRY_WARN_DAYS = 30
TLS_VERSIONS = [
    ssl.TLSVersion.TLSv1,
    ssl.TLSVersion.TLSv1_1,
    ssl.TLSVersion.TLSv1_2,
    ssl.TLSVersion.TLSv1_3,
]
WEAK_VERSIONS = {"TLSv1", "TLSv1_1"}
 
# Probing deprecated TLS versions is the point here, so silence Python's warning about them
warnings.filterwarnings("ignore", category=DeprecationWarning, message="ssl.TLSVersion")
 
 
def _connect(host, port, context):
    """Open a TLS connection; returns (DER cert bytes, negotiated version, cipher)."""
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True), ssock.version(), ssock.cipher()
 
 
def fetch_cert(host, port):
    """Try a verified connection first; fall back to unverified so bad certs can still be inspected."""
    result = {"verified": True, "verify_error": None}
    try:
        der, version, cipher = _connect(host, port, ssl.create_default_context())
    except ssl.SSLCertVerificationError as e:
        result["verified"] = False
        result["verify_error"] = e.verify_message
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        der, version, cipher = _connect(host, port, ctx)
    result.update(der=der, negotiated=version, cipher=cipher[0], cipher_bits=cipher[2])
    return result
 
 
def _name_attr(name, oid):
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None
 
 
def parse_cert(der) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "self_signed": cert.subject == cert.issuer,
        "serial": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "sans": sans,  # list, not dict: every entry shares the "DNS" type
        "wildcards": [s for s in sans if s.startswith("*.")],
    }
 
 
def probe_protocols(host, port):
    """Attempt one handshake per TLS version. True = server accepted it."""
    supported = {}
    for version in TLS_VERSIONS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # let local OpenSSL attempt legacy versions
            ctx.minimum_version = version
            ctx.maximum_version = version
            _connect(host, port, ctx)
            supported[version.name] = True
        except (ssl.SSLError, ValueError):
            supported[version.name] = False
        except OSError:  # reset/timeout during handshake = rejected
            supported[version.name] = False
    return supported
 
 
def assess(conn, cert, protocols):
    now = datetime.now(timezone.utc)
    days_left = (cert["not_after"] - now).days
    warnings = []
    if not conn["verified"]:
        warnings.append(f"Verification failed: {conn['verify_error']}")
    if cert["not_before"] > now:
        warnings.append("Certificate not yet valid")
    if days_left < 0:
        warnings.append(f"EXPIRED {-days_left} days ago")
    elif days_left < EXPIRY_WARN_DAYS:
        warnings.append(f"Expires in {days_left} days")
    if cert["self_signed"]:
        warnings.append("Self-signed certificate")
    weak = [v for v, ok in protocols.items() if ok and v in WEAK_VERSIONS]
    if weak:
        warnings.append(f"Weak protocols enabled: {', '.join(weak)}")
    if conn["cipher_bits"] and conn["cipher_bits"] < 128:
        warnings.append(f"Weak cipher: {conn['cipher']} ({conn['cipher_bits']} bits)")
    return {"days_left": days_left, "warnings": warnings}
 
 
def inspect(host, port):
    conn = fetch_cert(host, port)
    cert = parse_cert(conn["der"])
    protocols = probe_protocols(host, port)
    return {
        "host": f"{host}:{port}",
        "verified": conn["verified"],
        "negotiated": conn["negotiated"],
        "cipher": conn["cipher"],
        "cert": cert,
        "protocols": protocols,
        "assessment": assess(conn, cert, protocols),
    }
 
 
def print_report(r):
    c, a = r["cert"], r["assessment"]
    print(f"\n=== {r['host']} ===")
    print(f"  Subject:    {c['subject_cn']}")
    print(f"  Issuer:     {c['issuer_cn']} ({c['issuer_org']})")
    print(f"  Valid:      {c['not_before']:%Y-%m-%d} -> {c['not_after']:%Y-%m-%d} ({a['days_left']} days left)")
    print(f"  Verified:   {r['verified']}")
    print(f"  Negotiated: {r['negotiated']} / {r['cipher']}")
    print(f"  Protocols:  " + ", ".join(f"{v}={'yes' if ok else 'no'}" for v, ok in r["protocols"].items()))
    print(f"  SANs ({len(c['sans'])}): " + ", ".join(c["sans"][:20]) + (" ..." if len(c["sans"]) > 20 else ""))
    for w in a["warnings"]:
        print(f"  [!] {w}")
    if not a["warnings"]:
        print("  [ok] No issues found")
 
 
def parse_target(target):
    parsed = urlsplit(target if "://" in target else f"//{target}")
    if not parsed.hostname:
        raise ValueError(f"Invalid TLS target: {target}")
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme.lower() == "http" else 443
    return parsed.hostname, port
 
 
def inspect_targets(targets):
    results = []
    for target in targets:
        try:
            host, port = parse_target(target)
            result = inspect(host, port)
        except socket.gaierror:
            result = {"host": target, "error": "DNS lookup failed"}
        except (TimeoutError, socket.timeout):
            result = {"host": target, "error": "Connection timed out"}
        except (ConnectionRefusedError, ssl.SSLError, OSError, ValueError) as error:
            result = {"host": target, "error": str(error)}
        results.append(result)
    return results