"""SSL/TLS certificate inspection for HTTPS targets."""

import socket
import ssl
from datetime import datetime, timezone


def check_ssl(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    hostname = (hostname or "").strip()
    if not hostname:
        return {"error": "Hostname required", "available": False}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        if not cert:
            return {"available": False, "error": "No certificate returned"}

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        def parse_cert_date(s):
            if not s:
                return None
            return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        expiry = parse_cert_date(not_after)
        now = datetime.now(timezone.utc)
        days_left = None
        expired = False
        if expiry:
            days_left = (expiry - now).days
            expired = days_left < 0

        sans = []
        for typ, val in cert.get("subjectAltName", ()):
            if typ == "DNS":
                sans.append(val)

        warnings = []
        if expired:
            warnings.append({"severity": "high", "message": "Certificate has expired"})
        elif days_left is not None and days_left <= 30:
            warnings.append({
                "severity": "medium",
                "message": f"Certificate expires in {days_left} day(s)",
            })
        if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            warnings.append({
                "severity": "high",
                "message": f"Outdated protocol: {version}",
            })

        return {
            "available": True,
            "host": hostname,
            "port": port,
            "protocol": version,
            "cipher": cipher[0] if cipher else None,
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName", "Unknown"),
            "valid_from": not_before,
            "valid_until": not_after,
            "days_until_expiry": days_left,
            "expired": expired,
            "san_dns": sans[:10],
            "warnings": warnings,
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "available": True,
            "host": hostname,
            "port": port,
            "verification_failed": True,
            "error": str(e)[:200],
            "warnings": [{"severity": "high", "message": "Certificate verification failed"}],
        }
    except Exception as e:
        return {"available": False, "host": hostname, "port": port, "error": str(e)[:200]}
