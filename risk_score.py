"""Aggregate risk score from scan results (0 = low risk, 100 = critical)."""

RISKY_PORTS = {
    21: ("FTP", 12),
    23: ("Telnet", 25),
    445: ("SMB", 18),
    3389: ("RDP", 15),
    6379: ("Redis", 22),
    27017: ("MongoDB", 22),
    9200: ("Elasticsearch", 20),
    5900: ("VNC", 14),
    1433: ("MSSQL", 10),
    3306: ("MySQL", 8),
}


def calculate_risk_score(
    open_ports: dict,
    vulnerabilities: list | None = None,
    ssl_info: dict | None = None,
    cve_high_count: int = 0,
) -> dict:
    score = 0
    factors = []

    for port, info in (open_ports or {}).items():
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        if p in RISKY_PORTS:
            name, pts = RISKY_PORTS[p]
            score += pts
            factors.append({"points": pts, "label": f"Exposed {name} (port {p})"})
        elif p not in (80, 443, 8080, 8443):
            score += 3
            svc = (info or {}).get("name", "service") if isinstance(info, dict) else "service"
            if score <= 95:
                factors.append({"points": 3, "label": f"Open port {p} ({svc})"})

    open_count = len(open_ports or {})
    if open_count > 15:
        score += 10
        factors.append({"points": 10, "label": f"Many open ports ({open_count})"})
    elif open_count > 8:
        score += 5
        factors.append({"points": 5, "label": f"Several open ports ({open_count})"})

    for v in vulnerabilities or []:
        sev = (v.get("severity") or "").lower()
        if sev == "high":
            score += 20
            factors.append({"points": 20, "label": v.get("description", "High severity issue")[:60]})
        elif sev == "medium":
            score += 10
            factors.append({"points": 10, "label": v.get("description", "Medium severity issue")[:60]})
        else:
            score += 5

    if ssl_info and ssl_info.get("available"):
        for w in ssl_info.get("warnings") or []:
            sev = (w.get("severity") or "").lower()
            pts = 15 if sev == "high" else 8
            score += pts
            factors.append({"points": pts, "label": f"TLS: {w.get('message', '')}"})
        if ssl_info.get("verification_failed"):
            score += 18
            factors.append({"points": 18, "label": "TLS certificate verification failed"})
    elif 443 in [int(p) for p in (open_ports or {}) if str(p).isdigit()]:
        pass
    elif any(str(p) == "443" for p in (open_ports or {})):
        ssl_missing = not (ssl_info and ssl_info.get("available"))
        if ssl_missing:
            score += 5
            factors.append({"points": 5, "label": "Port 443 open but TLS check unavailable"})

    if cve_high_count > 0:
        pts = min(25, cve_high_count * 8)
        score += pts
        factors.append({"points": pts, "label": f"{cve_high_count} high-severity CVE reference(s)"})

    score = min(100, max(0, score))

    if score >= 75:
        level, label, color = "critical", "Critical", "#f43f5e"
    elif score >= 50:
        level, label, color = "high", "High", "#fb923c"
    elif score >= 25:
        level, label, color = "medium", "Medium", "#fbbf24"
    else:
        level, label, color = "low", "Low", "#34d399"

    return {
        "score": score,
        "level": level,
        "label": label,
        "color": color,
        "factors": factors[:12],
        "summary": _summary(score, open_count, len(vulnerabilities or [])),
    }


def _summary(score: int, ports: int, vulns: int) -> str:
    if score >= 75:
        return "Immediate review recommended. Multiple serious exposures detected."
    if score >= 50:
        return "Elevated risk. Address exposed services and findings promptly."
    if score >= 25:
        return "Moderate risk. Review open ports and harden exposed services."
    if ports == 0:
        return "No open ports detected in this scan scope."
    return "Relatively low risk for the scanned surface. Continue regular monitoring."
