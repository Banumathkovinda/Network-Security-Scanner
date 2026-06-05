"""
CVE lookup via NIST NVD API 2.0 (keyword search).
Optional: set NVD_API_KEY env for higher rate limits.
"""

import os
import re
import time
import urllib.parse
import urllib.request
import json
from datetime import datetime

_CACHE = {}
_CACHE_TTL = 3600
_LAST_REQUEST = 0.0
_MIN_INTERVAL = 6.5  # NVD: ~5 req/30s without API key

_SKIP_VERSIONS = {
    "unknown",
    "detected",
    "response received",
    "auth required",
    "from signature",
}


def _rate_limit():
    global _LAST_REQUEST
    elapsed = time.time() - _LAST_REQUEST
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _LAST_REQUEST = time.time()


def _normalize_version(version: str) -> str | None:
    if not version:
        return None
    v = version.strip().lower()
    if v in _SKIP_VERSIONS or v.startswith("error:"):
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", version)
    return m.group(1) if m else None


def lookup_cves(product: str, version: str | None = None, max_results: int = 10):
    product = (product or "").strip()
    if not product or product.lower() == "unknown":
        return {"error": "Valid product name required", "cves": []}

    ver = _normalize_version(version or "")
    keyword = f"{product} {ver}".strip() if ver else product
    cache_key = keyword.lower()
    cached = _CACHE.get(cache_key)
    if cached and (time.time() - cached["ts"]) < _CACHE_TTL:
        return cached["data"]

    params = {"keywordSearch": keyword, "resultsPerPage": min(max_results, 20)}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        params["apiKey"] = api_key
        global _MIN_INTERVAL
        _MIN_INTERVAL = 0.7

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    _rate_limit()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkSecurityScanner/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e), "cves": [], "keyword": keyword}

    cves = []
    for item in payload.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        cvss = None
        severity = "unknown"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss = cvss_data.get("baseScore")
                severity = (cvss_data.get("baseSeverity") or "unknown").lower()
                break
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        cves.append({
            "id": cve_id,
            "severity": severity,
            "score": cvss,
            "description": desc[:400],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        })

    result = {
        "keyword": keyword,
        "product": product,
        "version": ver or version,
        "total_results": payload.get("totalResults", len(cves)),
        "cves": cves,
        "source": "NVD API 2.0",
        "lookup_time": datetime.now().isoformat(),
    }
    _CACHE[cache_key] = {"ts": time.time(), "data": result}
    return result


def lookup_cves_for_scan(port_scan_result: dict, max_per_service: int = 5):
    if port_scan_result.get("error"):
        return {"error": port_scan_result["error"], "services": []}

    services = []
    tcp = port_scan_result.get("tcp") or {}
    for port, info in tcp.items():
        if info.get("state") != "open":
            continue
        product = info.get("product", "Unknown")
        version = info.get("version", "Unknown")
        if product == "Unknown":
            continue
        ver = _normalize_version(version)
        if not ver:
            continue
        lookup = lookup_cves(product, ver, max_results=max_per_service)
        services.append({
            "port": int(port),
            "service": info.get("name"),
            "product": product,
            "version": version,
            "cve_lookup": lookup,
        })
    return {
        "host": port_scan_result.get("host"),
        "resolved_ip": port_scan_result.get("resolved_ip"),
        "services": services,
        "lookup_time": datetime.now().isoformat(),
    }
