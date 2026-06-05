"""
Optional Nmap integration. Requires Nmap installed and on PATH.
https://nmap.org/download.html
"""

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

from scanner_lib import SimpleNetworkScanner

_WINDOWS_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def get_nmap_path() -> str | None:
    """Return path to nmap executable (PATH or common Windows install dirs)."""
    found = shutil.which("nmap")
    if found:
        return found
    for path in _WINDOWS_NMAP_PATHS:
        if os.path.isfile(path):
            return path
    return None


def is_nmap_available() -> bool:
    return get_nmap_path() is not None


def _parse_nmap_xml(xml_text: str, hostname: str, resolved_ip):
    tcp = {}
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            port_id = port_elem.get("portid")
            if not port_id:
                continue
            port = int(port_id)
            service_elem = port_elem.find("service")
            name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "Unknown") if service_elem is not None else "Unknown"
            version = service_elem.get("version", "Unknown") if service_elem is not None else "Unknown"
            if product == "Unknown" and service_elem is not None:
                extrainfo = service_elem.get("extrainfo", "")
                if extrainfo:
                    version = extrainfo
            tcp[port] = {
                "state": "open",
                "name": name.upper() if len(name) <= 6 else name.capitalize(),
                "product": product or "Unknown",
                "version": version or "Unknown",
                "confidence": 95,
                "verified": True,
                "verification": {"verification_method": "nmap", "confidence": 95},
            }
    return {
        "host": hostname,
        "resolved_ip": resolved_ip,
        "tcp": tcp,
        "scan_time": datetime.now().isoformat(),
        "scan_metadata": {
            "scan_method": "nmap",
            "ports_open": len(tcp),
            "nmap_available": True,
        },
    }


def nmap_port_scan(host: str, ports: str = "quick", timeout: int = 120):
    if not is_nmap_available():
        return {
            "error": "Nmap is not installed or not on PATH. Install from https://nmap.org/download.html",
            "scan_time": datetime.now().isoformat(),
        }

    hostname, resolved_ip, err = SimpleNetworkScanner.resolve_target(host)
    if err:
        return {"error": err, "scan_time": datetime.now().isoformat()}

    if ports == "quick":
        port_arg = None
        extra = ["-F"]
    elif "-" in str(ports):
        port_arg = str(ports)
        extra = []
    else:
        port_arg = str(ports)
        extra = []

    nmap_bin = get_nmap_path() or "nmap"
    cmd = [
        nmap_bin,
        "-sT",
        "-sV",
        "--version-intensity",
        "2",
        "-T4",
        "-oX",
        "-",
        *extra,
    ]
    if port_arg:
        cmd.extend(["-p", port_arg])
    cmd.append(hostname)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Nmap scan timed out after {timeout}s", "scan_time": datetime.now().isoformat()}
    except Exception as e:
        return {"error": str(e), "scan_time": datetime.now().isoformat()}

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or proc.stdout or "Nmap failed").strip()[:500]
        return {"error": err, "scan_time": datetime.now().isoformat()}

    try:
        result = _parse_nmap_xml(proc.stdout, hostname, resolved_ip)
        if proc.stderr and "Note: Host seems down" in proc.stderr:
            result["warning"] = "Host may be down or blocking scans"
        return result
    except ET.ParseError as e:
        return {"error": f"Failed to parse Nmap output: {e}", "scan_time": datetime.now().isoformat()}
