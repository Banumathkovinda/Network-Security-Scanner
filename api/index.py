import os
import sys

# Ensure project root is on path (Vercel runs this file from api/)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS

from scanner_lib import SimpleNetworkScanner

app = Flask(__name__)
CORS(app)

scanner = SimpleNetworkScanner()


@app.get("/")
def index():
    return send_from_directory("..", "index.html")


@app.post("/api/scan/network")
def scan_network():
    data = request.get_json(silent=True) or {}
    network = data.get("network")
    if not network:
        return jsonify({"error": "Network range is required"}), 400

    try:
        live_hosts = scanner.ping_sweep(network)
        return jsonify({"hosts": live_hosts})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/scan/host")
def scan_host():
    data = request.get_json(silent=True) or {}
    host = data.get("host")
    ports = data.get("ports", "1-1000")
    if not host:
        return jsonify({"error": "Host is required"}), 400

    try:
        results = scanner.port_scan(host, ports)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/scan/quick")
def quick_scan():
    data = request.get_json(silent=True) or {}
    host = data.get("host")
    if not host:
        return jsonify({"error": "Host is required"}), 400

    try:
        results = scanner.port_scan(host, "quick")
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/vulnerability/check")
def check_vulnerabilities():
    data = request.get_json(silent=True) or {}
    open_ports = data.get("ports", [])

    vulnerabilities = []

    for port_info in open_ports:
        port = port_info.get("port")
        service = (port_info.get("service") or "").lower()

        if service in ["ssh", "ftp", "telnet"]:
            vulnerabilities.append(
                {
                    "port": port,
                    "service": service,
                    "severity": "medium",
                    "description": f"Unencrypted {service.upper()} service detected",
                    "recommendation": "Use encrypted alternatives or implement strong authentication",
                }
            )

        if port == 23 and service == "telnet":
            vulnerabilities.append(
                {
                    "port": port,
                    "service": "telnet",
                    "severity": "high",
                    "description": "Telnet service transmits credentials in plaintext",
                    "recommendation": "Disable Telnet and use SSH instead",
                }
            )

        if port == 21 and service == "ftp":
            vulnerabilities.append(
                {
                    "port": port,
                    "service": "ftp",
                    "severity": "medium",
                    "description": "FTP service may allow anonymous access",
                    "recommendation": "Disable anonymous FTP or use SFTP",
                }
            )

    return jsonify({"vulnerabilities": vulnerabilities})
