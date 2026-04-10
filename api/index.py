from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
import socket
import ipaddress
from datetime import datetime


app = Flask(__name__)
CORS(app)


class SimpleNetworkScanner:
    def ping_host(self, host, timeout=0.3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, 80))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_port(self, host, port, timeout=0.5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def get_service_name(self, port):
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt",
        }
        return common_services.get(port, "Unknown")

    def ping_sweep(self, network):
        network_obj = ipaddress.ip_network(network, strict=False)
        live_hosts = []

        # Limit to first 50 hosts to prevent long scans
        hosts_to_scan = list(network_obj.hosts())[:50]
        for host in hosts_to_scan:
            if self.ping_host(str(host)):
                live_hosts.append(str(host))

        return live_hosts

    def port_scan(self, host, ports):
        if isinstance(ports, str):
            if ports == "quick":
                port_list = [
                    21,
                    22,
                    23,
                    25,
                    53,
                    80,
                    110,
                    143,
                    443,
                    993,
                    995,
                    1433,
                    3306,
                    3389,
                    5432,
                    5900,
                    8080,
                ]
            elif "-" in ports:
                start, end = map(int, ports.split("-"))
                port_list = list(range(start, end + 1))
            else:
                port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
        else:
            port_list = ports

        results = {"host": host, "tcp": {}, "scan_time": datetime.now().isoformat()}

        for port in port_list:
            if self.scan_port(host, port):
                results["tcp"][port] = {
                    "state": "open",
                    "name": self.get_service_name(port),
                    "product": "Unknown",
                    "version": "Unknown",
                }

        return results


scanner = SimpleNetworkScanner()


@app.get("/")
def index():
    # Serve the static UI from repo root.
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

