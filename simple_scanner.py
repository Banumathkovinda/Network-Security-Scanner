from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
from rich.console import Console

from scanner_lib import SimpleNetworkScanner

app = Flask(__name__)
CORS(app)
console = Console()

scanner = SimpleNetworkScanner()


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/scan/network", methods=["POST"])
def scan_network():
    data = request.json
    network = data.get("network")

    if not network:
        return jsonify({"error": "Network range is required"}), 400

    try:
        result = scanner.ping_sweep(network)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/host", methods=["POST"])
def scan_host():
    data = request.json
    host = data.get("host")
    ports = data.get("ports", "1-1000")

    if not host:
        return jsonify({"error": "Host is required"}), 400

    try:
        results = scanner.port_scan(host, ports)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/quick", methods=["POST"])
def quick_scan():
    data = request.json
    host = data.get("host")

    if not host:
        return jsonify({"error": "Host is required"}), 400

    try:
        results = scanner.port_scan(host, "quick")
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vulnerability/check", methods=["POST"])
def check_vulnerabilities():
    data = request.json
    host = data.get("host")
    open_ports = data.get("ports", [])

    vulnerabilities = []

    for port_info in open_ports:
        port = port_info.get("port")
        service = port_info.get("service", "").lower()

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


if __name__ == "__main__":
    print("Starting Network Security Scanner...")
    print("Open your browser and go to: http://127.0.0.1:8080")
    print("If that doesn't work, try: http://localhost:8080")
    app.run(debug=False, host="0.0.0.0", port=8080, threaded=True)
