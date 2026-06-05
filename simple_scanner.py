import os
from flask import Flask, send_from_directory, request, jsonify, session
from flask_cors import CORS
from scanner_lib import SimpleNetworkScanner
from nmap_scanner import is_nmap_available, nmap_port_scan
from cve_lookup import lookup_cves, lookup_cves_for_scan
from scheduler_service import (
    get_scheduler,
    list_schedules,
    add_schedule,
    remove_schedule,
    email_status,
)
from auth import auth_enabled, is_authenticated, require_auth, check_request_auth
import scan_storage
from ssl_check import check_ssl
from risk_score import calculate_risk_score


def build_security_summary(host, port_data: dict, vulnerabilities=None):
    """SSL check (if 443 open) + risk score for a port scan result."""
    tcp = port_data.get("tcp") or {}
    hostname = port_data.get("host") or host
    ssl_info = None
    if any(str(p) == "443" for p in tcp):
        ssl_info = check_ssl(hostname, 443)
    risk = calculate_risk_score(tcp, vulnerabilities, ssl_info)
    return {"ssl": ssl_info, "risk_score": risk}

_env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.isfile(_env_path):
    for line in open(_env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me-for-production")
CORS(app, supports_credentials=True)
scanner = SimpleNetworkScanner()
get_scheduler()


@app.before_request
def before_request():
    return check_request_auth()


@app.after_request
def disable_asset_cache(response):
    """Avoid stale UI after updates (Docker/local)."""
    path = request.path or ""
    if path == "/" or path.endswith(".html") or path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/login.html")
def login_page():
    return send_from_directory(".", "login.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


@app.route("/api/auth/status")
def auth_status():
    return jsonify({
        "auth_required": auth_enabled(),
        "authenticated": is_authenticated(),
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    if not auth_enabled():
        session["authenticated"] = True
        return jsonify({"ok": True, "auth_required": False})
    data = request.json or {}
    expected_key = os.environ.get("SCANNER_API_KEY", "").strip()
    expected_pw = os.environ.get("SCANNER_PASSWORD", "").strip()
    if data.get("api_key") and expected_key and data["api_key"] == expected_key:
        session["authenticated"] = True
        return jsonify({"ok": True, "api_key": expected_key})
    if data.get("password") and expected_pw and data["password"] == expected_pw:
        session["authenticated"] = True
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid password or API key"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/nmap/status")
def nmap_status():
    return jsonify({"available": is_nmap_available()})


@app.route("/api/email/status")
def get_email_status():
    return jsonify(email_status())


@app.route("/api/scans", methods=["GET"])
@require_auth
def get_scans():
    scan_type = request.args.get("type")
    return jsonify({"scans": scan_storage.list_scans(scan_type=scan_type)})


@app.route("/api/scans", methods=["POST"])
@require_auth
def post_scan():
    data = request.json or {}
    scan_type = data.get("type")
    target = data.get("target")
    payload = data.get("data")
    if not scan_type or not target or payload is None:
        return jsonify({"error": "type, target, and data required"}), 400
    return jsonify(scan_storage.save_scan(scan_type, target, payload, data.get("label"))), 201


@app.route("/api/scans/<scan_id>")
@require_auth
def get_one_scan(scan_id):
    record = scan_storage.get_scan(scan_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    return jsonify(record)


@app.route("/api/scans/compare")
@require_auth
def compare_scans_route():
    id_a = request.args.get("a")
    id_b = request.args.get("b")
    if not id_a or not id_b:
        return jsonify({"error": "Query params a and b required"}), 400
    result = scan_storage.compare_scans(id_a, id_b)
    if result.get("error"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/scan/network", methods=["POST"])
@require_auth
def scan_network():
    data = request.json or {}
    network = data.get("network")
    if not network:
        return jsonify({"error": "Network range is required"}), 400
    try:
        result = scanner.ping_sweep(network)
        if not result.get("error") and data.get("save", True):
            meta = scan_storage.save_scan("network", network, result)
            result["saved_scan_id"] = meta["id"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/host", methods=["POST"])
@require_auth
def scan_host():
    data = request.json or {}
    host = data.get("host")
    ports = data.get("ports", "1-1000")
    use_nmap = data.get("use_nmap", False)
    if not host:
        return jsonify({"error": "Host is required"}), 400
    try:
        if use_nmap:
            result = nmap_port_scan(host, ports)
        else:
            result = scanner.port_scan(host, ports)
        if not result.get("error") and data.get("save", True):
            meta = scan_storage.save_scan("port", host, result)
            result["saved_scan_id"] = meta["id"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/quick", methods=["POST"])
@require_auth
def quick_scan():
    data = request.json or {}
    host = data.get("host")
    use_nmap = data.get("use_nmap", False)
    if not host:
        return jsonify({"error": "Host is required"}), 400
    try:
        if use_nmap:
            result = nmap_port_scan(host, "quick")
        else:
            result = scanner.port_scan(host, "quick")
        if not result.get("error") and data.get("save", True):
            meta = scan_storage.save_scan("port", host, result)
            result["saved_scan_id"] = meta["id"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/nmap", methods=["POST"])
@require_auth
def scan_nmap():
    data = request.json or {}
    host = data.get("host")
    ports = data.get("ports", "quick")
    if not host:
        return jsonify({"error": "Host is required"}), 400
    if not is_nmap_available():
        return jsonify({"error": "Nmap is not installed."}), 503
    try:
        result = nmap_port_scan(host, ports)
        if not result.get("error") and data.get("save", True):
            meta = scan_storage.save_scan("port", host, result)
            result["saved_scan_id"] = meta["id"]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cve/lookup", methods=["POST"])
@require_auth
def cve_lookup_route():
    data = request.json or {}
    product = data.get("product")
    version = data.get("version")
    if not product:
        return jsonify({"error": "Product is required"}), 400
    return jsonify(lookup_cves(product, version, max_results=data.get("max_results", 10)))


@app.route("/api/cve/lookup-scan", methods=["POST"])
@require_auth
def cve_lookup_scan_route():
    data = request.json or {}
    port_data = data.get("scan_result")
    if not port_data:
        host = data.get("host")
        use_nmap = data.get("use_nmap", False)
        if not host:
            return jsonify({"error": "host or scan_result required"}), 400
        if use_nmap and is_nmap_available():
            port_data = nmap_port_scan(host, "quick")
        else:
            port_data = scanner.port_scan(host, "quick")
    return jsonify(lookup_cves_for_scan(port_data, max_per_service=data.get("max_per_service", 5)))


@app.route("/api/schedules", methods=["GET"])
@require_auth
def get_schedules():
    return jsonify({"schedules": list_schedules(), "email": email_status()})


@app.route("/api/schedules", methods=["POST"])
@require_auth
def create_schedule():
    data = request.json or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "Target is required"}), 400
    job = add_schedule(
        target=target,
        interval_hours=data.get("interval_hours", 24),
        scan_type=data.get("scan_type", "quick"),
        email=data.get("email"),
        include_cve=data.get("include_cve", False),
        use_nmap=data.get("use_nmap", False),
    )
    if job.get("error"):
        return jsonify(job), 400
    return jsonify(job), 201


@app.route("/api/schedules/<job_id>", methods=["DELETE"])
@require_auth
def delete_schedule(job_id):
    result = remove_schedule(job_id)
    if result.get("error"):
        return jsonify(result), 404
    return jsonify(result)


def compute_vulnerabilities(open_ports):
    vulnerabilities = []
    for port_info in open_ports:
        port = port_info.get("port")
        service = (port_info.get("service") or "").lower()

        if service in ["ssh", "ftp", "telnet"]:
            vulnerabilities.append({
                "port": port,
                "service": service,
                "severity": "medium",
                "description": f"Unencrypted {service.upper()} service detected",
                "recommendation": "Use encrypted alternatives or implement strong authentication",
            })

        if port == 23 and service == "telnet":
            vulnerabilities.append({
                "port": port,
                "service": "telnet",
                "severity": "high",
                "description": "Telnet service transmits credentials in plaintext",
                "recommendation": "Disable Telnet and use SSH instead",
            })

        if port == 21 and service == "ftp":
            vulnerabilities.append({
                "port": port,
                "service": "ftp",
                "severity": "medium",
                "description": "FTP service may allow anonymous access",
                "recommendation": "Disable anonymous FTP or use SFTP",
            })
    return vulnerabilities


@app.route("/api/vulnerability/check", methods=["POST"])
@require_auth
def check_vulnerabilities():
    data = request.json or {}
    return jsonify({"vulnerabilities": compute_vulnerabilities(data.get("ports", []))})


@app.route("/api/ssl/check", methods=["POST"])
@require_auth
def ssl_check_route():
    data = request.json or {}
    host = data.get("host")
    if not host:
        return jsonify({"error": "Host is required"}), 400
    port = int(data.get("port", 443))
    return jsonify(check_ssl(host, port))


@app.route("/api/security/enrich", methods=["POST"])
@require_auth
def security_enrich():
    """Add SSL + risk score to an existing port scan (+ optional vulns)."""
    data = request.json or {}
    host = data.get("host")
    port_data = data.get("port_scan") or data.get("scan_result")
    if not host and port_data:
        host = port_data.get("host")
    if not port_data:
        return jsonify({"error": "port_scan or scan_result required"}), 400
    vulns = data.get("vulnerabilities")
    if vulns is None and data.get("run_vuln_check", True):
        ports = [
            {"port": int(p), "service": i.get("name", "")}
            for p, i in (port_data.get("tcp") or {}).items()
        ]
        vulns = compute_vulnerabilities(ports)
    summary = build_security_summary(host or "unknown", port_data, vulns)
    return jsonify(summary)


@app.route("/api/security/report", methods=["POST"])
@require_auth
def security_report():
    """Quick port scan + vuln check + SSL + risk score in one report."""
    data = request.json or {}
    host = data.get("host")
    if not host:
        return jsonify({"error": "Host is required"}), 400
    use_nmap = data.get("use_nmap", False)
    try:
        if use_nmap and is_nmap_available():
            port_data = nmap_port_scan(host, "quick")
        else:
            port_data = scanner.port_scan(host, "quick")
        if port_data.get("error"):
            return jsonify(port_data), 500

        ports = [
            {"port": int(p), "service": i.get("name", "")}
            for p, i in (port_data.get("tcp") or {}).items()
        ]
        vulnerabilities = compute_vulnerabilities(ports)
        summary = build_security_summary(host, port_data, vulnerabilities)
        if not port_data.get("error"):
            meta = scan_storage.save_scan("port", host, port_data)
            port_data["saved_scan_id"] = meta["id"]

        return jsonify({
            "host": host,
            "port_scan": port_data,
            "vulnerabilities": vulnerabilities,
            "ssl": summary["ssl"],
            "risk_score": summary["risk_score"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"Starting Network Security Scanner on port {port}...")
    print(f"Open: http://127.0.0.1:{port}")
    print(f"Nmap: {is_nmap_available()} | Auth: {auth_enabled()}")
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)
