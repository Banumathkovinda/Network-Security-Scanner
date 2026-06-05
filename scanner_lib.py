"""
Shared scan logic: open-port detection, service/version fingerprinting, result verification.
"""

import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime


class ScanVerification:
    def __init__(self):
        self.attempts = 0
        self.successful_attempts = 0
        self.errors = []
        self.timing_ms = 0
        self.confidence = 0
        self.verified = False
        self.verification_method = ""

    def to_dict(self):
        return {
            "attempts": self.attempts,
            "successful_attempts": self.successful_attempts,
            "errors": self.errors,
            "timing_ms": round(self.timing_ms, 2),
            "confidence": self.confidence,
            "verified": self.verified,
            "verification_method": self.verification_method,
        }


class SimpleNetworkScanner:
    def __init__(self):
        self.scan_results = {}
        self.scan_active = False
        self.verification_enabled = True

    @staticmethod
    def resolve_target(target: str):
        """Resolve hostname to IPv4; pass through literal IPs unchanged."""
        target = (target or "").strip()
        if not target:
            return None, None, "Target is empty"
        try:
            ipaddress.ip_address(target)
            return target, target, None
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
            if not infos:
                return target, None, f"Could not resolve: {target}"
            ip = infos[0][4][0]
            return target, ip, None
        except socket.gaierror as e:
            return target, None, f"Could not resolve {target}: {e}"

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
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
        }
        return services.get(port, "Unknown")

    def discover_host(self, host, timeout=0.3):
        discovery_ports = [80, 443, 22, 3389, 445, 139, 21, 23, 53]
        for port in discovery_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return True, port
            except Exception:
                continue
        return False, None

    def _discover_single_target(self, hostname, ip):
        """Check one host (by IP) after resolving a domain or IP."""
        is_alive, responding_port = self.discover_host(ip)
        live_hosts = [ip] if is_alive else []
        discovery_details = {}
        if is_alive and responding_port:
            discovery_details[ip] = {
                "responding_port": responding_port,
                "service": self.get_service_name(responding_port),
                "hostname": hostname if hostname != ip else None,
            }
        label = f"{hostname} ({ip})" if hostname != ip else ip
        return {
            "hosts": live_hosts,
            "total_scanned": 1,
            "network_range": label,
            "target_hostname": hostname if hostname != ip else None,
            "resolved_ip": ip,
            "discovery_method": "fast-tcp-syn",
            "discovery_ports_checked": [80, 443, 22, 3389, 445, 139, 21, 23, 53],
            "host_details": discovery_details,
        }

    def ping_sweep(self, network):
        network = (network or "").strip()
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError:
            hostname, ip, err = self.resolve_target(network)
            if err:
                return {"error": err}
            try:
                return self._discover_single_target(hostname, ip)
            except Exception as e:
                return {"error": str(e)}

        try:
            live_hosts = []
            discovery_details = {}
            hosts_to_scan = list(network_obj.hosts())[:20]

            for host in hosts_to_scan:
                is_alive, responding_port = self.discover_host(str(host))
                if is_alive:
                    live_hosts.append(str(host))
                    if responding_port:
                        discovery_details[str(host)] = {
                            "responding_port": responding_port,
                            "service": self.get_service_name(responding_port),
                        }

            return {
                "hosts": live_hosts,
                "total_scanned": len(hosts_to_scan),
                "network_range": str(network_obj),
                "discovery_method": "fast-tcp-syn",
                "discovery_ports_checked": [80, 443, 22, 3389, 445, 139, 21, 23, 53],
                "host_details": discovery_details,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _safe_decode(data: bytes) -> str:
        return data.decode("utf-8", errors="replace").strip()

    def _verify_port_scan(self, host, port, max_attempts=2):
        verification = ScanVerification()
        verification.attempts = max_attempts

        start_time = time.time()
        successful = 0
        errors = []

        for attempt in range(max_attempts):
            try:
                if self.scan_port(host, port, timeout=0.8):
                    successful += 1
                elif self.scan_port(host, port, timeout=1.5):
                    successful += 1
            except Exception as e:
                errors.append(f"Attempt {attempt + 1}: {str(e)[:50]}")

        verification.timing_ms = (time.time() - start_time) * 1000
        verification.successful_attempts = successful
        verification.errors = errors

        if successful == max_attempts:
            verification.verified = True
            verification.confidence = 100
            verification.verification_method = "multiple_success"
        elif successful > 0 and len(errors) == 0:
            verification.verified = True
            verification.confidence = 70 if successful == 1 else 85
            verification.verification_method = "partial_success"
        elif successful > 0:
            verification.verified = True
            verification.confidence = 50
            verification.verification_method = "with_errors"
        else:
            verification.verified = False
            verification.confidence = 0
            verification.verification_method = "failed"

        return successful > 0, verification

    def _calculate_confidence(self, fingerprint, verification):
        confidence = verification.confidence
        product = fingerprint.get("product", "Unknown")
        version = fingerprint.get("version", "Unknown")

        if product != "Unknown" and version != "Unknown":
            if version not in ["detected", "response received", "auth required"]:
                confidence = min(100, confidence + 20)
            else:
                confidence = min(100, confidence + 10)
        elif product != "Unknown":
            confidence = min(100, confidence + 5)

        return min(100, max(0, confidence))

    def _summarize_verifications(self, tcp_results):
        if not tcp_results:
            return {"total": 0, "verified": 0, "unverified": 0, "avg_confidence": 0}
        total = len(tcp_results)
        verified = sum(1 for p in tcp_results.values() if p.get("verified", False))
        avg_confidence = sum(p.get("confidence", 0) for p in tcp_results.values()) / total
        return {
            "total": total,
            "verified": verified,
            "unverified": total - verified,
            "avg_confidence": round(avg_confidence, 1),
        }

    def _fingerprint_http(self, host: str, port: int, use_ssl: bool, timeout: float = 1.5):
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=host)
            else:
                sock = raw
            sock.settimeout(timeout)
            req = (
                f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            sock.sendall(req)
            data = b""
            while len(data) < 65536:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                except socket.timeout:
                    break
            sock.close()
            text = self._safe_decode(data)
            headers = {}
            lines = text.splitlines()
            status_line = lines[0] if lines else ""

            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")

            if server:
                m = re.match(r"^([^/]+)/([0-9.]+)", server)
                if m:
                    return {"product": m.group(1).strip(), "version": m.group(2).strip()}
                m = re.search(r"(nginx|apache|lighttpd|nodejs|express|python|gunicorn|uwsgi)[/\s-]?v?([0-9.]+)?", server, re.I)
                if m:
                    return {"product": m.group(1).capitalize(), "version": m.group(2) or "detected"}
                return {"product": server.split()[0] if server.split() else "Web Server", "version": "detected"}

            if powered_by:
                m = re.search(r"(php|asp\.net|python|perl|ruby)/?([0-9.]+)?", powered_by, re.I)
                if m:
                    prod = m.group(1).upper() if m.group(1).lower() == "php" else m.group(1).capitalize()
                    return {"product": prod, "version": m.group(2) or "detected"}
                return {"product": powered_by.split()[0], "version": "detected"}

            body = text.split("\r\n\r\n")[-1] if "\r\n\r\n" in text else ""
            if "apache" in body.lower():
                return {"product": "Apache", "version": "from signature"}
            if "nginx" in body.lower():
                return {"product": "Nginx", "version": "from signature"}
            if "iis" in body.lower():
                return {"product": "Microsoft IIS", "version": "detected"}

            if status_line.startswith("HTTP/"):
                parts = status_line.split()
                if len(parts) >= 2:
                    if "content-type" in headers:
                        ct = headers["content-type"]
                        if "application/json" in ct:
                            return {"product": "API Server", "version": parts[0]}
                        if "text/html" in ct:
                            return {"product": "Web Server", "version": parts[0]}
                    return {"product": "HTTP Server", "version": parts[0]}

            return {"product": "HTTP Service", "version": "response received"}
        except Exception as e:
            return {"product": "HTTP Service", "version": f"error: {str(e)[:30]}"}

    def _fingerprint_mysql(self, host: str, port: int, timeout: float = 1.5):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            data = sock.recv(8192)
            sock.close()
            if len(data) < 5:
                return {"product": "MySQL/MariaDB", "version": "detected"}
            payload = data[4:]
            if not payload:
                return {"product": "MySQL/MariaDB", "version": "detected"}
            if payload[0] == 0xFF:
                if len(payload) > 3:
                    error_msg = self._safe_decode(payload[3:])
                    ver_match = re.search(r'(\d+\.\d+\.\d+)', error_msg)
                    if ver_match:
                        return {"product": "MySQL", "version": ver_match.group(1)}
                return {"product": "MySQL/MariaDB", "version": "auth required"}
            if payload[0] == 0x0A and len(payload) > 2:
                end = payload.find(b"\x00", 1)
                ver = self._safe_decode(payload[1:end] if end != -1 else payload[1:50]).strip()
                if ver:
                    if "maria" in ver.lower():
                        return {"product": "MariaDB", "version": ver}
                    return {"product": "MySQL", "version": ver}
            text = self._safe_decode(data)
            ver_match = re.search(r'(\d+\.\d+\.\d+[-\w]*)', text)
            if ver_match:
                return {"product": "MySQL/MariaDB", "version": ver_match.group(1)}
            return {"product": "MySQL/MariaDB", "version": "detected"}
        except Exception as e:
            return {"product": "MySQL/MariaDB", "version": f"error: {str(e)[:30]}"}

    def _fingerprint_banner_line(self, host: str, port: int, timeout: float = 1.5):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(2048)
        sock.close()
        line = self._safe_decode(data.splitlines()[0]) if data else ""
        if not line:
            return {"product": "Unknown", "version": "Unknown"}
        if line.upper().startswith("SSH-"):
            parts = line.split("-", 3)
            if len(parts) >= 3:
                return {"product": parts[1] or "SSH", "version": parts[2]}
            return {"product": "SSH", "version": line}
        if re.match(r"^\d{3}\s", line):
            rest = line.split(None, 1)
            msg = (rest[1] if len(rest) > 1 else "").strip()
            if port == 21:
                return {"product": "FTP", "version": msg[:200] or line[:200]}
            if port == 25:
                return {"product": "SMTP", "version": msg[:200] or line[:200]}
            return {"product": "Service", "version": msg[:200] or line[:200]}
        return {"product": line.split()[0] if line.split() else "Service", "version": line}

    def _fingerprint_generic(self, host: str, port: int, timeout: float = 1.0):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(2048)
        sock.close()
        if not data:
            return {"product": "Unknown", "version": "Unknown"}
        text = self._safe_decode(data[:512])
        return {"product": "Service", "version": text[:200]}

    def fingerprint_service(self, host: str, port: int, timeout: float = 1.2):
        name = self.get_service_name(port)
        try:
            if port in (80, 8080, 8000, 8888, 3000, 5000, 9000):
                fp = self._fingerprint_http(host, port, use_ssl=False, timeout=timeout)
                return {"name": name, **fp}
            if port == 443:
                fp = self._fingerprint_http(host, port, use_ssl=True, timeout=timeout)
                return {"name": "HTTPS", **fp}
            if port == 3306:
                fp = self._fingerprint_mysql(host, port, timeout=timeout)
                return {"name": "MySQL", **fp}
            if port in (22, 21, 23, 25, 110, 143, 993, 995):
                fp = self._fingerprint_banner_line(host, port, timeout=timeout)
                return {"name": name, **fp}
            fp = self._fingerprint_generic(host, port, timeout=timeout)
            return {"name": name, **fp}
        except Exception:
            return {"name": name, "product": "Unknown", "version": "Unknown"}

    def port_scan(self, host, ports):
        try:
            hostname, resolved_ip, resolve_err = self.resolve_target(host)
            if resolve_err:
                return {"error": resolve_err, "scan_time": datetime.now().isoformat()}

            if isinstance(ports, str):
                if ports == "quick":
                    port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
                elif "-" in ports:
                    start, end = map(int, ports.split("-"))
                    port_list = list(range(start, end + 1))
                else:
                    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
            else:
                port_list = ports

            results = {
                "host": hostname,
                "resolved_ip": resolved_ip,
                "tcp": {},
                "scan_time": datetime.now().isoformat(),
                "scan_metadata": {
                    "ports_requested": len(port_list),
                    "verification_enabled": self.verification_enabled,
                    "scan_method": "TCP_SYN",
                },
            }

            for port in port_list:
                port_open, verification = self._verify_port_scan(hostname, port)
                if port_open:
                    start_time = time.time()
                    fp = self.fingerprint_service(hostname, port)
                    fp_time = (time.time() - start_time) * 1000
                    confidence = self._calculate_confidence(fp, verification)
                    results["tcp"][port] = {
                        "state": "open",
                        "name": fp.get("name") or self.get_service_name(port),
                        "product": fp.get("product", "Unknown"),
                        "version": fp.get("version", "Unknown"),
                        "confidence": confidence,
                        "verified": verification.verified,
                        "verification": verification.to_dict(),
                        "fingerprint_time_ms": round(fp_time, 2),
                    }

            results["scan_metadata"]["ports_open"] = len(results["tcp"])
            results["scan_metadata"]["verification_summary"] = self._summarize_verifications(results["tcp"])
            return results
        except Exception as e:
            return {"error": str(e), "scan_time": datetime.now().isoformat()}
