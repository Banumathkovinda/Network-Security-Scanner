from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
import socket
import threading
import time
import json
import ipaddress
from datetime import datetime
from rich.console import Console

app = Flask(__name__)
CORS(app)
console = Console()

class SimpleNetworkScanner:
    def __init__(self):
        self.scan_results = {}
        self.scan_active = False
        
    def ping_host(self, host, timeout=0.3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, 80))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_port(self, host, port, timeout=0.5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_service_name(self, port):
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return common_services.get(port, 'Unknown')
    
    def ping_sweep(self, network):
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            live_hosts = []
            
            # Limit to first 50 hosts to prevent long scans
            hosts_to_scan = list(network_obj.hosts())[:50]
            
            for host in hosts_to_scan:
                if self.ping_host(str(host)):
                    live_hosts.append(str(host))
                    
            return live_hosts
        except Exception as e:
            return {'error': str(e)}
    
    def port_scan(self, host, ports):
        try:
            if isinstance(ports, str):
                if ports == 'quick':
                    port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
                elif '-' in ports:
                    start, end = map(int, ports.split('-'))
                    port_list = list(range(start, end + 1))
                else:
                    port_list = [int(p.strip()) for p in ports.split(',')]
            else:
                port_list = ports
            
            results = {
                'host': host,
                'tcp': {},
                'scan_time': datetime.now().isoformat()
            }
            
            for port in port_list:
                if self.scan_port(host, port):
                    results['tcp'][port] = {
                        'state': 'open',
                        'name': self.get_service_name(port),
                        'product': 'Unknown',
                        'version': 'Unknown'
                    }
            
            return results
        except Exception as e:
            return {'error': str(e)}

scanner = SimpleNetworkScanner()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/scan/network', methods=['POST'])
def scan_network():
    data = request.json
    network = data.get('network')
    
    if not network:
        return jsonify({'error': 'Network range is required'}), 400
    
    try:
        live_hosts = scanner.ping_sweep(network)
        return jsonify({'hosts': live_hosts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/host', methods=['POST'])
def scan_host():
    data = request.json
    host = data.get('host')
    ports = data.get('ports', '1-1000')
    
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    
    try:
        results = scanner.port_scan(host, ports)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/quick', methods=['POST'])
def quick_scan():
    data = request.json
    host = data.get('host')
    
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    
    try:
        results = scanner.port_scan(host, 'quick')
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerability/check', methods=['POST'])
def check_vulnerabilities():
    data = request.json
    host = data.get('host')
    open_ports = data.get('ports', [])
    
    vulnerabilities = []
    
    for port_info in open_ports:
        port = port_info.get('port')
        service = port_info.get('service', '').lower()
        
        if service in ['ssh', 'ftp', 'telnet']:
            vulnerabilities.append({
                'port': port,
                'service': service,
                'severity': 'medium',
                'description': f'Unencrypted {service.upper()} service detected',
                'recommendation': 'Use encrypted alternatives or implement strong authentication'
            })
        
        if port == 23 and service == 'telnet':
            vulnerabilities.append({
                'port': port,
                'service': 'telnet',
                'severity': 'high',
                'description': 'Telnet service transmits credentials in plaintext',
                'recommendation': 'Disable Telnet and use SSH instead'
            })
        
        if port == 21 and service == 'ftp':
            vulnerabilities.append({
                'port': port,
                'service': 'ftp',
                'severity': 'medium',
                'description': 'FTP service may allow anonymous access',
                'recommendation': 'Disable anonymous FTP or use SFTP'
            })
    
    return jsonify({'vulnerabilities': vulnerabilities})

if __name__ == '__main__':
    print("Starting Network Security Scanner...")
    print("Open your browser and go to: http://127.0.0.1:8080")
    print("If that doesn't work, try: http://localhost:8080")
    app.run(debug=False, host='0.0.0.0', port=8080, threaded=True)
