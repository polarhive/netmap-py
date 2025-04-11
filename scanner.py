import socket
import ipaddress
import time
import uuid
import threading
import base64
import json
import os
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, render_template, redirect, url_for, send_from_directory
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'
scans = {}

# Load configurations from JSON files
def load_config():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.json')
    mapping_path = os.path.join(script_dir, 'mapping.json')
    
    config = {}
    port_mapping = {}
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        with open(mapping_path, 'r') as f:
            port_mapping = json.load(f)
    except FileNotFoundError as e:
        print(f"Config file not found: {e}") 

    vulnerability_scores = {}
    for port, details in port_mapping.items():
        vulnerability_scores[int(port)] = details.get("score", 1)
    
    return config, port_mapping, vulnerability_scores

# Load configuration
CONFIG, PORT_MAPPING, VULNERABILITY_SCORES = load_config()

class ScanResult:
    def __init__(self):
        self.status = 'running'
        self.results = [] 
        self.start_time = time.time()
        self.end_time = None
        self.summary = {
            'total_hosts_scanned': 0,  # Initialize to zero
            'vuln_counts': {'Low': 0, 'Medium': 0, 'High': 0},
            'scanned_hosts': 0
        }
        self.graph_data = None
        self.csv_path = None
        self.current_host = None
        self.current_port = None
        self.progress = 0

def parse_ip_range(ip_range):
    ips = []
    try:
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        elif '-' in ip_range:
            if ip_range.count('.') == 3 and '-' in ip_range.split('.')[-1]:
                base = '.'.join(ip_range.split('.')[:-1])
                start, end = ip_range.split('.')[-1].split('-')
                for i in range(int(start), int(end)+1):
                    ips.append(f"{base}.{i}")
            else:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                while start <= end:
                    ips.append(str(start))
                    start += 1
        else:
            ips.append(ip_range.strip())
    except Exception as e:
        print(f"Error parsing IP range: {e}")
    return ips

def parse_ports(ports_str):
    ports = set()
    try:
        parts = ports_str.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start.strip()), int(end.strip()) + 1))
            else:
                ports.add(int(part))
    except Exception as e:
        print(f"Error parsing ports: {e}")
    return sorted(ports)

def check_port(ip, port, timeout=None):
    if timeout is None:
        timeout = CONFIG.get('scan', {}).get('timeout', 1)
        
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def calculate_vulnerability(open_ports):
    total = sum(VULNERABILITY_SCORES.get(port, 0) for port in open_ports)
    if total <= 3:
        return 'Low'
    elif total <= 6:
        return 'Medium'
    else:
        return 'High'

def get_port_details(port):
    port_str = str(port)
    if port_str in PORT_MAPPING:
        return PORT_MAPPING[port_str]
    return {
        "service": "Unknown",
        "description": "Unknown service",
        "common_exploits": "Unknown"
    }

def create_csv_file(scan_id):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    csv_settings = CONFIG.get('scan', {}).get('csv_export', {})
    csv_path = csv_settings.get('path', 'scan_results')
    include_timestamp = csv_settings.get('include_timestamp', True)
    
    csv_dir = os.path.join(script_dir, csv_path)
    
    if not os.path.exists(csv_dir):
        os.makedirs(csv_dir)
    
    if include_timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'scan_{scan_id}_{timestamp}.csv'
    else:
        filename = f'scan_{scan_id}.csv'
        
    file_path = os.path.join(csv_dir, filename)
    
    with open(file_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['IP Address', 'Open Ports', 'Services', 'Vulnerability Level'])
    
    return file_path

def append_to_csv(csv_path, host_result):
    try:
        with open(csv_path, 'a', newline='') as csv_file:
            writer = csv.writer(csv_file)
            
            ip = host_result['ip']
            open_ports = ','.join(map(str, host_result['open_ports'])) if host_result['open_ports'] else 'None'
            
            services = []
            for port_detail in host_result['port_details']:
                service = port_detail['details']['service']
                services.append(f"{service} ({port_detail['port']})")
            services_str = ','.join(services) if services else 'None'
            
            vuln_level = host_result['vulnerability']
            
            writer.writerow([ip, open_ports, services_str, vuln_level])
    except Exception as e:
        print(f"Error writing to CSV: {e}")

def scan_host(ip, ports, scan_id, port_executor):
    open_ports = []
    port_details = []
    futures = {}
    
    # Submit all port check tasks
    for port in ports:
        # Update current host/port being scanned
        scans[scan_id].current_host = ip
        scans[scan_id].current_port = port
        futures[port_executor.submit(check_port, ip, port)] = port
        
    # Process results as they complete
    for future in as_completed(futures):
        port = futures[future]
        try:
            if future.result():
                open_ports.append(port)
                port_details.append({
                    "port": port,
                    "details": get_port_details(port)
                })
        except Exception:
            pass
            
    if open_ports:
        vuln = calculate_vulnerability(open_ports)
        host_result = {
            'ip': ip,
            'open_ports': sorted(open_ports),
            'port_details': sorted(port_details, key=lambda x: x["port"]),
            'vulnerability': vuln
        }
        scans[scan_id].results.append(host_result)
        
        if scans[scan_id].csv_path:
            append_to_csv(scans[scan_id].csv_path, host_result)
    
    # Update progress percentage
    total_ips = scans[scan_id].summary.get('total_hosts_scanned', 0)
    if total_ips > 0:
        scans[scan_id].progress = min(100, int(len(scans[scan_id].results) / total_ips * 100))

def generate_graph(results):
    vuln_counts = {'Low': 0, 'Medium': 0, 'High': 0}
    port_counts = {port: 0 for port in VULNERABILITY_SCORES.keys()}  # Initialize only specific ports
    host_port_counts = {}

    # Calculate data for graphs
    for host in results:
        rating = host.get('vulnerability')
        if rating in vuln_counts:
            vuln_counts[rating] += 1

        for port in host.get('open_ports', []):
            if port in port_counts:  # Only count specific ports
                port_counts[port] += 1

        num_ports = len(host.get('open_ports', []))
        host_port_counts[num_ports] = host_port_counts.get(num_ports, 0) + 1

    graphs = {}

    # Pie chart for vulnerability levels
    if any(vuln_counts.values()):
        fig, ax = plt.subplots()
        labels = [key for key, value in vuln_counts.items() if value > 0]
        sizes = [value for value in vuln_counts.values() if value > 0]
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        ax.axis('equal')
        buf = BytesIO()
        plt.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        graphs['vulnerability_pie'] = base64.b64encode(buf.read()).decode('utf-8')

    # Bar chart for port number vs number of times open
    if any(port_counts.values()):
        fig, ax = plt.subplots()
        ports = list(port_counts.keys())
        counts = list(port_counts.values())
        ax.bar(ports, counts, color='blue')
        ax.set_title('Port Number vs Number of Times Open')
        ax.set_xlabel('Port Number')
        ax.set_ylabel('Number of Times Open')
        buf = BytesIO()
        plt.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        graphs['port_bar'] = base64.b64encode(buf.read()).decode('utf-8')

    # Bar chart for number of ports open vs number of hosts
    if host_port_counts:
        fig, ax = plt.subplots()
        num_ports = list(host_port_counts.keys())
        num_hosts = list(host_port_counts.values())
        ax.bar(num_ports, num_hosts, color='orange')
        ax.set_title('Number of Ports Open vs Number of Hosts')
        ax.set_xlabel('Number of Ports Open')
        ax.set_ylabel('Number of Hosts')
        buf = BytesIO()
        plt.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        graphs['host_bar'] = base64.b64encode(buf.read()).decode('utf-8')

    return graphs

def run_scan(ip_range, ports_str, scan_id):
    try:
        ips = parse_ip_range(ip_range)
        ports = parse_ports(ports_str)
        total_ips = len(ips)
        
        # Set total hosts to scan in summary
        scans[scan_id].summary['total_hosts_scanned'] = total_ips
        
        csv_enabled = CONFIG.get('scan', {}).get('csv_export', {}).get('enabled', True)
        if csv_enabled:
            scans[scan_id].csv_path = create_csv_file(scan_id)
        
        host_workers = CONFIG.get('scan', {}).get('host_workers', 50)
        port_workers = CONFIG.get('scan', {}).get('port_workers', 200)
        
        with ThreadPoolExecutor(max_workers=port_workers) as port_executor:
            with ThreadPoolExecutor(max_workers=host_workers) as host_executor:
                host_futures = []
                for ip in ips:
                    host_futures.append(host_executor.submit(scan_host, ip, ports, scan_id, port_executor))
                for future in as_completed(host_futures):
                    future.result()
        scans[scan_id].summary['total_ips'] = total_ips
    except Exception as e:
        print(f"Scan error: {e}")
    finally:
        scans[scan_id].end_time = time.time()
        scans[scan_id].graph_data = generate_graph(scans[scan_id].results)
        scans[scan_id].status = 'completed'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ip_range = request.form['ip_range']
        auto_scan = request.form.get('auto_scan')
        if auto_scan:
            # Use the most vulnerable ports (sorted by score descending)
            ports_str = ','.join(map(str, sorted(VULNERABILITY_SCORES.keys(), key=lambda p: VULNERABILITY_SCORES[p], reverse=True)))
        else:
            ports_str = request.form['ports']
        scan_id = str(uuid.uuid4())
        scans[scan_id] = ScanResult()
        threading.Thread(target=run_scan, args=(ip_range, ports_str, scan_id)).start()
        return redirect(url_for('results', scan_id=scan_id))
    return render_template('index.html')

@app.route('/results/<scan_id>')
def results(scan_id):
    result = scans.get(scan_id)
    if not result:
        return "Scan not found", 404

    summary = {}
    if result.end_time:
        summary['duration'] = round(result.end_time - result.start_time, 2)
    
    # Ensure total_hosts_scanned is always set
    summary['total_hosts_scanned'] = result.summary.get('total_ips', result.summary.get('total_hosts_scanned', 0))
    
    vuln_counts = {'Low': 0, 'Medium': 0, 'High': 0}
    for host in result.results:
        rating = host.get('vulnerability')
        if rating in vuln_counts:
            vuln_counts[rating] += 1
    summary['vuln_counts'] = vuln_counts
    summary['scanned_hosts'] = len(result.results)  # Add count of currently scanned hosts
    
    # Add current host/port information
    summary['current_host'] = result.current_host
    summary['current_port'] = result.current_port
    summary['progress'] = result.progress

    csv_filename = os.path.basename(result.csv_path) if result.csv_path else None

    return render_template('results.html', 
                           status=result.status,
                           results=result.results,
                           summary=summary,
                           graph_data=result.graph_data,
                           csv_filename=csv_filename)

@app.route('/download/<filename>')
def download_file(filename):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_settings = CONFIG.get('scan', {}).get('csv_export', {})
    csv_path = csv_settings.get('path', 'scan_results')
    csv_dir = os.path.join(script_dir, csv_path)
    
    return send_from_directory(
        directory=csv_dir,
        path=filename,
        as_attachment=True
    )

if __name__ == '__main__':
    server_config = CONFIG.get('server', {})
    app.run(
        host=server_config.get('host', '0.0.0.0'),
        port=server_config.get('port', 5000),
        debug=server_config.get('debug', True)
    )

