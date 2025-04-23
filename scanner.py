import socket
import ipaddress
import time
import uuid
import threading
import base64
import json
import os
import csv
import numpy as np  
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime
import nmap
import platform
from pathlib import Path
import seaborn

app = Flask(__name__)
app.secret_key = 'supersecretkey'
scans = {}

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

CONFIG, PORT_MAPPING, VULNERABILITY_SCORES = load_config()

class ScanResult:
    def __init__(self):
        self.status = 'running'
        self.results = [] 
        self.start_time = time.time()
        self.end_time = None
        self.summary = {
            'total_hosts_scanned': 0, 
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
        details = PORT_MAPPING[port_str]
        if "cves" not in details:
            details["cves"] = []
        return details
    return {
        "service": "Unknown",
        "description": "Unknown service",
        "common_exploits": "Unknown",
        "cves": []  
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

# experimental
def get_os_info(ip):
    os_config = CONFIG.get('scan', {}).get('os_fingerprinting', {})
    if not os_config.get('enabled', False):
        return None

    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O --osscan-guess')
        
        if ip in nm.all_hosts():
            os_matches = nm[ip].get('osmatch', [])
            if os_matches:
                best_match = os_matches[0]
                accuracy = int(best_match.get('accuracy', '0'))
                
                accuracy_threshold = os_config.get('accuracy_threshold', 80)
                if accuracy >= accuracy_threshold:
                    return {
                        'name': best_match.get('name', 'Unknown'),
                        'accuracy': str(accuracy),
                        'type': best_match.get('osclass', [{}])[0].get('type', 'Unknown')
                    }
                
    except Exception as e:
        print(f"OS detection error for {ip}: {e}")
    
    return None

def scan_host(ip, ports, scan_id, port_executor):
    open_ports = []
    port_details = []
    futures = {}
    
    os_info = get_os_info(ip)
    
    for port in ports:
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
            'vulnerability': vuln,
            'os_info': os_info  # Add OS info to the results
        }
        scans[scan_id].results.append(host_result)
        
        if scans[scan_id].csv_path:
            append_to_csv(scans[scan_id].csv_path, host_result)
    
    # Update progress percentage
    total_ips = scans[scan_id].summary.get('total_hosts_scanned', 0)
    if total_ips > 0:
        scans[scan_id].progress = min(100, int(len(scans[scan_id].results) / total_ips * 100))

def generate_graph(results):
    graphs = {}
    if len(results) <= 1:
        return graphs

    # Set consistent style for all plots
    plt.style.use('bmh')  # Use built-in style instead of seaborn
    colors = {'primary': '#3498db', 'secondary': '#2ecc71', 'warning': '#f1c40f', 'danger': '#e74c3c'}

    def setup_figure(fig, ax):
        fig.set_facecolor('#ffffff')
        ax.set_facecolor('#ffffff')
        ax.grid(True, linestyle='--', alpha=0.3)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.tick_params(labelsize=9)
        ax.title.set_size(11)

    vuln_counts = {'Low': 0, 'Medium': 0, 'High': 0}
    host_port_counts = {}
    
    # Create data for heatmap
    host_port_matrix = []
    ip_addresses = []
    all_ports = set()
    
    # Collect data for heatmap
    for host in results:
        ip_addresses.append(host['ip'])
        for port in host.get('open_ports', []):
            all_ports.add(port)
    
    # Sort ports for consistent display
    all_ports = sorted(list(all_ports))
    
    # Create matrix for heatmap
    for host in results:
        row = [1 if port in host.get('open_ports', []) else 0 for port in all_ports]
        host_port_matrix.append(row)
        
        rating = host.get('vulnerability')
        if rating in vuln_counts:
            vuln_counts[rating] += 1

        num_ports = len(host.get('open_ports', []))
        host_port_counts[num_ports] = host_port_counts.get(num_ports, 0) + 1

    # Generate heatmap if we have data
    if host_port_matrix and all_ports:
        fig, ax = plt.subplots(figsize=(12, max(8, len(ip_addresses) * 0.3)))
        setup_figure(fig, ax)
        im = ax.imshow(host_port_matrix, aspect='auto', cmap='YlOrRd')
        
        # Customize the plot
        ax.set_xticks(range(len(all_ports)))
        ax.set_xticklabels(all_ports, rotation=45, ha='right')
        ax.set_yticks(range(len(ip_addresses)))
        ax.set_yticklabels(ip_addresses)
        
        ax.set_title('Port Distribution Across Hosts')
        ax.set_xlabel('Ports')
        ax.set_ylabel('IP Addresses')
        
        # Add colorbar
        plt.colorbar(im, ax=ax, label='Port Status (Open/Closed)')
        
        # Adjust layout to prevent label cutoff
        plt.tight_layout()
        
        # Save heatmap
        buf = BytesIO()
        plt.savefig(buf, format="png", dpi=300, bbox_inches='tight')
        plt.close(fig)
        buf.seek(0)
        graphs['port_heatmap'] = base64.b64encode(buf.read()).decode('utf-8')

    # Existing pie chart code
    if any(vuln_counts.values()):
        fig, ax = plt.subplots(figsize=(8, 8))
        setup_figure(fig, ax)
        labels = [key for key, value in vuln_counts.items() if value > 0]
        sizes = [value for value in vuln_counts.values() if value > 0]
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%', 
                                         colors=[colors['primary'], colors['warning'], colors['danger']],
                                         startangle=140)
        ax.axis('equal')
        plt.setp(autotexts, size=9, weight="bold")
        plt.setp(texts, size=10)
        buf = BytesIO()
        plt.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        graphs['vulnerability_pie'] = base64.b64encode(buf.read()).decode('utf-8')

    # Existing bar chart code
    if host_port_counts:
        fig, ax = plt.subplots(figsize=(8, 6))
        setup_figure(fig, ax)
        num_ports = list(host_port_counts.keys())
        num_hosts = list(host_port_counts.values())
        ax.bar(num_ports, num_hosts, color=colors['primary'])
        ax.set_title('Number of Ports Open vs Number of Hosts')
        ax.set_xlabel('Number of Ports Open')
        ax.set_ylabel('Number of Hosts')
        buf = BytesIO()
        plt.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        graphs['host_bar'] = base64.b64encode(buf.read()).decode('utf-8')

    # Add service distribution chart
    if results:
        service_counts = {}
        for host in results:
            for port_detail in host.get('port_details', []):
                service = port_detail['details']['service']
                if service != 'Unknown':
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        if service_counts:
            fig, ax = plt.subplots(figsize=(10, 6))
            setup_figure(fig, ax)
            services = list(service_counts.keys())
            counts = list(service_counts.values())
            
            # Sort by count descending
            sorted_indices = sorted(range(len(counts)), key=lambda k: counts[k], reverse=True)
            services = [services[i] for i in sorted_indices]
            counts = [counts[i] for i in sorted_indices]
            
            ax.barh(services, counts, color=colors['secondary'])
            ax.set_title('Service Distribution')
            ax.set_xlabel('Number of Hosts')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format="png")
            plt.close(fig)
            buf.seek(0)
            graphs['service_distribution'] = base64.b64encode(buf.read()).decode('utf-8')

        # Add vulnerability score distribution
        port_scores = []
        for host in results:
            for port in host.get('open_ports', []):
                port_scores.append(VULNERABILITY_SCORES.get(port, 0))
                
        if port_scores:
            fig, ax = plt.subplots(figsize=(8, 5))
            setup_figure(fig, ax)
            ax.hist(port_scores, bins=10, color=colors['danger'], alpha=0.7)
            ax.set_title('Vulnerability Score Distribution')
            ax.set_xlabel('Vulnerability Score')
            ax.set_ylabel('Frequency')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format="png")
            plt.close(fig)
            buf.seek(0)
            graphs['vuln_score_dist'] = base64.b64encode(buf.read()).decode('utf-8')

    # Add port vulnerability heatmap
    if host_port_matrix and all_ports:
        fig, ax = plt.subplots(figsize=(12, max(8, len(ip_addresses) * 0.3)))
        setup_figure(fig, ax)
        
        # Create vulnerability score matrix
        vuln_matrix = []
        for host in results:
            row = [VULNERABILITY_SCORES.get(port, 0) if port in host.get('open_ports', []) else 0 for port in all_ports]
            vuln_matrix.append(row)
        
        im = ax.imshow(vuln_matrix, aspect='auto', cmap='RdYlGn_r')  # Red for high vulnerability
        
        ax.set_xticks(range(len(all_ports)))
        ax.set_xticklabels(all_ports, rotation=45, ha='right')
        ax.set_yticks(range(len(ip_addresses)))
        ax.set_yticklabels(ip_addresses)
        
        ax.set_title('Port Vulnerability Heatmap')
        ax.set_xlabel('Ports')
        ax.set_ylabel('IP Addresses')
        
        plt.colorbar(im, ax=ax, label='Vulnerability Score')
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format="png", dpi=300, bbox_inches='tight')
        plt.close(fig)
        buf.seek(0)
        graphs['port_vuln_heatmap'] = base64.b64encode(buf.read()).decode('utf-8')

    # Add vulnerability distribution heatmap
    if results and all_ports:
        # Get unique ports and vulnerability levels
        sorted_ports = sorted(all_ports)
        vulnerabilities = ['Low', 'Medium', 'High']
        
        # Create data matrix
        data = np.zeros((len(vulnerabilities), len(sorted_ports)))
        
        # Fill data matrix with actual counts of vulnerabilities per port
        for host in results:
            vuln_level = host.get('vulnerability')
            if vuln_level in vulnerabilities:
                vuln_idx = vulnerabilities.index(vuln_level)
                for port in host.get('open_ports', []):
                    if port in sorted_ports:
                        port_idx = sorted_ports.index(port)
                        data[vuln_idx][port_idx] += 1
        
        # Create the heatmap
        fig, ax = plt.subplots(figsize=(12, 6))
        setup_figure(fig, ax)
        im = ax.imshow(data, cmap='YlOrRd', aspect='auto')
        
        # Set labels
        ax.set_xticks(range(len(sorted_ports)))
        ax.set_yticks(range(len(vulnerabilities)))
        ax.set_xticklabels([f"Port {p}" for p in sorted_ports], rotation=45, ha='right')
        ax.set_yticklabels(vulnerabilities)
        
        # Add text annotations with white or black text depending on background
        for i in range(len(vulnerabilities)):
            for j in range(len(sorted_ports)):
                value = data[i][j]
                color = 'white' if value/data.max() > 0.5 else 'black'
                ax.text(j, i, int(value), ha='center', va='center', color=color)
        
        # Add colorbar and title
        plt.colorbar(im, label='Number of hosts')
        ax.set_title('Vulnerability Distribution by Port')
        
        # Adjust layout and save
        plt.tight_layout()
        
        buf = BytesIO()
        plt.savefig(buf, format="png", dpi=300, bbox_inches='tight')
        plt.close(fig)
        buf.seek(0)
        graphs['vuln_dist_heatmap'] = base64.b64encode(buf.read()).decode('utf-8')

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

@app.route('/get_local_ip', methods=['GET'])
def get_local_ip():
    hostname = socket.gethostname()
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = socket.gethostbyname(hostname)
    
    return jsonify({'ip': local_ip})

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
    
    summary['total_hosts_scanned'] = result.summary.get('total_ips', result.summary.get('total_hosts_scanned', 0))
    
    vuln_counts = {'Low': 0, 'Medium': 0, 'High': 0}
    for host in result.results:
        rating = host.get('vulnerability')
        if rating in vuln_counts:
            vuln_counts[rating] += 1
    summary['vuln_counts'] = vuln_counts
    summary['scanned_hosts'] = len(result.results) 
    
    summary['current_host'] = result.current_host
    summary['current_port'] = result.current_port
    summary['progress'] = result.progress

    csv_filename = os.path.basename(result.csv_path) if result.csv_path else None
    
    os_fingerprinting_enabled = CONFIG.get('scan', {}).get('os_fingerprinting', {}).get('enabled', False)

    return render_template('results.html', 
                           status=result.status,
                           results=result.results,
                           summary=summary,
                           graph_data=result.graph_data,
                           csv_filename=csv_filename,
                           os_fingerprinting_enabled=os_fingerprinting_enabled) 

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

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            new_config = {
                "scan": {
                    "timeout": float(request.form.get('timeout', 1)),
                    "host_workers": int(request.form.get('host_workers', 50)),
                    "port_workers": int(request.form.get('port_workers', 200)),
                    "os_fingerprinting": {
                        "enabled": request.form.get('os_fingerprinting') == 'true',
                        "accuracy_threshold": int(request.form.get('accuracy_threshold', 80))
                    },
                    "csv_export": {
                        "enabled": request.form.get('csv_export') == 'true',
                        "path": request.form.get('csv_path', 'data'),
                        "include_timestamp": request.form.get('include_timestamp') == 'true'
                    }
                },
                "server": {
                    "host": request.form.get('host', '0.0.0.0'),
                    "port": int(request.form.get('port', 5001)),
                    "debug": request.form.get('debug') == 'true'
                }
            }
            
            config_path = Path(__file__).parent / 'config.json'
            with open(config_path, 'w') as f:
                json.dump(new_config, f, indent=4)
            
            global CONFIG, PORT_MAPPING, VULNERABILITY_SCORES
            CONFIG, PORT_MAPPING, VULNERABILITY_SCORES = load_config()
            
            return jsonify({"status": "success", "message": "Settings updated successfully"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400
            
    return render_template('settings.html', config=CONFIG)

if __name__ == '__main__':
    server_config = CONFIG.get('server', {})
    app.run(
        ssl_context=('certs/cert.pem', 'certs/key.pem'), 
        host=server_config.get('host', '0.0.0.0'),
        port=server_config.get('port', 5000),
        debug=server_config.get('debug', True)
    )

