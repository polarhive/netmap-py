import socket
import ipaddress
import time
import uuid
import threading
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, render_template, redirect, url_for
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'supersecretkey'
scans = {}

VULNERABILITY_SCORES = {
    21: 1,   # FTP
    22: 2,   # SSH
    23: 3,   # Telnet
    80: 1,   # HTTP
    443: 1,  # HTTPS
    445: 4,  # SMB
    3389: 3, # RDP
    5900: 2, # VNC
    8080: 1, # HTTP Alt
}

class ScanResult:
    def __init__(self):
        self.status = 'running'
        self.results = [] 
        self.start_time = time.time()
        self.end_time = None
        self.summary = {}
        self.graph_data = None 

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

def check_port(ip, port, timeout=1):
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

def scan_host(ip, ports, scan_id, port_executor):
    open_ports = []
    futures = {port_executor.submit(check_port, ip, port): port for port in ports}
    for future in as_completed(futures):
        port = futures[future]
        try:
            if future.result():
                open_ports.append(port)
        except Exception:
            pass
    if open_ports:
        vuln = calculate_vulnerability(open_ports)
        scans[scan_id].results.append({
            'ip': ip,
            'open_ports': sorted(open_ports),
            'vulnerability': vuln
        })

def generate_graph(results):
    vuln_counts = {'Low': 0, 'Medium': 0, 'High': 0}
    for host in results:
        rating = host.get('vulnerability')
        if rating in vuln_counts:
            vuln_counts[rating] += 1

    labels = []
    sizes = []
    for key, value in vuln_counts.items():
        if value > 0:
            labels.append(key)
            sizes.append(value)

    if sizes:
        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        ax.axis('equal') 
        buf = BytesIO()
        plt.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        graph_base64 = base64.b64encode(buf.read()).decode('utf-8')
        return graph_base64
    return None

def run_scan(ip_range, ports_str, scan_id):
    try:
        ips = parse_ip_range(ip_range)
        ports = parse_ports(ports_str)
        total_ips = len(ips)
        with ThreadPoolExecutor(max_workers=200) as port_executor:
            with ThreadPoolExecutor(max_workers=50) as host_executor:
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
    summary['total_hosts_scanned'] = result.summary.get('total_ips', 0)
    vuln_counts = {'Low': 0, 'Medium': 0, 'High': 0}
    for host in result.results:
        rating = host.get('vulnerability')
        if rating in vuln_counts:
            vuln_counts[rating] += 1
    summary['vuln_counts'] = vuln_counts

    return render_template('results.html', 
                           status=result.status,
                           results=result.results,
                           summary=summary,
                           graph_data=result.graph_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

