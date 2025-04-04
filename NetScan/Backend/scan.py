from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import json
from datetime import datetime
import random
import time
import uuid

app = Flask(__name__, static_folder='static')

# Mock data storage
scan_history = []
mock_scan_results = {}

# Helper function to validate IP address format
def is_valid_ip(ip):
    # Basic validation - can be improved for more robust checking
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

# Helper function to validate IP range or list
def validate_ip_target(target):
    # Check if it's a single IP
    if is_valid_ip(target):
        return True
    
    # Check if it's a comma-separated list
    if ',' in target:
        for ip in target.split(','):
            if not is_valid_ip(ip.strip()):
                return False
        return True
    
    # Check if it's a range (e.g., 192.168.1.1-10)
    if '-' in target:
        parts = target.split('-')
        if len(parts) != 2:
            return False
        
        base_parts = parts[0].split('.')
        if len(base_parts) != 4:
            return False
        
        try:
            end = int(parts[1])
            if end < 0 or end > 255:
                return False
            
            # Extract the base part of the IP
            base_ip = '.'.join(base_parts[:3])
            start = int(base_parts[3])
            
            if start < 0 or start > 255 or start > end:
                return False
                
            return True
        except ValueError:
            return False
    
    return False

# Generate mock scan results based on scan type and options
def generate_mock_results(target, scan_type, options=None):
    if options is None:
        options = {}
    
    # Base results structure
    scan_id = str(uuid.uuid4())
    
    # Parse target to get primary IP for result generation
    primary_ip = target.split(',')[0].split('-')[0].strip()
    
    # Use the IP as a seed for random generation to ensure consistent results for the same IP
    ip_parts = [int(part) for part in primary_ip.split('.')]
    random.seed(sum(ip_parts))
    
    results = {
        "id": scan_id,
        "target": target,
        "scanType": scan_type,
        "timestamp": datetime.now().isoformat(),
        "command": f"nmap {' '.join(options.get('flags', []))} {target}",
        "status": "Completed",
        "hostStatus": "Up" if random.random() > 0.1 else "Down",  # 10% chance host is down
        "ports": [],
        "os": None,
        "vulnerabilities": []
    }
    
    # If host is down, return early
    if results["hostStatus"] == "Down":
        return results
    
    # Define possible services and versions for different ports
    possible_services = {
        21: [
            {"service": "FTP", "version": "vsftpd 3.0.3", "state": "open"},
            {"service": "FTP", "version": "ProFTPD 1.3.6", "state": "open"},
            {"service": "FTP", "version": "Pure-FTPd", "state": "filtered"}
        ],
        22: [
            {"service": "SSH", "version": "OpenSSH 8.2p1", "state": "open"},
            {"service": "SSH", "version": "OpenSSH 7.9p1", "state": "open"},
            {"service": "SSH", "version": "Dropbear sshd 2019.78", "state": "filtered"}
        ],
        23: [
            {"service": "Telnet", "version": "Linux telnetd", "state": "open"},
            {"service": "Telnet", "version": "BusyBox telnetd", "state": "open"}
        ],
        25: [
            {"service": "SMTP", "version": "Postfix", "state": "filtered"},
            {"service": "SMTP", "version": "Exim 4.93", "state": "open"}
        ],
        53: [
            {"service": "DNS", "version": "BIND 9.16.1", "state": "open"},
            {"service": "DNS", "version": "dnsmasq 2.80", "state": "open"}
        ],
        80: [
            {"service": "HTTP", "version": "Apache httpd 2.4.41", "state": "open"},
            {"service": "HTTP", "version": "nginx 1.18.0", "state": "open"},
            {"service": "HTTP", "version": "lighttpd 1.4.55", "state": "open"}
        ],
        443: [
            {"service": "HTTPS", "version": "Apache httpd 2.4.41", "state": "open"},
            {"service": "HTTPS", "version": "nginx 1.18.0", "state": "open"},
            {"service": "HTTPS", "version": "lighttpd 1.4.55", "state": "open"}
        ],
        3306: [
            {"service": "MySQL", "version": "MySQL 5.7.33", "state": "open"},
            {"service": "MySQL", "version": "MySQL 8.0.23", "state": "open"},
            {"service": "MySQL", "version": "MariaDB 10.5.9", "state": "open"}
        ],
        8080: [
            {"service": "HTTP-Proxy", "version": "Apache Tomcat 9.0.45", "state": "open"},
            {"service": "HTTP-Proxy", "version": "Jetty 9.4.36", "state": "open"}
        ],
        27017: [
            {"service": "MongoDB", "version": "MongoDB 4.4.4", "state": "open"},
            {"service": "MongoDB", "version": "MongoDB 5.0.0", "state": "open"}
        ],
        6379: [
            {"service": "Redis", "version": "Redis 6.2.1", "state": "open"},
            {"service": "Redis", "version": "Redis 5.0.10", "state": "open"}
        ]
    }
    
    # Possible OS detection results
    possible_os = [
        {"name": "Linux 5.4", "accuracy": "95%", "type": "Server", "details": "Linux 5.4.0-1024-aws"},
        {"name": "Linux 4.15", "accuracy": "92%", "type": "Server", "details": "Ubuntu 18.04 LTS"},
        {"name": "Linux 5.10", "accuracy": "97%", "type": "Server", "details": "Debian 11"},
        {"name": "FreeBSD 13.0", "accuracy": "94%", "type": "Server", "details": "FreeBSD 13.0-RELEASE"},
        {"name": "Windows Server 2019", "accuracy": "96%", "type": "Server", "details": "Microsoft Windows Server 2019"},
        {"name": "Windows 10", "accuracy": "93%", "type": "Workstation", "details": "Microsoft Windows 10 Pro"}
    ]
    
    # Possible vulnerabilities
    possible_vulns = [
        {
            "id": "CVE-2022-36763",
            "name": "Apache HTTP Server vulnerable to DoS",
            "severity": "Medium",
            "port": 80,
            "service": "HTTP",
            "description": "The HTTP server on port 80 is vulnerable to a denial of service attack.",
            "remediation": "Update Apache HTTP Server to the latest version."
        },
        {
            "id": "CVE-2023-25136",
            "name": "OpenSSH Authentication Bypass",
            "severity": "High",
            "port": 22,
            "service": "SSH",
            "description": "The SSH server may allow authentication bypass under specific conditions.",
            "remediation": "Update OpenSSH to the latest stable version."
        },
        {
            "id": "CVE-2021-44790",
            "name": "Apache mod_lua Buffer Overflow",
            "severity": "Low",
            "port": 80,
            "service": "HTTP",
            "description": "A buffer overflow in mod_lua could allow an attacker to execute arbitrary code.",
            "remediation": "Apply the latest security patches for Apache HTTP Server."
        },
        {
            "id": "CVE-2022-40897",
            "name": "MySQL Remote Code Execution",
            "severity": "Critical",
            "port": 3306,
            "service": "MySQL",
            "description": "A vulnerability in MySQL could allow remote attackers to execute arbitrary code.",
            "remediation": "Apply the latest security patches for MySQL."
        },
        {
            "id": "CVE-2023-1829",
            "name": "Redis Command Injection",
            "severity": "High",
            "port": 6379,
            "service": "Redis",
            "description": "Redis is vulnerable to command injection attacks.",
            "remediation": "Update Redis to the latest version."
        },
        {
            "id": "CVE-2022-31129",
            "name": "MongoDB Privilege Escalation",
            "severity": "Medium",
            "port": 27017,
            "service": "MongoDB",
            "description": "MongoDB contains a vulnerability that could allow privilege escalation.",
            "remediation": "Update MongoDB to the latest version."
        },
        {
            "id": "CVE-2023-3519",
            "name": "Nginx HTTP/2 Request Smuggling",
            "severity": "High",
            "port": 443,
            "service": "HTTPS",
            "description": "A vulnerability in Nginx that can lead to HTTP request smuggling.",
            "remediation": "Upgrade Nginx to version 1.25.1 or later."
        }
    ]
    
    # Determine which ports are open based on the IP
    # Let's use the last octet of the IP to influence port selection
    last_octet = ip_parts[3]
    
    # Select a set of ports based on the last octet
    available_ports = list(possible_services.keys())
    num_ports = max(3, min(last_octet % 10 + 3, len(available_ports)))
    
    # Deterministically select ports based on IP
    selected_port_indices = [(last_octet + i * ip_parts[2]) % len(available_ports) for i in range(num_ports)]
    selected_ports = [available_ports[i] for i in selected_port_indices]
    
    # Add the selected ports with their services to the results
    for port in selected_ports:
        service_options = possible_services[port]
        selected_service_index = (last_octet + ip_parts[1] + port) % len(service_options)
        port_info = service_options[selected_service_index].copy()
        port_info["port"] = port
        results["ports"].append(port_info)
    
    # Full port scan for intense or super scans adds more ports
    if scan_type in ['intense', 'super'] or options.get('port_range') == 'all':
        # Add more ports
        additional_port_count = min(last_octet % 5 + 2, len(available_ports) - num_ports)
        remaining_ports = [p for p in available_ports if p not in selected_ports]
        
        if remaining_ports:
            for i in range(additional_port_count):
                idx = (last_octet + i * ip_parts[0]) % len(remaining_ports)
                port = remaining_ports[idx]
                service_options = possible_services[port]
                selected_service = service_options[(last_octet + port) % len(service_options)].copy()
                selected_service["port"] = port
                results["ports"].append(selected_service)
    
    # Add OS detection if selected
    if options.get('os_detection') or scan_type in ['aggressive', 'intense', 'super']:
        os_index = (sum(ip_parts)) % len(possible_os)
        results["os"] = possible_os[os_index]
    
    # Add vulnerabilities if applicable
    if options.get('vuln_scan') or scan_type == 'super':
        # Associate vulnerabilities with open ports
        relevant_vulns = []
        for port_info in results["ports"]:
            port = port_info["port"]
            service = port_info["service"]
            
            # Find matching vulnerabilities
            matching_vulns = [v for v in possible_vulns if v["port"] == port or v["service"] == service]
            
            # Deterministically select vulns based on IP
            if matching_vulns:
                vuln_index = (sum(ip_parts) + port) % len(matching_vulns)
                relevant_vulns.append(matching_vulns[vuln_index])
        
        # Add some randomness but keep it deterministic with the IP seed
        # Limit to 1-3 vulnerabilities
        max_vulns = min(3, len(relevant_vulns))
        if max_vulns > 0:
            num_vulns = last_octet % max_vulns + 1
            results["vulnerabilities"] = relevant_vulns[:num_vulns]
    
    # Reset the random seed to not affect other operations
    random.seed()
    
    # Store the results for later retrieval
    mock_scan_results[scan_id] = results
    
    # Add to scan history
    scan_history.append({
        "id": scan_id,
        "target": target,
        "type": scan_type,
        "timestamp": results["timestamp"],
        "status": results["status"]
    })
    
    return results

# Routes
@app.route('/')
def index():
    return send_from_directory('static', 'NetScanner.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    
    # Validate required fields
    if not data.get('target'):
        return jsonify({"error": "Target IP address is required"}), 400
    
    if not data.get('scanType'):
        return jsonify({"error": "Scan type is required"}), 400
    
    # Validate IP
    if not validate_ip_target(data['target']):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    # Extract options
    options = {
        "os_detection": data.get('osDetection', False),
        "version_detection": data.get('versionDetection', False),
        "vuln_scan": data.get('vulnScan', False),
        "script_scan": data.get('scriptScan', False),
        "fingerprinting": data.get('fingerprinting', False),
        "timing": data.get('timing', False),
        "port_range": data.get('portRange', ''),
        "flags": []
    }
    
    # Build flags based on options
    if options["os_detection"]:
        options["flags"].append("-O")
    if options["version_detection"]:
        options["flags"].append("-sV")
    if options["vuln_scan"]:
        options["flags"].append("--script=vuln")
    if options["script_scan"]:
        options["flags"].append("-sC")
    if options["fingerprinting"]:
        options["flags"].append("-A")
    if options["timing"]:
        options["flags"].append("-T4")
    
    if options["port_range"]:
        if options["port_range"].lower() == 'all':
            options["flags"].append("-p-")
        else:
            options["flags"].append(f"-p {options['port_range']}")
    
    # Simulate scan duration based on complexity
    scan_type = data['scanType']
    scan_duration = 1  # seconds
    
    if scan_type == 'intense' or options["port_range"] == 'all':
        scan_duration = 3
    elif scan_type == 'super':
        scan_duration = 4
    
    time.sleep(scan_duration)
    
    # Generate mock results
    results = generate_mock_results(data['target'], scan_type, options)
    
    return jsonify(results)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id in mock_scan_results:
        return jsonify(mock_scan_results[scan_id])
    else:
        return jsonify({"error": "Scan not found"}), 404

@app.route('/api/scan/history', methods=['GET'])
def get_scan_history():
    return jsonify(scan_history)

@app.route('/api/scan/import', methods=['POST'])
def import_scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not file.filename.endswith('.json'):
        return jsonify({"error": "Only JSON files are supported"}), 400
    
    try:
        # Read and parse the JSON file
        scan_data = json.loads(file.read())
        
        # Generate a new ID
        scan_id = str(uuid.uuid4())
        
        # Update the ID in the data
        if isinstance(scan_data, dict):
            scan_data["id"] = scan_id
            
            # Store in mock results
            mock_scan_results[scan_id] = scan_data
            
            # Add to history
            scan_history.append({
                "id": scan_id,
                "target": scan_data.get("target", "Unknown"),
                "type": scan_data.get("scanType", "Unknown"),
                "timestamp": scan_data.get("timestamp", datetime.now().isoformat()),
                "status": scan_data.get("status", "Imported")
            })
            
            return jsonify(scan_data)
        else:
            return jsonify({"error": "Invalid JSON format"}), 400
    
    except Exception as e:
        return jsonify({"error": f"Error importing file: {str(e)}"}), 400

# Main entry point
if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('static', exist_ok=True)
    
    # For development, use debug mode
    app.run(debug=True, host='0.0.0.0', port=5000)