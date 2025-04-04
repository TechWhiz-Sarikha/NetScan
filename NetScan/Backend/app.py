from flask import Flask, request, jsonify
import subprocess
import re
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Predefined scan types
SCAN_COMMANDS = {
    "quickscan": ["nmap", "-sn"],
    "intense": ["nmap", "-T4", "-A", "-v"],
    "intense_udp": ["nmap", "-sU", "-T4", "-A", "-v"],
    "ping": ["nmap", "-sn"],
    "all_tcp": ["nmap", "-p-"],  # Fixed all TCP ports scan
    "no_ping": ["nmap", "-Pn"],
    "traceroute": ["nmap", "--traceroute"],
    "comprehensive": ["nmap", "-p", "1-65535", "-T4", "-A", "-v"]
}

# Validate IP address / Domain
def is_valid_target(target):
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"  # IPv4 regex
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z]{2,6})+$"  # Simple domain regex
    return re.match(ip_pattern, target) or re.match(domain_pattern, target)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip = data.get("ip")
    scan_type = data.get("scanType")

    if not ip or not scan_type:
        return jsonify({"error": "IP address and scan type are required"}), 400

    if not is_valid_target(ip):
        return jsonify({"error": "Invalid IP address or domain"}), 400

    if scan_type not in SCAN_COMMANDS:
        return jsonify({"error": "Invalid scan type"}), 400

    try:
        command = SCAN_COMMANDS[scan_type] + [ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        return jsonify({
            "mode": scan_type,
            "output": result.stdout if result.returncode == 0 else f"Error: {result.stderr}",
            "return_code": result.returncode
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
