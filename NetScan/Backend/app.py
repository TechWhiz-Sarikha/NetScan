from flask import Flask, request, jsonify
import subprocess
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SCAN_COMMANDS = {
    "quickscan": ["nmap", "-sn"],
    "intense": ["nmap", "-T4", "-A", "-v"],
    "intense_udp": ["nmap", "-sU", "-T4", "-A", "-v"],  # Fixed UDP scan
    "ping": ["nmap", "-sn"],
    "all_tcp": ["nmap", "-p", "-"],  # Fixed all TCP scan
    "no_ping": ["nmap", "-Pn"],
    "traceroute": ["nmap", "--traceroute"],
    "comprehensive": ["nmap", "-p", "1-65535", "-T4", "-A", "-v"]  # Fixed syntax
}

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip = data.get("ip")
    scan_type = data.get("scanType")

    if not ip or not scan_type:
        return jsonify({"error": "IP address and scan type are required"}), 400

    if scan_type not in SCAN_COMMANDS:
        return jsonify({"error": "Invalid scan type"}), 400

    try:
        command = SCAN_COMMANDS[scan_type] + [ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        return jsonify({
            "mode": scan_type,
            "output": result.stdout if result.returncode == 0 else result.stderr
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
