from flask import Flask, request, jsonify
import subprocess
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow frontend requests

@app.route('/quickscan', methods=['POST'])
def quick_scan():
    data = request.json
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    try:
        # Quick Scan: Only checks live hosts
        command = ["nmap", "-sn", ip]

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        return jsonify({
            "mode": "quick",
            "output": result.stdout if result.returncode == 0 else result.stderr
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
