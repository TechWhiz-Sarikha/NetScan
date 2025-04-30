Automated Network Enumeration and Vulnerability Analysis Tool

This project is a user-friendly, web-based network scanner and vulnerability analysis tool developed using Flask, Nmap, and OpenVAS/NVD feeds. It offers both beginner-friendly quick scans and advanced authenticated deep scans, complete with vulnerability correlation, report generation, and an AI chatbot for real-time guidance.

🚀 Features
🖥️ Quick Scan: Open port and live host detection (no login required)

🔐 Deep Scan: OS fingerprinting, service version detection, NSE scripts (login required)

🧠 AI Chatbot: Real-time interpretation and guidance on scan results

📄 PDF Report Generation: Export scan summaries and CVE data

💾 Scan History: Store and retrieve past scans (authenticated users)

📊 Interactive Visualizations: Track vulnerabilities and trends

🔐 Security Measures: JWT, bcrypt, CSRF protection, AES-256 encryption

🧑‍💻 Technology Stack

Layer	Tools Used
Frontend	HTML5, CSS3, JavaScript, Bootstrap
Backend	Python 3.x, Flask, Subprocess
Database	SQLite (or MySQL)
Vulnerability	Nmap, OpenVAS, NVD, CVE Feed
PDF Reports	xhtml2pdf / FPDF
Authentication	JWT, bcrypt.js
📷 Screenshots

Quick Scan Result	Deep Scan Result with AI Chat
📂 Project Structure
arduino
Copy
Edit
network-scanner-tool/
│
├── app/
│   ├── static/
│   ├── templates/
│   ├── routes/
│   ├── api/
│   └── utils/
│
├── database/
│   └── schema.sql
│
├── reports/
├── requirements.txt
├── config.py
└── run.py
🔧 Installation
bash
Copy
Edit
git clone https://github.com/your-username/network-scanner-tool.git
cd network-scanner-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
Ensure Nmap is installed and accessible from your system path.

🛡️ Security Highlights
Passwords hashed using bcrypt

AES-256 encryption for stored credentials

CSRF protection tokens

JWT for authenticated sessions

Secure subprocess handling to avoid injection

📑 Report Generation
After a deep scan:

PDF reports include metadata, scan type, timestamps, CVEs, severity levels, and recommendations.

Reports are stored and downloadable.

🧠 AI Assistant
The embedded AI assistant helps:

Break down scan result terms (e.g., "CVE-2023-12345")

Suggest remediation

Provide NVD references

🔮 Future Enhancements
Scheduled scans and notifications (email/SMS)

Integration with SIEM tools

CVSS score-based visualization

Offline capability for air-gapped environments

Voice-based chatbot assistant

📜 License
This project is licensed under the MIT License.

👥 Team
Sarikha S (2212012)

Sri Gomathi R (2212013)

Aruna Varshini S (2212019)

National Engineering College, Kovilpatti
Under the guidance of Dr. J. Naskath, Associate Professor

