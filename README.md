# 🔍 Automated Network Enumeration and Vulnerability Analysis Tool

[![Python](https://img.shields.io/badge/Built%20With-Python-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-orange.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

This project is a user-friendly, web-based network scanner and vulnerability analysis tool developed using **Flask**, **Nmap**, and threat intelligence feeds from **OpenVAS** and **NVD**. It supports both basic and advanced scan modes, correlates scan results with known vulnerabilities, and includes an AI chatbot to help interpret results in real-time.

---

## 🚀 Features

- 🔍 Quick Scan (no login): Detects live hosts and open ports
- 🧠 Deep Scan (with login): Includes OS detection, service versioning, and NSE scripts
- 🤖 AI Chatbot: Explains technical scan results in plain English
- 📊 Real-Time Scan Status: Live feedback while scanning
- 📂 Scan History: Stored securely for each authenticated user
- 📄 PDF Report Generation: Well-formatted reports with CVE data and remediation advice
- 🔐 Security: JWT tokens, bcrypt hashing, CSRF protection, AES-256 encryption

---

## 🧑‍💻 Technology Stack

| Layer           | Tools Used                        |
|----------------|------------------------------------|
| Frontend       | HTML5, CSS3, JavaScript, Bootstrap |
| Backend        | Python 3.x, Flask, Subprocess      |
| Database       | SQLite (or MySQL)                  |
| Vulnerability  | Nmap, OpenVAS, NVD, CVE Feed       |
| Reporting      | xhtml2pdf / FPDF                   |
| Authentication | JWT, bcrypt.js                     |

---
# 🔍 Automated Network Enumeration and Vulnerability Analysis Tool

[![Python](https://img.shields.io/badge/Built%20With-Python-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-orange.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

This project is a user-friendly, web-based network scanner and vulnerability analysis tool developed using **Flask**, **Nmap**, and threat intelligence feeds from **OpenVAS** and **NVD**. It supports both basic and advanced scan modes, correlates scan results with known vulnerabilities, and includes an AI chatbot to help interpret results in real-time.

---

## 🚀 Features

- 🔍 Quick Scan (no login): Detects live hosts and open ports
- 🧠 Deep Scan (with login): Includes OS detection, service versioning, and NSE scripts
- 🤖 AI Chatbot: Explains technical scan results in plain English
- 📊 Real-Time Scan Status: Live feedback while scanning
- 📂 Scan History: Stored securely for each authenticated user
- 📄 PDF Report Generation: Well-formatted reports with CVE data and remediation advice
- 🔐 Security: JWT tokens, bcrypt hashing, CSRF protection, AES-256 encryption

---

## 🧑‍💻 Technology Stack

| Layer           | Tools Used                        |
|----------------|------------------------------------|
| Frontend       | HTML5, CSS3, JavaScript, Bootstrap |
| Backend        | Python 3.x, Flask, Subprocess      |
| Database       | SQLite (or MySQL)                  |
| Vulnerability  | Nmap, OpenVAS, NVD, CVE Feed       |
| Reporting      | xhtml2pdf / FPDF                   |
| Authentication | JWT, bcrypt.js                     |

---

## 📷 Screenshots

> *(Add screenshots in the `/assets` folder and link them here)*

| Quick Scan | Deep Scan + AI Chatbot |
|------------|-------------------------|
| ![Quick Scan](assets/quick_scan.png) | ![Deep Scan](assets/deep_scan.png) |


---

## 🔧 Installation Instructions

### Prerequisites
- Python 3.10 or above
- Nmap installed on your system
- Git

### Steps

```bash
git clone https://github.com/your-username/network-vuln-scanner.git
cd network-vuln-scanner
python3 -m venv venv
source venv/bin/activate  # On Windows use venv\Scripts\activate
pip install -r requirements.txt
python run.py

## 📑 Report Generation

PDF reports are generated for Deep Scans.

- Includes metadata: IP range, CVEs, severity, date, and recommendations.
- Stored under `/reports/` and accessible from the UI.

---

## 🧠 AI Assistant

The built-in AI assistant offers simplified explanations for technical scan results.

It answers questions like:

- “What is CVE-2023-12345?”
- “How do I fix an open FTP port?”

---

## 🛡️ Security Highlights

- 🔐 Passwords encrypted using `bcrypt`
- 🔑 JWT-based session authentication
- 🧼 Input sanitization for IPs and domains
- 📄 CSRF token protection for form submissions
- 🔒 AES-256 for securely storing session data

---

## 🔮 Future Enhancements

- Scheduled background scans
- CVSS score-based vulnerability visualization
- SIEM integration support
- SMS/email alerts on critical CVEs
- Expert mode with full Nmap CLI options
- Voice-based chatbot integration
- Mobile-responsive and offline versions

---

## 📜 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for more details.

---

## 👥 Contributors

- **Sarikha S** – 2212012  
- **Sri Gomathi R** – 2212013  
- **Aruna Varshini S** – 2212019  

**Department of Computer Science and Engineering**  
National Engineering College, Kovilpatti

**Supervisor:** Dr. J. Naskath, M.E., Ph.D.  
Associate Professor, CSE






