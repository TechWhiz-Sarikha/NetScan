# 🔍 Automated Network Enumeration and Vulnerability Analysis Tool

[![Python](https://img.shields.io/badge/Built%20With-Python-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-orange.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

This project is a user-friendly, web-based network scanner and vulnerability analysis tool developed using **Flask**, **Nmap**, and **OpenVAS/NVD feeds**. It offers both beginner-friendly quick scans and advanced authenticated deep scans, complete with vulnerability correlation, report generation, and an AI chatbot for real-time guidance.

---

## 🚀 Features

- 🖥️ **Quick Scan**: Open port and live host detection (no login required)
- 🔐 **Deep Scan**: OS fingerprinting, service version detection, NSE scripts (login required)
- 🧠 **AI Chatbot**: Real-time interpretation and guidance on scan results
- 📄 **PDF Report Generation**: Export scan summaries and CVE data
- 💾 **Scan History**: Store and retrieve past scans (authenticated users)
- 📊 **Interactive Visualizations**: Track vulnerabilities and trends
- 🔐 **Security Measures**: JWT, bcrypt, CSRF protection, AES-256 encryption

---

## 🧑‍💻 Technology Stack

| Layer           | Tools Used                        |
|----------------|------------------------------------|
| Frontend       | HTML5, CSS3, JavaScript, Bootstrap |
| Backend        | Python 3.x, Flask, Subprocess      |
| Database       | SQLite (or MySQL)                  |
| Vulnerability  | Nmap, OpenVAS, NVD, CVE Feed       |
| PDF Reports    | xhtml2pdf / FPDF                   |
| Authentication | JWT, bcrypt.js                     |

---

## 📷 Screenshots

| Quick Scan Result | Deep Scan Result with AI Chat |
|------------------|-------------------------------|
| ![QuickScan](assets/quick_scan.png) | ![DeepScan](assets/deep_scan_ai.png) |

---

## 📂 Project Structure

