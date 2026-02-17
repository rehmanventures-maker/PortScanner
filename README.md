# PortScanner
# Python TCP & UDP Multithreaded Port Scanner

A fast, multithreaded TCP and UDP port scanner written in Python.  
This tool resolves a target domain to an IP address, scans TCP ports 1–65535 and UDP ports 1–10000, and logs open or filtered ports with known services.

---

## 🚀 Features

- Resolves domain names to IP addresses (DNS resolution)
- Multithreaded TCP port scanning (1–65535)
- Multithreaded UDP port scanning (1–10000)
- Identifies common services on well-known ports
- Correctly handles UDP open / filtered states
- Logs detailed scan results to a file
- Uses only Python standard libraries

---

## 🧠 How It Works

### TCP Scanning
- Uses `socket.connect_ex()` to test TCP ports
- A return value of `0` indicates an open port
- Multithreading significantly reduces scan time

### UDP Scanning
- Sends empty UDP packets to each port
- If data is received → port is open
- If no response → port is **Open | Filtered**
- This behavior mirrors real-world scanners like Nmap

---

## 📦 Requirements

- Python 3.8 or higher
- No external dependencies required

---

## ▶️ Usage

Clone the repository:

```bash
git clone https://github.com/yourusername/python-port-scanner.git
cd python-port-scanner
