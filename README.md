# PortScanner

A fast, multithreaded TCP port scanner written in Python.  
This tool resolves a target domain to an IP address, scans TCP ports 1–9999, and logs all open ports with known services.

---

## 🚀 Features

- Resolves domain names to IP addresses (DNS resolution)
- Multithreaded TCP port scanning (ports 1–9999)
- Identifies common services on well-known ports
- Logs detailed scan results to a file
- Uses only Python standard libraries
- Real-time terminal output of open ports

---

## 🧠 How It Works

- Resolves the target domain to an IP address
- Uses TCP `socket.connect_ex()` to test each port
- A return value of `0` indicates the port is open
- Scans ports concurrently using `ThreadPoolExecutor` to reduce total scan time
- Saves results to a text log file for easy review

---

## 📦 Requirements

- Python 3.8+
- No external dependencies required


