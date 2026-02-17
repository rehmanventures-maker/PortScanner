from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from datetime import datetime


class PortScanner:
    """
    Multithreaded TCP and UDP Port Scanner.
    Resolves a target domain to an IP address, scans all ports,
    and records open ports with known services.
    """

    # Common ports mapped to well-known services
    COMMON_PORTS = {
        20: "FTP (Data Transfer)",
        21: "FTP (Control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Proxy",
    }

    def __init__(self, target):
        """
        Initialize the scanner.

        :param target: Domain name or IP address to scan
        """
        self.target = target
        self.target_ip = None

        # Store results separately for clarity
        self.open_tcp_ports = []   # (port, service)
        self.open_udp_ports = []   # (port, service/status)

        self.log_file = f"port_scan_log_{target}.txt"

    # -------------------- SETUP --------------------

    def resolve_target(self):
        """
        Resolve the domain name to an IP address.
        """
        try:
            self.target_ip = socket.gethostbyname(self.target)
            print(f"Target resolved: {self.target} -> {self.target_ip}")
            return True
        except socket.gaierror:
            print("Error: Unable to resolve target.")
            return False

    # -------------------- TCP SCANNING --------------------

    def scan_tcp_port(self, port):
        """
        Scan a single TCP port.

        :param port: Port number to scan
        :return: (port, service) if open, otherwise None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((self.target_ip, port))
            sock.close()

            # TCP connect_ex returns 0 if port is open
            if result == 0:
                service = self.COMMON_PORTS.get(port, "Unknown Service")
                return (port, service)

        except Exception:
            pass

        return None

    def scan_all_tcp_ports(self):
        """
        Scan all TCP ports using multithreading.
        """
        print("\n[+] Scanning TCP ports...\n")

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [
                executor.submit(self.scan_tcp_port, port)
                for port in range(1, 10000)
            ]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, service = result
                    self.open_tcp_ports.append(result)
                    print(f"TCP {port} OPEN ({service})")

    # -------------------- UDP SCANNING --------------------


    def write_log(self, start_time):
        """
        Write scan results and summary to a log file.
        """
        with open(self.log_file, "w") as log:
            log.write("Port Scan Results\n")
            log.write(f"Target: {self.target}\n")
            log.write(f"Resolved IP: {self.target_ip}\n")
            log.write(f"Scan started: {start_time}\n")
            log.write("=" * 60 + "\n")

            log.write("\nTCP OPEN PORTS\n")
            log.write("-" * 60 + "\n")
            for port, service in sorted(self.open_tcp_ports):
                log.write(f"TCP {port:<6} {service}\n")

            

            log.write("=" * 60 + "\n")
            log.write(f"Scan completed: {datetime.now()}\n")
            log.write(f"TCP open ports: {len(self.open_tcp_ports)}\n")
            log.write(f"UDP open/filtered ports: {len(self.open_udp_ports)}\n")

    # -------------------- CONTROL --------------------

    def start(self):
        """
        Start TCP scanning.
        """
        if not self.resolve_target():
            return

        start_time = datetime.now()

        self.scan_all_tcp_ports()
        self.write_log(start_time)

        print(f"\nScan completed in {datetime.now() - start_time}")
        print(f"TCP open ports: {len(self.open_tcp_ports)}")
        print(f"Results saved to {self.log_file}")


# -------------------- ENTRY POINT --------------------

def main():
    """
    Program entry point.
    """
    target = input("Enter domain or IP address: ").strip()
    scanner = PortScanner(target)
    scanner.start()


if __name__ == "__main__":
    main()
