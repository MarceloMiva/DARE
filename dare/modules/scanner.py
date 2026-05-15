"""
DARE — Port & Service Scanner Module

Covers:
  - TCP connect scan (top ports)
  - Full port range scan
  - Service banner grabbing
  - Common service identification
  - UDP common ports (ICMP-based check)
"""

import socket
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2375: "Docker", 3000: "Dev-Server", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}


class ScannerModule:
    NAME = "Port & Service Scanner"

    def __init__(self, target: str, log):
        self.target = target
        self.log = log
        self.open_ports = []
        self.lock = threading.Lock()

    def run(self):
        self.log.section(f"Port & Service Scanner — {self.target or 'No target'}")

        if not self.target:
            self.target = input("\033[1;36m[+] Enter target IP or hostname: \033[0m").strip()

        try:
            self.ip = socket.gethostbyname(self.target)
            self.log.info(f"Resolved: {self.target} → {self.ip}")
        except socket.gaierror as e:
            self.log.error(f"Could not resolve target: {e}")
            return

        options = {
            "1": ("Top 100 Common Ports",  self.scan_common),
            "2": ("Custom Port Range",     self.scan_range),
            "3": ("Banner Grab",           self.banner_grab_menu),
            "4": ("Full Scan + Banners",   self.full_scan),
        }

        print()
        for k, (name, _) in options.items():
            print(f"  \033[1;32m[{k}]\033[0m {name}")
        print()

        choice = input("\033[1;36m[scanner]> \033[0m").strip()
        if choice in options:
            options[choice][1]()
        else:
            self.log.error("Invalid option.")

    def _tcp_connect(self, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((self.ip, port))
                return result == 0
        except Exception:
            return False

    def _grab_banner(self, port: int, timeout: float = 2.0) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.ip, port))
                # Send HTTP HEAD for web ports
                if port in (80, 8080, 8888, 3000):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                elif port in (443, 8443):
                    return "[HTTPS — use curl/openssl for banner]"
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner[:200] if banner else "[No banner]"
        except Exception as e:
            return f"[Error: {e}]"

    def _scan_ports(self, ports: list, workers: int = 150):
        self.open_ports = []
        self.log.info(f"Scanning {len(ports)} ports with {workers} threads...")

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(self._tcp_connect, p): p for p in ports}
            for future in as_completed(future_map):
                port = future_map[future]
                if future.result():
                    service = COMMON_PORTS.get(port, "Unknown")
                    with self.lock:
                        self.open_ports.append(port)
                    self.log.success(f"OPEN  {port:<8} {service}")

        self.open_ports.sort()
        self.log.info(f"Scan complete. {len(self.open_ports)} open port(s) found.")

    def scan_common(self):
        self.log.section("Top Common Ports Scan")
        self._scan_ports(list(COMMON_PORTS.keys()))

    def scan_range(self):
        self.log.section("Custom Range Scan")
        try:
            start = int(input("  Start port [1]: ").strip() or "1")
            end   = int(input("  End port [1024]: ").strip() or "1024")
            ports = list(range(start, end + 1))
            self._scan_ports(ports)
        except ValueError:
            self.log.error("Invalid port numbers.")

    def banner_grab_menu(self):
        self.log.section("Banner Grabbing")
        try:
            raw = input("  Enter port(s) to grab (comma-separated): ").strip()
            ports = [int(p.strip()) for p in raw.split(",")]
            for port in ports:
                banner = self._grab_banner(port)
                self.log.result(f"Port {port}", banner)
        except ValueError:
            self.log.error("Invalid port input.")

    def full_scan(self):
        self.log.section("Full Scan + Banner Grab")
        self.scan_common()
        if self.open_ports:
            self.log.section("Banner Grabbing Open Ports")
            for port in self.open_ports:
                banner = self._grab_banner(port)
                self.log.result(f"Port {port}", banner)
