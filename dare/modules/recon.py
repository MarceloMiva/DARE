"""
DARE — Recon & OSINT Module

Covers:
  - DNS enumeration (A, MX, NS, TXT, CNAME records)
  - Subdomain brute-force
  - WHOIS lookup
  - Reverse DNS
  - Geolocation (via ip-api.com)
  - Email harvesting hints
"""

import socket
import subprocess
import json
import urllib.request
import urllib.error

try:
    import dns.resolver
    DNS_LIB = True
except ImportError:
    DNS_LIB = False


class ReconModule:
    NAME = "Recon & OSINT"

    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "admin", "dev", "staging", "api",
        "test", "vpn", "portal", "login", "remote", "webmail",
        "blog", "shop", "store", "cdn", "static", "assets",
        "dashboard", "app", "mobile", "beta", "old", "backup",
        "ns1", "ns2", "mx", "smtp", "pop", "imap", "support",
    ]

    def __init__(self, target: str, log):
        self.target = target
        self.log = log

    def run(self):
        self.log.section(f"Recon & OSINT — {self.target or 'No target'}")

        if not self.target:
            self.target = input("\033[1;36m[+] Enter target domain or IP: \033[0m").strip()

        options = {
            "1": ("DNS Record Lookup",     self.dns_lookup),
            "2": ("Subdomain Bruteforce",  self.subdomain_bruteforce),
            "3": ("Reverse DNS",           self.reverse_dns),
            "4": ("IP Geolocation",        self.geolocate),
            "5": ("WHOIS (system)",        self.whois_lookup),
            "6": ("Run All",               self.run_all),
        }

        print()
        for k, (name, _) in options.items():
            print(f"  \033[1;32m[{k}]\033[0m {name}")
        print()

        choice = input("\033[1;36m[recon]> \033[0m").strip()
        if choice in options:
            options[choice][1]()
        else:
            self.log.error("Invalid option.")

    def dns_lookup(self):
        self.log.section("DNS Record Lookup")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        if DNS_LIB:
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, rtype)
                    for rdata in answers:
                        self.log.success(f"{rtype:<8} → {rdata}")
                except Exception:
                    self.log.debug(f"No {rtype} records found.")
        else:
            self.log.warn("dnspython not installed. Using socket fallback (A records only).")
            self._dns_socket_fallback()

    def _dns_socket_fallback(self):
        try:
            ip = socket.gethostbyname(self.target)
            self.log.success(f"A       → {ip}")
        except socket.gaierror as e:
            self.log.error(f"DNS resolution failed: {e}")

    def subdomain_bruteforce(self):
        self.log.section("Subdomain Bruteforce")
        self.log.info(f"Testing {len(self.SUBDOMAIN_WORDLIST)} subdomains against {self.target}")
        found = []

        for sub in self.SUBDOMAIN_WORDLIST:
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                self.log.success(f"FOUND  {fqdn:<40} → {ip}")
                found.append((fqdn, ip))
            except socket.gaierror:
                self.log.debug(f"MISS   {fqdn}")

        self.log.info(f"Found {len(found)} subdomains.")

    def reverse_dns(self):
        self.log.section("Reverse DNS Lookup")
        target = self.target
        try:
            hostname = socket.gethostbyaddr(target)[0]
            self.log.success(f"PTR → {hostname}")
        except socket.herror as e:
            self.log.error(f"No PTR record: {e}")

    def geolocate(self):
        self.log.section("IP Geolocation")
        try:
            ip = socket.gethostbyname(self.target)
            url = f"http://ip-api.com/json/{ip}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())

            if data.get("status") == "success":
                fields = ["country", "regionName", "city", "zip", "isp", "org", "as", "lat", "lon"]
                for f in fields:
                    self.log.result(f.capitalize(), str(data.get(f, "N/A")))
            else:
                self.log.error(f"Geolocation failed: {data.get('message')}")
        except Exception as e:
            self.log.error(f"Geolocation error: {e}")

    def whois_lookup(self):
        self.log.section("WHOIS Lookup")
        try:
            result = subprocess.run(["whois", self.target], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("%")]
                for line in lines[:40]:
                    self.log.raw(f"  {line}")
            else:
                self.log.error("whois command failed or not installed.")
        except FileNotFoundError:
            self.log.error("'whois' not found. Install it: sudo apt install whois")
        except subprocess.TimeoutExpired:
            self.log.error("WHOIS timed out.")

    def run_all(self):
        self.dns_lookup()
        self.subdomain_bruteforce()
        self.reverse_dns()
        self.geolocate()
        self.whois_lookup()
