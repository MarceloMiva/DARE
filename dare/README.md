# ⚡ DARE — Dynamic Attack & Recon Engine

> **Dynamic Attack & Recon Engine | Multi-Module CTF & Pentest CLI**
>
> *by Fashipe Oluwadamilare Ayoola*

```
  ██████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▒██    ▒ ▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
░ ▓██▄   ▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
  ▒   ██▒░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
▒██████▒▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
```

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Kali-lightgrey)]()
[![Ethics](https://img.shields.io/badge/use-authorized%20only-red)]()

---

## ⚠️ Legal Disclaimer

> **DARE is intended for authorized penetration testing, CTF competitions, and security education ONLY.**
>
> - Always obtain **written permission** before testing any system you do not own.
> - Unauthorized use is **illegal** under the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse Act, and equivalent laws worldwide.
> - The authors assume **no liability** for misuse of this tool.

---

## 📦 Features

| Module | Description |
|--------|-------------|
| 🔍 **Recon & OSINT** | DNS records, subdomain bruteforce, WHOIS, reverse DNS, IP geolocation |
| 🔌 **Port Scanner** | TCP connect scan, banner grabbing, service identification, threading |
| 🌐 **Web Enumeration** | Header analysis, directory bruteforce, tech fingerprinting, robots.txt, SQLi/XSS hints |
| 🔑 **Hash Tools** | Hash identification, generation (MD5/SHA/etc), dictionary cracking |
| 🔡 **Encoder/Decoder** | Base64, URL, HTML, Hex, ROT13, Caesar, Binary, JWT decode, auto-detect |
| 💣 **Exploit Helper** | Service → CVE mapping, reverse shell generator, PrivEsc checklists (Linux/Windows) |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Linux / macOS / Kali Linux (recommended)

### Installation

```bash
git clone https://github.com/yourusername/dare.git
cd dare
pip install -r requirements.txt
chmod +x dare.py
```

### Run — Interactive Menu
```bash
python3 dare.py
```

### Run — Direct Module
```bash
python3 dare.py --module recon --target example.com
python3 dare.py --module scan  --target 192.168.1.1 --verbose
python3 dare.py --module web   --target http://testsite.com --output results.txt
python3 dare.py --module hash
python3 dare.py --module encode
python3 dare.py --module exploit
```

---

## 📁 Project Structure

```
dare/
├── dare.py          # Entry point
├── requirements.txt
├── README.md
├── modules/
│   ├── recon.py           # OSINT & DNS
│   ├── scanner.py         # Port/service scanner
│   ├── web.py             # Web enumeration
│   ├── hash_tools.py      # Hash ID & cracking
│   ├── encoder.py         # Encode/decode utilities
│   └── exploit_helper.py  # Exploit reference & shell generator
└── utils/
    ├── banner.py           # ASCII art & menus
    └── logger.py           # Colored output & file logging
```

---

## 🧩 Module Details

### 🔍 Recon & OSINT
- A, AAAA, MX, NS, TXT, CNAME, SOA record lookup
- Subdomain bruteforce (30+ common names)
- IP geolocation via ip-api.com
- WHOIS lookup (requires `whois` binary)
- Reverse DNS (PTR records)

### 🔌 Port Scanner
- TCP connect scan with threading (150 workers)
- Covers 40+ common service ports
- Custom port range support
- Banner grabbing for open ports
- Service identification

### 🌐 Web Enumeration
- HTTP response header analysis
- Security header detection (missing CSP, HSTS, etc.)
- Directory/file bruteforce (40+ common paths)
- CMS & technology fingerprinting (WordPress, Django, React, Laravel, etc.)
- robots.txt & sitemap.xml fetching
- SQLi & XSS payload reference

### 🔑 Hash Tools
- Identifies: MD5, SHA1/224/256/384/512, NTLM, bcrypt, SHA512crypt, MD5crypt
- Generates all common hash types
- Dictionary attack with custom wordlist support (rockyou.txt compatible)
- Built-in mini wordlist for quick tests

### 🔡 Encoder / Decoder
- Base64, URL, HTML entity, Hex, Binary
- ROT13 & Caesar cipher (custom shift)
- JWT decode (header + payload, no signature verification)
- Auto-detect & decode (tries all formats)

### 💣 Exploit Helper
- Maps 13 common services to known CVEs and MSF modules
- Generates ready-to-use reverse shell payloads (Bash, Python, PHP, Perl, PowerShell, Ruby, Netcat)
- Linux privilege escalation checklist (SUID, sudo, cron, kernel)
- Windows privilege escalation checklist (tokens, services, scheduled tasks)
- SearchSploit / ExploitDB usage guide

---

## 🖥️ Sample Output

```
[*] [10:42:31] Resolved: example.com → 93.184.216.34
[+] [10:42:32] OPEN  80       HTTP
[+] [10:42:32] OPEN  443      HTTPS
[+] [10:42:33] Port 80    → Apache/2.4.41 (Ubuntu)
[!] [10:42:33] Missing security headers: X-Frame-Options, Content-Security-Policy
```

---

## ➕ Adding Your Own Module

1. Create `modules/your_module.py`
2. Implement a class with `__init__(self, target, log)` and `run(self)` method
3. Import it in `dare.py` and add to the `modules` dict

```python
# modules/your_module.py
class YourModule:
    NAME = "Your Module"

    def __init__(self, target, log):
        self.target = target
        self.log = log

    def run(self):
        self.log.section("Your Module")
        self.log.success("Hello from your module!")
```

---

## 📚 Recommended Tools to Pair With

| Tool | Purpose |
|------|---------|
| [Nmap](https://nmap.org) | Full-featured port scanner |
| [Metasploit](https://metasploit.com) | Exploitation framework |
| [Burp Suite](https://portswigger.net/burp) | Web proxy & scanner |
| [sqlmap](https://sqlmap.org) | Automated SQLi |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | Login brute-forcer |
| [Gobuster](https://github.com/OJ/gobuster) | Directory bruteforce |
| [LinPEAS/WinPEAS](https://github.com/carlospolop/PEASS-ng) | PrivEsc enumeration |

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Commit changes (`git commit -m 'Add new module'`)
4. Push (`git push origin feature/new-module`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

Built for the security community. Inspired by frameworks like [Metasploit](https://metasploit.com), [Reconspider](https://github.com/bhavsec/reconspider), and various CTF writeups.

> **Remember: Hack ethically. Get permission. Learn responsibly.**
> [

![CI](https://github.com/MarceloMiva/DARE/actions/workflows/ci.yml/badge.svg)

](https://github.com/MarceloMiva/DARE/actions/workflows/ci.yml)
