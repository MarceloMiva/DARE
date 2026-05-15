"""
DARE — Web Enumeration Module

Covers:
  - HTTP header analysis
  - Directory/path bruteforce
  - Technology fingerprinting
  - robots.txt & sitemap.xml fetch
  - Common file discovery
  - Basic SQL injection test hints
  - XSS reflection test hints
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common dirs/files to check
DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel",
    "wp-admin", "wp-login.php", "phpmyadmin", "cpanel",
    "uploads", "backup", "backups", "db", "database",
    "config", "conf", "api", "v1", "v2", "swagger",
    "docs", "documentation", ".git", ".env", ".htaccess",
    "robots.txt", "sitemap.xml", "web.config", "crossdomain.xml",
    "server-status", "server-info", "info.php", "phpinfo.php",
    "test", "test.php", "debug", "shell.php", "cmd.php",
    "index.php", "index.html", "index.bak", "readme.md",
    "CHANGELOG", "LICENSE", "package.json", "composer.json",
]

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
    "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
    "X-XSS-Protection", "X-Content-Type-Options", "Access-Control-Allow-Origin",
    "Set-Cookie", "WWW-Authenticate", "Location",
]

# Common SQLi test payloads (for manual inspection hints only)
SQLI_HINTS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users;--",
    "1' AND SLEEP(5)--",
]

# Common XSS payloads
XSS_HINTS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "';alert(1)//",
]


class WebModule:
    NAME = "Web Enumeration"

    def __init__(self, target: str, log):
        self.target = target
        self.log = log
        # Build normalized base URL
        if target and not target.startswith("http"):
            self.base_url = f"http://{target}"
        else:
            self.base_url = target or ""

    def run(self):
        self.log.section(f"Web Enumeration — {self.base_url or 'No target'}")

        if not self.base_url:
            raw = input("\033[1;36m[+] Enter target URL (e.g. http://example.com): \033[0m").strip()
            if not raw.startswith("http"):
                raw = f"http://{raw}"
            self.base_url = raw.rstrip("/")

        options = {
            "1": ("HTTP Header Analysis",    self.header_analysis),
            "2": ("Directory Bruteforce",    self.dir_bruteforce),
            "3": ("robots.txt & sitemap",    self.fetch_robots_sitemap),
            "4": ("Technology Fingerprint",  self.fingerprint),
            "5": ("SQLi Payload Hints",      self.sqli_hints),
            "6": ("XSS Payload Hints",       self.xss_hints),
            "7": ("Run All",                 self.run_all),
        }

        print()
        for k, (name, _) in options.items():
            print(f"  \033[1;32m[{k}]\033[0m {name}")
        print()

        choice = input("\033[1;36m[web]> \033[0m").strip()
        if choice in options:
            options[choice][1]()
        else:
            self.log.error("Invalid option.")

    def _get(self, url: str, timeout: int = 5):
        """Perform HTTP GET, return (status_code, headers_dict, body_str)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 DARE/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="ignore")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception as e:
            return None, {}, str(e)

    def header_analysis(self):
        self.log.section("HTTP Header Analysis")
        status, headers, _ = self._get(self.base_url)
        if status is None:
            self.log.error(f"Could not connect to {self.base_url}")
            return

        self.log.result("Status Code", str(status))
        for h in INTERESTING_HEADERS:
            val = headers.get(h) or headers.get(h.lower())
            if val:
                self.log.result(h, val)

        # Security header warnings
        missing = []
        security_headers = ["X-Frame-Options", "Content-Security-Policy",
                            "Strict-Transport-Security", "X-Content-Type-Options"]
        for sh in security_headers:
            if not (headers.get(sh) or headers.get(sh.lower())):
                missing.append(sh)
        if missing:
            self.log.warn(f"Missing security headers: {', '.join(missing)}")

    def dir_bruteforce(self):
        self.log.section("Directory Bruteforce")
        self.log.info(f"Testing {len(DIR_WORDLIST)} paths on {self.base_url}")
        found = []

        def check(path):
            url = f"{self.base_url}/{path}"
            status, _, _ = self._get(url)
            return path, url, status

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, p): p for p in DIR_WORDLIST}
            for fut in as_completed(futures):
                path, url, status = fut.result()
                if status and status not in (404, None):
                    color = "\033[1;32m" if status == 200 else "\033[1;33m"
                    self.log.raw(f"  {color}[{status}]\033[0m  {url}")
                    found.append((status, url))
                else:
                    self.log.debug(f"[{status}] {url}")

        self.log.info(f"Found {len(found)} interesting path(s).")

    def fetch_robots_sitemap(self):
        self.log.section("robots.txt & sitemap.xml")
        for path in ["robots.txt", "sitemap.xml", "sitemap_index.xml"]:
            url = f"{self.base_url}/{path}"
            status, _, body = self._get(url)
            if status == 200:
                self.log.success(f"Found: {url}")
                for line in body.splitlines()[:20]:
                    if line.strip():
                        self.log.raw(f"    {line}")
            else:
                self.log.debug(f"Not found: {path}")

    def fingerprint(self):
        self.log.section("Technology Fingerprint")
        status, headers, body = self._get(self.base_url)
        if status is None:
            self.log.error("Could not connect.")
            return

        checks = {
            "WordPress":    ["wp-content", "wp-includes", "wordpress"],
            "Drupal":       ["Drupal", "drupal.js", "/sites/default/"],
            "Joomla":       ["/components/com_", "Joomla"],
            "Laravel":      ["laravel_session", "X-Laravel"],
            "Django":       ["csrftoken", "django"],
            "React":        ["react", "__REACT", "_reactRootContainer"],
            "jQuery":       ["jquery", "jQuery"],
            "Bootstrap":    ["bootstrap.min.css", "Bootstrap"],
            "PHP":          ["X-Powered-By: PHP", ".php"],
            "Apache":       ["Apache/"],
            "Nginx":        ["nginx"],
            "IIS":          ["IIS", "ASP.NET"],
            "Node.js":      ["X-Powered-By: Express"],
        }

        all_text = " ".join(headers.values()) + body
        detected = []
        for tech, signatures in checks.items():
            if any(s.lower() in all_text.lower() for s in signatures):
                detected.append(tech)
                self.log.success(f"Detected: {tech}")

        if not detected:
            self.log.warn("No specific technologies fingerprinted.")

    def sqli_hints(self):
        self.log.section("SQL Injection Payload Reference")
        self.log.warn("These are manual testing hints. Test in URL params, form fields, headers.")
        self.log.warn("Only test on systems you are authorized to test!\n")
        for p in SQLI_HINTS:
            self.log.raw(f"  \033[1;33m→\033[0m  {p}")
        self.log.raw("\n  Tools: sqlmap, manual testing, Burp Suite")

    def xss_hints(self):
        self.log.section("XSS Payload Reference")
        self.log.warn("Test these in input fields, URL params, and headers.")
        self.log.warn("Only test on systems you are authorized to test!\n")
        for p in XSS_HINTS:
            self.log.raw(f"  \033[1;33m→\033[0m  {p}")
        self.log.raw("\n  Tools: XSStrike, Dalfox, Burp Suite")

    def run_all(self):
        self.header_analysis()
        self.fetch_robots_sitemap()
        self.fingerprint()
        self.dir_bruteforce()
