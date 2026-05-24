"""
╔══════════════════════════════════════════════════════════╗
║   Security Misconfiguration Detection Tool  (CLI)        ║
║   Usage:  python scanner_cli.py <URL>                    ║
║   Example: python scanner_cli.py https://example.com     ║
╚══════════════════════════════════════════════════════════╝

Install dependencies first:
    pip install requests beautifulsoup4
"""

import sys
import json
import csv
import datetime
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
RED     = "\033[91m"
ORANGE  = "\033[93m"
YELLOW  = "\033[33m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
DIM     = "\033[2m"
TEAL    = "\033[38;5;37m"

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     CYAN,
}

# ─── Remediation Database ─────────────────────────────────────────────────────

REMEDIATION = {
    "Missing Header: Content-Security-Policy": {
        "fix":  "Add a Content-Security-Policy header in your server/app config.",
        "code": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';"
    },
    "Missing Header: X-Frame-Options": {
        "fix":  "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
        "code": "X-Frame-Options: DENY"
    },
    "Missing Header: Strict-Transport-Security": {
        "fix":  "Enable HSTS to force HTTPS connections.",
        "code": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Missing Header: X-Content-Type-Options": {
        "fix":  "Add this header to stop browsers from MIME-sniffing responses.",
        "code": "X-Content-Type-Options: nosniff"
    },
    "Missing Header: Referrer-Policy": {
        "fix":  "Add Referrer-Policy to control referrer data sharing.",
        "code": "Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Missing Header: Permissions-Policy": {
        "fix":  "Restrict browser features you don't need.",
        "code": "Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
    "Wildcard CORS Policy Detected": {
        "fix":  "Replace wildcard CORS with a specific allowed origin.",
        "code": "Access-Control-Allow-Origin: https://yourtrustedsite.com"
    },
    "Directory Listing Enabled": {
        "fix":  "Disable directory listing in your web server config.",
        "code": "Apache: Options -Indexes  |  Nginx: autoindex off;"
    },
    "POST Form Without CSRF Token": {
        "fix":  "Add a hidden CSRF token to every POST form.",
        "code": "Flask-WTF: use {{ form.hidden_tag() }} in your template"
    },
    "Password Field Missing autocomplete": {
        "fix":  "Add autocomplete attribute to password input fields.",
        "code": "<input type='password' autocomplete='new-password'>"
    },
    "Debug / Error Information Exposed": {
        "fix":  "Disable debug mode in production and use custom error pages.",
        "code": "Flask: app.config['DEBUG'] = False"
    },
    "Sensitive Keyword Found in HTML Comment": {
        "fix":  "Remove all sensitive data from HTML comments before deploying.",
        "code": "Search & delete comments with: passwords, tokens, API keys, TODOs"
    },
}

def get_remediation(title):
    for key, val in REMEDIATION.items():
        if key.lower() in title.lower():
            return val
    if "cookie" in title.lower():
        return {
            "fix":  "Set Secure, HttpOnly, and SameSite flags on all cookies.",
            "code": "Flask: response.set_cookie('name', value, secure=True, httponly=True, samesite='Lax')"
        }
    if "server version" in title.lower():
        return {
            "fix":  "Hide server version from response headers.",
            "code": "Apache: ServerTokens Prod  |  Nginx: server_tokens off;"
        }
    if "x-powered-by" in title.lower():
        return {
            "fix":  "Remove X-Powered-By header.",
            "code": "Express.js: app.disable('x-powered-by')  |  PHP: expose_php = Off"
        }
    if "exposed" in title.lower() or "accessible" in title.lower():
        return {
            "fix":  "Restrict access to sensitive admin/config paths.",
            "code": ".htaccess: <FilesMatch '\\.(env|git|config)$'> Deny from all </FilesMatch>"
        }
    return None


# ─── Banner ───────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{RED}{BOLD}
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝  
{RESET}
{CYAN}   Security Misconfiguration Detection Tool for Web Applications{RESET}
{DIM}   ─────────────────────────────────────────────────────────────{RESET}
""")


def print_finding(finding):
    sev   = finding["severity"]
    color = SEV_COLOR.get(sev, RESET)
    print(f"  {color}{BOLD}[{sev}]{RESET}  {BOLD}{finding['title']}{RESET}")
    print(f"         {DIM}{finding['detail']}{RESET}")

    rem = get_remediation(finding["title"])
    if rem:
        print(f"         {TEAL}🔧 Fix: {rem['fix']}{RESET}")
        print(f"         {DIM}   ↳  {rem['code']}{RESET}")
    print()


# ─── 1. Fetch target ──────────────────────────────────────────────────────────
def fetch_target(url):
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"},
            timeout=10,
            allow_redirects=True
        )
        return resp
    except requests.exceptions.ConnectionError:
        print(f"{RED}[ERROR] Cannot connect to {url}. Check URL or internet.{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[ERROR] Request timed out for {url}.{RESET}")
        sys.exit(1)


# ─── 2. Security Headers ──────────────────────────────────────────────────────
def check_security_headers(response):
    findings = []
    headers  = response.headers

    required_headers = [
        ("Content-Security-Policy",   "HIGH",   "No CSP header — XSS and code injection attacks are not mitigated."),
        ("X-Frame-Options",           "MEDIUM", "Missing X-Frame-Options — site may be vulnerable to Clickjacking."),
        ("Strict-Transport-Security", "HIGH",   "Missing HSTS — browser may connect over insecure HTTP."),
        ("X-Content-Type-Options",    "MEDIUM", "Missing X-Content-Type-Options — MIME-sniffing risk."),
        ("Referrer-Policy",           "LOW",    "No Referrer-Policy — sensitive URL data may leak to third parties."),
        ("Permissions-Policy",        "LOW",    "No Permissions-Policy — browser features are unrestricted."),
    ]

    for name, sev, detail in required_headers:
        if name not in headers:
            findings.append({
                "category": "Missing Security Header",
                "severity": sev,
                "title":    f"Missing Header: {name}",
                "detail":   detail,
            })

    server = headers.get("Server", "")
    if server and any(char.isdigit() for char in server):
        findings.append({
            "category": "Information Disclosure",
            "severity": "LOW",
            "title":    f"Server Version Disclosed: {server}",
            "detail":   "Exact server version helps attackers find known exploits.",
        })

    powered = headers.get("X-Powered-By", "")
    if powered:
        findings.append({
            "category": "Information Disclosure",
            "severity": "LOW",
            "title":    f"X-Powered-By Exposed: {powered}",
            "detail":   "Technology stack info exposed — aids attacker fingerprinting.",
        })

    return findings


# ─── 3. Cookie Security ───────────────────────────────────────────────────────
def check_cookies(response):
    findings = []
    for cookie in response.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("missing SameSite attribute")
        if issues:
            findings.append({
                "category": "Insecure Cookie",
                "severity": "MEDIUM",
                "title":    f"Insecure Cookie: '{cookie.name}'",
                "detail":   "Cookie issues: " + "; ".join(issues) + ".",
            })
    return findings


# ─── 4. CORS ──────────────────────────────────────────────────────────────────
def check_cors(response):
    findings = []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        findings.append({
            "category": "CORS Misconfiguration",
            "severity": "HIGH",
            "title":    "Wildcard CORS Policy Detected",
            "detail":   "Access-Control-Allow-Origin: * allows any site to make cross-origin requests.",
        })
    return findings


# ─── 5. HTML Content ──────────────────────────────────────────────────────────
def check_html_content(response, url):
    findings = []
    soup     = BeautifulSoup(response.text, "html.parser")
    text     = response.text.lower()

    debug_signs = [
        ("traceback (most recent call last)", "Python stack trace visible"),
        ("sqlexception",                       "SQL exception message exposed"),
        ("mysql_fetch",                        "MySQL function name exposed"),
        ("fatal error:",                       "PHP Fatal Error exposed"),
        ("warning: include",                   "PHP Warning exposed"),
        ("debug = true",                       "Debug mode appears enabled"),
        ("app.debug",                          "Debug flag found in response"),
    ]
    for sign, detail in debug_signs:
        if sign in text:
            findings.append({
                "category": "Debug/Error Exposure",
                "severity": "MEDIUM",
                "title":    "Debug / Error Information Exposed",
                "detail":   detail + " — reveals internal application structure.",
            })
            break

    dir_signs = ["index of /", "parent directory", "[to parent directory]"]
    if any(s in text for s in dir_signs):
        findings.append({
            "category": "Directory Listing",
            "severity": "HIGH",
            "title":    "Directory Listing Enabled",
            "detail":   "Server exposes file/folder list — sensitive files accessible.",
        })

    forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")
    for form in forms:
        inputs      = form.find_all("input")
        input_names = [i.get("name", "").lower() for i in inputs]
        has_csrf    = any("csrf" in n or "token" in n or "_token" in n for n in input_names)
        if not has_csrf:
            findings.append({
                "category": "CSRF",
                "severity": "MEDIUM",
                "title":    "POST Form Without CSRF Token",
                "detail":   f"Form (action={form.get('action','?')}) has no CSRF token field.",
            })
            break

    pwd_fields = soup.find_all("input", {"type": "password"})
    for field in pwd_fields:
        ac = field.get("autocomplete", "").lower()
        if ac not in ("off", "new-password", "current-password"):
            findings.append({
                "category": "Insecure Form",
                "severity": "LOW",
                "title":    "Password Field Missing autocomplete='off'",
                "detail":   "Browser may cache passwords — risk on shared devices.",
            })
            break

    html_comments = soup.find_all(string=lambda t: isinstance(t, Comment))
    for comment in html_comments:
        c = comment.lower()
        if any(kw in c for kw in ["password", "secret", "api_key", "token", "todo", "hack", "remove"]):
            findings.append({
                "category": "Information Disclosure",
                "severity": "LOW",
                "title":    "Sensitive Keyword Found in HTML Comment",
                "detail":   f"Comment contains: '{comment.strip()[:80]}'",
            })
            break

    return findings


# ─── 6. Exposed Paths ─────────────────────────────────────────────────────────
def check_default_paths(url):
    findings   = []
    paths_list = [
        ("/admin",           "Admin panel"),
        ("/admin/login",     "Admin login page"),
        ("/wp-admin",        "WordPress admin"),
        ("/phpmyadmin",      "phpMyAdmin"),
        ("/manager/html",    "Tomcat Manager"),
        ("/.env",            ".env config file"),
        ("/config.php",      "Config PHP file"),
        ("/debug",           "Debug endpoint"),
        ("/console",         "Web console"),
        ("/actuator",        "Spring Boot Actuator"),
        ("/actuator/health", "Spring Boot Health"),
        ("/server-status",   "Apache server-status"),
        ("/elmah.axd",       "ELMAH error log"),
        ("/.git/HEAD",       "Exposed .git folder"),
        ("/backup.zip",      "Backup archive"),
    ]

    for path, label in paths_list:
        try:
            test_url = urljoin(url, path)
            r = requests.get(
                test_url, timeout=6, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}
            )
            if r.status_code in (200, 301, 302, 403):
                findings.append({
                    "category": "Exposed Admin/Sensitive Path",
                    "severity": "HIGH" if r.status_code == 200 else "MEDIUM",
                    "title":    f"{label} Accessible: {path}  [{r.status_code}]",
                    "detail":   f"Path '{path}' returned HTTP {r.status_code}.",
                })
        except Exception:
            pass

    return findings


# ─── Save Reports ─────────────────────────────────────────────────────────────
def save_reports(url, findings, elapsed):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url  = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "")

    # JSON — include remediation
    findings_with_fix = []
    for f in findings:
        entry = dict(f)
        rem = get_remediation(f["title"])
        if rem:
            entry["remediation"]      = rem["fix"]
            entry["remediation_code"] = rem["code"]
        findings_with_fix.append(entry)

    json_file = f"report_{safe_url}_{timestamp}.json"
    report = {
        "target":    url,
        "timestamp": timestamp,
        "scan_time": f"{elapsed:.2f}s",
        "total":     len(findings),
        "findings":  findings_with_fix,
    }
    with open(json_file, "w") as f:
        json.dump(report, f, indent=2)

    # CSV — include remediation columns
    csv_file = f"report_{safe_url}_{timestamp}.csv"
    with open(csv_file, "w", newline="") as f:
        fieldnames = ["category", "severity", "title", "detail", "remediation", "remediation_code"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in findings_with_fix:
            row.setdefault("remediation", "")
            row.setdefault("remediation_code", "")
            writer.writerow(row)

    print(f"{GREEN}[✓] Reports saved:{RESET}")
    print(f"    JSON → {json_file}")
    print(f"    CSV  → {csv_file}\n")


# ─── Main Scanner ─────────────────────────────────────────────────────────────
def scan(url):
    if not url.startswith("http"):
        url = "https://" + url

    print(f"{CYAN}{BOLD}[*] Starting scan on: {url}{RESET}\n")
    start = datetime.datetime.now()

    response = fetch_target(url)
    elapsed  = (datetime.datetime.now() - start).total_seconds()

    print(f"{GREEN}[✓] Connected  |  Status: {response.status_code}  |  Time: {elapsed:.2f}s{RESET}\n")
    print(f"{DIM}{'─'*60}{RESET}\n")

    all_findings = []
    all_findings += check_security_headers(response)
    all_findings += check_cookies(response)
    all_findings += check_cors(response)
    all_findings += check_html_content(response, url)

    print(f"{CYAN}[*] Checking exposed paths... (this may take a moment){RESET}")
    all_findings += check_default_paths(url)
    print()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    if not all_findings:
        print(f"{GREEN}{BOLD}[✓] No issues found! Site looks well configured.{RESET}\n")
    else:
        print(f"{BOLD}{'─'*60}")
        print(f"  SCAN FINDINGS  ({len(all_findings)} issues found)")
        print(f"{'─'*60}{RESET}\n")
        for f in all_findings:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1
            print_finding(f)

    print(f"{BOLD}{'─'*60}")
    print(f"  SUMMARY")
    print(f"{'─'*60}{RESET}")
    print(f"  {RED}CRITICAL : {counts['CRITICAL']}{RESET}")
    print(f"  {ORANGE}HIGH     : {counts['HIGH']}{RESET}")
    print(f"  {YELLOW}MEDIUM   : {counts['MEDIUM']}{RESET}")
    print(f"  {GREEN}LOW      : {counts['LOW']}{RESET}")
    print(f"\n  Total Issues : {len(all_findings)}")
    print(f"  Scan Time    : {elapsed:.2f}s")
    print(f"  Target       : {url}")
    print(f"{DIM}{'─'*60}{RESET}\n")

    save_reports(url, all_findings, elapsed)
    return all_findings


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    banner()

    if len(sys.argv) < 2:
        print(f"{YELLOW}Usage:   python scanner_cli.py <URL>{RESET}")
        print(f"{YELLOW}Example: python scanner_cli.py https://example.com{RESET}\n")
        sys.exit(0)

    target_url = sys.argv[1]
    scan(target_url)
