"""
╔══════════════════════════════════════════════════════════╗
║   Security Misconfiguration Detection Tool (Web App)     ║
║   Run:  streamlit run scanner_app.py                     ║
╚══════════════════════════════════════════════════════════╝

Install dependencies first:
    pip install requests beautifulsoup4 streamlit
"""

import json
import csv
import datetime
import requests
import streamlit as st
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
import io

# ─── Page Config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Security Misconfiguration Detector",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0d0d0d; color: #f1f1f1; }

    .main-title {
        font-size: 2.4rem; font-weight: 900;
        color: #ffffff; margin-bottom: 0;
    }
    .main-subtitle {
        font-size: 1.05rem; color: #888;
        margin-top: 0.2rem; margin-bottom: 1.5rem;
    }
    .brand-red   { color: #e63946; }
    .brand-green { color: #2ec4b6; }

    .badge {
        display: inline-block; padding: 2px 10px;
        border-radius: 4px; font-size: 0.7rem;
        font-weight: 700; letter-spacing: 1px;
    }
    .badge-CRITICAL { background: #e63946; color: white; }
    .badge-HIGH     { background: #f4a261; color: #111; }
    .badge-MEDIUM   { background: #ffd166; color: #111; }
    .badge-LOW      { background: #2ec4b6; color: #111; }
    .badge-INFO     { background: #4cc9f0; color: #111; }

    .finding-card {
        background: #1a1a1a;
        border-left: 4px solid #e63946;
        border-radius: 6px;
        padding: 14px 16px;
        margin-bottom: 12px;
    }
    .finding-card.HIGH     { border-left-color: #f4a261; }
    .finding-card.MEDIUM   { border-left-color: #ffd166; }
    .finding-card.LOW      { border-left-color: #2ec4b6; }
    .finding-title  { font-weight: 700; font-size: 0.95rem; color: #f1f1f1; }
    .finding-detail { color: #aaa; font-size: 0.85rem; margin-top: 4px; }
    .finding-fix {
        background: #0f2a1a;
        border: 1px solid #1a4a2a;
        border-radius: 4px;
        padding: 8px 12px;
        margin-top: 10px;
        font-size: 0.82rem;
        color: #7ddc9a;
    }
    .fix-label {
        font-weight: 700;
        color: #2ec4b6;
        font-size: 0.78rem;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }
    .fix-code {
        font-family: monospace;
        background: #0a1a10;
        padding: 6px 10px;
        border-radius: 3px;
        font-size: 0.78rem;
        color: #a8e6c0;
        margin-top: 4px;
        white-space: pre-wrap;
        word-break: break-all;
    }

    .stat-box {
        background: #1a1a1a; border-radius: 8px;
        padding: 16px; text-align: center;
        border: 1px solid #2a2a2a;
    }
    .stat-number { font-size: 2rem; font-weight: 900; }
    .stat-label  { font-size: 0.8rem; color: #777; margin-top: 2px; }

    .stTextInput > div > div > input {
        background-color: #1a1a1a !important;
        color: #f1f1f1 !important;
        border: 1px solid #333 !important;
        border-radius: 6px !important;
        font-size: 1rem !important;
    }

    .stButton > button {
        background-color: #e63946 !important;
        color: white !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 0.5rem 2rem !important;
        font-size: 1rem !important;
        width: 100%;
    }
    .stButton > button:hover { background-color: #c1121f !important; }

    hr { border-color: #2a2a2a !important; }
    #MainMenu, footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─── Remediation Database ─────────────────────────────────────────────────────

REMEDIATION = {
    "Missing Header: Content-Security-Policy": {
        "fix": "Add a Content-Security-Policy header in your server/app configuration.",
        "code": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';"
    },
    "Missing Header: X-Frame-Options": {
        "fix": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
        "code": "X-Frame-Options: DENY"
    },
    "Missing Header: Strict-Transport-Security": {
        "fix": "Enable HSTS to force HTTPS connections. Add to your server config:",
        "code": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Missing Header: X-Content-Type-Options": {
        "fix": "Add this header to stop browsers from MIME-sniffing responses.",
        "code": "X-Content-Type-Options: nosniff"
    },
    "Missing Header: Referrer-Policy": {
        "fix": "Add Referrer-Policy to control how much referrer info is shared.",
        "code": "Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Missing Header: Permissions-Policy": {
        "fix": "Add Permissions-Policy to restrict browser features you don't need.",
        "code": "Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
    "Wildcard CORS Policy Detected": {
        "fix": "Replace wildcard CORS with a specific allowed origin list.",
        "code": "Access-Control-Allow-Origin: https://yourtrustedsite.com"
    },
    "Directory Listing Enabled": {
        "fix": "Disable directory listing in your web server config.",
        "code": "# Apache: Add 'Options -Indexes' in .htaccess\n# Nginx: Add 'autoindex off;' in server block"
    },
    "POST Form Without CSRF Token": {
        "fix": "Add a hidden CSRF token field to every POST form.",
        "code": "# Flask-WTF example:\nfrom flask_wtf import FlaskForm\n# In template: {{ form.hidden_tag() }}"
    },
    "Password Field Missing autocomplete='off'": {
        "fix": "Add autocomplete attribute to password input fields.",
        "code": "<input type='password' autocomplete='new-password'>"
    },
    "Debug / Error Information Exposed": {
        "fix": "Disable debug mode in production and use custom error pages.",
        "code": "# Flask:\napp.config['DEBUG'] = False\napp.config['PROPAGATE_EXCEPTIONS'] = False"
    },
    "Sensitive Keyword Found in HTML Comment": {
        "fix": "Remove all sensitive information from HTML comments before deploying.",
        "code": "# Review and delete comments containing:\n# passwords, tokens, API keys, TODOs with sensitive info"
    },
}

def get_remediation(title):
    """Match finding title to a remediation entry (partial match)."""
    for key, val in REMEDIATION.items():
        if key.lower() in title.lower() or title.lower().startswith(key.lower()[:25]):
            return val
    # Category-based fallbacks
    if "cookie" in title.lower():
        return {
            "fix": "Set Secure, HttpOnly, and SameSite flags on all cookies.",
            "code": "# Flask example:\nresponse.set_cookie('session', value, secure=True, httponly=True, samesite='Lax')"
        }
    if "server version" in title.lower():
        return {
            "fix": "Hide server version info from response headers.",
            "code": "# Apache: ServerTokens Prod\n# Nginx: server_tokens off;\n# IIS: Remove X-Powered-By in web.config"
        }
    if "x-powered-by" in title.lower():
        return {
            "fix": "Remove X-Powered-By header to avoid technology fingerprinting.",
            "code": "# Express.js: app.disable('x-powered-by')\n# PHP: expose_php = Off  (in php.ini)"
        }
    if "exposed" in title.lower() or "accessible" in title.lower():
        return {
            "fix": "Restrict or remove access to sensitive admin/config paths.",
            "code": "# Block in .htaccess:\n<FilesMatch '\\.(env|git|config)$'>\n  Deny from all\n</FilesMatch>"
        }
    return None


# ─── Scanner Functions ────────────────────────────────────────────────────────

def fetch_target(url):
    resp = requests.get(
        url,
        headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"},
        timeout=10,
        allow_redirects=True,
    )
    return resp


def check_security_headers(response):
    findings = []
    headers  = response.headers

    required = [
        ("Content-Security-Policy",  "HIGH",   "No CSP header — XSS and code injection attacks are not mitigated."),
        ("X-Frame-Options",          "MEDIUM", "Missing X-Frame-Options — site may be vulnerable to Clickjacking."),
        ("Strict-Transport-Security","HIGH",   "Missing HSTS — browser may connect over insecure HTTP."),
        ("X-Content-Type-Options",   "MEDIUM", "Missing X-Content-Type-Options — MIME-sniffing risk."),
        ("Referrer-Policy",          "LOW",    "No Referrer-Policy — sensitive URL data may leak to third parties."),
        ("Permissions-Policy",       "LOW",    "No Permissions-Policy — browser features are unrestricted."),
    ]

    for name, sev, detail in required:
        if name not in headers:
            findings.append({
                "category": "Missing Security Header",
                "severity": sev,
                "title":    f"Missing Header: {name}",
                "detail":   detail,
            })

    server = headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
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
                "detail":   "Issues: " + "; ".join(issues) + ".",
            })
    return findings


def check_cors(response):
    findings = []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        findings.append({
            "category": "CORS Misconfiguration",
            "severity": "HIGH",
            "title":    "Wildcard CORS Policy Detected",
            "detail":   "Any website can make cross-origin requests to this server.",
        })
    return findings


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
        has_csrf    = any("csrf" in n or "token" in n for n in input_names)
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


def check_default_paths(url, progress_bar, status_text):
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
        ("/server-status",   "Apache server-status"),
        ("/elmah.axd",       "ELMAH error log"),
        ("/.git/HEAD",       "Exposed .git folder"),
        ("/backup.zip",      "Backup archive"),
    ]

    total = len(paths_list)
    for i, (path, label) in enumerate(paths_list):
        status_text.text(f"🔍 Checking path: {path}")
        progress_bar.progress((i + 1) / total)
        try:
            test_url = urljoin(url, path)
            r = requests.get(
                test_url, timeout=5, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}
            )
            if r.status_code in (200, 301, 302, 403):
                sev = "HIGH" if r.status_code == 200 else "MEDIUM"
                findings.append({
                    "category": "Exposed Path",
                    "severity": sev,
                    "title":    f"{label} Accessible: {path}  [{r.status_code}]",
                    "detail":   f"Path '{path}' returned HTTP {r.status_code}.",
                })
        except Exception:
            pass

    return findings


def severity_order(f):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(f["severity"], 5)


def badge_html(sev):
    return f'<span class="badge badge-{sev}">{sev}</span>'


def finding_card_html(f):
    sev = f["severity"]
    rem = get_remediation(f["title"])

    fix_section = ""
    if rem:
        fix_section = f"""
        <div class="finding-fix">
            <div class="fix-label">🔧 HOW TO FIX</div>
            <div>{rem['fix']}</div>
            <div class="fix-code">{rem['code']}</div>
        </div>
        """

    return f"""
    <div class="finding-card {sev}">
        {badge_html(sev)}
        <div class="finding-title" style="margin-top:6px">{f['title']}</div>
        <div class="finding-detail">{f['detail']}</div>
        <div style="font-size:0.75rem; color:#555; margin-top:6px">📁 {f['category']}</div>
        {fix_section}
    </div>
    """


def generate_json(url, findings, elapsed):
    findings_with_fix = []
    for f in findings:
        entry = dict(f)
        rem = get_remediation(f["title"])
        if rem:
            entry["remediation"] = rem["fix"]
            entry["remediation_code"] = rem["code"]
        findings_with_fix.append(entry)

    report = {
        "target":    url,
        "timestamp": datetime.datetime.now().isoformat(),
        "scan_time": f"{elapsed:.2f}s",
        "total":     len(findings),
        "findings":  findings_with_fix,
    }
    return json.dumps(report, indent=2)


def generate_csv(findings):
    output = io.StringIO()
    fieldnames = ["category", "severity", "title", "detail", "remediation", "remediation_code"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for f in findings:
        row = dict(f)
        rem = get_remediation(f["title"])
        if rem:
            row["remediation"] = rem["fix"]
            row["remediation_code"] = rem["code"]
        else:
            row["remediation"] = ""
            row["remediation_code"] = ""
        writer.writerow(row)
    return output.getvalue()


# ─── UI Layout ────────────────────────────────────────────────────────────────

st.markdown("""
<div style="padding: 1.5rem 0 0.5rem 0">
    <div class="main-title">🔒 Security Misconfiguration <span class="brand-red">Detector</span></div>
    <div class="main-subtitle">Automated web application security scanner — OWASP Top 10 aligned</div>
</div>
<hr>
""", unsafe_allow_html=True)

col_url, col_btn = st.columns([5, 1])
with col_url:
    url_input = st.text_input(
        label="Target URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
    )
with col_btn:
    scan_btn = st.button("🔍 Scan")

st.markdown("<hr>", unsafe_allow_html=True)

# ─── Run Scan ─────────────────────────────────────────────────────────────────
if scan_btn:
    url = url_input.strip()
    if not url:
        st.error("Please enter a URL to scan.")
        st.stop()

    if not url.startswith("http"):
        url = "https://" + url

    st.markdown(f"**Target:** `{url}`")

    progress_bar  = st.progress(0)
    status_text   = st.empty()
    all_findings  = []
    start         = datetime.datetime.now()

    try:
        status_text.text("📡 Connecting to target...")
        progress_bar.progress(10)
        response = fetch_target(url)
        elapsed  = (datetime.datetime.now() - start).total_seconds()

        status_text.text("🔎 Checking security headers...")
        progress_bar.progress(25)
        all_findings += check_security_headers(response)

        status_text.text("🍪 Checking cookie security...")
        progress_bar.progress(40)
        all_findings += check_cookies(response)

        status_text.text("🌐 Checking CORS policy...")
        progress_bar.progress(50)
        all_findings += check_cors(response)

        status_text.text("📄 Analysing HTML content...")
        progress_bar.progress(60)
        all_findings += check_html_content(response, url)

        path_findings = check_default_paths(url, progress_bar, status_text)
        all_findings += path_findings

        elapsed = (datetime.datetime.now() - start).total_seconds()
        progress_bar.progress(100)
        status_text.text("✅ Scan complete!")

    except Exception as e:
        st.error(f"❌ Scan failed: {e}")
        st.stop()

    all_findings.sort(key=severity_order)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.markdown(f"""<div class="stat-box">
        <div class="stat-number" style="color:#e63946">{counts['CRITICAL']}</div>
        <div class="stat-label">CRITICAL</div></div>""", unsafe_allow_html=True)
    c2.markdown(f"""<div class="stat-box">
        <div class="stat-number" style="color:#f4a261">{counts['HIGH']}</div>
        <div class="stat-label">HIGH</div></div>""", unsafe_allow_html=True)
    c3.markdown(f"""<div class="stat-box">
        <div class="stat-number" style="color:#ffd166">{counts['MEDIUM']}</div>
        <div class="stat-label">MEDIUM</div></div>""", unsafe_allow_html=True)
    c4.markdown(f"""<div class="stat-box">
        <div class="stat-number" style="color:#2ec4b6">{counts['LOW']}</div>
        <div class="stat-label">LOW</div></div>""", unsafe_allow_html=True)
    c5.markdown(f"""<div class="stat-box">
        <div class="stat-number" style="color:#f1f1f1">{len(all_findings)}</div>
        <div class="stat-label">TOTAL  ({elapsed:.1f}s)</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not all_findings:
        st.success("✅ No issues found! The site appears well configured.")
    else:
        st.markdown(f"### 🚨 Findings  &nbsp; <span style='color:#777;font-size:0.9rem'>({len(all_findings)} issues)</span>", unsafe_allow_html=True)

        filter_sev = st.multiselect(
            "Filter by severity:",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )

        filtered = [f for f in all_findings if f["severity"] in filter_sev]

        for f in filtered:
            st.markdown(finding_card_html(f), unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("### 📄 Download Report")

    dl1, dl2 = st.columns(2)
    json_data = generate_json(url, all_findings, elapsed)
    csv_data  = generate_csv(all_findings)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    with dl1:
        st.download_button(
            label="⬇️ Download JSON Report",
            data=json_data,
            file_name=f"scan_report_{timestamp}.json",
            mime="application/json",
        )
    with dl2:
        st.download_button(
            label="⬇️ Download CSV Report",
            data=csv_data,
            file_name=f"scan_report_{timestamp}.csv",
            mime="text/csv",
        )

else:
    st.markdown("""
    <div style="text-align:center; color:#444; padding: 3rem 0;">
        <div style="font-size:4rem">🛡️</div>
        <div style="font-size:1.1rem; margin-top:1rem">Enter a URL above and click <b>Scan</b> to begin</div>
        <div style="font-size:0.85rem; margin-top:0.5rem; color:#333">
            Checks: Security Headers • Cookies • CORS • Directory Listing • CSRF • 
            Exposed Paths • Debug Info • HTML Comments
        </div>
    </div>
    """, unsafe_allow_html=True)