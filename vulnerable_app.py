"""
╔══════════════════════════════════════════════════════════╗
║   Vulnerable Flask Test Application                      ║
║   FOR EDUCATIONAL / DEMO PURPOSES ONLY                   ║
║   Run:  python vulnerable_app.py                         ║
║   Then scan:  http://localhost:5000                      ║
╚══════════════════════════════════════════════════════════╝

WARNING: This app is INTENTIONALLY insecure.
Run ONLY on localhost for demo/testing purposes.
"""

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# ─── MISCONFIGURATION 1: Debug mode ON ───────────────────────────────────────
app.config['DEBUG'] = True
app.secret_key = "supersecretkey123"

# ─── HOME PAGE ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # MISCONFIGURATION 2: No security headers set anywhere
    # MISCONFIGURATION 3: Sensitive keyword in HTML comment
    # MISCONFIGURATION 4: Password field without autocomplete=off
    # MISCONFIGURATION 5: POST form without CSRF token
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TestBank - Home</title>
    </head>
    <body>
        <h1>Welcome to TestBank</h1>
        <p>Your trusted online banking portal.</p>

        <!-- TODO: remove this before production - admin password is admin@1234 -->
        <!-- API_KEY: sk-test-abc123xyz789 -->

        <h2>Login</h2>
        <form method="POST" action="/login">
            <input type="text"     name="username" placeholder="Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <input type="submit"   value="Login">
        </form>

        <h2>Contact Us</h2>
        <form method="POST" action="/contact">
            <input type="text"   name="name"    placeholder="Your Name"><br><br>
            <input type="text"   name="message" placeholder="Message"><br><br>
            <input type="submit" value="Send">
        </form>
    </body>
    </html>
    """
    return html


# ─── LOGIN ROUTE ──────────────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # MISCONFIGURATION 6: Debug/error info exposed in response
    if username == "admin" and password == "admin123":
        return f"<h2>Welcome {username}!</h2><p>Login successful.</p>"
    else:
        # Exposing internal error details
        return f"""
        <h2>Login Failed</h2>
        <p>DEBUG INFO: User '{username}' not found in database table 'users'.</p>
        <p>SQLError: SELECT * FROM users WHERE username='{username}' returned 0 rows.</p>
        <a href="/">Go Back</a>
        """


# ─── CONTACT ROUTE ────────────────────────────────────────────────────────────
@app.route("/contact", methods=["POST"])
def contact():
    name = request.form.get("name", "")
    return f"<h2>Thanks {name}, your message was received!</h2><a href='/'>Go Back</a>"


# ─── MISCONFIGURATION 7: Exposed admin path ──────────────────────────────────
@app.route("/admin")
def admin():
    return """
    <h1>Admin Panel</h1>
    <p>Welcome to the admin dashboard.</p>
    <ul>
        <li>Total Users: 1,204</li>
        <li>Active Sessions: 47</li>
        <li>Server: Apache/2.4.41</li>
    </ul>
    """


# ─── MISCONFIGURATION 8: Exposed .env style config path ─────────────────────
@app.route("/.env")
def env_file():
    return """DB_HOST=localhost
DB_USER=root
DB_PASS=root1234
SECRET_KEY=mysecretkey
API_KEY=sk-prod-abc123xyz
DEBUG=True
""", 200, {"Content-Type": "text/plain"}


# ─── MISCONFIGURATION 9: Exposed debug endpoint ──────────────────────────────
@app.route("/debug")
def debug_route():
    return """
    <h2>Debug Info</h2>
    <pre>
    app.debug = True
    Database: MySQL 5.7 @ localhost:3306
    Python: 3.10.2
    Flask: 2.2.0
    Traceback (most recent call last):
      File "app.py", line 42, in connect_db
        conn = pymysql.connect(host='localhost', user='root', password='root1234')
    </pre>
    """


# ─── MISCONFIGURATION 10: Directory listing style page ───────────────────────
@app.route("/files")
def files():
    return """
    <html><body>
    <h1>Index of /files</h1>
    <pre>
    Parent Directory
    config.php
    backup.zip
    database.sql
    passwords.txt
    </pre>
    </body></html>
    """


# ─── MISCONFIGURATION 11: CORS wildcard header ───────────────────────────────
@app.after_request
def add_headers(response):
    # Wildcard CORS — intentionally insecure
    response.headers["Access-Control-Allow-Origin"] = "*"
    # No security headers added intentionally
    return response


# ─── RUN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════╗
║   Vulnerable Test App is running!                        ║
║   Open: http://localhost:5000                            ║
║                                                          ║
║   Now scan it with:                                      ║
║   python scanner_cli.py http://localhost:5000            ║
║   OR open Streamlit app and scan http://localhost:5000   ║
╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=True)
