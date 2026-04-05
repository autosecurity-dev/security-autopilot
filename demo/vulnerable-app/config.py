# ⚠️  DEMO FILE — this code is intentionally vulnerable
# It is never executed. Faults exist to trigger semgrep SAST rules.

import subprocess
import sqlite3
import hashlib

# VULN: Hardcoded Django secret key
SECRET_KEY = "hardcoded-django-secret-key-do-not-use-in-production-1234"

# VULN: Hardcoded database credentials
DB_CONFIG = {
    "host": "localhost",
    "user": "admin",
    "password": "admin123",
    "database": "myapp",
}

# VULN: Shell injection — user input passed directly to subprocess with shell=True
def run_report(report_name):
    subprocess.call("generate_report " + report_name, shell=True)

# VULN: SQL injection — string formatting in query
def get_user(username):
    conn = sqlite3.connect("myapp.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return cursor.fetchone()

# VULN: Weak hashing — MD5 used for passwords
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULN: Hardcoded API key inline
SENDGRID_API_KEY = "SG.AAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
