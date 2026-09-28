#!/usr/bin/env python3
"""Generate PIPELINE_AUTH_PBKDF2 using only the Python standard library."""
import base64, getpass, hashlib, os
password = getpass.getpass("Password: ")
confirm = getpass.getpass("Confirm : ")
if password != confirm or not password:
    raise SystemExit("password mismatch or empty")
iterations = 310000
salt = os.urandom(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
print(f"{iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}")
