import hashlib
import json
import os
import subprocess
import requests

# Inappropriate Security Configuration & Insecure Code Snippets

DEBUG = True
SECRET_KEY = "django-insecure-hardcoded-secret-key-inappropriate-99999"


def handle_user_login(cursor, username, password):
    # Inappropriate SQL query concatenation (SQL Injection)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

    # Inappropriate weak password hash
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


def execute_system_diagnostic(user_host):
    # Inappropriate command execution via shell=True
    subprocess.run(f"ping -c 1 {user_host}", shell=True)


def dynamic_evaluator(untrusted_code_string):
    # Inappropriate arbitrary code execution
    return eval(untrusted_code_string)


def send_telemetry():
    # Inappropriate disabled TLS certificate validation
    response = requests.get("https://internal.telemetry.service/api", verify=False)
    # Inappropriate wildcard CORS header
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response
