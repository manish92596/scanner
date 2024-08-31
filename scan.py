import hmac
import hashlib
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import threading
import time
import mysql.connector
import os
import importlib.util
import inspect
import logging
from contextlib import contextmanager

from api.List_APIs import list_routes_in_file

# Flask app setup
app = Flask(__name__)
CORS(app)

# Global variables to cache the results
cached_api_routes = None
cached_vulnerabilities = None
last_update_time = 0
update_interval = 2  # seconds

# Database connection parameters
db_params = {
    "host": None,
    "user": None,
    "password": None,
    "database": None,
    "port": None
}

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set your webhook secret here
WEBHOOK_SECRET = "manish302"

@contextmanager
def connect_to_database():
    """Establish and return a MySQL database connection."""
    conn = mysql.connector.connect(
        host=db_params["host"],
        user=db_params["user"],
        password=db_params["password"],
        database=db_params["database"],
        port=db_params["port"]
    )
    try:
        yield conn
    finally:
        conn.close()

def verify_signature(payload, signature):
    """Verify the webhook signature."""
    hash_object = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256)
    expected_signature = 'sha256=' + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def save_file_content(file_path, content):
    """Save the content of the file to the specified path."""
    with open(file_path, 'w') as file:
        file.write(content)

def save_to_new_txt(file_content):
    """Save the file content to 'new.txt'."""
    with open('new.txt', 'w') as file:
        file.write(file_content)

def parse_api_route_line(line):
    """Parse path and methods from a line in the API routes file."""
    path = line.split("'path': ")[1].split(',')[0].strip().strip("'")
    methods = line.split("'methods': ")[1].strip().strip("[]}").replace("[", "").replace("'", "")
    return path, methods

def update_api_routes(cursor, file_path):
    """Update the database with the contents of the all_apis.txt file."""
    cursor.execute("DELETE FROM api_routes")
    with open(file_path, 'r') as file:
        for line in file:
            if 'path' in line and 'methods' in line:
                path, methods = parse_api_route_line(line)
                cursor.execute(
                    "INSERT INTO api_routes (path, methods) VALUES (%s, %s)",
                    (path, methods)
                )
    logging.info("API routes database updated.")

def parse_vulnerability_line(line):
    """Parse vulnerability type and route name from a line in the vulnerabilities file."""
    if ':' in line:
        return line.split(':')[0].strip(), None
    elif '-' in line:
        return None, line.split('-')[1].strip()
    return None, None

def update_vulnerabilities(cursor, file_path):
    """Update the database with the contents of the all_vulnerabilities.txt file."""
    cursor.execute("DELETE FROM vulnerabilities")
    current_vulnerability = None
    with open(file_path, 'r') as file:
        for line in file:
            vulnerability_type, route_name = parse_vulnerability_line(line)
            if vulnerability_type:
                current_vulnerability = vulnerability_type
            elif route_name and current_vulnerability:
                cursor.execute(
                    "INSERT INTO vulnerabilities (vulnerability_type, route_name) VALUES (%s, %s)",
                    (current_vulnerability, route_name)
                )
    logging.info("Vulnerabilities database updated.")

def load_analyzers():
    """Dynamically load all vulnerability analyzers from the 'vulnerabilities' directory."""
    analyzers = {}
    vulnerabilities_path = os.path.join(os.path.dirname(__file__), 'vulnerabilities')

    for filename in os.listdir(vulnerabilities_path):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            module_path = os.path.join(vulnerabilities_path, filename)
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for name, func in inspect.getmembers(module, inspect.isfunction):
                if name.startswith('analyze_file_for_'):
                    analyzers[module_name] = func

    return analyzers

def update_caches(file_path):
    global cached_api_routes, cached_vulnerabilities, last_update_time

    if time.time() - last_update_time < update_interval:
        return

    changes_detected = False

    # Update API routes
    new_api_routes = list_routes_in_file(file_path)
    if new_api_routes != cached_api_routes:
        cached_api_routes = new_api_routes
        with open('all_apis.txt', 'w') as api_file:
            for route in cached_api_routes:
                api_file.write(f"{route}\n")
        changes_detected = True

    # Update vulnerabilities
    analyzers = load_analyzers()
    new_vulnerabilities = {}

    for vuln_name, analyzer_func in analyzers.items():
        formatted_vuln_name = vuln_name.replace('_', ' ')
        new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

    if new_vulnerabilities != cached_vulnerabilities:
        cached_vulnerabilities = new_vulnerabilities
        with open('all_vulnerabilities.txt', 'w') as vuln_file:
            for vuln_type, vuln_list in cached_vulnerabilities.items():
                if vuln_list:
                    vuln_file.write(f"{vuln_type}:\n")
                    for vuln in vuln_list:
                        vuln_file.write(f" - {vuln}\n")
                    vuln_file.write("\n")
        changes_detected = True

    last_update_time = time.time()

    if changes_detected:
        with connect_to_database() as conn:
            cursor = conn.cursor()
            update_api_routes(cursor, 'all_apis.txt')
            update_vulnerabilities(cursor, 'all_vulnerabilities.txt')
            conn.commit()

@app.route('/dummy', methods=['GET'])
def dummy_endpoint():
    return jsonify({"status": "Dummy endpoint reached."}), 200

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    # Verify the webhook secret if it exists
    if WEBHOOK_SECRET:
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature or not verify_signature(request.data, signature):
            abort(400, 'Invalid signature')

    data = request.json

    # Handle the push event
    if data.get('ref') == 'refs/heads/main':
        for commit in data.get('commits', []):
            for modified_file in commit.get('modified', []):
                if modified_file == "e-commerce.py":
                    file_content = data.get('head_commit', {}).get('message')  # Assuming the file content is part of the message
                    save_file_content("e-commerce.py", file_content)
                    save_to_new_txt(file_content)

                    # Optionally, trigger cache update or any other processing
                    threading.Thread(target=update_caches, args=("e-commerce.py",)).start()
                    return jsonify({"status": "Processing started for e-commerce.py"}), 200

    return jsonify({"status": "No action required"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
