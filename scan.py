
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import mysql.connector
import os
import importlib.util
import inspect

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

def connect_to_database():
    """Establish and return a MySQL database connection."""
    return mysql.connector.connect(
        host=db_params["host"],
        user=db_params["user"],
        password=db_params["password"],
        database=db_params["database"],
        port=db_params["port"]
    )

def update_api_routes(cursor, file_path):
    """Update the database with the contents of the all_apis.txt file."""
    
    # Delete all existing data from the api_routes table
    cursor.execute("DELETE FROM api_routes")

    # Open and read the file
    with open(file_path, 'r') as file:
        for line in file:
            # Parsing the path and methods from the line
            if 'path' in line and 'methods' in line:
                path = line.split("'path': ")[1].split(',')[0].strip().strip("'")
                methods = line.split("'methods': ")[1].strip().strip("[]}").replace("[", "").replace("'", "")
                
                # Insert the parsed data into the database
                cursor.execute(
                    "INSERT INTO api_routes (path, methods) VALUES (%s, %s)",
                    (path, methods)
                )

    print("API routes database updated.")

def update_vulnerabilities(cursor, file_path):
    """Update the database with the contents of the all_vulnerabilities.txt file."""
    
    # Delete all existing data from the vulnerabilities table
    cursor.execute("DELETE FROM vulnerabilities")

    # Open and read the file
    with open(file_path, 'r') as file:
        current_vulnerability = None
        for line in file:
            if ':' in line:  # Identifies the vulnerability type
                current_vulnerability = line.split(':')[0].strip()
            elif '-' in line and current_vulnerability:  # Identifies the route name
                route_name = line.split('-')[1].strip()
                
                # Insert the parsed data into the database
                cursor.execute(
                    "INSERT INTO vulnerabilities (vulnerability_type, route_name) VALUES (%s, %s)",
                    (current_vulnerability, route_name)
                )

    print("Vulnerabilities database updated.")

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
            
            # Automatically find functions starting with 'analyze_file_for_'
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
        new_vulnerabilities[vuln_name] = set(analyzer_func(file_path))

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
        conn = connect_to_database()
        cursor = conn.cursor()
        update_api_routes(cursor, 'all_apis.txt')
        update_vulnerabilities(cursor, 'all_vulnerabilities.txt')
        conn.commit()
        cursor.close()
        conn.close()

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    data = request.json
    file_path = data.get('file_path')
    
    db_params["host"] = data.get('db_host')
    db_params["user"] = data.get('db_user')
    db_params["password"] = data.get('db_password')
    db_params["database"] = data.get('db_name')
    db_params["port"] = data.get('db_port')
    
    if not os.path.exists(file_path):
        return jsonify({"error": "The file does not exist."}), 400

    update_caches(file_path)
    return jsonify({"status": "Scanning started."}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
