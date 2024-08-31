import subprocess
import logging
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import importlib.util
import inspect
from flask import Flask, request, jsonify

from api.List_APIs import list_routes_in_file

# Setup logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("events_log.txt"),
                    ])

logger = logging.getLogger(__name__)

# Global variables to cache the results
cached_api_routes = None
cached_vulnerabilities = None

app = Flask(__name__)

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_path, debounce_time=1.0):
        self.file_path = os.path.abspath(file_path)
        self.debounce_time = debounce_time
        self.last_modified = time.time()

    def on_modified(self, event):
        event_path = os.path.abspath(event.src_path)

        if event_path == self.file_path:
            now = time.time()
            if now - self.last_modified >= self.debounce_time:
                self.last_modified = now
                logger.info(f"Detected change in {self.file_path}. Updating caches...")
                update_caches(self.file_path)
            else:
                logger.debug(f"Change detected, but within debounce period. Ignoring.")

def run_import_apis():
    """Run the import_apis.py script."""
    try:
        logger.info("Running import_apis.py...")
        subprocess.run(["python", "import_apis.py"], check=True)
        logger.info("import_apis.py executed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running import_apis.py: {e}")

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
    global cached_api_routes, cached_vulnerabilities

    changes_detected = False

    logger.debug("Search API routes...")
    new_api_routes = list_routes_in_file(file_path)
    added_routes = []
    removed_routes = []

    if cached_api_routes is not None:
        added_routes = [route for route in new_api_routes if route not in cached_api_routes]
        removed_routes = [route for route in cached_api_routes if route not in new_api_routes]

    cached_api_routes = new_api_routes

    if added_routes or removed_routes:
        changes_detected = True
        logger.info(f"API routes added: {added_routes}")
        logger.info(f"API routes removed: {removed_routes}")
        with open('all_apis.txt', 'w') as api_file:
            for route in cached_api_routes:
                api_file.write(f"{route}\n")

    logger.debug("Search for vulnerabilities...")
    analyzers = load_analyzers()
    new_vulnerabilities = {}
    updated_vulnerabilities = {}

    for vuln_name, analyzer_func in analyzers.items():
        formatted_vuln_name = vuln_name.replace('_', ' ')
        vuln_list = set(analyzer_func(file_path))
        if cached_vulnerabilities is not None:
            added_vulns = vuln_list - cached_vulnerabilities.get(formatted_vuln_name, set())
            if added_vulns:
                updated_vulnerabilities[formatted_vuln_name] = added_vulns
        new_vulnerabilities[formatted_vuln_name] = vuln_list

    if new_vulnerabilities != cached_vulnerabilities:
        cached_vulnerabilities = new_vulnerabilities
        logger.info(f"Updated vulnerabilities: {updated_vulnerabilities}")
        with open('all_vulnerabilities.txt', 'w') as vuln_file:
            for vuln_type, vuln_list in cached_vulnerabilities.items():
                if vuln_list:
                    vuln_file.write(f"{vuln_type}:\n")
                    for vuln in vuln_list:
                        vuln_file.write(f" - {vuln}\n")
                    vuln_file.write("\n")
        changes_detected = True

    if changes_detected:
        run_import_apis()

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    repo = data.get('repo')
    file_path = data.get('file_path')
    branch = data.get('branch')
    token = data.get('token')
    db_host = data.get('db_host')
    db_user = data.get('db_user')
    db_password = data.get('db_password')
    db_name = data.get('db_name')
    db_port = data.get('db_port')

    logger.info(f"Received scan request for repo: {repo}, file: {file_path}, branch: {branch}")

    # Update the database connection parameters
    os.environ['DB_HOST'] = db_host
    os.environ['DB_USER'] = db_user
    os.environ['DB_PASSWORD'] = db_password
    os.environ['DB_NAME'] = db_name
    os.environ['DB_PORT'] = db_port

    # Perform the scan
    update_caches(file_path)
    return jsonify({"status": "Scan completed"}), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the API scanner.')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host for the Flask server')
    parser.add_argument('--port', type=int, default=5000, help='Port for the Flask server')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
