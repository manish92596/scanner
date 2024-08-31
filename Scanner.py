import subprocess
import logging
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import importlib.util
import inspect

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

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_path, debounce_time=1.0):
        self.file_path = os.path.abspath(file_path)
        self.debounce_time = debounce_time
        self.last_modified = time.time()

    def on_modified(self, event):
        # Ensure that we're comparing absolute paths
        event_path = os.path.abspath(event.src_path)

        if event_path == self.file_path:
            now = time.time()
            if now - self.last_modified >= self.debounce_time:
                self.last_modified = now
                logger.info(f"Detected change in {self.file_path}. Updating caches...")
                update_caches(self.file_path)
            else:
                logger.debug(f"Change detected, but within debounce period. Ignoring.")

def run_import_apis(db_host, db_user, db_password, db_name, db_port):
    """Run the import_apis.py script with database credentials."""
    try:
        logger.info("Running import_apis.py...")
        subprocess.run([
            "python", "import_apis.py",
            f"--db_host={db_host}",
            f"--db_user={db_user}",
            f"--db_password={db_password}",
            f"--db_name={db_name}",
            f"--db_port={db_port}"
        ], check=True)
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
            
            # Automatically find functions starting with 'analyze_file_for_'
            for name, func in inspect.getmembers(module, inspect.isfunction):
                if name.startswith('analyze_file_for_'):
                    analyzers[module_name] = func

    return analyzers

def update_caches(file_path, db_host, db_user, db_password, db_name, db_port):
    global cached_api_routes, cached_vulnerabilities

    # Track if there's a change
    changes_detected = False

    # Update API routes
    logger.debug("Search API routes...")
    new_api_routes = list_routes_in_file(file_path)
    if new_api_routes != cached_api_routes:
        cached_api_routes = new_api_routes
        with open('all_apis.txt', 'w') as api_file:
            for route in cached_api_routes:
                api_file.write(f"{route}\n")
        logger.info(f"API routes updated: {new_api_routes}")        
        changes_detected = True

    # Update vulnerabilities
    logger.debug("Search for vulnerabilities...")
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
        logger.info(f"Vulnerabilities updated: {new_vulnerabilities}")
        changes_detected = True

    # If changes were detected, run the import_apis script
    if changes_detected:
        run_import_apis(db_host, db_user, db_password, db_name, db_port)

def monitor_file(file_path, db_host, db_user, db_password, db_name, db_port):
    # Perform an initial scan
    logger.info(f"Performing initial scan of {file_path}...")
    update_caches(file_path, db_host, db_user, db_password, db_name, db_port)

    event_handler = FileChangeHandler(file_path)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(os.path.abspath(file_path)), recursive=False)
    observer.start()
    logger.info(f"Started monitoring {file_path} for changes...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    # Parse the command-line arguments to get the file path and database connection details
    parser = argparse.ArgumentParser(description='Run the API scanner.')
    parser.add_argument('--repo', type=str, required=True, help='GitHub repository (e.g., owner/repo)')
    parser.add_argument('--file_path', type=str, required=True, help='Path to the file to be scanned (e.g., e-commerce.py)')
    parser.add_argument('--branch', type=str, required=True, help='Branch to fetch the file from')
    parser.add_argument('--token', type=str, required=True, help='GitHub API token')
    parser.add_argument('--db_host', type=str, required=True, help='MySQL database host')
    parser.add_argument('--db_user', type=str, required=True, help='MySQL database user')
    parser.add_argument('--db_password', type=str, required=True, help='MySQL database password')
    parser.add_argument('--db_name', type=str, required=True, help='MySQL database name')
    parser.add_argument('--db_port', type=int, required=True, help='MySQL database port')

    args = parser.parse_args()

    file_path = args.file_path  # Use the file path provided by the user

    # Ensure the file exists before monitoring
    if not os.path.exists(file_path):
        logger.error(f"The file {file_path} does not exist. Exiting...")
        exit(1)

    # Monitor the file for changes and update caches accordingly
    monitor_file(file_path, args.db_host, args.db_user, args.db_password, args.db_name, args.db_port)
