

import subprocess
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import requests
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
WEBHOOK_SECRET = "manish302"

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
        # Replace underscores with spaces in vulnerability names
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
        # Run the import_apis_vul.py script to handle database updates
        try:
            subprocess.run(["python", "import_apis_vul.py"], check=True)
            print("import_apis_vul.py executed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error running import_apis_vul.py: {e}")

def get_file_content_url(repo, path, commit_sha):
    return f"https://raw.githubusercontent.com/{repo}/{commit_sha}/{path}"

def process_commit(repo, commit_sha):
    """Process a commit by fetching file content and saving it for further processing."""
    commit_url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"

    response = requests.get(commit_url, headers={"Accept": "application/vnd.github.v3+json"})
    if response.status_code == 200:
        commit_data = response.json()
        for file in commit_data['files']:
            filename = file['filename']

            # Fetch the full content of the file at the specific commit
            file_url = get_file_content_url(repo, filename, commit_sha)
            file_response = requests.get(file_url)
            
            if file_response.status_code == 200:
                full_content = file_response.text

                # Save the content to a dummy file (e.g., api.py) for further processing
                dummy_file_path = "api.py"
                with open(dummy_file_path, 'w') as dummy_file:
                    dummy_file.write(full_content)
                    print(f"Saved content of {filename} to {dummy_file_path}")
                
                # Process the saved file content (using threading for background processing)
                threading.Thread(target=update_caches, args=(dummy_file_path,)).start()
            else:
                print(f"Failed to fetch file content for {filename}, status code: {file_response.status_code}")
    else:
        print(f"Failed to fetch commit data: {response.status_code}")

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """Handle incoming webhook events and process the received file content."""
    data = request.json
    
    try:
        commit_sha = data['after']
        print(f"Processing commit SHA: {commit_sha}")
        
        # Extract the repository information from the webhook data
        repo_full_name = data['repository']['full_name']
        
        # Start processing the commit
        process_commit(repo_full_name, commit_sha)
        
        return jsonify({"status": "Processing started"}), 200
    
    except KeyError as e:
        print(f"KeyError: Missing key in JSON data - {e}")
        return jsonify({"error": f"Missing key: {e}"}), 400
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
