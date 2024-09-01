# # import hmac
# # import hashlib
# # from flask import Flask, jsonify, request, abort
# # from flask_cors import CORS
# # import threading
# # import time
# # import mysql.connector
# # import os
# # import importlib.util
# # import inspect
# # import logging
# # from contextlib import contextmanager

# # from api.List_APIs import list_routes_in_file

# # # Flask app setup
# # app = Flask(__name__)
# # CORS(app)

# # # Global variables to cache the results
# # cached_api_routes = None
# # cached_vulnerabilities = None
# # last_update_time = 0
# # update_interval = 2  # seconds

# # # Database connection parameters

# # db_params = {
# #     "host": "api-security-db.co0ynpevyflj.ap-south-1.rds.amazonaws.com",
# #     "user": "root",
# #     "password": "abhi1301",
# #     "database": "api_database",
# #     "port": 5506,
# # }



# # # Initialize logging
# # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # # Set your webhook secret here
# # WEBHOOK_SECRET = "manish302"

# # @contextmanager
# # def connect_to_database():
# #     """Establish and return a MySQL database connection."""
# #     conn = mysql.connector.connect(
# #         host=db_params["host"],
# #         user=db_params["user"],
# #         password=db_params["password"],
# #         database=db_params["database"],
# #         port=db_params["port"]
# #     )
# #     try:
# #         yield conn
# #     finally:
# #         conn.close()

# # def verify_signature(payload, signature):
# #     """Verify the webhook signature."""
# #     hash_object = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256)
# #     expected_signature = 'sha256=' + hash_object.hexdigest()
# #     return hmac.compare_digest(expected_signature, signature)

# # def save_file_content(file_path, content):
# #     """Save the content of the file to the specified path."""
# #     with open(file_path, 'w') as file:
# #         file.write(content)

# # def save_to_new_txt(file_content):
# #     """Save the file content to 'new.txt'."""
# #     with open('new.txt', 'w') as file:
# #         file.write(file_content)

# # def parse_api_route_line(line):
# #     """Parse path and methods from a line in the API routes file."""
# #     path = line.split("'path': ")[1].split(',')[0].strip().strip("'")
# #     methods = line.split("'methods': ")[1].strip().strip("[]}").replace("[", "").replace("'", "")
# #     return path, methods

# # def update_api_routes(cursor, file_path):
# #     """Update the database with the contents of the all_apis.txt file."""
# #     cursor.execute("DELETE FROM api_routes")
# #     with open(file_path, 'r') as file:
# #         for line in file:
# #             if 'path' in line and 'methods' in line:
# #                 path, methods = parse_api_route_line(line)
# #                 cursor.execute(
# #                     "INSERT INTO api_routes (path, methods) VALUES (%s, %s)",
# #                     (path, methods)
# #                 )
# #     logging.info("API routes database updated.")

# # def parse_vulnerability_line(line):
# #     """Parse vulnerability type and route name from a line in the vulnerabilities file."""
# #     if ':' in line:
# #         return line.split(':')[0].strip(), None
# #     elif '-' in line:
# #         return None, line.split('-')[1].strip()
# #     return None, None

# # def update_vulnerabilities(cursor, file_path):
# #     """Update the database with the contents of the all_vulnerabilities.txt file."""
# #     cursor.execute("DELETE FROM vulnerabilities")
# #     current_vulnerability = None
# #     with open(file_path, 'r') as file:
# #         for line in file:
# #             vulnerability_type, route_name = parse_vulnerability_line(line)
# #             if vulnerability_type:
# #                 current_vulnerability = vulnerability_type
# #             elif route_name and current_vulnerability:
# #                 cursor.execute(
# #                     "INSERT INTO vulnerabilities (vulnerability_type, route_name) VALUES (%s, %s)",
# #                     (current_vulnerability, route_name)
# #                 )
# #     logging.info("Vulnerabilities database updated.")

# # def load_analyzers():
# #     """Dynamically load all vulnerability analyzers from the 'vulnerabilities' directory."""
# #     analyzers = {}
# #     vulnerabilities_path = os.path.join(os.path.dirname(__file__), 'vulnerabilities')

# #     for filename in os.listdir(vulnerabilities_path):
# #         if filename.endswith('.py') and not filename.startswith('__'):
# #             module_name = filename[:-3]
# #             module_path = os.path.join(vulnerabilities_path, filename)
# #             spec = importlib.util.spec_from_file_location(module_name, module_path)
# #             module = importlib.util.module_from_spec(spec)
# #             spec.loader.exec_module(module)
# #             for name, func in inspect.getmembers(module, inspect.isfunction):
# #                 if name.startswith('analyze_file_for_'):
# #                     analyzers[module_name] = func

# #     return analyzers

# # def update_caches(file_path):
# #     global cached_api_routes, cached_vulnerabilities, last_update_time

# #     if time.time() - last_update_time < update_interval:
# #         return

# #     changes_detected = False

# #     # Update API routes
# #     new_api_routes = list_routes_in_file(file_path)
# #     if new_api_routes != cached_api_routes:
# #         cached_api_routes = new_api_routes
# #         with open('all_apis.txt', 'w') as api_file:
# #             for route in cached_api_routes:
# #                 api_file.write(f"{route}\n")
# #         changes_detected = True

# #     # Update vulnerabilities
# #     analyzers = load_analyzers()
# #     new_vulnerabilities = {}

# #     for vuln_name, analyzer_func in analyzers.items():
# #         formatted_vuln_name = vuln_name.replace('_', ' ')
# #         new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

# #     if new_vulnerabilities != cached_vulnerabilities:
# #         cached_vulnerabilities = new_vulnerabilities
# #         with open('all_vulnerabilities.txt', 'w') as vuln_file:
# #             for vuln_type, vuln_list in cached_vulnerabilities.items():
# #                 if vuln_list:
# #                     vuln_file.write(f"{vuln_type}:\n")
# #                     for vuln in vuln_list:
# #                         vuln_file.write(f" - {vuln}\n")
# #                     vuln_file.write("\n")
# #         changes_detected = True

# #     last_update_time = time.time()

# #     if changes_detected:
# #         with connect_to_database() as conn:
# #             cursor = conn.cursor()
# #             update_api_routes(cursor, 'all_apis.txt')
# #             update_vulnerabilities(cursor, 'all_vulnerabilities.txt')
# #             conn.commit()

# # @app.route('/dummy', methods=['GET'])
# # def dummy_endpoint():
# #     return jsonify({"status": "Dummy endpoint reached."}), 200

# # # @app.route('/scan', methods=['POST'])
# # # def scan_endpoint():
# # #     # Verify the webhook secret if it exists
# # #     if WEBHOOK_SECRET:
# # #         signature = request.headers.get('X-Hub-Signature-256')
# # #         if not signature or not verify_signature(request.data, signature):
# # #             abort(400, 'Invalid signature')

# # #     data = request.json

# # #     # Handle the push event
# # #     if data.get('ref') == 'refs/heads/main':
# # #         for commit in data.get('commits', []):
# # #             for modified_file in commit.get('modified', []):
# # #                 if modified_file == "e-commerce.py":
# # #                     file_content = data.get('head_commit', {}).get('message')  # Assuming the file content is part of the message
# # #                     save_file_content("e-commerce.py", file_content)
# # #                     save_to_new_txt(file_content)

# # #                     # Optionally, trigger cache update or any other processing
# # #                     threading.Thread(target=update_caches, args=("e-commerce.py",)).start()
# # #                     return jsonify({"status": "Processing started for e-commerce.py"}), 200

# # #     return jsonify({"status": "No action required"}), 200

# # @app.route('/scan', methods=['POST'])
# # def scan_endpoint():
# #     # Verify the webhook secret if it exists
# #     if WEBHOOK_SECRET:
# #         signature = request.headers.get('X-Hub-Signature-256')
# #         if not signature or not verify_signature(request.data, signature):
# #             abort(400, 'Invalid signature')

# #     data = request.json

# #     # Save the JSON content to dummy.py
# #     if data:
# #         print("data coming")
# #         dummy_file_path = "dummy.py"
# #         with open(dummy_file_path, 'w') as dummy_file:
# #             dummy_file.write(str(data))  # Convert the JSON content to a string and save it

# #         # Trigger cache update or any other processing using the dummy.py file
# #         threading.Thread(target=update_caches, args=(dummy_file_path,)).start()
# #         return jsonify({"status": "Processing started for dummy.py"}), 200

# #     return jsonify({"status": "No action required"}), 200


# # if __name__ == '__main__':
# #     app.run(debug=True, host='0.0.0.0', port=5001)















# import hmac
# import hashlib
# from flask import Flask, jsonify, request, abort
# from flask_cors import CORS
# import threading
# import requests  # For API requests
# import base64  # For decoding base64 content
# import mysql.connector
# import os
# import time  # To handle timing for updates
# import logging
# from contextlib import contextmanager
# import importlib
# import inspect
# from api.List_APIs import list_routes_in_file

# # Flask app setup
# app = Flask(__name__)
# CORS(app)

# # Global variables to cache the results
# cached_api_routes = None
# cached_vulnerabilities = None
# last_update_time = 0
# update_interval = 2  # Interval in seconds between updates

# # Database connection parameters
# db_params = {
#     "host": "api-security-db.co0ynpevyflj.ap-south-1.rds.amazonaws.com",
#     "user": "root",
#     "password": "abhi1301",
#     "database": "api_database",
#     "port": 5506,
# }

# # Initialize logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# WEBHOOK_SECRET = "manish302"
# GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Store your GitHub token as an environment variable

# @contextmanager
# def connect_to_database():
#     conn = mysql.connector.connect(
#         host=db_params["host"],
#         user=db_params["user"],
#         password=db_params["password"],
#         database=db_params["database"],
#         port=db_params["port"]
#     )
#     try:
#         yield conn
#     finally:
#         conn.close()

# def verify_signature(payload, signature):
#     """Verify the webhook signature."""
#     hash_object = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256)
#     expected_signature = 'sha256=' + hash_object.hexdigest()
#     return hmac.compare_digest(expected_signature, signature)

# def get_file_content_from_github(repo, path, commit_sha):
#     """Fetch the file content from GitHub based on the repository, file path, and commit SHA."""
#     url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={commit_sha}"
#     headers = {
#         "Authorization": f"token {GITHUB_TOKEN}",
#         "Accept": "application/vnd.github.v3+json"
#     }
#     response = requests.get(url, headers=headers)
#     if response.status_code == 200:
#         file_content = base64.b64decode(response.json()['content']).decode('utf-8')
#         return file_content
#     else:
#         logging.error(f"Failed to fetch file content for {path} from GitHub. Status code: {response.status_code}")
#         return None

# def save_to_database(cursor, api_routes, vulnerabilities):
#     """Save the API routes and vulnerabilities directly to the database."""
#     cursor.execute("DELETE FROM api_routes")
#     for route, methods in api_routes:
#         cursor.execute(
#             "INSERT INTO api_routes (path, methods) VALUES (%s, %s)",
#             (route, methods)
#         )
    
#     cursor.execute("DELETE FROM vulnerabilities")
#     for vuln_type, routes in vulnerabilities.items():
#         for route_name in routes:
#             cursor.execute(
#                 "INSERT INTO vulnerabilities (vulnerability_type, route_name) VALUES (%s, %s)",
#                 (vuln_type, route_name)
#             )
#     logging.info("Database updated with API routes and vulnerabilities.")

# def load_analyzers():
#     """Dynamically load all vulnerability analyzers from the 'vulnerabilities' directory."""
#     analyzers = {}
#     vulnerabilities_path = os.path.join(os.path.dirname(__file__), 'vulnerabilities')

#     for filename in os.listdir(vulnerabilities_path):
#         if filename.endswith('.py') and not filename.startswith('__'):
#             module_name = filename[:-3]
#             module_path = os.path.join(vulnerabilities_path, filename)
#             spec = importlib.util.spec_from_file_location(module_name, module_path)
#             module = importlib.util.module_from_spec(spec)
#             spec.loader.exec_module(module)
#             for name, func in inspect.getmembers(module, inspect.isfunction):
#                 if name.startswith('analyze_file_for_'):
#                     analyzers[module_name] = func

#     return analyzers

# def update_caches(file_path):
#     """Process the API routes and vulnerabilities from the file and update the database."""
#     global cached_api_routes, cached_vulnerabilities, last_update_time

#     if time.time() - last_update_time < update_interval:
#         return

#     changes_detected = False

#     # Update API routes
#     new_api_routes = list_routes_in_file(file_path)
#     if new_api_routes != cached_api_routes:
#         cached_api_routes = new_api_routes
#         changes_detected = True

#     # Update vulnerabilities
#     analyzers = load_analyzers()
#     new_vulnerabilities = {}

#     for vuln_name, analyzer_func in analyzers.items():
#         formatted_vuln_name = vuln_name.replace('_', ' ')
#         new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

#     if new_vulnerabilities != cached_vulnerabilities:
#         cached_vulnerabilities = new_vulnerabilities
#         changes_detected = True

#     last_update_time = time.time()

#     if changes_detected:
#         with connect_to_database() as conn:
#             cursor = conn.cursor()
#             save_to_database(cursor, cached_api_routes, cached_vulnerabilities)
#             conn.commit()

# @app.route('/scan', methods=['POST'])
# def scan_endpoint():
#     """Handle incoming webhook events and process modified files."""
#     if WEBHOOK_SECRET:
#         signature = request.headers.get('X-Hub-Signature-256')
#         if not signature or not verify_signature(request.data, signature):
#             abort(400, 'Invalid signature')

#     data = request.json
#     print("Data is coming")
#     if data.get('ref') == 'refs/heads/main':  # Ensure we're processing only the main branch
#         repo_full_name = data['repository']['full_name']
#         commit_sha = data['after']

#         for commit in data.get('commits', []):
#             for modified_file in commit.get('modified', []):
#                 file_content = get_file_content_from_github(repo_full_name, modified_file, commit_sha)
#                 if file_content:
#                     dummy_file_path = "dummy.py"
#                     with open(dummy_file_path, 'w') as dummy_file:
#                         dummy_file.write(file_content)

#                     threading.Thread(target=update_caches, args=(dummy_file_path,)).start()

#         return jsonify({"status": "Processing started"}), 200

#     return jsonify({"status": "No action required"}), 200

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5001)





























import hmac
import hashlib
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import threading
import mysql.connector
import os
import time
import logging
from contextlib import contextmanager
import importlib
import inspect
from api.List_APIs import list_routes_in_file

# Flask app setup
app = Flask(__name__)
CORS(app)

# Global variables to cache the results
cached_api_routes = None
cached_vulnerabilities = None
last_update_time = 0
update_interval = 2  # Interval in seconds between updates

# Database connection parameters
db_params = {
    "host": "api-security-db.co0ynpevyflj.ap-south-1.rds.amazonaws.com",
    "user": "root",
    "password": "abhi1301",
    "database": "api_database",
    "port": 5506,
}

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

WEBHOOK_SECRET = "manish302"

@contextmanager
def connect_to_database():
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

def save_to_database(cursor, api_routes, vulnerabilities):
    """Save the API routes and vulnerabilities directly to the database."""
    cursor.execute("DELETE FROM api_routes")
    for route, methods in api_routes:
        cursor.execute(
            "INSERT INTO api_routes (path, methods) VALUES (%s, %s)",
            (route, methods)
        )
    
    cursor.execute("DELETE FROM vulnerabilities")
    for vuln_type, routes in vulnerabilities.items():
        for route_name in routes:
            cursor.execute(
                "INSERT INTO vulnerabilities (vulnerability_type, route_name) VALUES (%s, %s)",
                (vuln_type, route_name)
            )
    logging.info("Database updated with API routes and vulnerabilities.")

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
    """Process the API routes and vulnerabilities from the file and update the database."""
    global cached_api_routes, cached_vulnerabilities, last_update_time

    if time.time() - last_update_time < update_interval:
        return

    changes_detected = False

    # Update API routes
    new_api_routes = list_routes_in_file(file_path)
    if new_api_routes != cached_api_routes:
        cached_api_routes = new_api_routes
        changes_detected = True

    # Update vulnerabilities
    analyzers = load_analyzers()
    new_vulnerabilities = {}

    for vuln_name, analyzer_func in analyzers.items():
        formatted_vuln_name = vuln_name.replace('_', ' ')
        new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

    if new_vulnerabilities != cached_vulnerabilities:
        cached_vulnerabilities = new_vulnerabilities
        changes_detected = True

    last_update_time = time.time()

    if changes_detected:
        with connect_to_database() as conn:
            cursor = conn.cursor()
            save_to_database(cursor, cached_api_routes, cached_vulnerabilities)
            conn.commit()

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    print("1")
    """Handle incoming webhook events and process the received file content."""
    # if WEBHOOK_SECRET:
    #     signature = request.headers.get('X-Hub-Signature-256')
    #     if not signature or not verify_signature(request.data, signature):
    #         abort(400, 'Invalid signature')

    data = request.json
    print(data['after'],"Hello", data)
    print("2")
    if 'file_path' in data and 'file_content' in data:
        file_path = data['file_path']
        file_content = data['file_content']
        print("3")
        # Save the content to a dummy.py file for further processing
        dummy_file_path = "dummy.py"
        with open(dummy_file_path, 'w') as dummy_file:
            dummy_file.write(file_content)
            print("4")
        # Process the saved file content
        threading.Thread(target=update_caches, args=(dummy_file_path,)).start()
        print("5")
        return jsonify({"status": "Processing started"}), 200

    return jsonify({"status": "No action required"}), 400

@app.route('/home', methods=['GET'])
def root():
    print("Amn")
    return jsonify({"status": "Success"}),200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
