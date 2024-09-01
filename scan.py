












# # import hmac
# # import hashlib
# # from flask import Flask, jsonify, request, abort
# # from flask_cors import CORS
# # import threading
# # import mysql.connector
# # import os
# # import time
# # import logging
# # from contextlib import contextmanager
# # import importlib
# # import inspect

# # import requests
# # from api.List_APIs import list_routes_in_file

# # # Flask app setup
# # app = Flask(__name__)
# # CORS(app)

# # # Global variables to cache the results
# # cached_api_routes = None
# # cached_vulnerabilities = None
# # last_update_time = 0
# # update_interval = 2  # Interval in seconds between updates

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

# # WEBHOOK_SECRET = "manish302"

# # @contextmanager
# # def connect_to_database():
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

# # def save_to_database(cursor, api_routes, vulnerabilities):
# #     """Save the API routes and vulnerabilities directly to the database."""
# #     cursor.execute("DELETE FROM api_routes")
# #     for route, methods in api_routes:
# #         cursor.execute(
# #             "INSERT INTO api_routes (path, methods) VALUES (%s, %s)",
# #             (route, methods)
# #         )
    
# #     cursor.execute("DELETE FROM vulnerabilities")
# #     for vuln_type, routes in vulnerabilities.items():
# #         for route_name in routes:
# #             cursor.execute(
# #                 "INSERT INTO vulnerabilities (vulnerability_type, route_name) VALUES (%s, %s)",
# #                 (vuln_type, route_name)
# #             )
# #     logging.info("Database updated with API routes and vulnerabilities.")

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
# #     """Process the API routes and vulnerabilities from the file and update the database."""
# #     global cached_api_routes, cached_vulnerabilities, last_update_time

# #     if time.time() - last_update_time < update_interval:
# #         return

# #     changes_detected = False

# #     # Update API routes
# #     new_api_routes = list_routes_in_file(file_path)
# #     if new_api_routes != cached_api_routes:
# #         cached_api_routes = new_api_routes
# #         changes_detected = True

# #     # Update vulnerabilities
# #     analyzers = load_analyzers()
# #     new_vulnerabilities = {}

# #     for vuln_name, analyzer_func in analyzers.items():
# #         formatted_vuln_name = vuln_name.replace('_', ' ')
# #         new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

# #     if new_vulnerabilities != cached_vulnerabilities:
# #         cached_vulnerabilities = new_vulnerabilities
# #         changes_detected = True

# #     last_update_time = time.time()

# #     if changes_detected:
# #         with connect_to_database() as conn:
# #             cursor = conn.cursor()
# #             save_to_database(cursor, cached_api_routes, cached_vulnerabilities)
# #             conn.commit()




# # def get_file_content_url(repo, path, commit_sha):
# #     return f"https://raw.githubusercontent.com/{repo}/{commit_sha}/{path}"

# # # Function to process the commit
# # def process_commit(repo, commit_sha):
# #     # GitHub API URL for the specific commit
# #     commit_url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"

# #     # Make the API request to get commit details
# #     response = requests.get(commit_url, headers={"Accept": "application/vnd.github.v3+json"})

# #     print("4")
# #     if response.status_code == 200:
# #         commit_data = response.json()
# #         print("5")
# #         for file in commit_data['files']:
# #             filename = file['filename']
# #             patch = file.get('patch', None)

# #             print(f"File: {filename}")
            
# #             # Fetch the full content of the file at the specific commit
# #             file_url = get_file_content_url(repo, filename, commit_sha)
# #             file_response = requests.get(file_url)
            
# #             if file_response.status_code == 200:
# #                 full_content = file_response.text
# #                 print("Full File Content:")
# #                 print(full_content)
# #                 # Save the content to a dummy.py file for further processing
# #                 dummy_file_path = "api.py"
# #                 with open(dummy_file_path, 'w') as dummy_file:
# #                     dummy_file.write(full_content)
# #                     print(f"Saved content of {filename} to dummy.py")
# #                 # Process the saved file content (using threading for background processing)
# #                 threading.Thread(target=update_caches, args=(dummy_file_path,)).start()
# #             else:
# #                 print(f"Failed to fetch file content for {filename}, status code: {file_response.status_code}")
            
# #     else:
# #         print(f"Failed to fetch commit data: {response.status_code}")


# # @app.route('/scan', methods=['POST'])
# # def scan_endpoint():
# #     print("1")
# #     """Handle incoming webhook events and process the received file content."""
# #     print("1")
# #     data = request.json
# #     print("2")
# #     try:
# #         commit_sha = data['after']
# #         print(f"Processing commit SHA: {commit_sha}")
        
# #         # Extract the repository information from the webhook data
# #         repo_full_name = data['repository']['full_name']
        
# #         print("3")
# #         # Start processing the commit
# #         process_commit(repo_full_name, commit_sha)

# #         print("6")
        
# #         return jsonify({"status": "Processing started"}), 200
    
# #     except KeyError as e:
# #         print(f"KeyError: Missing key in JSON data - {e}")
# #         return jsonify({"error": f"Missing key: {e}"}), 400
    
# #     except Exception as e:
# #         print(f"An error occurred: {e}")
# #         return jsonify({"error": "An unexpected error occurred"}), 500

# # @app.route('/home', methods=['GET'])
# # def root():
# #     print("Amn")
# #     return jsonify({"status": "Success"}),200

# # if __name__ == '__main__':
# #     app.run(debug=True, host='0.0.0.0', port=5001)



































# # fined gain code 

# from flask import Flask, jsonify, request
# from flask_cors import CORS
# import subprocess
# import time
# import os
# import importlib.util
# import inspect

# from api.List_APIs import list_routes_in_file

# # Flask app setup
# app = Flask(__name__)
# CORS(app)

# # Global variables to cache the results
# cached_api_routes = None
# cached_vulnerabilities = None
# last_update_time = 0
# update_interval = 2  # seconds

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
            
#             # Automatically find functions starting with 'analyze_file_for_'
#             for name, func in inspect.getmembers(module, inspect.isfunction):
#                 if name.startswith('analyze_file_for_'):
#                     analyzers[module_name] = func

#     return analyzers

# def update_caches(file_path):
#     global cached_api_routes, cached_vulnerabilities, last_update_time

#     if time.time() - last_update_time < update_interval:
#         return

#     changes_detected = False

#     # Update API routes
#     new_api_routes = list_routes_in_file(file_path)
#     if new_api_routes != cached_api_routes:
#         cached_api_routes = new_api_routes
#         with open('all_apis.txt', 'w') as api_file:
#             for route in cached_api_routes:
#                 api_file.write(f"{route}\n")
#         changes_detected = True

#     # Update vulnerabilities
#     analyzers = load_analyzers()
#     new_vulnerabilities = {}

#     for vuln_name, analyzer_func in analyzers.items():
#         # Replace underscores with spaces in vulnerability names
#         formatted_vuln_name = vuln_name.replace('_', ' ')
#         new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

#     if new_vulnerabilities != cached_vulnerabilities:
#         cached_vulnerabilities = new_vulnerabilities
#         with open('all_vulnerabilities.txt', 'w') as vuln_file:
#             for vuln_type, vuln_list in cached_vulnerabilities.items():
#                 if vuln_list:
#                     vuln_file.write(f"{vuln_type}:\n")
#                     for vuln in vuln_list:
#                         vuln_file.write(f" - {vuln}\n")
#                     vuln_file.write("\n")
#         changes_detected = True

#     last_update_time = time.time()

#     if changes_detected:
#         # Instead of directly updating the database, run the import_apis_vul.py script
#         try:
#             subprocess.run(["python", "import_apis_vul.py"], check=True)
#             print("import_apis_vul.py executed successfully.")
#         except subprocess.CalledProcessError as e:
#             print(f"Error running import_apis_vul.py: {e}")

# @app.route('/scan', methods=['POST'])
# def scan_endpoint():
#     data = request.json
#     file_path = data.get('file_path')
    
#     # Ensure the necessary database parameters are provided
#     db_params = {
#         "host": data.get('db_host'),
#         "user": data.get('db_user'),
#         "password": data.get('db_password'),
#         "database": data.get('db_name'),
#         "port": data.get('db_port')
#     }

#     if not os.path.exists(file_path):
#         return jsonify({"error": "The file does not exist."}), 400

#     update_caches(file_path)
#     return jsonify({"status": "Scanning started."}), 200

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5001)





# without webhook ,fully run


# import subprocess
# from flask import Flask, jsonify, request
# from flask_cors import CORS
# import threading
# import time
# import requests
# import os
# import importlib.util
# import inspect

# from api.List_APIs import list_routes_in_file

# # Flask app setup
# app = Flask(__name__)
# CORS(app)

# # Global variables to cache the results
# cached_api_routes = None
# cached_vulnerabilities = None
# last_update_time = 0
# update_interval = 2  # seconds
# WEBHOOK_SECRET = "manish302"

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
            
#             # Automatically find functions starting with 'analyze_file_for_'
#             for name, func in inspect.getmembers(module, inspect.isfunction):
#                 if name.startswith('analyze_file_for_'):
#                     analyzers[module_name] = func

#     return analyzers

# def update_caches(file_path):
#     global cached_api_routes, cached_vulnerabilities, last_update_time

#     if time.time() - last_update_time < update_interval:
#         return

#     changes_detected = False

#     # Update API routes
#     new_api_routes = list_routes_in_file(file_path)
#     if new_api_routes != cached_api_routes:
#         cached_api_routes = new_api_routes
#         with open('all_apis.txt', 'w') as api_file:
#             for route in cached_api_routes:
#                 api_file.write(f"{route}\n")
#         changes_detected = True

#     # Update vulnerabilities
#     analyzers = load_analyzers()
#     new_vulnerabilities = {}

#     for vuln_name, analyzer_func in analyzers.items():
#         # Replace underscores with spaces in vulnerability names
#         formatted_vuln_name = vuln_name.replace('_', ' ')
#         new_vulnerabilities[formatted_vuln_name] = set(analyzer_func(file_path))

#     if new_vulnerabilities != cached_vulnerabilities:
#         cached_vulnerabilities = new_vulnerabilities
#         with open('all_vulnerabilities.txt', 'w') as vuln_file:
#             for vuln_type, vuln_list in cached_vulnerabilities.items():
#                 if vuln_list:
#                     vuln_file.write(f"{vuln_type}:\n")
#                     for vuln in vuln_list:
#                         vuln_file.write(f" - {vuln}\n")
#                     vuln_file.write("\n")
#         changes_detected = True

#     last_update_time = time.time()

#     if changes_detected:
#         # Run the import_apis_vul.py script to handle database updates
#         try:
#             subprocess.run(["python", "import_apis_vul.py"], check=True)
#             print("import_apis_vul.py executed successfully.")
#         except subprocess.CalledProcessError as e:
#             print(f"Error running import_apis_vul.py: {e}")

# def get_file_content_url(repo, path, commit_sha):
#     return f"https://raw.githubusercontent.com/{repo}/{commit_sha}/{path}"

# def process_commit(repo, commit_sha):
#     """Process a commit by fetching file content and saving it for further processing."""
#     commit_url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"

#     response = requests.get(commit_url, headers={"Accept": "application/vnd.github.v3+json"})
#     if response.status_code == 200:
#         commit_data = response.json()
#         for file in commit_data['files']:
#             filename = file['filename']

#             # Fetch the full content of the file at the specific commit
#             file_url = get_file_content_url(repo, filename, commit_sha)
#             file_response = requests.get(file_url)
            
#             if file_response.status_code == 200:
#                 full_content = file_response.text

#                 # Save the content to a dummy file (e.g., api.py) for further processing
#                 dummy_file_path = "api.py"
#                 with open(dummy_file_path, 'w') as dummy_file:
#                     dummy_file.write(full_content)
#                     print(f"Saved content of {filename} to {dummy_file_path}")
                
#                 # Process the saved file content (using threading for background processing)
#                 threading.Thread(target=update_caches, args=(dummy_file_path,)).start()
#             else:
#                 print(f"Failed to fetch file content for {filename}, status code: {file_response.status_code}")
#     else:
#         print(f"Failed to fetch commit data: {response.status_code}")

# @app.route('/scan', methods=['POST'])
# def scan_endpoint():
#     """Handle incoming webhook events and process the received file content."""
#     data = request.json
    
#     try:
#         commit_sha = data['after']
#         print(f"Processing commit SHA: {commit_sha}")
        
#         # Extract the repository information from the webhook data
#         repo_full_name = data['repository']['full_name']
        
#         # Start processing the commit
#         process_commit(repo_full_name, commit_sha)
        
#         return jsonify({"status": "Processing started"}), 200
    
#     except KeyError as e:
#         print(f"KeyError: Missing key in JSON data - {e}")
#         return jsonify({"error": f"Missing key: {e}"}), 400
    
#     except Exception as e:
#         print(f"An error occurred: {e}")
#         return jsonify({"error": "An unexpected error occurred"}), 500

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5001)









# webhook new




import subprocess
from flask import Flask, jsonify, request,abort
from flask_cors import CORS
import threading
import time
import requests
import os
import importlib.util
import inspect
import hmac
import hashlib

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


def verify_signature(payload, signature, secret):
    """Verify the payload signature using HMAC-SHA256."""
    computed_signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_signature, signature)


@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """Handle incoming webhook events and process the received file content."""
    signature=request.headers.get('X-Hub-Signature-256')
    if signature is None:
        print("No signature provided.")
        return jsonify({"error": "No signature provided"}), 400
    
     # Verify the signature
    payload = request.data
    if not verify_signature(payload, signature.split('=')[1], WEBHOOK_SECRET):
        print("Signature verification failed.")
        abort(400, 'Signature verification failed')



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
