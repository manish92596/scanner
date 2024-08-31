import mysql.connector
import os
import argparse

def connect_to_database(host, user, password, database, port):
    """Establish and return a MySQL database connection."""
    return mysql.connector.connect(
        host=host,       # MySQL server host
        user=user,       # MySQL username
        password=password,  # MySQL password
        database=database,  # Database name
        port=port        # Port number
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

def monitor_files_and_update_db(conn, sleep_interval=5):
    """Monitor the files and update the database if changes are detected."""
    last_api_modified_time = None
    last_vulnerabilities_modified_time = None
    cursor = conn.cursor()

    api_file_path = 'all_apis.txt'
    vulnerabilities_file_path = 'all_vulnerabilities.txt'

    # Check if the API routes file has been modified
    current_api_modified_time = os.path.getmtime(api_file_path)
    
    if last_api_modified_time is None or current_api_modified_time != last_api_modified_time:
        # If the file is modified, update the API routes database
        update_api_routes(cursor, api_file_path)
        conn.commit()  # Commit the transaction
        
        # Update the last modified time
        last_api_modified_time = current_api_modified_time

    # Check if the vulnerabilities file has been modified
    current_vulnerabilities_modified_time = os.path.getmtime(vulnerabilities_file_path)

    if last_vulnerabilities_modified_time is None or current_vulnerabilities_modified_time != last_vulnerabilities_modified_time:
        # If the file is modified, update the vulnerabilities database
        update_vulnerabilities(cursor, vulnerabilities_file_path)
        conn.commit()  # Commit the transaction
        
        # Update the last modified time
        last_vulnerabilities_modified_time = current_vulnerabilities_modified_time

    cursor.close()
    conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Update API routes and vulnerabilities in the database.')

    # Add command-line arguments for the database connection details
    parser.add_argument('--db_host', type=str, required=True, help='MySQL database host')
    parser.add_argument('--db_user', type=str, required=True, help='MySQL database user')
    parser.add_argument('--db_password', type=str, required=True, help='MySQL database password')
    parser.add_argument('--db_name', type=str, required=True, help='MySQL database name')
    parser.add_argument('--db_port', type=int, required=True, help='MySQL database port')

    args = parser.parse_args()

    # Establish a persistent database connection using the provided arguments
    conn = connect_to_database(
        host=args.db_host,
        user=args.db_user,
        password=args.db_password,
        database=args.db_name,
        port=args.db_port
    )

    # Monitor the files and update the database if changes are detected
    monitor_files_and_update_db(conn)
