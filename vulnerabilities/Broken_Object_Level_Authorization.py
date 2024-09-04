import ast

class BOLAAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = []
        self.current_function = None
        self.auth_check_found = False
        self.db_access_found = False

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.auth_check_found = False
        self.db_access_found = False

        # Skip common authentication/session management routes
        if self.is_authentication_route(node.name):
            self.generic_visit(node)
            return

        # Walk through the function's statements
        self.generic_visit(node)

        # If database access is found without authentication/authorization check, flag it as vulnerable
        if self.db_access_found and not self.auth_check_found:
            self.vulnerable_routes.append(self.current_function)

    def is_authentication_route(self, function_name):
        # Common routes that typically do not involve BOLA
        auth_routes = {'login', 'signup', 'logout'}
        return function_name in auth_routes

    def visit_If(self, node):
        # Check if this 'if' statement is performing an authorization check
        if self.is_authorization_check(node):
            self.auth_check_found = True
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check if the function call is related to database access
        if self.is_database_access(node):
            self.db_access_found = True
        self.generic_visit(node)

    def is_authorization_check(self, node):
        """
        Check if an If statement is performing an authorization check.
        Look for conditions involving session, user_id, or roles.
        """
        authorization_keywords = {'session', 'user_id', 'role', 'current_user', 'is_admin', 'has_access'}

        if isinstance(node.test, (ast.Compare, ast.Call, ast.BoolOp)):
            for keyword in authorization_keywords:
                if any(isinstance(val, ast.Name) and val.id == keyword for val in ast.walk(node.test)):
                    return True
        return False

    def is_database_access(self, node):
        """
        Check if a function call is related to database access, like querying or modifying data.
        """
        db_keywords = {'execute', 'fetchone', 'fetchall', 'commit', 'insert', 'update', 'delete'}
        
        # Check if the function name matches typical database operation names
        if isinstance(node.func, ast.Attribute) and node.func.attr in db_keywords:
            return True
        return False

def analyze_file_for_bola(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = BOLAAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

def check_broken_object_level_authorization(auth_check):
    """
    Check if the authorization process is vulnerable to Broken Object Level Authorization (BOLA).

    Parameters:
        auth_check (str): The authorization check to analyze.

    Returns:
        bool: True if the authorization is vulnerable, False otherwise.
    """
    # Example: Check for missing or bypassed authorization checks
    bypass_patterns = ["bypass_authorization", "no_auth_check"]
    return any(pattern in auth_check for pattern in bypass_patterns)




# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_bola(file_path)
#     if vulnerabilities:
#         print(f"Broken Object Level Authorization Vulnerability found in the following routes in {file_path}:")
#         for route in vulnerabilities:
#             print(f" - Route: {route}")
#     else:
#         print("No Broken Object Level Authorization vulnerabilities found.")

# if __name__ == "__main__":
#     main()
