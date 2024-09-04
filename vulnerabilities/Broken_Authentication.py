import ast

class AuthAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = []
        self.current_function = None
        self.has_session_check = False
        self.handles_password_insecurely = False

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.has_session_check = False
        self.handles_password_insecurely = False

        # Walk through the function's statements
        self.generic_visit(node)

        # Identify potential issues
        if self.handles_password_insecurely or (not self.has_session_check and self.requires_authentication(node)):
            self.vulnerable_routes.append(self.current_function)

    def visit_If(self, node):
        # Detect if the 'if' statement includes a session or authentication check
        if self.is_session_check(node):
            self.has_session_check = True
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Detect if passwords are being handled insecurely (e.g., plain text assignment)
        if self.is_password_handling_insecure(node):
            self.handles_password_insecurely = True
        self.generic_visit(node)

    def is_session_check(self, node):
        """
        Check if an 'if' statement is performing a session or authentication check.
        """
        auth_keywords = {'session', 'user_id', 'is_authenticated', 'logged_in'}
        
        if isinstance(node.test, (ast.Compare, ast.Call, ast.BoolOp)):
            for keyword in auth_keywords:
                if any(isinstance(val, ast.Name) and val.id == keyword for val in ast.walk(node.test)):
                    return True
        return False

    def is_password_handling_insecure(self, node):
        """
        Check if passwords are being handled insecurely (e.g., stored in plain text).
        """
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == 'password' for target in node.targets):
                if isinstance(node.value, ast.Constant) or isinstance(node.value, ast.Name):
                    # If password is being directly assigned a string (using ast.Constant) or another variable, it's insecure
                    return True
        return False

    def requires_authentication(self, node):
        """
        Determine if a function is likely to require authentication (heuristic).
        """
        # Example heuristic: Function name indicates it likely requires authentication
        auth_indicating_keywords = {'order', 'checkout', 'admin', 'profile', 'dashboard', 'update', 'delete'}
        
        if any(keyword in self.current_function.lower() for keyword in auth_indicating_keywords):
            return True
        return False

def check_broken_authentication(auth_process):
    """
    Check if the authentication process is vulnerable to Broken Authentication.

    Parameters:
        auth_process (str): The authentication process to analyze.

    Returns:
        bool: True if the process is vulnerable, False otherwise.
    """
    # Example: Check if weak passwords or insecure login processes are used
    weak_patterns = ["'weak_password'", "'password123'", "login"]
    return any(pattern in auth_process for pattern in weak_patterns)




def analyze_file_for_auth(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = AuthAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_auth(file_path)
#     if vulnerabilities:
#         print(f"Broken Authentication vulnerabilities found in the following routes in {file_path}:")
#         for route in vulnerabilities:
#             print(f" - Route: {route}")
#     else:
#         print("No Broken Authentication vulnerabilities found.")

# if __name__ == "__main__":
#     main()
