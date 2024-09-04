import ast

class BFLAAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = []
        self.current_function = None
        self.has_auth_decorator = False
        self.has_auth_check = False

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.has_auth_decorator = self.has_proper_auth_decorator(node)
        self.has_auth_check = False

        # Walk through the function's statements
        self.generic_visit(node)

        # Identify potential issues
        if not self.has_auth_decorator and not self.has_auth_check and self.is_sensitive_function():
            self.vulnerable_routes.append(self.current_function)

    def visit_If(self, node):
        # Detect if the 'if' statement includes an authorization check
        if self.is_auth_check(node):
            self.has_auth_check = True
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect if any authorization-related function is being called directly
        if self.is_auth_check_call(node):
            self.has_auth_check = True
        self.generic_visit(node)

    def has_proper_auth_decorator(self, node):
        """
        Check if a function has an appropriate authorization decorator.
        """
        auth_decorators = {'login_required', 'requires_roles', 'admin_required'}

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in auth_decorators:
                return True
            elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                if decorator.func.id in auth_decorators:
                    return True
        return False

    def is_auth_check(self, node):
        """
        Check if an 'if' statement is performing an authorization check.
        """
        auth_keywords = {'role', 'is_admin', 'has_permission', 'is_authorized'}

        if isinstance(node.test, (ast.Compare, ast.Call, ast.BoolOp)):
            for keyword in auth_keywords:
                if any(isinstance(val, ast.Name) and val.id == keyword for val in ast.walk(node.test)):
                    return True
        return False

    def is_auth_check_call(self, node):
        """
        Check if a direct authorization-related function is being called.
        """
        auth_functions = {'check_permission', 'verify_role', 'authorize', 'is_authorized', 'has_access'}

        if isinstance(node.func, ast.Name) and node.func.id in auth_functions:
            return True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in auth_functions:
            return True
        return False

    def is_sensitive_function(self):
        """
        Determine if a function is likely to be sensitive and should require authorization.
        """
        sensitive_keywords = {'admin', 'delete', 'update', 'modify', 'manage', 'create', 'approve'}

        if any(keyword in self.current_function.lower() for keyword in sensitive_keywords):
            return True
        return False
def check_bfla(function_call):
    vulnerable_functions = ["delete_user", "modify_account", "change_role"]
    return any(func in function_call for func in vulnerable_functions)

# def check_bfla(function_call):
#     """
#     Check if the function call is vulnerable to Broken Function Level Authorization.

#     Parameters:
#         function_call (str): The function call to analyze.

#     Returns:
#         bool: True if the function call might be vulnerable, False otherwise.
#     """
#     # Example: check if sensitive functions are called without proper checks
#     sensitive_functions = ["delete_user", "modify_account", "create_admin"]
#     return function_call in sensitive_functions


def analyze_file_for_bfla(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = BFLAAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_bfla(file_path)
#     if vulnerabilities:
#         print(f"Broken Function Level Authorization vulnerabilities found in the following routes in {file_path}:")
#         for route in vulnerabilities:
#             print(f" - Route: {route}")
#     else:
#         print("No Broken Function Level Authorization vulnerabilities found.")

# if __name__ == "__main__":
#     main()
