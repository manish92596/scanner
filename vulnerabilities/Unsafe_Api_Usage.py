import ast
import os

class UnsafeAPIUsageAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = set()  # Using a set to avoid duplicates
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for HTTP requests using external URLs without validation
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id in ['requests', 'http', 'urllib', 'urllib2']:
                if node.func.attr in ['get', 'post', 'put', 'delete', 'patch']:
                    if not self.is_url_validated(node) or not self.is_response_checked(node):
                        self.vulnerable_routes.add(self.current_function)
        self.generic_visit(node)

    def is_url_validated(self, node):
        parent = node.parent
        while parent:
            if isinstance(parent, ast.If):
                if 'validate_url' in ast.dump(parent.test) or 'is_safe_url' in ast.dump(parent.test):
                    return True
            parent = getattr(parent, 'parent', None)
        return False

    def is_response_checked(self, node):
        parent = node.parent
        while parent:
            if isinstance(parent, ast.If):
                if 'status_code' in ast.dump(parent.test):
                    return True
            parent = getattr(parent, 'parent', None)
        return False

    def analyze_file_for_unsafe_api_usage(self, file_path):
        with open(file_path, 'r') as file:
            node = ast.parse(file.read())
        ast.increment_lineno(node, 1)
        
        # Attach parent references for traversal
        for n in ast.walk(node):
            for child in ast.iter_child_nodes(n):
                child.parent = n
                
        self.visit(node)

def analyze_file_for_unsafe_api_usage(file_path):
    analyzer = UnsafeAPIUsageAnalyzer()
    analyzer.analyze_file_for_unsafe_api_usage(file_path)
    return analyzer.vulnerable_routes

def check_unsafe_api_usage(api_call):
    """
    Check if the API call is unsafe and potentially vulnerable to exploits.

    Parameters:
        api_call (str): The API call to analyze.

    Returns:
        bool: True if the API call is unsafe, False otherwise.
    """
    # Example: Check if API uses unvalidated input or lacks response checks
    unsafe_patterns = ["execute", "run", "call"]
    return any(pattern in api_call for pattern in unsafe_patterns)





# def main(directory):
#     vulnerable_routes = set()
#     for dirpath, _, filenames in os.walk(directory):
#         for filename in filenames:
#             if filename.endswith('.py'):
#                 vulnerable_routes.update(analyze_file_for_unsafe_api_usage(os.path.join(dirpath, filename)))

#     if vulnerable_routes:
#         print("Unsafe API usage found in the following routes:")
#         for route in vulnerable_routes:
#             print(f" - {route}")
#     else:
#         print("No unsafe API usage found.")

# if __name__ == '__main__':
#     main('.')  # Run this in the directory of your Python projects
