import ast

class SSRFAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = set()
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.generic_visit(node)

    def visit_Call(self, node):
        # Look for HTTP calls that might involve user input in URLs
        if isinstance(node.func, ast.Attribute) and node.func.attr in ['get', 'post', 'put', 'delete']:
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ['requests', 'http', 'urllib', 'urllib2']:
                if self.is_user_input_in_url(node):
                    self.vulnerable_routes.add(self.current_function)
        self.generic_visit(node)

    def is_user_input_in_url(self, node):
        for arg in node.args:
            if isinstance(arg, ast.BinOp):  # String concatenation
                if self.contains_user_input(arg):
                    return True
            elif isinstance(arg, ast.JoinedStr):  # f-strings
                if self.contains_user_input(arg):
                    return True
            elif isinstance(arg, ast.Name):  # Variable that could be user-controlled
                if self.is_potential_user_controlled_variable(arg.id):
                    return True
            elif isinstance(arg, ast.Call):  # Function calls that might return user input
                if self.contains_user_input(arg):
                    return True
        return False

    def contains_user_input(self, node):
        user_input_sources = {'request', 'session', 'args', 'form', 'json', 'query', 'input', 'data'}
        if isinstance(node, ast.Name) and node.id in user_input_sources:
            return True
        for child in ast.iter_child_nodes(node):
            if self.contains_user_input(child):
                return True
        return False

    def is_potential_user_controlled_variable(self, var_name):
        user_controlled_keywords = {'url', 'target', 'user', 'id', 'query', 'name', 'param', 'path'}
        return any(keyword in var_name.lower() for keyword in user_controlled_keywords)

def analyze_file_for_ssrf(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = SSRFAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

def check_ssrf(url):
    """
    Check if the provided URL is potentially vulnerable to SSRF attacks.
    
    Parameters:
        url (str): The URL to analyze.

    Returns:
        bool: True if the URL might be vulnerable to SSRF, False otherwise.
    """
    # Simulated logic: Check if URL points to metadata services which is common in SSRF attacks
    metadata_services = [
        "http://169.254.169.254/latest/meta-data",  # AWS metadata
        "http://metadata.google.internal",  # Google Cloud metadata
        "http://169.254.169.254/metadata/v1",  # DigitalOcean metadata
    ]
    return any(service in url for service in metadata_services)



# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_ssrf(file_path)
#     if vulnerabilities:
#         print("SSRF vulnerabilities found in the following routes:")
#         for route in vulnerabilities:
#             print(f" - {route}")
#     else:
#         print("No SSRF vulnerabilities found.")

# if __name__ == "__main__":
#     main()
