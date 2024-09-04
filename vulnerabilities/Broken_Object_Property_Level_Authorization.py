import ast

class BOPAAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_endpoints = []
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.is_vulnerable = False

        # Analyze function body
        self.generic_visit(node)

        # If the function is determined to be vulnerable, add to list
        if self.is_vulnerable:
            self.vulnerable_endpoints.append(self.current_function)

    def visit_Call(self, node):
        """
        Check for any database queries or operations that could indicate
        access to sensitive properties (like user details, orders, etc.)
        without proper authorization checks.
        """
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['execute', 'fetchone', 'fetchall']:
                if self.is_query_accessing_sensitive_data(node):
                    if not self.has_authorization_check(node):
                        self.is_vulnerable = True
        self.generic_visit(node)

    def is_query_accessing_sensitive_data(self, node):
        """
        Check if the query is accessing sensitive fields such as `user_id`,
        `social_security_number`, `order_id`, etc.
        """
        sensitive_fields = ['user_id', 'social_security_number', 'order_id', 'password']
        for field in sensitive_fields:
            if field in ast.dump(node):
                return True
        return False

    def has_authorization_check(self, node):
        """
        Check if there is an authorization check around the query.
        This method will walk up the tree to see if the call is within
        a conditional that checks the session or user ID.
        """
        parent = node
        while parent:
            if isinstance(parent, ast.If):
                # Simple check for session or user_id checks in the condition
                if 'session' in ast.dump(parent.test) or 'user_id' in ast.dump(parent.test):
                    return True
            parent = getattr(parent, 'parent', None)
        return False

def analyze_file_for_broken_property_auth(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = BOPAAnalyzer()
    
    # Attach parent references for traversal
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node
    
    analyzer.visit(tree)
    return analyzer.vulnerable_endpoints


def check_bopa(data_access):
    """
    Check if the data access process is vulnerable to Broken Property-Level Authorization (BOPA).

    Parameters:
        data_access (str): The data access process to analyze.

    Returns:
        bool: True if the data access is vulnerable, False otherwise.
    """
    # Example: Detect access to sensitive properties without checks
    sensitive_accesses = ["access_sensitive_data", "get_user_password"]
    return any(access in data_access for access in sensitive_accesses)



# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_broken_property_auth(file_path)
#     if vulnerabilities:
#         print(f"BOPA vulnerabilities found in the following routes in {file_path}:")
#         for endpoint in vulnerabilities:
#             print(f" - Endpoint: {endpoint}")
#     else:
#         print("No BOPA vulnerabilities found.")

# if __name__ == "__main__":
#     main()
