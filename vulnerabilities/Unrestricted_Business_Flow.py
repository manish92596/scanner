import ast

class UnrestrictedBusinessFlowAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_endpoints = []
        self.current_function = None
        self.has_auth_check = False

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.has_auth_check = False

        # Analyze function body
        self.generic_visit(node)

        # If there is no auth check, mark the function as vulnerable
        if not self.has_auth_check and self.requires_protection(node):
            self.vulnerable_endpoints.append(self.current_function)

    def visit_If(self, node):
        # Check if the 'if' statement includes an authentication or authorization check
        if self.is_auth_check(node):
            self.has_auth_check = True
        self.generic_visit(node)

    def is_auth_check(self, node):
        """
        Check if an 'if' statement is performing a session or authorization check.
        """
        auth_keywords = {'session', 'user_id', 'is_authenticated', 'role', 'admin'}
        
        if isinstance(node.test, (ast.Compare, ast.Call, ast.BoolOp)):
            for keyword in auth_keywords:
                if any(isinstance(val, ast.Name) and val.id == keyword for val in ast.walk(node.test)):
                    return True
        return False

    def requires_protection(self, node):
        """
        Determine if a function is likely to require protection based on its name or content.
        """
        sensitive_keywords = {'process', 'payment', 'admin', 'delete', 'order', 'checkout'}
        
        if any(keyword in self.current_function.lower() for keyword in sensitive_keywords):
            return True
        return False

def analyze_file_for_unrestricted_business_flow(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = UnrestrictedBusinessFlowAnalyzer()
    
    # Attach parent references for traversal
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node
    
    analyzer.visit(tree)
    return analyzer.vulnerable_endpoints

# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_unrestricted_business_flow(file_path)
#     if vulnerabilities:
#         print(f"Unrestricted Access to Sensitive Business Flows vulnerabilities found in the following routes in {file_path}:")
#         for endpoint in vulnerabilities:
#             print(f" - Endpoint: {endpoint}")
#     else:
#         print("No vulnerabilities found.")

# if __name__ == "__main__":
#     main()
