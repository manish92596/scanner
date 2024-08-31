import ast

class SecurityMisconfigAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = set()
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = None

    def visit_Call(self, node):
        # Check for CORS misconfiguration
        if isinstance(node.func, ast.Name) and node.func.id == 'CORS':
            for keyword in node.keywords:
                if keyword.arg == 'resources':
                    if isinstance(keyword.value, ast.Dict):
                        for key, value in zip(keyword.value.keys, keyword.value.values):
                            if isinstance(value, ast.Dict):
                                for k, v in zip(value.keys, value.values):
                                    if isinstance(k, ast.Constant) and k.value == 'origins' and isinstance(v, ast.Constant) and v.value == '*':
                                        self.vulnerable_routes.add(self.current_function)

        # Check for Flask debug mode
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'run':
            for keyword in node.keywords:
                if keyword.arg == 'debug' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.vulnerable_routes.add(self.current_function)

        # Check for insecure deserialization
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'loads' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
            self.vulnerable_routes.add(self.current_function)

        self.generic_visit(node)

def analyze_file_for_security_misconfig(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = SecurityMisconfigAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_security_misconfig(file_path)
#     if vulnerabilities:
#         print("Routes with Security Misconfiguration vulnerabilities found in the following routes:")
#         for route in vulnerabilities:
#             print(f" - {route}")
#     else:
#         print("No Security Misconfiguration vulnerabilities found.")

# if __name__ == "__main__":
#     main()
