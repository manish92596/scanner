import ast

class ImproperInventoryManagementAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = []

    def visit_FunctionDef(self, node):
        # Check if the function is exposing API inventory without proper controls
        if self.is_exposing_inventory(node):
            self.vulnerable_routes.append(node.name)
        self.generic_visit(node)

    def is_exposing_inventory(self, node):
        # This is a basic check to see if the function lists all endpoints, similar to the '/api/all-endpoints' route.
        if isinstance(node, ast.FunctionDef):
            for n in ast.walk(node):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    if n.func.attr == 'iter_rules':  # Detecting the use of 'url_map.iter_rules()'
                        return True
        return False

def analyze_file_for_improper_inventory_management(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = ImproperInventoryManagementAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

# def main():
#     file_path = '../e-commerce.py'
#     vulnerabilities = analyze_file_for_improper_inventory_management(file_path)
#     if vulnerabilities:
#         print(f"Vulnerabilities found in the following routes:")
#         for vuln in vulnerabilities:
#             print(f" - {vuln}")
#     else:
#         print("No Improper Inventory Management vulnerabilities found.")

# if __name__ == "__main__":
#     main()
