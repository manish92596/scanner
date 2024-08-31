import os
import ast

class ResourceConsumptionAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = []
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        user_controlled_vars = self.find_user_controlled_vars(node)

        # Check for resource-heavy operations influenced by user-controlled input or fixed large loops
        if self.contains_resource_heavy_operations(node.body, user_controlled_vars):
            self.vulnerable_routes.append(self.current_function)

        self.generic_visit(node)

    def find_user_controlled_vars(self, node):
        """
        Identify variables that are controlled by user input.
        """
        user_controlled_vars = set()

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                if isinstance(stmt.value, ast.Call):
                    if self.is_user_input(stmt.value):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                user_controlled_vars.add(target.id)

        return user_controlled_vars

    def is_user_input(self, call_node):
        """
        Check if the function call is associated with user input (e.g., request.form, request.args).
        """
        if isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name) and call_node.func.value.id == 'request':
                if call_node.func.attr in {'form', 'args', 'json'}:
                    return True
        return False

    def contains_resource_heavy_operations(self, body, user_controlled_vars):
        """
        Detect resource-heavy operations influenced by user-controlled variables or large fixed loops.
        """
        for stmt in body:
            if isinstance(stmt, ast.For) or isinstance(stmt, ast.While):
                # Check for loops influenced by user-controlled variables
                if isinstance(stmt.iter, ast.Name) and stmt.iter.id in user_controlled_vars:
                    return True
                # Check for loops with large fixed iterations
                if isinstance(stmt.iter, ast.Call) and self.is_large_fixed_loop(stmt.iter):
                    return True
            if isinstance(stmt, ast.Call) and self.is_potentially_expensive_operation(stmt, user_controlled_vars):
                return True
        return False

    def is_large_fixed_loop(self, call_node):
        """
        Check if the loop involves a large fixed iteration count (e.g., range(1000000)).
        """
        if isinstance(call_node.func, ast.Name) and call_node.func.id == 'range':
            if isinstance(call_node.args[0], ast.Constant) and call_node.args[0].value >= 100000:  # Threshold for large loops
                return True
        return False

    def is_potentially_expensive_operation(self, call_node, user_controlled_vars):
        """
        Check if the operation is potentially expensive and influenced by user input.
        """
        # Check if the call is resource-heavy and influenced by user-controlled variables
        if isinstance(call_node.func, ast.Name):
            if call_node.func.id in {'range', 'list', 'dict', 'set', 'append'}:
                for arg in call_node.args:
                    if isinstance(arg, ast.Name) and arg.id in user_controlled_vars:
                        return True
        if isinstance(call_node.func, ast.Attribute):
            if call_node.func.attr in {'sort', 'append', 'extend', 'update', 'execute'}:
                for arg in call_node.args:
                    if isinstance(arg, ast.Name) and arg.id in user_controlled_vars:
                        return True
        return False

def analyze_file_for_resource_consumption(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = ResourceConsumptionAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

# def main():
#     root_directory = '.'  # Set to the current directory
#     vulnerabilities = []
    
#     for subdir, _, files in os.walk(root_directory):
#         for file in files:
#             if file.endswith('.py'):
#                 filepath = os.path.join(subdir, file)
#                 vulnerabilities.extend(analyze_file_for_resource_consumption(filepath))

#     if vulnerabilities:
#         print("Unrestricted Resource Consumption vulnerabilities found:")
#         for vuln in vulnerabilities:
#             print(f"Route: {vuln}\n")
#     else:
#         print("No Unrestricted Resource Consumption vulnerabilities found.")

# if __name__ == '__main__':
#     main()
