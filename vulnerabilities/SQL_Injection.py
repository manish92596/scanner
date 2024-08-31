import os
import re
import ast

class SQLInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_routes = set()
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check if the function being called is 'execute'
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            query = self.get_query_string(node)
            if query and contains_user_input(query):
                self.vulnerable_routes.add(self.current_function)
        self.generic_visit(node)

    def get_query_string(self, node):
        try:
            if isinstance(node.args[0], ast.Constant):  # Handles string literals
                return node.args[0].value
            elif isinstance(node.args[0], ast.BinOp):  # Handles concatenation
                return self.flatten_concat(node.args[0])
            elif isinstance(node.args[0], ast.JoinedStr):  # Handles f-strings
                return ''.join(part.value for part in node.args[0].values if isinstance(part, ast.Constant))
            else:
                return ast.dump(node.args[0])  # Fallback to dumping the AST for complex cases
        except:
            return None

    def flatten_concat(self, node):
        if isinstance(node, ast.BinOp):
            left = self.flatten_concat(node.left)
            right = self.flatten_concat(node.right)
            return left + right
        elif isinstance(node, ast.Constant):
            return node.value
        else:
            return ast.dump(node)

def contains_user_input(query_code):
    user_input_patterns = [
        r"\+",             # String concatenation
        r"\%",             # String formatting
        r"\{",             # f-string or .format() interpolation
        r"request\.form",  # Flask form data
        r"request\.args",  # Flask query parameters
        r"request\.json",  # Flask JSON payload
        r"input",          # Generic variable often used for user input
        r"search",         # Generic term often used in search functionality
        r"query",          # Generic variable often used for dynamic queries
        r"params"          # Often used for SQL parameters
    ]

    for pattern in user_input_patterns:
        if re.search(pattern, query_code):
            return True
    
    return False

def analyze_file_for_sql_injection(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = SQLInjectionAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_routes

# def main():
#     root_directory = '.'  # Set to the current directory
#     vulnerabilities = set()
    
#     for subdir, _, files in os.walk(root_directory):
#         for file in files:
#             if file.endswith('.py'):
#                 filepath = os.path.join(subdir, file)
#                 vulnerabilities.update(analyze_file_for_sql_injection(filepath))

#     if vulnerabilities:
#         print("SQL Injection vulnerabilities found in the following routes:")
#         for route in vulnerabilities:
#             print(f" - {route}")
#     else:
#         print("No SQL Injection vulnerabilities found.")

# if __name__ == '__main__':
#     main()
