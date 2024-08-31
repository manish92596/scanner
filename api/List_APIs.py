import ast

class RouteLister(ast.NodeVisitor):
    def __init__(self):
        self.routes = []

    def visit_FunctionDef(self, node):
        # Check if the function has a decorator with `@app.route`
        if node.decorator_list:
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr == 'route':
                        route_info = self.extract_route_info(decorator)
                        if route_info:
                            self.routes.append(route_info)
        self.generic_visit(node)

    def extract_route_info(self, decorator):
        # Extract route path and methods from the decorator
        route_info = {
            'path': None,
            'methods': 'GET'  # Default method if not specified
        }
        if decorator.args:
            route_info['path'] = decorator.args[0].s  # Extract the path string
        if decorator.keywords:
            for keyword in decorator.keywords:
                if keyword.arg == 'methods':
                    route_info['methods'] = [m.s for m in keyword.value.elts]  # Extract the methods list
        return route_info

def list_routes_in_file(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    lister = RouteLister()
    lister.visit(tree)
    return lister.routes

# def main():
#     file_path = "./e-commerce.py"  # Replace with the path to your e-commerce file
#     routes = list_routes_in_file(file_path)

#     print(f"Routes/APIs found in {file_path}:")
#     for route in routes:
#         methods = ', '.join(route['methods']) if isinstance(route['methods'], list) else route['methods']
#         print(f"Path: {route['path']}, Methods: {methods}")
    
#     # Save routes to a file
#     with open('routes_output.txt', 'w') as f:
#         f.write(f"Routes/APIs found in {file_path}:\n")
#         for route in routes:
#             methods = ', '.join(route['methods']) if isinstance(route['methods'], list) else route['methods']
#             route_info = f"Path: {route['path']}, Methods: {methods}\n"
#             f.write(route_info)

# if __name__ == "__main__":
#     main()
