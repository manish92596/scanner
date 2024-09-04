# test_list_api.py
import pytest
import ast
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from scanner.api.List_APIs import list_routes_in_file, RouteLister

@pytest.fixture
def sample_code():
    """Provide a sample Flask application code as a test fixture."""
    return """
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/api/data', methods=['POST'])
def get_data():
    return "Data Received"

@app.route('/api/info', methods=['GET', 'POST'])
def get_info():
    return "Info"

@app.route('/health', methods=['GET'])
def health_check():
    return "OK"
"""

def normalize_methods(methods):
    """Helper function to normalize methods to list format."""
    if isinstance(methods, str):
        return [methods]
    return methods

def test_list_routes_in_file(tmp_path, sample_code):
    """Test the list_routes_in_file function."""
    test_file = tmp_path / "test_flask_app.py"
    test_file.write_text(sample_code)

    expected_routes = [
        {'path': '/', 'methods': ['GET']},
        {'path': '/api/data', 'methods': ['POST']},
        {'path': '/api/info', 'methods': ['GET', 'POST']},
        {'path': '/health', 'methods': ['GET']}
    ]

    routes = list_routes_in_file(test_file)
    
    
    for route in routes:
        route['methods'] = normalize_methods(route['methods'])

    assert routes == expected_routes

def test_extract_route_info():
    """Test the extract_route_info method of RouteLister."""
    lister = RouteLister()

    # Manually create an example decorator node to simulate @app.route('/example', methods=['POST'])
    example_decorator = ast.Call(
        func=ast.Attribute(value=ast.Name(id='app', ctx=ast.Load()), attr='route', ctx=ast.Load()),
        args=[ast.Str(s='/example')],
        keywords=[ast.keyword(arg='methods', value=ast.List(elts=[ast.Str(s='POST')], ctx=ast.Load()))]
    )
    route_info = lister.extract_route_info(example_decorator)

    expected_info = {
        'path': '/example',
        'methods': ['POST']
    }

    assert route_info == expected_info

def test_visit_FunctionDef(sample_code):
    """Test the visit_FunctionDef method of RouteLister."""
    tree = ast.parse(sample_code)
    lister = RouteLister()
    lister.visit(tree)

    expected_routes = [
        {'path': '/', 'methods': ['GET']},
        {'path': '/api/data', 'methods': ['POST']},
        {'path': '/api/info', 'methods': ['GET', 'POST']},
        {'path': '/health', 'methods': ['GET']}
    ]

    # Normalize the methods in the routes for comparison
    for route in lister.routes:
        route['methods'] = normalize_methods(route['methods'])

    assert lister.routes == expected_routes
