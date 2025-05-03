from flask import Flask, request, jsonify
from flask_restx import Api, Resource
import os

app = Flask(__name__)
api = Api(app, version="1.0", title="Test API", description="A simple API")

ns = api.namespace('api', description='App operations')

@ns.route('/hello')
class HelloResource(Resource):
    def get(self):
        """Returns a hello world message"""
        return {"message": "Hello World!"}


# Public homepage
@app.route('/')
def home():
    return "Welcome to the simple web app!"


# Simulated purchase database
fake_orders = {
    "1001": {"item": "Laptop", "price": "$1200"},
    "1002": {"item": "Smartphone", "price": "$800"},
    "1003": {"item": "Headphones", "price": "$200"}
}


# Admin page (with intentionally hardcoded credentials)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # VULNERABILITY: Hardcoded credentials (CWE-798)
        if username == 'admin' and password == 'password123':
            return "Welcome, admin!"
        else:
            return "Invalid credentials.", 401
    return '''
        <form method="post">
            Username: <input type="text" name="username" />
            Password: <input type="password" name="password" />
            <input type="submit" />
        </form>
    '''

# API endpoint returning sample data
@app.route('/api/data', methods=['GET'])
def api_data():
    return jsonify({"data": "This is some data!"})

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABILITY: Reflected XSS (CWE-79)
    return f"<h1>Search results for: {query}</h1>"

# Critical Vulnerability: Command Injection
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    if not host:
        return "Please provide a host parameter.", 400
    # VULNERABILITY: Command injection risk (CWE-77)
    os.system(f"ping -c 1 {host}")
    return f"Pinging {host}..."

# Complex Business Logic Vulnerability: Broken Access Control (IDOR)
@app.route('/purchase', methods=['POST'])
def purchase():
    item_id = request.form.get('item_id')
    if item_id in fake_orders:
        return f"Purchase successful! Access your order at /order/{item_id}"
    else:
        return "Invalid item ID.", 404

@app.route('/order/<order_id>', methods=['GET'])
def view_order(order_id):
    # VULNERABILITY: No proper access control check
    order = fake_orders.get(order_id)
    if order:
        return jsonify(order)
    else:
        return "Order not found.", 404

@app.route('/openapi.json')
def openapi_spec():
    return api.__schema__

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
