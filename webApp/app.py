from flask import Flask, request, jsonify, render_template_string
from flask_restx import Api, Resource
import os

app = Flask(__name__)
api = Api(
    app,
    version="1.0",
    title="Test API",
    description="A simple API",
    doc='/api/docs',
    prefix='/api'
)

ns = api.namespace('api', description='App operations')

@ns.route('/hello')
class HelloResource(Resource):
    def get(self):
        return {"message": "Hello World!"}


# Simulated purchase database
fake_orders = {
    "1001": {"item": "Laptop", "price": "$1200"},
    "1002": {"item": "Smartphone", "price": "$800"},
    "1003": {"item": "Headphones", "price": "$200"}
}


@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Vulnerable Web App</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { padding: 40px; background-color: #f8f9fa; }
            .container { max-width: 800px; }
            .section { margin-bottom: 40px; }
            .form-control, .btn { margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="mb-4">Welcome to the Vulnerable Web App!</h1>

            <div class="section">
                <h2>Navigation</h2>
                <ul class="list-group">
                    <li class="list-group-item"><a href="/admin">Admin</a></li>
                    <li class="list-group-item"><a href="/ping?host=localhost">Ping</a></li>
                    <li class="list-group-item"><a href="/api/data">API Data</a></li>
                    <li class="list-group-item"><a href="/purchase">Purchase</a></li>
                    <li class="list-group-item"><a href="/api/docs">Swagger Docs</a></li>
                </ul>
            </div>

            <div class="section">
                <h2>Search</h2>
                <form method="GET" action="/search">
                    <input class="form-control" name="q" placeholder="Enter search term" />
                    <button class="btn btn-primary mt-2" type="submit">Search</button>
                </form>
            </div>

            <div class="section">
                <h2>Ping</h2>
                <form method="GET" action="/ping">
                    <input class="form-control" name="host" placeholder="Enter host to ping" />
                    <button class="btn btn-warning mt-2" type="submit">Ping</button>
                </form>
            </div>

            <div class="section">
                <h2>View Order</h2>
                <form method="GET" onsubmit="redirectToOrder(event)">
                    <input class="form-control" id="orderIdInput" placeholder="Enter Order ID (e.g., 1001)" />
                    <button class="btn btn-info mt-2" type="submit">View Order</button>
                </form>
            </div>

        </div>

        <script>
        function redirectToOrder(event) {
            event.preventDefault();
            const orderId = document.getElementById('orderIdInput').value;
            if (orderId) {
                window.location.href = '/order/' + encodeURIComponent(orderId);
            }
        }
        </script>

    </body>
    </html>
    ''')



@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # ⚠️ Vulnerability: Hardcoded credentials (CWE-798)
        if username == 'admin' and password == 'password123':
            return "Welcome, admin!"
        else:
            return "Invalid credentials.", 401

    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="container mt-5">
        <h2>Admin Login</h2>
        <form method="post" id="adminForm">
            <input class="form-control" type="text" name="username" placeholder="Username" />
            <input class="form-control" type="password" name="password" placeholder="Password" />
            <button class="btn btn-danger mt-3" type="submit">Login</button>
        </form>
        <script>
        document.getElementById("adminForm").addEventListener("submit", function(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            fetch("/admin", {
                method: "POST",
                body: formData
            })
            .then(res => res.text())
            .then(alert);
        });
        </script>
    </body>
    </html>
    '''


@app.route('/api/data', methods=['GET'])
def api_data():
    return jsonify({"data": "This is some data!"})


@app.route('/search')
def search():
    query = request.args.get('q', '')
    # ⚠️ Vulnerability: Reflected Cross-Site Scripting (CWE-79)
    return render_template_string(f"<div>Search results for: {query}</div>")


@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    if not host:
        return "Please provide a host parameter.", 400

    # ⚠️ Vulnerability: Command injection via unsanitized shell input (CWE-77)
    os.system(f"ping -c 1 {host}")
    return f"Pinging {host}..."


@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        # ⚠️ Vulnerability: No authentication or ownership validation (CWE-639)
        if item_id in fake_orders:
            return f"Purchase successful! Access your order at /order/{item_id}"
        else:
            return "Invalid item ID.", 404

    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Purchase Item</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="container mt-5">
        <h2>Purchase Form</h2>
        <form method="post" id="purchaseForm">
            <input class="form-control" type="text" name="item_id" placeholder="Item ID" />
            <button class="btn btn-success mt-3" type="submit">Purchase</button>
        </form>
        <script>
        document.getElementById("purchaseForm").addEventListener("submit", function(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            fetch("/purchase", {
                method: "POST",
                body: formData
            })
            .then(res => res.text())
            .then(alert);
        });
        </script>
    </body>
    </html>
    '''


@app.route('/order/<order_id>', methods=['GET'])
def view_order(order_id):
    # ⚠️ Vulnerability: Broken Access Control — Insecure Direct Object Reference (CWE-639)
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
