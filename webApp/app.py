from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Public homepage
@app.route('/')
def home():
    return "Welcome to the simple web app!"

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

# Critical Vulnerability: Command Injection
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    if not host:
        return "Please provide a host parameter.", 400
    # VULNERABILITY: Command injection risk (CWE-77)
    os.system(f"ping -c 1 {host}")
    return f"Pinging {host}..."

# Subtle Vulnerability: Information Disclosure without authorization
@app.route('/api/secrets', methods=['GET'])
def secrets():
    # VULNERABILITY: No authentication or authorization check
    return jsonify({"secret": "FLAG{this_should_not_be_public}"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
