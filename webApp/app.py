from flask import Flask, request, jsonify

app = Flask(__name__)

# Public homepage
@app.route('/')
def home():
    return "Welcome to the simple web app!"

# Admin page (VULNERABLE: Hardcoded credentials)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # VULNERABILITY: Hardcoded credentials (bad practice)
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

# API endpoint
@app.route('/api/data', methods=['GET'])
def api_data():
    return jsonify({"data": "This is some data!"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
