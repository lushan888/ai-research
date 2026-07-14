from flask import Flask, request, render_template_string, make_response, session, jsonify
import sqlite3
import secrets
import html
from urllib.parse import parse_qs

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.after_request
def add_security_headers(response):
    # Fix #1176: Add CSP frame-ancestors to prevent clickjacking on crypto withdrawal
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    return response

# Simulated user database
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user1': {'password': 'user123', 'role': 'user'}
}

# CSRF token generation and validation
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    return token == session.get('csrf_token')

# Confirmation token for two-step critical operations
def generate_confirmation_token():
    return secrets.token_urlsafe(16)

def validate_confirmation_token(token):
    return token == session.get('confirm_token')

# Make csrf_token available in templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/')
def index():
    return '''
    <h1>AI Research Platform</h1>
    <form action="/login" method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p><a href="/search?q=test">Search</a></p>

@app.route('/login', methods=['POST'])
def login():
    # Regenerate session on login to prevent session fixation
    username = request.form.get('username')
    password = request.form.get('password')
    
        user = users[username]
        if user['password'] == password:
            resp = make_response(f"Welcome {username}!")
            # Use secure session instead of plain cookie
            session.clear()
            session['username'] = username
            session['role'] = user['role']
            return resp
    
    return "Invalid credentials", 401
@app.before_request
def sanitize_query_params():
    """Validate and deduplicate HTTP query parameters on every request.
    
    Prevents HTTP Parameter Pollution (HPP) attacks where an attacker sends
    duplicate parameters (?admin=true&admin=false) to bypass security checks.
    """
    if not request.query_string:
        return
    
    raw = request.query_string.decode('utf-8')
    
    # Reject requests with duplicate parameters outright
    seen = set()
    for pair in raw.split('&'):
        if not pair:
            continue
        key = pair.split('=')[0]
        if key in seen:
            return jsonify({
                'error': 'Duplicate parameter detected',
                'message': 'HTTP Parameter Pollution attack detected'
            }), 400
        seen.add(key)


@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Fix XSS: Escape user input before rendering
    safe_query = html.escape(query)
    template = '''
    <!DOCTYPE html>
    <html>
        <title>Search</title>
    </head>
    <body>
        <h1>Search Results for: ''' + safe_query + '''</h1>
        <p>You searched for: ''' + safe_query + '''</p>
    </body>
    </html>
    '''

@app.route('/change_email', methods=['POST'])
def change_email():
    # Fix CSRF: Validate CSRF token
    if 'username' not in session:
        return "Not authenticated", 401
    
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    new_email = request.form.get('email')
    # Fix XSS: Escape output
    safe_email = html.escape(new_email)
    safe_username = html.escape(session['username'])
    return f"Email changed to {safe_email} for user {safe_username}"

@app.route('/profile')
def profile():
    if 'username' not in session:
        return "Not authenticated", 401
    safe_username = html.escape(session['username'])
    return f"Profile of {safe_username}"

@app.route('/transfer', methods=['POST'])
def transfer():
    # Fix CSRF: Validate CSRF token
    if 'username' not in session:
        return "Not authenticated", 401
    
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    # Fix #1176: Two-step confirmation for critical financial operations
    # Step 1: Request confirmation token
    if request.form.get('action') == 'request_confirm':
        amount = request.form.get('amount')
        to_user = request.form.get('to')
        session['confirm_token'] = generate_confirmation_token()
        session['confirm_amount'] = amount
        session['confirm_to'] = to_user
        return jsonify({
            'status': 'confirmation_required',
            'token': session['confirm_token'],
            'amount': amount,
            'to': to_user,
            'message': f'Please confirm transfer of {amount} to {to_user}'
        })
    
    # Step 2: Validate confirmation token
    confirm_token = request.form.get('confirm_token')
    if not confirm_token or not validate_confirmation_token(confirm_token):
        return "Confirmation required or expired", 403
    
    # Verify the confirmed values match
    amount = request.form.get('amount')
    to_user = request.form.get('to')
    if amount != session.get('confirm_amount') or to_user != session.get('confirm_to'):
        return "Confirmation mismatch", 400
    
    # Clear confirmation after use
    session.pop('confirm_token', None)
    session.pop('confirm_amount', None)
    session.pop('confirm_to', None)
    
    # Fix XSS: Escape output
    safe_amount = html.escape(str(amount))
    safe_to = html.escape(to_user)
    return f"Transferred {safe_amount} to {safe_to}"

if __name__ == '__main__':
    # Security: Disable debug in production
    app.run(debug=False)
