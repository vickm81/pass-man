from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from models import db, User, Password
from encryption import encrypt_password, decrypt_password
import os
from flask_cors import CORS
import secrets
import string
from urllib.parse import urlparse
import re
from datetime import datetime, timedelta
import logging
from argon2 import PasswordHasher, exceptions
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Generate secure secret key if one doesn't exist
if not os.environ.get('SECRET_KEY'):
    app.secret_key = os.urandom(24)
else:
    app.secret_key = os.environ.get('SECRET_KEY')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup logging
logging.basicConfig(level=logging.DEBUG)

# Initialize security components
ph = PasswordHasher()  # Initialize Argon2 password hasher
csrf = CSRFProtect(app)  # CSRF protection
db.init_app(app)

# Setup rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
# Setup CORS with strict configuration
CORS(app, resources={
    r"/api/*": {
        "origins": ["chrome-extension://nabilbgijbgjlijicjnknmifpgnlpfek"],
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "X-CSRF-Token"],
        "expose_headers": ["Content-Type"],
        "methods": ["GET", "POST", "OPTIONS"]
    }
})

# Session configuration for security
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)  # Session expires after 1 hour
)

@app.before_request
def create_tables():
    db.create_all()

@app.before_request
def session_expiry_check():
    """Check if user session has expired"""
    if 'username' in session:
        if 'last_activity' not in session:
            session['last_activity'] = datetime.utcnow().timestamp()
        else:
            last_activity = datetime.fromtimestamp(session['last_activity'])
            # Log out after 30 minutes of inactivity
            if (datetime.utcnow() - last_activity).total_seconds() > 1800:
                session.clear()
                return redirect(url_for('index'))
            # Update last activity time
            session['last_activity'] = datetime.utcnow().timestamp()

def sanitize_input(data):
    """Sanitize user input to prevent XSS"""
    if isinstance(data, str):
        # First use bleach to clean any HTML
        cleaned = bleach.clean(data, tags=[], strip=True)
        # Then escape any remaining HTML characters
        return escape(cleaned)
    return data

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10/hour")  # Rate limit registration attempts
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        master_password = request.form.get('master_password', '')
        
        # Input validation
        if not username or not master_password:
            return "Username and password are required", 400
            
        if len(master_password) < 12:
            return "Master password must be at least 12 characters long", 400
            
        if User.query.filter_by(username=username).first():
            return "User already exists!", 400
        
        # Hash the master password with Argon2 before storing it
        hashed_password = ph.hash(master_password)

        new_user = User(username=username, master_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def login():
    if request.method == 'GET':
        return render_template('index.html')
        
    username = sanitize_input(request.form.get('username', ''))
    master_password = request.form.get('master_password', '')

    if not username or not master_password:
        error = "Username and password are required"
        return render_template('index.html', error=error)

    user = User.query.filter_by(username=username).first()

    if user:
        try:
            if ph.verify(user.master_password, master_password):
                session.clear()
                session['username'] = username
                session['user_id'] = user.id
                session['last_activity'] = datetime.utcnow().timestamp()
                session.modified = True
                return redirect(url_for('dashboard'))
        except (exceptions.VerifyMismatchError, exceptions.VerificationError, exceptions.InvalidHash):
            logging.warning(f"Failed login attempt for user: {username}")
            pass

    error = "Invalid credentials!"
    return render_template('index.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=escape(session['username']))

@app.route('/get_passwords', methods=['GET'])
@login_required
def get_passwords():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    
    try:
        passwords = [
            {
                'id': p.id,
                'website': escape(decrypt_password(p.website, user.master_password).decode()),
                'username': escape(decrypt_password(p.username, user.master_password).decode()),
                'password': escape(decrypt_password(p.password, user.master_password).decode()),
            }
            for p in user_passwords
        ]
        return render_template("table.html", passwords=passwords)
    except Exception as e:
        logging.error(f"Error decrypting passwords: {e}")
        return jsonify({'error': 'Could not retrieve passwords'}), 500

@app.route('/get_credentials', methods=['GET'])
def get_credentials():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    website = sanitize_input(request.args.get('website', ''))
    if not website:
        return jsonify({'error': 'Website parameter is required'}), 400
        
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    
    try:
        passwords = [
            {
                'website': decrypt_password(p.website, user.master_password).decode(),
                'username': decrypt_password(p.username, user.master_password).decode(),
                'password': decrypt_password(p.password, user.master_password).decode(),
            }
            for p in user_passwords
        ]

        for entry in passwords:
            if entry['website'] in website:  # Supports subdomains like "example.com" matching "example.com/login"
                # Use escape to prevent XSS when returning data
                safe_entry = {k: escape(v) for k, v in entry.items()}
                return jsonify(safe_entry)

        return jsonify({"error": "No credentials found"}), 404
    except Exception as e:
        logging.error(f"Error retrieving credentials: {e}")
        return jsonify({'error': 'Could not retrieve credentials'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
            
        website = sanitize_input(data.get('website', ''))
        username = sanitize_input(data.get('username', ''))
        password = data.get('password', '')

        if not all([website, username, password]):
            return jsonify({'error': 'Missing required fields'}), 400


        # Encrypt the data
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        encrypted_website = encrypt_password(website, user.master_password)
        encrypted_username = encrypt_password(username, user.master_password)
        encrypted_password = encrypt_password(password, user.master_password)

        # Save to the database
        new_password = Password(
            user_id=user_id,
            website=encrypted_website,
            username=encrypted_username,
            password=encrypted_password,
        )
        db.session.add(new_password)
        db.session.commit()

        return jsonify({'message': 'Password added successfully'}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding password: {e}")
        return jsonify({'error': 'Failed to add password'}), 500

@app.route('/generate_password', methods=['GET'])
@login_required
def generate_password():
    try:
        length = int(request.args.get('length', 12))
        # Limit length to prevent DoS
        if length < 8:
            length = 8
        elif length > 100:
            length = 100
            
        # Ensure password has at least one of each character type
        chars = []
        chars.append(secrets.choice(string.ascii_lowercase))
        chars.append(secrets.choice(string.ascii_uppercase))
        chars.append(secrets.choice(string.digits))
        chars.append(secrets.choice(string.punctuation))
        
        # Fill the rest with random characters
        charset = string.ascii_letters + string.digits + string.punctuation
        chars.extend(secrets.choice(charset) for _ in range(length - 4))
        
        # Shuffle the password
        password_list = list(chars)
        secrets.SystemRandom().shuffle(password_list)
        random_password = ''.join(password_list)
        
        return jsonify({'password': random_password})
    except Exception as e:
        logging.error(f"Error generating password: {e}")
        return jsonify({'error': 'Could not generate password'}), 500

def normalize_url(url):
    """Normalize URLs for consistent matching."""
    try:
        parsed = urlparse(url)
        # Extract domain and remove 'www.'
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception as e:
        return url.lower()

def url_matches(stored_url, current_url):
    """Check if URLs match, considering subdomains."""
    
    stored = stored_url
    current = normalize_url(current_url)
    
    # Check exact match first
    if stored == current:
        return True
    
    # Check if stored URL is a parent domain of current URL
    if current.endswith('.' + stored):
        return True
    
    return False

@app.route('/api/handle-credentials', methods=['POST', 'OPTIONS'])
@csrf.exempt  # Only if this endpoint is used by the Chrome extension
def handle_credentials():
    """Combined endpoint for handling credential operations."""
    
    # Handle CORS preflight request
    if request.method == 'OPTIONS':
        return '', 200
    
    # Check authentication
    if 'username' not in session:
        app.logger.debug("No user session found")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Missing request data'}), 400
        
        action = sanitize_input(data.get('action', ''))
        
        user_id = session.get('user_id')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Handle GET credentials request
        if action == 'get':
            if 'url' not in data:
                return jsonify({'error': 'Missing URL parameter'}), 400
            
            current_url = sanitize_input(data['url'])
            
            stored_passwords = Password.query.filter_by(user_id=user_id).all()
            
            matching_credentials = []
            
            for stored_pass in stored_passwords:
                try:
                    decrypted_website = decrypt_password(stored_pass.website, user.master_password).decode()
                    
                    if url_matches(decrypted_website, current_url):
                        cred = {
                            'website': escape(decrypted_website),
                            'username': escape(decrypt_password(stored_pass.username, user.master_password).decode()),
                            'password': escape(decrypt_password(stored_pass.password, user.master_password).decode()),
                            'last_used': stored_pass.last_used.isoformat() if hasattr(stored_pass, 'last_used') and stored_pass.last_used else None
                        }
                        matching_credentials.append(cred)
                except Exception as e:
                    app.logger.error(f"Error processing stored password: {e}")
                    continue
            
            if not matching_credentials:
                return jsonify({'error': 'No credentials found'}), 404
            
            return jsonify({
                'credentials': matching_credentials,
                'url': escape(current_url)
            })
        
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
            
        credential_id = data.get('id')
        website = sanitize_input(data.get('website', ''))
        username = sanitize_input(data.get('username', ''))
        password = data.get('password', '')

        if not all([credential_id, website, username, password]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Get the credential to update
        credential = Password.query.filter_by(id=credential_id, user_id=user_id).first()
        if not credential:
            return jsonify({'error': 'Credential not found'}), 404

        # Encrypt the updated data
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        credential.website = encrypt_password(website, user.master_password)
        credential.username = encrypt_password(username, user.master_password)
        credential.password = encrypt_password(password, user.master_password)
        credential.last_used = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating password: {e}")
        return jsonify({'error': 'Failed to update password'}), 500

@app.route('/delete_password', methods=['POST'])
@login_required
def delete_password():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
            
        credential_id = data.get('id')

        if not credential_id:
            return jsonify({'error': 'Missing credential ID'}), 400

        # Get the credential to delete
        credential = Password.query.filter_by(id=credential_id, user_id=user_id).first()
        if not credential:
            return jsonify({'error': 'Credential not found'}), 404

        db.session.delete(credential)
        db.session.commit()
        return jsonify({'message': 'Password deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting password: {e}")
        return jsonify({'error': 'Failed to delete password'}), 500

# Error handlers for common HTTP errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('400.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Security headers middleware with fixes for Bootstrap icons
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' https:; " \
                                                "script-src 'self' https://cdn.jsdelivr.net; " \
                                                "style-src 'self' https://cdn.jsdelivr.net; " \
                                                "img-src 'self' data:; " \
                                                "font-src 'self' https://cdn.jsdelivr.net; " \
                                                "connect-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('certs/cert.pem', 'certs/key.pem'))