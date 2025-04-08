from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from models import db, User, Password
from encryption import encrypt_password, decrypt_password
import os
from flask_cors import CORS
import secrets
import string
from urllib.parse import urlparse
import re
from datetime import datetime
import logging
from argon2 import PasswordHasher, exceptions 

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
logging.basicConfig(level=logging.DEBUG)
ph = PasswordHasher()  # Initialize Argon2 password hasher
db.init_app(app)
CORS(app, resources={
    r"/api/*": {
        "origins": ["chrome-extension://nabilbgijbgjlijicjnknmifpgnlpfek"],
        "supports_credentials": True
    }
})

@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_password']

        if User.query.filter_by(username=username).first():
            return "User already exists!", 400
        
        # Hash the master password with Argon2 before storing it
        hashed_password = ph.hash(master_password)

        new_user = User(username=username, master_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    master_password = request.form['master_password']

    user = User.query.filter_by(username=username).first()  # Get user from DB

    if user:
        try:
            # Verify the password using Argon2
            if ph.verify(user.master_password, master_password):
                session['username'] = username
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
        except exceptions.VerifyMismatchError:
            pass  # Password doesn't match
        except exceptions.VerificationError:
            pass  # Other verification error (e.g., hash format invalid)
        except exceptions.InvalidHash:
            pass  # Hash is invalid

    return "Invalid credentials!", 400

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/get_passwords', methods=['GET'])
def get_passwords():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    master_password = User.query.get(user_id).master_password

    passwords = [
        {
            'id': p.id,  # Include the ID
            'website': decrypt_password(p.website, master_password).decode(),
            'username': decrypt_password(p.username, master_password).decode(),
            'password': decrypt_password(p.password, master_password).decode(),
        }
        for p in user_passwords
    ]
    return render_template("table.html", passwords=passwords)

@app.route('/get_passwords_ext',methods=['GET'])
def get_passwords_ext():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    master_password = User.query.get(user_id).master_password

    passwords = [
        {
            'website': decrypt_password(p.website, master_password).decode(),
            'username': decrypt_password(p.username, master_password).decode(),
            'password': decrypt_password(p.password, master_password).decode(),
        }
        for p in user_passwords
    ]
    return render_template("table_ext.html",passwords=passwords)

@app.route('/get_credentials', methods=['GET'])
def get_credentials():
    website = request.args.get('website')
    user_id = session['user_id']
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    master_password = User.query.get(user_id).master_password

    passwords = [
        {
            'website': decrypt_password(p.website, master_password).decode(),
            'username': decrypt_password(p.username, master_password).decode(),
            'password': decrypt_password(p.password, master_password).decode(),
        }
        for p in user_passwords
    ]

    # if not website or not master_password:
    #     return jsonify({"error": "Missing parameters"}), 400


    for entry in passwords:
        if entry['website'] in website:  # Supports subdomains like "example.com" matching "example.com/login"
            print(entry)
            return jsonify(entry)

    return jsonify({"error": "No credentials found"}), 404

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    data = request.json
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    if not (website and username and password):
        return jsonify({'error': 'Missing fields'}), 400

    # Encrypt the data
    master_password = User.query.get(user_id).master_password
    salt = os.urandom(16)
    encrypted_website = encrypt_password(website, master_password)
    encrypted_username = encrypt_password(username, master_password)
    encrypted_password = encrypt_password(password, master_password)

    # Save to the database
    new_password = Password(
        user_id=user_id,
        website=encrypted_website,
        username=encrypted_username,
        password=encrypted_password,
        salt=salt
    )
    db.session.add(new_password)
    db.session.commit()

    return jsonify({'message': 'Password added successfully'}), 201

@app.route('/generate_password', methods=['GET'])
def generate_password():
    length = int(request.args.get('length', 12))  # Default length is 12
    charset = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(secrets.choice(charset) for _ in range(length))
    return jsonify({'password': random_password})

def normalize_url(url):
    """Normalize URLs for consistent matching."""
    try:
        app.logger.debug(f"Normalizing URL: {url}")
        parsed = urlparse(url)
        # Extract domain and remove 'www.'
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        app.logger.debug(f"Normalized domain: {domain}")
        return domain
    except Exception as e:
        app.logger.debug(f"Error normalizing URL: {e}")
        return url.lower()

def url_matches(stored_url, current_url):
    """Check if URLs match, considering subdomains."""
    app.logger.debug(f"Comparing URLs - Stored: {stored_url}, Current: {current_url}")
    
    stored = stored_url
    current = normalize_url(current_url)
    
    # Check exact match first
    if stored == current:
        app.logger.debug("Exact match found!")
        return True
    
    # Check if stored URL is a parent domain of current URL
    if current.endswith('.' + stored):
        app.logger.debug("Parent domain match found!")
        return True
    
    app.logger.debug("No match found")
    return False

@app.route('/api/handle-credentials', methods=['POST', 'OPTIONS'])
def handle_credentials():
    """Combined endpoint for handling credential operations."""
    app.logger.debug(f"=== Starting credential handler ===")
    app.logger.debug(f"Request method: {request.method}")
    
    # Handle CORS preflight request
    if request.method == 'OPTIONS':
        return '', 200
    
    # Check authentication
    if 'username' not in session:
        app.logger.debug("No user session found")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        app.logger.debug(f"Received data: {data}")
        
        if not data:
            return jsonify({'error': 'Missing request data'}), 400
        
        action = data.get('action')
        app.logger.debug(f"Requested action: {action}")
        
        user_id = session.get('user_id')
        app.logger.debug(f"User ID from session: {user_id}")
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Handle GET credentials request
        if action == 'get':
            if 'url' not in data:
                return jsonify({'error': 'Missing URL parameter'}), 400
            
            current_url = data['url']
            app.logger.debug(f"Searching credentials for URL: {current_url}")
            
            stored_passwords = Password.query.filter_by(user_id=user_id).all()
            app.logger.debug(f"Found {len(stored_passwords)} stored passwords")
            
            matching_credentials = []
            
            for stored_pass in stored_passwords:
                try:
                    decrypted_website = decrypt_password(stored_pass.website, user.master_password).decode()
                    app.logger.debug(f"Checking stored website: {decrypted_website}")
                    
                    if url_matches(decrypted_website, current_url):
                        cred = {
                            'website': decrypted_website,
                            'username': decrypt_password(stored_pass.username, user.master_password).decode(),
                            'password': decrypt_password(stored_pass.password, user.master_password).decode(),
                            'last_used': stored_pass.last_used.isoformat() if hasattr(stored_pass, 'last_used') and stored_pass.last_used else None
                        }
                        matching_credentials.append(cred)
                        app.logger.debug(f"Added credential for username: {cred['username']}")
                except Exception as e:
                    app.logger.error(f"Error processing stored password: {e}")
                    continue
            
            if not matching_credentials:
                return jsonify({'error': 'No credentials found'}), 404
            
            return jsonify({
                'credentials': matching_credentials,
                'url': current_url
            })
        
        # Handle UPDATE last used timestamp request
        elif action == 'update':
            if not data.get('website') or not data.get('username'):
                return jsonify({'error': 'Missing parameters'}), 400
            
            app.logger.debug(f"Updating last used for website: {data['website']}")
            
            stored_passwords = Password.query.filter_by(user_id=user_id).all()
            for stored_pass in stored_passwords:
                try:
                    decrypted_website = decrypt_password(stored_pass.website, user.master_password).decode()
                    decrypted_username = decrypt_password(stored_pass.username, user.master_password).decode()
                    
                    if (decrypted_website == data['website'] and 
                        decrypted_username == data['username']):
                        stored_pass.last_used = datetime.utcnow()
                        db.session.commit()
                        return jsonify({'message': 'Last used timestamp updated'}), 200
                except Exception as e:
                    app.logger.error(f"Error processing stored password during update: {e}")
                    continue
            
            return jsonify({'error': 'Credential not found'}), 404
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500



@app.route('/update_password', methods=['POST'])
def update_password():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    data = request.json
    credential_id = data.get('id')
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    if not all([credential_id, website, username, password]):
        return jsonify({'error': 'Missing fields'}), 400

    # Get the credential to update
    credential = Password.query.filter_by(id=credential_id, user_id=user_id).first()
    if not credential:
        return jsonify({'error': 'Credential not found'}), 404

    # Encrypt the updated data
    master_password = User.query.get(user_id).master_password
    try:
        credential.website = encrypt_password(website, master_password)
        credential.username = encrypt_password(username, master_password)
        credential.password = encrypt_password(password, master_password)
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/delete_password', methods=['POST'])
def delete_password():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    data = request.json
    credential_id = data.get('id')

    if not credential_id:
        return jsonify({'error': 'Missing credential ID'}), 400

    # Get the credential to delete
    credential = Password.query.filter_by(id=credential_id, user_id=user_id).first()
    if not credential:
        return jsonify({'error': 'Credential not found'}), 404

    try:
        db.session.delete(credential)
        db.session.commit()
        return jsonify({'message': 'Password deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
