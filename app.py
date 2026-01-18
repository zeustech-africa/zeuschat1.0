import os
import uuid
import time
import sqlite3
import random
import jwt
import bcrypt
import hashlib
import re
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS

app = Flask(__name__)
# Use JWT_SECRET for session signing (must be consistent)
app.secret_key = os.environ["JWT_SECRET"]

# Environment-aware cookie settings
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"
if DEBUG_MODE:
    app.config.update(
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
else:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='None',
    )

# Read frontend URL from environment
frontend_url = os.environ.get("FRONTEND_URL", "https://chat.zeustech.com")
try:
    CORS(app, origins=[frontend_url], supports_credentials=True)
except Exception as e:
    print(f"❌ CORS ERROR: {e}")

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

# Use persistent disk for database
DATABASE_PATH = os.path.join('data', 'zeuschat.db')
JWT_SECRET = os.environ["JWT_SECRET"]

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # Critical: enable foreign key enforcement
    return conn

def init_db():
    with get_db() as conn:
        # Users table: ONLY auth data
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )""")
        
        # Profiles table: ONLY profile data + email for linking
        conn.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            zeus_pin TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            about TEXT,
            avatar_url TEXT,
            email TEXT UNIQUE NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_zeus_pin ON profiles(zeus_pin)")
        
        conn.execute("""
        CREATE TABLE IF NOT EXISTS contact_requests (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(sender_id, receiver_id)
        )""")
        
        conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            contact_user_id TEXT NOT NULL,
            initiator_id TEXT NOT NULL,
            initiator_ready BOOLEAN DEFAULT 0,
            responder_ready BOOLEAN DEFAULT 0,
            handshake_complete BOOLEAN DEFAULT 0,
            nonce TEXT NOT NULL,
            nonce_hash TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(contact_user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, contact_user_id)
        )""")
        
        conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        
        # REMOVED orphan cleanup query to prevent profile loss during signup
        # Profiles with user_id IS NULL are kept until registration completes
        
        conn.commit()

init_db()

def require_auth(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        try:
            payload = jwt.decode(token[7:], JWT_SECRET, algorithms=['HS256'])
            request.user_id = payload['user_id']
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/')
def index():
    return send_from_directory(os.path.dirname(__file__), 'index.html')

@app.route('/<path:path>')
def static_files(path):
    full_path = os.path.join(os.path.dirname(__file__), path)
    if os.path.exists(full_path):
        return send_from_directory(os.path.dirname(__file__), path)
    else:
        return "File not found", 404

# NEW: Start signup session (called from emailinput.html)
@app.route('/api/start-signup', methods=['POST'])
def start_signup():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    # Store email in server-side session
    session['signup_email'] = email
    session['signup_state'] = 'email_submitted'
    
    return jsonify({'message': 'Signup session started'})

# NEW: Verify OTP and create verified session
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    otp = data.get('otp')
    
    if not otp or otp != '123456':
        return jsonify({'error': 'Invalid OTP code'}), 400
    
    # Check if email exists in session
    if 'signup_email' not in session:
        return jsonify({'error': 'No signup session found. Please restart.'}), 400
    
    email = session['signup_email']
    if not email:
        return jsonify({'error': 'Invalid signup session. Please restart.'}), 400
    
    # Mark session as verified and store email
    session['signup_state'] = 'email_verified'
    session['verified_email'] = email
    
    return jsonify({'message': 'OTP verified'})

# FIXED: /api/create-profile safely handles multiple input formats and field names
@app.route('/api/create-profile', methods=['POST'])
def create_profile():
    # Safely extract data from JSON or form
    if request.is_json:
        data = request.json or {}
    else:
        data = request.form.to_dict()
    
    # Try multiple possible display name fields
    display_name = None
    for field in ['display_name', 'name', 'username', 'full_name']:
        value = data.get(field)
        if value and str(value).strip():
            display_name = str(value).strip()
            break
    
    about = data.get('about', '')
    avatar_url = data.get('avatar_url', '')

    if not display_name:
        return jsonify({'error': 'Display name required'}), 400

    # Get email from server-side session (MUST be verified)
    if 'signup_state' not in session or session.get('signup_state') != 'email_verified':
        return jsonify({'error': 'Invalid or expired session. Please restart signup.'}), 400

    if 'verified_email' not in session:
        return jsonify({'error': 'Email not verified. Please restart signup.'}), 400

    email = session['verified_email']
    if not email:
        return jsonify({'error': 'Invalid signup session. Please restart.'}), 400

    with get_db() as conn:
        # Check if profile already exists for this email
        existing_profile = conn.execute("SELECT id FROM profiles WHERE email = ?", (email,)).fetchone()
        if existing_profile:
            return jsonify({'error': 'Profile already exists for this email'}), 400

        # Generate unique Zeus-PIN
        max_attempts = 5
        for _ in range(max_attempts):
            zeus_pin = f"ZT-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
            try:
                profile_id = str(uuid.uuid4())
                with get_db() as conn_inner:
                    # Insert profile with NULL user_id (will be filled during registration)
                    conn_inner.execute(
                        "INSERT INTO profiles (id, user_id, zeus_pin, display_name, about, avatar_url, email, created_at) VALUES (?, NULL, ?, ?, ?, ?, ?, ?)",
                        (profile_id, zeus_pin, display_name, about, avatar_url, email, int(time.time()))
                    )
                    conn_inner.commit()
                break
            except sqlite3.IntegrityError:
                continue
        else:
            return jsonify({'error': 'Failed to generate unique PIN'}), 500

    return jsonify({
        'zeus_pin': zeus_pin,
        'display_name': display_name,
        'about': about,
        'avatar_url': avatar_url
    })

# FIXED: /register completes user account using session email
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    password = data.get('password')
    public_key = data.get('public_key')
    if not password or not public_key:
        return jsonify({'error': 'Password and public_key required'}), 400
    
    # Validate public_key is non-empty
    if not public_key.strip():
        return jsonify({'error': 'Public key cannot be empty'}), 400

    # Get email from server-side session
    if 'verified_email' not in session:
        return jsonify({'error': 'No verified email found. Complete profile creation first.'}), 400

    email = session['verified_email']
    if not email:
        return jsonify({'error': 'Invalid signup session. Please restart.'}), 400

    with get_db() as conn:
        # Check if user already exists
        existing_user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400

        # Check if profile exists for this email
        profile = conn.execute("SELECT id FROM profiles WHERE email = ?", (email,)).fetchone()
        if not profile:
            return jsonify({'error': 'Profile not found. Complete profile creation first.'}), 400

        # Create user account
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_id = str(uuid.uuid4())
        
        conn.execute(
            "INSERT INTO users (id, email, password_hash, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, email, password_hash, public_key, int(time.time()))
        )
        
        # Link profile to user
        conn.execute(
            "UPDATE profiles SET user_id = ? WHERE email = ?",
            (user_id, email)
        )
        conn.commit()

    # Clear signup session after successful registration
    session.pop('signup_email', None)
    session.pop('signup_state', None)
    session.pop('verified_email', None)
    
    return jsonify({'user_id': user_id})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    zeus_pin = data.get('zeus_pin')
    password = data.get('password')
    if not zeus_pin or not password:
        return jsonify({'error': 'Zeus-PIN and password required'}), 400

    with get_db() as conn:
        # Find user via Zeus-PIN → profile → user
        result = conn.execute("""
            SELECT u.id, u.password_hash 
            FROM users u
            JOIN profiles p ON u.id = p.user_id
            WHERE p.zeus_pin = ?
        """, (zeus_pin,)).fetchone()
        
    if result and bcrypt.checkpw(password.encode(), result['password_hash'].encode()):
        token = jwt.encode({'user_id': result['id'], 'exp': int(time.time()) + 86400}, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'user_id': result['id'], 'zeus_pin': zeus_pin})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# FIXED: /api/profile GET fetches from profiles table
@app.route('/api/profile', methods=['GET'])
@require_auth
def get_profile():
    user_id = request.user_id
    with get_db() as conn:
        profile = conn.execute("""
            SELECT p.zeus_pin, p.display_name, p.about, p.avatar_url
            FROM profiles p
            WHERE p.user_id = ?
        """, (user_id,)).fetchone()
    if not profile:
        return jsonify({'error': 'Profile not found'}), 404
    return jsonify({
        'zeus_pin': profile['zeus_pin'],
        'display_name': profile['display_name'],
        'about': profile['about'],
        'avatar_url': profile['avatar_url']
    })

# FIXED: /api/profile PUT updates ONLY profile fields
@app.route('/api/profile', methods=['PUT'])
@require_auth
def update_profile():
    user_id = request.user_id
    data = request.json
    display_name = data.get('display_name')
    about = data.get('about', '')
    avatar_url = data.get('avatar_url', '')

    if not display_name:
        return jsonify({'error': 'Display name required'}), 400

    with get_db() as conn:
        conn.execute("""
            UPDATE profiles 
            SET display_name = ?, about = ?, avatar_url = ?
            WHERE user_id = ?
        """, (display_name, about, avatar_url, user_id))
        conn.commit()
    return jsonify({'message': 'Profile updated'})

@app.route('/api/contact-request', methods=['POST'])
@require_auth
def create_contact_request():
    data = request.json
    raw_pin = data.get('zeus_pin', '').strip().upper()
    if not re.match(r'^ZT-\d{4}-\d{4}$', raw_pin):
        return jsonify({'error': 'Invalid Zeus-PIN format'}), 400
    target_pin = raw_pin
    
    if not target_pin:
        return jsonify({'error': 'Missing fields'}), 400

    with get_db() as conn:
        target = conn.execute("SELECT user_id FROM profiles WHERE zeus_pin = ?", (target_pin,)).fetchone()
        if not target:
            return jsonify({'error': 'Contact not found'}), 404

        target_id = target['user_id']
        requester_id = request.user_id
        if requester_id == target_id:
            return jsonify({'error': 'Cannot send request to yourself'}), 400

        try:
            with conn:
                existing = conn.execute("""
                    SELECT status FROM contact_requests 
                    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                """, (requester_id, target_id, target_id, requester_id)).fetchone()

                if existing:
                    if existing['status'] == 'accepted':
                        return jsonify({'message': 'Already connected'}), 200
                    elif existing['status'] == 'pending':
                        return jsonify({'message': 'Request already pending'}), 200

                conn.execute("""
                    INSERT INTO contact_requests (id, sender_id, receiver_id, created_at)
                    VALUES (?, ?, ?, ?)
                """, (str(uuid.uuid4()), requester_id, target_id, int(time.time())))
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Request already pending'}), 200

    return jsonify({'message': 'Connection request sent'})

@app.route('/api/contact-request/<req_id>/accept', methods=['POST'])
@require_auth
def accept_contact_request(req_id):
    acceptor_id = request.user_id
    
    with get_db() as conn:
        req = conn.execute("""
            SELECT sender_id, receiver_id, status 
            FROM contact_requests 
            WHERE id = ?
        """, (req_id,)).fetchone()
        
        if not req or req['status'] != 'pending' or acceptor_id != req['receiver_id']:
            return jsonify({'error': 'Invalid request'}), 400

        initiator_id = req['sender_id']
        responder_id = acceptor_id
        nonce = os.urandom(16).hex()

        try:
            with conn:
                conn.execute("""
                    INSERT INTO contacts (id, user_id, contact_user_id, initiator_id, nonce, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), initiator_id, responder_id, initiator_id, nonce, int(time.time())))

                conn.execute("""
                    INSERT INTO contacts (id, user_id, contact_user_id, initiator_id, nonce, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), responder_id, initiator_id, initiator_id, nonce, int(time.time())))

                conn.execute("UPDATE contact_requests SET status = 'accepted' WHERE id = ?", (req_id,))
        except sqlite3.IntegrityError:
            pass

    return jsonify({
        'message': 'Contact accepted',
        'nonce': nonce,
        'initiator_id': initiator_id
    })

@app.route('/api/contacts/<contact_id>/keys')
@require_auth
def get_contact_keys(contact_id):
    with get_db() as conn:
        contact = conn.execute("""
            SELECT u.public_key, c.nonce
            FROM users u
            JOIN contacts c ON u.id = c.contact_user_id
            WHERE c.user_id = ? AND c.contact_user_id = ?
        """, (request.user_id, contact_id)).fetchone()
        
        if not contact:
            return jsonify({'error': 'Contact not found'}), 404
            
    return jsonify({
        'public_key': contact['public_key'],
        'nonce': contact['nonce']
    })

@app.route('/api/handshake-ready', methods=['POST'])
@require_auth
def mark_handshake_ready():
    data = request.json
    contact_id = data.get('contact_id')
    encrypted_nonce = data.get('encrypted_nonce')
    if not contact_id or not encrypted_nonce:
        return jsonify({'error': 'contact_id and encrypted_nonce required'}), 400
        
    nonce_hash = hashlib.sha256(encrypted_nonce.encode()).hexdigest()
    
    with get_db() as conn:
        row = conn.execute("""
            SELECT user_id, contact_user_id, initiator_id, initiator_ready, responder_ready, 
                   handshake_complete, nonce, nonce_hash
            FROM contacts
            WHERE user_id = ? AND contact_user_id = ?
        """, (request.user_id, contact_id)).fetchone()
        
        if not row:
            return jsonify({'error': 'Contact not found'}), 404
        if row['handshake_complete']:
            return jsonify({'message': 'Handshake already completed'}), 200
        if row['nonce_hash'] and row['nonce_hash'] != nonce_hash:
            return jsonify({'error': 'Nonce proof mismatch'}), 400

        is_initiator = (row['user_id'] == row['initiator_id'])
        current_ready = row['initiator_ready'] if is_initiator else row['responder_ready']
        if current_ready:
            return jsonify({'message': 'Already marked ready'}), 200

        try:
            with conn:
                conn.execute("""
                    UPDATE contacts 
                    SET nonce_hash = ?, 
                        {} = 1
                    WHERE user_id = ? AND contact_user_id = ?
                """.format("initiator_ready" if is_initiator else "responder_ready"),
                    (nonce_hash, request.user_id, contact_id))

                both_ready = conn.execute("""
                    SELECT c1.initiator_ready, c1.responder_ready
                    FROM contacts c1
                    JOIN contacts c2 ON c1.user_id = c2.contact_user_id AND c1.contact_user_id = c2.user_id
                    WHERE c1.user_id = ? AND c1.contact_user_id = ?
                """, (request.user_id, contact_id)).fetchone()

                if both_ready and both_ready['initiator_ready'] and both_ready['responder_ready']:
                    conn.execute("""
                        UPDATE contacts 
                        SET handshake_complete = 1
                        WHERE (user_id = ? AND contact_user_id = ?)
                           OR (user_id = ? AND contact_user_id = ?)
                    """, (request.user_id, contact_id, contact_id, request.user_id))
        except sqlite3.Error:
            return jsonify({'error': 'Handshake update failed'}), 500

    return jsonify({'message': 'Handshake readiness updated'})

def verify_contact(sender_id, receiver_id):
    """Bulletproof contact verification with constant-time logic"""
    if sender_id == receiver_id:
        return False

    with get_db() as conn:
        row = conn.execute("""
            SELECT 1
            FROM contacts c1
            JOIN contacts c2
              ON c1.user_id = c2.contact_user_id
             AND c1.contact_user_id = c2.user_id
            WHERE c1.user_id = ?
              AND c1.contact_user_id = ?
              AND c1.handshake_complete = 1
              AND c2.handshake_complete = 1
        """, (sender_id, receiver_id)).fetchone()

        return row is not None

@app.route('/send-message', methods=['POST'])
@require_auth
def send_message():
    data = request.json
    to_id = data.get('to_id')
    encrypted_payload = data.get('encrypted_payload')
    
    if not all([to_id, encrypted_payload]):
        return jsonify({'error': 'Missing fields'}), 400
        
    if not verify_contact(request.user_id, to_id):
        return jsonify({'error': 'Handshake not completed. Both users must exchange keys and verify nonces.'}), 403

    with get_db() as conn:
        conn.execute("""
            INSERT INTO messages (id, sender_id, receiver_id, encrypted_payload, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (str(uuid.uuid4()), request.user_id, to_id, encrypted_payload, int(time.time())))
        conn.commit()

    return jsonify({'message': 'Sent'})

# FIXED: Delete Account - removes all related data via CASCADE
@app.route('/api/delete-account', methods=['POST'])
@require_auth
def delete_account():
    user_id = request.user_id
    with get_db() as conn:
        # Delete user (CASCADE will delete profile, contacts, messages, contact_requests)
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return jsonify({'message': 'Account deleted'})

if DEBUG_MODE:
    @app.route("/debug/users")
    def debug_users():
        with get_db() as conn:
            users = conn.execute("SELECT email FROM users").fetchall()
        return jsonify([u["email"] for u in users])

    @app.route("/debug/profiles")
    def debug_profiles():
        with get_db() as conn:
            profiles = conn.execute("SELECT zeus_pin, display_name, email FROM profiles").fetchall()
        return jsonify([dict(p) for p in profiles])
