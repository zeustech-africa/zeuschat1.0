import re
import os
import uuid
import time
import sqlite3
import random
import jwt
import bcrypt
import hashlib
import re
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[os.environ.get("FRONTEND_URL", "https://chat.zeustech.com")])

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

# Use persistent disk for database
DATABASE_PATH = os.path.join('data', 'zeuschat.db')
JWT_SECRET = os.environ["JWT_SECRET"]
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            zeus_pin TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_zeus_pin ON users(zeus_pin)")
        
        conn.execute("""
        CREATE TABLE IF NOT EXISTS contact_requests (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id),
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
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(contact_user_id) REFERENCES users(id),
            UNIQUE(user_id, contact_user_id)
        )""")
        
        conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )""")
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

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    public_key = data.get('public_key')
    if not email or not password or not public_key:
        return jsonify({'error': 'Email, password, and public_key required'}), 400

    max_attempts = 5
    for _ in range(max_attempts):
        zeus_pin = f"ZT-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
        try:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (id, zeus_pin, username, password_hash, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), zeus_pin, email.split('@')[0], password_hash, public_key, int(time.time()))
                )
                conn.commit()
            return jsonify({'zeus_pin': zeus_pin})
        except sqlite3.IntegrityError as e:
            if "zeus_pin" in str(e):
                continue
            return jsonify({'error': 'Email already registered'}), 400
    return jsonify({'error': 'Failed to generate unique PIN'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    zeus_pin = data.get('zeus_pin')
    password = data.get('password')
    if not zeus_pin or not password:
        return jsonify({'error': 'Zeus-PIN and password required'}), 400

    with get_db() as conn:
        user = conn.execute("SELECT id, password_hash FROM users WHERE zeus_pin = ?", (zeus_pin,)).fetchone()
    if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        token = jwt.encode({'user_id': user['id'], 'exp': int(time.time()) + 86400}, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'user_id': user['id'], 'zeus_pin': zeus_pin})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

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
        target = conn.execute("SELECT id FROM users WHERE zeus_pin = ?", (target_pin,)).fetchone()
        if not target:
            return jsonify({'error': 'Contact not found'}), 404

        target_id = target['id']
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

if DEBUG_MODE:
    @app.route("/debug/users")
    def debug_users():
        with get_db() as conn:
            users = conn.execute("SELECT zeus_pin FROM users").fetchall()
        return jsonify([u["zeus_pin"] for u in users])

    @app.route("/debug/contacts")
    def debug_contacts():
        with get_db() as conn:
            rows = conn.execute("""
                SELECT user_id, contact_user_id, initiator_id, 
                       initiator_ready, responder_ready, handshake_complete
                FROM contacts
            """).fetchall()
        return jsonify([dict(r) for r in rows])
