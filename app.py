import os
import uuid
import time
import sqlite3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Use persistent disk for database
DATABASE_PATH = os.path.join('data', 'zeuschat.db')

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            zeus_pin TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_zeus_pin ON users(zeus_pin);
        
        CREATE TABLE IF NOT EXISTS contact_requests (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id),
            UNIQUE(sender_id, receiver_id)
        );
        
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            contact_user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(contact_user_id) REFERENCES users(id),
            UNIQUE(user_id, contact_user_id)
        );
        
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        );
        """)
        conn.commit()

init_db()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    if os.path.exists(path):
        return send_from_directory('.', path)
    else:
        return "File not found", 404

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    zeus_pin = f"ZT-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (id, zeus_pin, username, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
                        (str(uuid.uuid4()), zeus_pin, email.split('@')[0], "fake-public-key", int(time.time())))
            conn.commit()
        return jsonify({'zeus_pin': zeus_pin})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    zeus_pin = data.get('zeus_pin')
    password = data.get('password')
    if not zeus_pin or not password:
        return jsonify({'error': 'Zeus-PIN and password required'}), 400

    with get_db() as conn:
        user = conn.execute("SELECT id FROM users WHERE zeus_pin = ? AND username = ?", (zeus_pin, password)).fetchone()
    if user:
        return jsonify({'success': True, 'user_id': user['id']})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/contact-request', methods=['POST'])
def create_contact_request():
    data = request.json
    target_pin = data.get('zeus_pin')
    requester_id = data.get('requester_id')
    
    if not requester_id or not target_pin:
        return jsonify({'error': 'Missing fields'}), 400

    with get_db() as conn:
        target = conn.execute("SELECT id FROM users WHERE zeus_pin = ?", (target_pin,)).fetchone()
        if not target:
            return jsonify({'error': 'Contact not found'}), 404

        target_id = target['id']
        if requester_id == target_id:
            return jsonify({'error': 'Cannot send request to yourself'}), 400

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
        conn.commit()

    return jsonify({'message': 'Connection request sent'})

@app.route('/api/contact-request/<req_id>/accept', methods=['POST'])
def accept_contact_request(req_id):
    data = request.json
    acceptor_id = data.get('acceptor_id')
    
    with get_db() as conn:
        req = conn.execute("""
            SELECT sender_id, receiver_id, status 
            FROM contact_requests 
            WHERE id = ?
        """, (req_id,)).fetchone()
        
        if not req or req['status'] != 'pending' or acceptor_id != req['receiver_id']:
            return jsonify({'error': 'Invalid request'}), 400

        conn.execute("UPDATE contact_requests SET status = 'accepted' WHERE id = ?", (req_id,))
        conn.execute("""
            INSERT INTO contacts (id, user_id, contact_user_id, created_at)
            VALUES (?, ?, ?, ?)
        """, (str(uuid.uuid4()), req['sender_id'], acceptor_id, int(time.time())))
        conn.execute("""
            INSERT INTO contacts (id, user_id, contact_user_id, created_at)
            VALUES (?, ?, ?, ?)
        """, (str(uuid.uuid4()), acceptor_id, req['sender_id'], int(time.time())))
        conn.commit()

    return jsonify({'message': 'Contact accepted'})

def verify_contact(sender_id, receiver_id):
    with get_db() as conn:
        return conn.execute("""
            SELECT 1 FROM contacts 
            WHERE user_id = ? AND contact_user_id = ?
        """, (sender_id, receiver_id)).fetchone() is not None

@app.route('/send-message', methods=['POST'])
def send_message():
    data = request.json
    from_id = data.get('from_id')
    to_id = data.get('to_id')
    content = data.get('content')
    
    if not all([from_id, to_id, content]):
        return jsonify({'error': 'Missing fields'}), 400
        
    if not verify_contact(from_id, to_id):
        return jsonify({'error': 'You must accept the contact request before messaging.'}), 403

    return jsonify({'message': 'Sent'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
