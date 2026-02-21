from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import sqlite3
import os
import secrets
import hashlib
from datetime import datetime
import json

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = secrets.token_hex(32)

# CORS Configuration - Allow all origins
CORS(app, 
   origins=["*"],
   supports_credentials=True,
   methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"])

# Database initialization
def init_db():
    """Initialize SQLite database with all required tables"""
    conn = sqlite3.connect('zeuschat.db')
    cursor = conn.cursor()
    
    # Users table with profile_pic field
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            zeus_pin TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            profile_pic TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP
        )
    ''')
    
    # Contacts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (contact_user_id) REFERENCES users(id)
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            file_url TEXT,
            ttl_seconds INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            viewed_at TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

# Initialize DB on startup
init_db()

# Helper functions
def generate_zeus_pin():
    """Generate unique Zeus PIN in format ZT-XXXX-XXXX"""
    return f"ZT-{secrets.randbelow(9000) + 1000}-{secrets.randbelow(9000) + 1000}"

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ============ API ENDPOINTS ============

@app.route('/api/start-signup', methods=['POST', 'OPTIONS'])
def start_signup():
    """Start registration process - validate email and send OTP"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').lower().strip()
        
        if not email or '@' not in email:
            return jsonify({'error': 'Invalid email address'}), 400
        
        # Check if user already exists
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 409
        conn.close()
        
        # Test mode: OTP is always 123456
        otp_code = '123456'
        
        # Store email in session for next step
        session['registration_email'] = email
        session['otp_code'] = otp_code
        
        print(f"📧 OTP sent to {email}: {otp_code}")
        
        return jsonify({
            'success': True,
            'message': 'OTP sent successfully',
            'test_otp': otp_code
        }), 200
        
    except Exception as e:
        print(f"❌ start-signup error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-otp', methods=['POST', 'OPTIONS'])
def verify_otp():
    """Verify OTP code"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').lower().strip()
        otp = data.get('otp', '').strip()
        
        # Test mode: accept 123456
        if otp != '123456':
            return jsonify({'error': 'Invalid OTP code'}), 400
        
        # Generate Zeus PIN
        zeus_pin = generate_zeus_pin()
        
        # Store in session
        session['zeus_pin'] = zeus_pin
        session['registration_email'] = email
        
        print(f"✅ OTP verified for {email} - Zeus PIN: {zeus_pin}")
        
        return jsonify({
            'success': True,
            'zeus_pin': zeus_pin,
            'email': email
        }), 200
        
    except Exception as e:
        print(f"❌ verify-otp error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/complete-registration', methods=['POST', 'OPTIONS'])
def complete_registration():
    """Complete registration - create user account"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').lower().strip()
        zeus_pin = data.get('zeus_pin', '').strip()
        password = data.get('password', '').strip()
        full_name = data.get('full_name', '').strip()
        profile_pic = data.get('profile_pic', '')  # Base64 encoded image
        
        if not all([email, zeus_pin, password, full_name]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (email, zeus_pin, password_hash, full_name, profile_pic)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, zeus_pin, password_hash, full_name, profile_pic))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        print(f"✅ User registered: {email} (ID: {user_id})")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user_id': user_id
        }), 201
        
    except sqlite3.IntegrityError as e:
        print(f"❌ Integrity error: {str(e)}")
        return jsonify({'error': 'Email or PIN already exists'}), 409
    except Exception as e:
        print(f"❌ complete-registration error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """User login with Zeus PIN and password"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        zeus_pin = data.get('zeus_pin', '').strip()
        password = data.get('password', '').strip()
        
        if not zeus_pin or not password:
            return jsonify({'error': 'PIN and password required'}), 400
        
        password_hash = hash_password(password)
        
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, full_name, profile_pic FROM users
            WHERE zeus_pin = ? AND password_hash = ?
        ''', (zeus_pin, password_hash))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid PIN or password'}), 401
        
        # Set session
        session['user_id'] = user[0]
        session['zeus_pin'] = zeus_pin
        
        print(f"✅ User logged in: {user[1]}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user[0],
                'email': user[1],
                'full_name': user[2],
                'profile_pic': user[3],
                'zeus_pin': zeus_pin
            }
        }), 200
        
    except Exception as e:
        print(f"❌ login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
def logout():
    """User logout"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Get current user profile"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = sqlite3.connect('zeuschat.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, email, full_name, profile_pic, zeus_pin, created_at
        FROM users WHERE id = ?
    ''', (user_id,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'success': True,
        'user': {
            'id': user[0],
            'email': user[1],
            'full_name': user[2],
            'profile_pic': user[3],
            'zeus_pin': user[4],
            'created_at': user[5]
        }
    }), 200

@app.route('/api/user/update-profile', methods=['POST', 'OPTIONS'])
def update_profile():
    """Update user profile"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    full_name = data.get('full_name', '')
    profile_pic = data.get('profile_pic', '')
    
    if not full_name:
        return jsonify({'error': 'Full name required'}), 400
    
    conn = sqlite3.connect('zeuschat.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users SET full_name = ?, profile_pic = ?
        WHERE id = ?
    ''', (full_name, profile_pic, user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Profile updated successfully'}), 200

# ============ MESSAGING SYSTEM ENDPOINTS ============

@app.route('/api/send-message', methods=['POST', 'OPTIONS'])
def send_message():
    """Send a message to a contact (requires accepted handshake)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        sender_id = session['user_id']
        receiver_zeus_pin = data.get('receiver_pin', '').strip()
        content = data.get('content', '').strip()
        ttl_seconds = data.get('ttl', 3600)  # Default 1 hour
        
        if not receiver_zeus_pin or not content:
            return jsonify({'error': 'Missing receiver_pin or content'}), 400
        
        # Find receiver by Zeus PIN
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (receiver_zeus_pin,))
        receiver = cursor.fetchone()
        if not receiver:
            conn.close()
            return jsonify({'error': 'Receiver not found'}), 404
        
        receiver_id = receiver[0]
        
        # Check contact handshake (CRITICAL: contacts must be accepted)
        cursor.execute('''
            SELECT status FROM contacts 
            WHERE user_id = ? AND contact_user_id = ? AND status = 'accepted'
        ''', (sender_id, receiver_id))
        
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Contact not accepted. Cannot send message.'}), 403
        
        # Insert message
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, content, file_url, ttl_seconds)
            VALUES (?, ?, ?, ?, ?)
        ''', (sender_id, receiver_id, content, '', ttl_seconds))
        
        message_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"✅ Message sent from user {sender_id} to {receiver_id}")
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'message': 'Message sent successfully'
        }), 200
        
    except Exception as e:
        print(f"❌ send_message error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-messages', methods=['GET'])
def get_messages():
    """Get unread messages for current user (auto-delete expired)"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        
        # Get current messages for user (not expired)
        cursor.execute('''
            SELECT id, sender_id, receiver_id, content, file_url, ttl_seconds, created_at, viewed_at
            FROM messages 
            WHERE receiver_id = ? 
            AND datetime(created_at, '+' || ttl_seconds || ' seconds') > datetime('now')
            ORDER BY created_at DESC
        ''', (user_id,))
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'sender_id': row[1],
                'receiver_id': row[2],
                'content': row[3],
                'file_url': row[4],
                'ttl_seconds': row[5],
                'created_at': row[6],
                'viewed_at': row[7]
            })
        
        # Auto-delete expired messages (TTL cleanup)
        cursor.execute('''
            DELETE FROM messages 
            WHERE receiver_id = ? 
            AND datetime(created_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
        ''', (user_id,))
        conn.commit()
        
        # Mark retrieved messages as viewed
        if messages:
            cursor.execute('''
                UPDATE messages 
                SET viewed_at = datetime('now')
                WHERE receiver_id = ? AND viewed_at IS NULL
            ''', (user_id,))
            conn.commit()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'messages': messages,
            'count': len(messages)
        }), 200
        
    except Exception as e:
        print(f"❌ get_messages error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-message', methods=['POST', 'OPTIONS'])
def delete_message():
    """Delete a message (by sender or receiver)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        message_id = data.get('message_id')
        
        if not message_id:
            return jsonify({'error': 'Missing message_id'}), 400
        
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        
        # Verify ownership and delete
        cursor.execute('''
            DELETE FROM messages 
            WHERE id = ? AND (sender_id = ? OR receiver_id = ?)
        ''', (message_id, user_id, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Message not found or not authorized'}), 404
        
        conn.commit()
        conn.close()
        
        print(f"✅ Message {message_id} deleted by user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Message deleted successfully'
        }), 200
        
    except Exception as e:
        print(f"❌ delete_message error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        conn = sqlite3.connect('zeuschat.db')
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Serve static files
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    if os.path.exists(path):
        return send_from_directory('.', path)
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 ZeusChat server starting on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
