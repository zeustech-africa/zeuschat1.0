import os
import secrets
import hashlib
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')

# ======== CORS CONFIGURATION =========
# Dynamic CORS - allows requests from any origin (Required for Render deployments)
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    # Allow all origins for now (can restrict later if needed)
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        # If no Origin header, allow from same domain
        response.headers['Access-Control-Allow-Origin'] = '*'
    
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

print("✅ Dynamic CORS initialized")

# ======== DATABASE SETUP =========
os.makedirs('data', exist_ok=True)
DATABASE_PATH = os.path.join('data', 'zeuschat.db')

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with required schema"""
    print("🔧 Initializing database...")
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                zeus_pin TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                profile_pic TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                ttl_seconds INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                viewed_at TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        
        # Verify tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"✅ Database initialized successfully")
        print(f"📊 Tables: {', '.join(tables)}")
        print(f"📊 Tables: {', '.join(tables)}")
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        if conn:
            conn.close()

# Initialize DB on startup
try:
    init_db()
except Exception as e:
    print(f"⚠️  Database initialization failed: {e}")
    print("⚠️  App will try to initialize on first request")

# ======== HELPER FUNCTIONS =========
def generate_zeus_pin():
    """Generate unique Zeus PIN in format ZT-XXXX-XXXX"""
    return f"ZT-{secrets.randbelow(9000) + 1000}-{secrets.randbelow(9000) + 1000}"

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ======== ROUTES - STATIC FILES =========
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    if os.path.exists(path):
        return send_from_directory('.', path)
    return send_from_directory('.', 'index.html')

# ======== API ENDPOINTS - HEALTH CHECK =========

@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring and debugging"""
    try:
        from datetime import datetime
        
        # Test database connection
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Get user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'tables': tables,
            'users': user_count,
            'timestamp': datetime.now().isoformat(),
            'environment': os.environ.get('FLASK_ENV', 'development'),
            'database_path': DATABASE_PATH
        }), 200
        
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now().isoformat() if 'datetime' in dir() else 'unknown'
        }), 500

# ======== API ENDPOINTS - REGISTRATION =========

@app.route('/api/start-signup', methods=['POST', 'OPTIONS'])
def start_signup():
    """Start signup process - email validation only"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.json or {}
        email = data.get('email', '').lower().strip()
        
        if not email or '@' not in email:
            return jsonify({'error': 'Invalid email address'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 409
        conn.close()
        
        print(f"✅ Signup started for email: {email}")
        return jsonify({
            'success': True,
            'message': 'Ready for OTP verification',
            'email': email
        }), 200
        
    except Exception as e:
        print(f"❌ start_signup error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-otp', methods=['POST', 'OPTIONS'])
def verify_otp():
    """Verify OTP and generate Zeus PIN"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        print(f"📥 Received OTP verification request")
        print(f"📊 Request headers: {dict(request.headers)}")
        print(f"📊 Request data: {request.get_data(as_text=True)}")
        
        data = request.json or {}
        email = data.get('email', '').lower().strip()
        otp = data.get('otp', '').strip()
        
        print(f"📧 Email: {email}")
        print(f"🔑 OTP: {otp}")
        
        if not email or not otp:
            print(f"❌ Missing email or OTP")
            return jsonify({'error': 'Email and OTP required', 'success': False}), 400
        
        # Test mode: accept 123456
        if otp != '123456':
            print(f"❌ Invalid OTP: {otp}")
            return jsonify({'error': 'Invalid OTP code', 'success': False}), 400
        
        # Generate unique Zeus PIN
        zeus_pin = generate_zeus_pin()
        
        print(f"✅ OTP verified for {email}, generated PIN: {zeus_pin}")
        
        response_data = {
            'success': True,
            'message': 'OTP verified successfully',
            'zeus_pin': zeus_pin,
            'email': email
        }
        
        print(f"📤 Sending response: {response_data}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"❌ verify_otp error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/complete-registration', methods=['POST', 'OPTIONS'])
def complete_registration():
    """Complete registration - create user account"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.json or {}
        email = data.get('email', '').lower().strip()
        zeus_pin = data.get('zeus_pin', '').strip()
        password = data.get('password', '').strip()
        full_name = data.get('full_name', '').strip()
        
        # Validate all required fields
        if not all([email, zeus_pin, password, full_name]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 409
        
        try:
            password_hash = hash_password(password)
            cursor.execute('''
                INSERT INTO users (email, zeus_pin, password_hash, full_name)
                VALUES (?, ?, ?, ?)
            ''', (email, zeus_pin, password_hash, full_name))
            
            conn.commit()
            user_id = cursor.lastrowid
            
            print(f"✅ Registration complete: User {user_id} ({email}) with PIN {zeus_pin}")
            
            return jsonify({
                'success': True,
                'message': 'Registration successful',
                'user_id': user_id,
                'zeus_pin': zeus_pin,
                'email': email
            }), 201
            
        except sqlite3.IntegrityError as e:
            conn.close()
            if 'UNIQUE constraint failed' in str(e):
                if 'email' in str(e):
                    return jsonify({'error': 'Email already registered'}), 409
                else:
                    return jsonify({'error': 'Zeus PIN already exists'}), 409
            return jsonify({'error': 'Registration failed'}), 400
        finally:
            if conn:
                conn.close()
        
    except Exception as e:
        print(f"❌ complete_registration error: {e}")
        return jsonify({'error': str(e)}), 500

# ======== API ENDPOINTS - LOGIN =========

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """Login with Zeus PIN and password"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.json or {}
        zeus_pin = data.get('zeus_pin', '').strip()
        password = data.get('password', '').strip()
        
        if not zeus_pin or not password:
            return jsonify({'error': 'Zeus PIN and password required'}), 400
        
        password_hash = hash_password(password)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, full_name, profile_pic 
            FROM users
            WHERE zeus_pin = ? AND password_hash = ?
        ''', (zeus_pin, password_hash))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid Zeus PIN or password'}), 401
        
        print(f"✅ Login successful: {user[1]}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user[0],
                'email': user[1],
                'full_name': user[2],
                'profile_pic': user[3],
                'zeus_pin': zeus_pin
            }
        }), 200
        
    except Exception as e:
        print(f"❌ login error: {e}")
        return jsonify({'error': str(e)}), 500

# ======== API ENDPOINTS - CONTACTS & MESSAGING =========

@app.route('/api/add-contact', methods=['POST', 'OPTIONS'])
def add_contact():
    """Add a contact by Zeus PIN"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.json or {}
        requester_pin = data.get('requester_zeus_pin', '').strip()
        contact_pin = data.get('contact_zeus_pin', '').strip()
        
        if not requester_pin or not contact_pin:
            return jsonify({'error': 'Both Zeus PINs required'}), 400
        
        if requester_pin == contact_pin:
            return jsonify({'error': 'Cannot add yourself as contact'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Find both users
        cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (requester_pin,))
        requester = cursor.fetchone()
        cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (contact_pin,))
        contact = cursor.fetchone()
        
        if not requester or not contact:
            conn.close()
            return jsonify({'error': 'One or both Zeus PINs not found'}), 404
        
        try:
            cursor.execute('''
                INSERT INTO contacts (user_id, contact_user_id, status)
                VALUES (?, ?, 'accepted')
            ''', (requester[0], contact[0]))
            conn.commit()
            print(f"✅ Contact added")
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Contact already exists'}), 409
        finally:
            conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Contact added successfully'
        }), 201
        
    except Exception as e:
        print(f"❌ add_contact error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send-message', methods=['POST', 'OPTIONS'])
def send_message():
    """Send a message to a contact"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.json or {}
        sender_pin = data.get('sender_zeus_pin', '').strip()
        receiver_pin = data.get('receiver_zeus_pin', '').strip()
        content = data.get('content', '').strip()
        ttl = int(data.get('ttl_seconds', 3600))
        
        if not all([sender_pin, receiver_pin, content]):
            return jsonify({'error': 'Sender, receiver, and message content required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Find both users
        cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (sender_pin,))
        sender = cursor.fetchone()
        cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (receiver_pin,))
        receiver = cursor.fetchone()
        
        if not sender or not receiver:
            conn.close()
            return jsonify({'error': 'Invalid sender or receiver'}), 404
        
        # Check if contact exists
        cursor.execute('''
            SELECT id FROM contacts 
            WHERE user_id = ? AND contact_user_id = ?
        ''', (sender[0], receiver[0]))
        
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Not connected with this contact'}), 403
        
        # Insert message
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, content, ttl_seconds)
            VALUES (?, ?, ?, ?)
        ''', (sender[0], receiver[0], content, ttl))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Message sent from {sender_pin} to {receiver_pin}")
        
        return jsonify({
            'success': True,
            'message': 'Message sent successfully'
        }), 201
        
    except Exception as e:
        print(f"❌ send_message error: {e}")
        return jsonify({'error': str(e)}), 500

# ======== SERVER STARTUP =========
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("🚀 Starting ZeusChat 1.0 Backend")
    print(f"📡 Database: {DATABASE_PATH}")
    print(f"🌐 Port: {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
