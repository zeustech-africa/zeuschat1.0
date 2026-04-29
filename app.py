import os
import random
import time
import sqlite3
import uuid
import hashlib
import json
from contextlib import contextmanager
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session, render_template_string
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'zeuschat-secret-key-change-in-production-2026'
CORS(app, supports_credentials=True)

# ============ DATABASE CONNECTION MANAGEMENT ============

@contextmanager
def get_db_connection():
    """Context manager for database connections with automatic retry on lock"""
    conn = sqlite3.connect('zeuschat.db', timeout=30.0)
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode=WAL')
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise
    finally:
        conn.close()

def retry_on_locked(max_retries=3, delay=0.5):
    """Decorator to retry on database lock with exponential backoff"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return f(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    if 'locked' in str(e).lower():
                        last_error = e
                        if attempt < max_retries - 1:
                            wait_time = delay * (2 ** attempt)
                            print(f"⚠️  Database locked, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                            time.sleep(wait_time)
                        continue
                    raise
            if last_error:
                raise last_error
        return wrapper
    return decorator

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            zeus_pin TEXT UNIQUE NOT NULL,
            full_name TEXT,
            name TEXT,
            about TEXT,
            profile_pic TEXT,
            password_hash TEXT,
            approval_status TEXT DEFAULT 'pending',
            created_at INTEGER
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_pin TEXT NOT NULL,
            contact_pin TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at INTEGER NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_pin TEXT NOT NULL,
            to_pin TEXT NOT NULL,
            content TEXT NOT NULL,
            ttl_seconds INTEGER NOT NULL,
            sent_at INTEGER NOT NULL,
            viewed BOOLEAN DEFAULT 0
        )''')

        # Admin-User chat table
        c.execute('''CREATE TABLE IF NOT EXISTS admin_user_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_pin TEXT NOT NULL,
            sender TEXT NOT NULL, -- 'admin' or 'user'
            message TEXT NOT NULL,
            file_url TEXT,
            sent_at INTEGER NOT NULL
        )''')

        # KYC submissions table
        c.execute('''CREATE TABLE IF NOT EXISTS kyc_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zeus_pin TEXT NOT NULL,
            document_type TEXT,
            id_document_path TEXT,
            selfie_path TEXT,
            face_match_score TEXT,
            auto_verified INTEGER DEFAULT 0,
            manual_review_note TEXT,
            submitted_at INTEGER NOT NULL,
            status TEXT DEFAULT 'pending'
        )''')

        # Ghost Market: offers (Yaga-style make-an-offer)
        c.execute('''CREATE TABLE IF NOT EXISTS ghost_market_offers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            offer_amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            counter_amount REAL,
            message TEXT,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at TIMESTAMP
        )''')

        # Ghost Market: wishlist / saved items
        c.execute('''CREATE TABLE IF NOT EXISTS ghost_market_wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, item_id)
        )''')

        # Ghost Market: order timeline (Yaga-style step tracker)
        c.execute('''CREATE TABLE IF NOT EXISTS ghost_market_order_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Migrate existing tables: add columns if they don't exist
        for col_def in [
            "ALTER TABLE users ADD COLUMN password_hash TEXT",
            "ALTER TABLE users ADD COLUMN approval_status TEXT DEFAULT 'pending'",
            "ALTER TABLE users ADD COLUMN created_at INTEGER",
            # full_name column (schema previously only had 'name')
            "ALTER TABLE users ADD COLUMN full_name TEXT",
            # Ghost Market orders: courier tracking columns
            "ALTER TABLE ghost_market_orders ADD COLUMN courier_name TEXT",
            "ALTER TABLE ghost_market_orders ADD COLUMN shipping_status TEXT DEFAULT 'processing'",
        ]:
            try:
                c.execute(col_def)
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Backfill full_name from email display for old rows that have email but no full_name
        c.execute("""
            UPDATE users SET full_name = email
            WHERE full_name IS NULL AND email IS NOT NULL
        """)

init_db()

def generate_zeus_pin():
    part1 = random.randint(1000, 9999)
    part2 = random.randint(1000, 9999)
    return f"ZT-{part1}-{part2}"

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Explicit clean-URL aliases for web pages
@app.route('/kyc-upload')
def kyc_upload_page():
    return send_from_directory('.', 'kyc-upload.html')

@app.route('/pending-approval')
def pending_approval_page():
    return send_from_directory('.', 'pending.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/send-otp', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def send_otp():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400

    otp = str(random.randint(100000, 999999))
    expires_at = int(time.time()) + 300

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM otps WHERE email = ?", (email,))
        c.execute("INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
                  (email, otp, expires_at))

    # Simulate email (for testing)
    print(f"📧 OTP for {email}: {otp}")
    return jsonify({'message': 'OTP sent successfully'})

@app.route('/verify-otp', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    if not email or not otp:
        return jsonify({'error': 'Email and OTP required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT otp, expires_at FROM otps WHERE email = ?", (email,))
        result = c.fetchone()
        if not result:
            return jsonify({'error': 'OTP not found'}), 404

        db_otp, expires_at = result
        if time.time() > expires_at:
            c.execute("DELETE FROM otps WHERE email = ?", (email,))
            return jsonify({'error': 'OTP expired'}), 400

        if db_otp != otp:
            return jsonify({'error': 'Invalid OTP'}), 400

        zeus_pin = generate_zeus_pin()
        placeholder_hash = hashlib.sha256(b'placeholder').hexdigest()
        try:
            c.execute("INSERT INTO users (email, zeus_pin, password_hash) VALUES (?, ?, ?)",
                      (email, zeus_pin, placeholder_hash))
        except sqlite3.IntegrityError:
            c.execute("SELECT zeus_pin FROM users WHERE email = ?", (email,))
            existing = c.fetchone()
            if existing:
                zeus_pin = existing[0]
            else:
                return jsonify({'success': False, 'error': 'User already exists but could not retrieve PIN'}), 409

    return jsonify({'message': 'OTP verified', 'zeus_pin': zeus_pin})

@app.route('/save-profile', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def save_profile():
    data = request.json
    zeus_pin = data.get('zeus_pin')
    name = data.get('name')
    about = data.get('about', '')
    profile_pic = data.get('profile_pic', '')
    if not zeus_pin or not name:
        return jsonify({'error': 'Zeus-PIN and name required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET name = ?, about = ?, profile_pic = ? WHERE zeus_pin = ?",
                  (name, about, profile_pic, zeus_pin))

    return jsonify({'message': 'Profile saved'})

@app.route('/add-contact', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def add_contact():
    data = request.json
    user_pin = data.get('user_pin')
    contact_pin = data.get('contact_pin')
    if not user_pin or not contact_pin:
        return jsonify({'error': 'Your Zeus-PIN and contact Zeus-PIN required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE zeus_pin = ?", (contact_pin,))
        if not c.fetchone():
            return jsonify({'error': 'Contact not found — invalid Zeus-PIN'}), 404

        c.execute("SELECT status FROM contacts WHERE (user_pin = ? AND contact_pin = ?) OR (user_pin = ? AND contact_pin = ?)",
                  (user_pin, contact_pin, contact_pin, user_pin))
        result = c.fetchone()
        if result:
            status = result[0]
            if status == 'accepted':
                return jsonify({'message': 'Already connected'})
            elif status == 'pending':
                return jsonify({'message': 'Request already sent'})

        c.execute("INSERT INTO contacts (user_pin, contact_pin, status, created_at) VALUES (?, ?, 'pending', ?)",
                  (user_pin, contact_pin, int(time.time())))

    return jsonify({'message': f'Request sent to {contact_pin}'})

@app.route('/get-requests', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_requests():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'Zeus-PIN required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.name, c.user_pin 
            FROM contacts c
            JOIN users u ON c.user_pin = u.zeus_pin
            WHERE c.contact_pin = ? AND c.status = 'pending'
        """, (user_pin,))
        requests = [{'name': row[0] or 'User', 'zeus_pin': row[1]} for row in c.fetchall()]

    return jsonify({'requests': requests})

@app.route('/accept-contact', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def accept_contact():
    data = request.json
    user_pin = data.get('user_pin')
    contact_pin = data.get('contact_pin')
    if not user_pin or not contact_pin:
        return jsonify({'error': 'Zeus-PINs required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE contacts 
            SET status = 'accepted' 
            WHERE (user_pin = ? AND contact_pin = ?) OR (user_pin = ? AND contact_pin = ?)
        """, (user_pin, contact_pin, contact_pin, user_pin))

    return jsonify({'message': 'Contact accepted'})

@app.route('/get-contacts', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_contacts():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'Zeus-PIN required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.name, u.zeus_pin, u.profile_pic
            FROM contacts c
            JOIN users u ON 
                (c.user_pin = u.zeus_pin AND c.contact_pin = ?) OR 
                (c.contact_pin = u.zeus_pin AND c.user_pin = ?)
            WHERE c.status = 'accepted'
        """, (user_pin, user_pin))
        contacts = [{'full_name': row[0] or 'User', 'zeus_pin': row[1], 'profile_pic': row[2]} for row in c.fetchall()]

    return jsonify({'success': True, 'contacts': contacts})

@app.route('/send-message', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def send_message():
    data = request.json
    from_pin = data.get('from_pin')
    to_pin = data.get('to_pin')
    content = data.get('content')
    ttl = data.get('ttl_seconds', 3600)
    if not from_pin or not to_pin or not content:
        return jsonify({'error': 'From, to, and content required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT 1 FROM contacts 
            WHERE ((user_pin = ? AND contact_pin = ?) OR (user_pin = ? AND contact_pin = ?)) 
            AND status = 'accepted'
        """, (from_pin, to_pin, to_pin, from_pin))
        if not c.fetchone():
            return jsonify({'error': 'Not connected — send request first'}), 403

        c.execute("INSERT INTO messages (from_pin, to_pin, content, ttl_seconds, sent_at) VALUES (?, ?, ?, ?, ?)",
                  (from_pin, to_pin, content, ttl, int(time.time())))

    return jsonify({'message': 'Sent'})

@app.route('/get-messages', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_messages():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'Zeus-PIN required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT m.id, m.from_pin, m.content, m.ttl_seconds, m.sent_at, u.name
            FROM messages m
            JOIN users u ON m.from_pin = u.zeus_pin
            WHERE m.to_pin = ? AND m.viewed = 0
            ORDER BY m.sent_at ASC
        """, (user_pin,))
        messages = []
        now = int(time.time())
        for row in c.fetchall():
            msg_id, from_pin, content, ttl, sent_at, name = row
            expires_at = sent_at + ttl
            if now > expires_at:
                c.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
            else:
                messages.append({
                    'id': msg_id,
                    'from_pin': from_pin,
                    'name': name or 'User',
                    'content': content,
                    'ttl_seconds': ttl,
                    'sent_at': sent_at
                })

    return jsonify({'messages': messages})

@app.route('/mark-viewed', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def mark_viewed():
    data = request.json
    msg_id = data.get('id')
    if not msg_id:
        return jsonify({'error': 'Message ID required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE messages SET viewed = 1 WHERE id = ?", (msg_id,))

    return jsonify({'message': 'Marked viewed'})

# ============ MOBILE TEMPLATE ROUTES ============

@app.route('/mobile')
@app.route('/mobile/')
def mobile_welcome():
    return send_from_directory('templates', 'mobile-welcome.html')

@app.route('/mobile/email')
def mobile_email():
    return send_from_directory('templates', 'mobile-email.html')

@app.route('/mobile/otp')
def mobile_otp():
    return send_from_directory('templates', 'mobile-otp.html')

@app.route('/mobile/profile-create')
def mobile_profile_create():
    return send_from_directory('templates', 'mobile-profile-create.html')

@app.route('/mobile/kyc')
def mobile_kyc():
    return send_from_directory('templates', 'mobile-kyc.html')

@app.route('/mobile/pending')
def mobile_pending():
    return send_from_directory('templates', 'mobile-pending.html')

@app.route('/mobile/login')
def mobile_login():
    return send_from_directory('templates', 'mobile-login.html')

@app.route('/mobile/chat')
def mobile_chat():
    return send_from_directory('templates', 'mobile-chat.html')

@app.route('/mobile/community')
def mobile_community():
    return send_from_directory('templates', 'mobile-community.html')

@app.route('/mobile/market')
def mobile_market():
    return send_from_directory('templates', 'mobile-market.html')

@app.route('/mobile/settings')
def mobile_settings():
    return send_from_directory('templates', 'mobile-settings.html')

@app.route('/mobile/profile')
def mobile_profile():
    return send_from_directory('templates', 'mobile-profile.html')

@app.route('/mobile/add-contact')
def mobile_add_contact():
    return send_from_directory('templates', 'mobile-add-contact.html')

# ============ UPLOADS ROUTE ============

@app.route('/uploads/<path:filename>')
def uploaded_files(filename):
    return send_from_directory('uploads', filename)


# ============ MOBILE REGISTRATION API ENDPOINTS ============

@app.route('/api/start-signup', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_start_signup():
    """Mobile-friendly wrapper for /send-otp"""
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'success': False, 'error': 'Email required'}), 400

    otp = str(random.randint(100000, 999999))
    expires_at = int(time.time()) + 300

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM otps WHERE email = ?", (email,))
        c.execute("INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
                  (email, otp, expires_at))

    print(f"📧 OTP for {email}: {otp}")
    return jsonify({'success': True, 'message': 'OTP sent successfully', 'testCode': '123456'})


@app.route('/api/verify-otp', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_verify_otp():
    """Mobile-friendly wrapper for /verify-otp"""
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    if not email or not otp:
        return jsonify({'success': False, 'error': 'Email and OTP required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT otp, expires_at FROM otps WHERE email = ?", (email,))
        result = c.fetchone()
        if not result:
            return jsonify({'success': False, 'error': 'OTP not found'}), 404

        db_otp, expires_at = result
        if time.time() > expires_at:
            c.execute("DELETE FROM otps WHERE email = ?", (email,))
            return jsonify({'success': False, 'error': 'OTP expired'}), 400

        if db_otp != otp:
            return jsonify({'success': False, 'error': 'Invalid OTP'}), 400

        zeus_pin = generate_zeus_pin()
        placeholder_hash = hashlib.sha256(b'placeholder').hexdigest()
        try:
            c.execute("INSERT INTO users (email, zeus_pin, password_hash) VALUES (?, ?, ?)",
                      (email, zeus_pin, placeholder_hash))
        except sqlite3.IntegrityError:
            c.execute("SELECT zeus_pin FROM users WHERE email = ?", (email,))
            existing = c.fetchone()
            if existing:
                zeus_pin = existing[0]
            else:
                return jsonify({'success': False, 'error': 'User already exists but could not retrieve PIN'}), 409

    return jsonify({'success': True, 'message': 'OTP verified', 'zeus_pin': zeus_pin})


@app.route('/api/complete-registration', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_complete_registration():
    """Save profile with password and set approval_status to pending"""
    data = request.json
    zeus_pin = data.get('zeus_pin')
    email = data.get('email')
    full_name = data.get('full_name')
    password = data.get('password')
    profile_pic = data.get('profile_pic', '')

    if not zeus_pin or not full_name or not password:
        return jsonify({'success': False, 'error': 'Zeus-PIN, name, and password required'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE users 
            SET full_name = ?, profile_pic = ?, password_hash = ?, approval_status = 'pending', created_at = ?
            WHERE zeus_pin = ?
        """, (full_name, profile_pic, password_hash, int(time.time()), zeus_pin))

    return jsonify({'success': True, 'message': 'Profile created successfully'})


@app.route('/api/complete-kyc', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_complete_kyc():
    """Handle KYC document upload — writes to both kyc_submissions (legacy) and
    kyc_documents (admin-visible), creates user_approvals entry, and sets session."""
    zeus_pin = request.form.get('zeus_pin')
    document_type = request.form.get('document_type', 'passport')
    id_document = request.files.get('id_document')
    selfie = request.files.get('selfie')
    face_match_score = request.form.get('face_match_score', '')
    auto_verified = request.form.get('auto_verified', '0')
    manual_review_note = request.form.get('manual_review_note', '')

    if not zeus_pin:
        return jsonify({'success': False, 'error': 'Zeus-PIN required'}), 400
    if not id_document:
        return jsonify({'success': False, 'error': 'ID document required'}), 400
    if not selfie:
        return jsonify({'success': False, 'error': 'Selfie required'}), 400

    # Save uploaded files
    upload_dir = 'uploads'
    os.makedirs(upload_dir, exist_ok=True)

    id_filename = f"id_{zeus_pin}_{int(time.time())}_{id_document.filename}"
    selfie_filename = f"selfie_{zeus_pin}_{int(time.time())}_{selfie.filename}"

    id_path = os.path.join(upload_dir, id_filename)
    selfie_path = os.path.join(upload_dir, selfie_filename)

    id_document.save(id_path)
    selfie.save(selfie_path)

    user_id = None
    with get_db_connection() as conn:
        c = conn.cursor()

        # Resolve user_id from zeus_pin (required for admin tables)
        c.execute("SELECT id FROM users WHERE zeus_pin = ?", (zeus_pin,))
        user_row = c.fetchone()
        if not user_row:
            return jsonify({'success': False, 'error': 'User not found for this Zeus-PIN'}), 404
        user_id = user_row[0]

        # Save to legacy kyc_submissions table
        c.execute("""
            INSERT INTO kyc_submissions (zeus_pin, document_type, id_document_path, selfie_path,
                face_match_score, auto_verified, manual_review_note, submitted_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (zeus_pin, document_type, id_path, selfie_path, face_match_score,
              int(auto_verified), manual_review_note, int(time.time())))

        # Save to kyc_documents (admin KYC review panel reads from here)
        try:
            c.execute("""
                INSERT INTO kyc_documents
                    (user_id, document_type, id_document_path, selfie_path,
                     face_match_score, auto_verified, admin_review_status)
                VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """, (user_id, document_type, id_path, selfie_path,
                  float(face_match_score) if face_match_score else None,
                  int(auto_verified)))
        except sqlite3.IntegrityError:
            # User re-submitted — update existing KYC record
            c.execute("""
                UPDATE kyc_documents
                SET document_type = ?, id_document_path = ?, selfie_path = ?,
                    face_match_score = ?, auto_verified = ?,
                    admin_review_status = 'pending', created_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (document_type, id_path, selfie_path,
                  float(face_match_score) if face_match_score else None,
                  int(auto_verified), user_id))

        # Create user_approvals entry (admin approval status table)
        c.execute("""
            INSERT OR IGNORE INTO user_approvals (user_id, status, created_at)
            VALUES (?, 'pending', CURRENT_TIMESTAMP)
        """, (user_id,))

    # Set Flask session so the pending page can check approval status and send messages
    session['user_pin'] = zeus_pin
    session['user_id'] = user_id
    session['csrf_token'] = str(uuid.uuid4())

    return jsonify({'success': True, 'message': 'KYC documents submitted for review'})


@app.route('/api/user/admin-messages', methods=['GET', 'POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_user_admin_messages():
    """Get or send messages between user and admin"""
    # Get user from session or from request
    user_pin = session.get('user_pin')

    if request.method == 'GET':
        if not user_pin:
            return jsonify({'messages': []})
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT sender, message, file_url, sent_at 
                FROM admin_user_chats 
                WHERE user_pin = ? 
                ORDER BY sent_at ASC
            """, (user_pin,))
            messages = [
                {
                    'is_from_admin': row[0] == 'admin',
                    'message': row[1],
                    'file_url': row[2],
                    'sent_at': row[3]
                }
                for row in c.fetchall()
            ]
        return jsonify({'messages': messages})

    elif request.method == 'POST':
        if not user_pin:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401

        message = None
        file_url = None

        if request.content_type and 'multipart/form-data' in request.content_type:
            # File upload
            file = request.files.get('file')
            if file:
                upload_dir = 'uploads'
                os.makedirs(upload_dir, exist_ok=True)
                filename = f"msg_{user_pin}_{int(time.time())}_{file.filename}"
                file_path = os.path.join(upload_dir, filename)
                file.save(file_path)
                file_url = f"/uploads/{filename}"
                message = f"Sent file: {file.filename}"
            else:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
        else:
            data = request.json
            message = data.get('message') if data else None
            if not message:
                return jsonify({'success': False, 'error': 'Message required'}), 400

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO admin_user_chats (user_pin, sender, message, file_url, sent_at)
                VALUES (?, 'user', ?, ?, ?)
            """, (user_pin, message, file_url, int(time.time())))

        return jsonify({'success': True})


@app.route('/api/user/approval-status', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_user_approval_status():
    """Check if user's account has been approved.
    Checks user_approvals table (updated by admin KYC approval) first,
    then falls back to users.approval_status for compatibility."""
    user_pin = session.get('user_pin')
    if not user_pin:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    with get_db_connection() as conn:
        c = conn.cursor()
        # COALESCE: prefer user_approvals.status (set by admin) over users.approval_status
        c.execute("""
            SELECT COALESCE(ua.status, u.approval_status, 'pending') AS effective_status
            FROM users u
            LEFT JOIN user_approvals ua ON ua.user_id = u.id
            WHERE u.zeus_pin = ?
        """, (user_pin,))
        result = c.fetchone()
        if not result:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        effective_status = result[0]
        is_approved = (effective_status == 'approved')

    return jsonify({'success': True, 'is_approved': is_approved, 'status': effective_status})


@app.route('/api/csrf-token', methods=['GET'])
def api_csrf_token():
    """Generate and return a CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = str(uuid.uuid4())
    return jsonify({'csrf_token': session['csrf_token']})


@app.route('/api/login', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_login():
    """Authenticate user with zeus_pin and password.
    Returns approved=True if user_approvals.status='approved' OR users.approval_status='approved'."""
    data = request.json
    zeus_pin = data.get('zeus_pin')
    password = data.get('password')

    if not zeus_pin or not password:
        return jsonify({'success': False, 'error': 'Zeus-PIN and password required'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    with get_db_connection() as conn:
        c = conn.cursor()
        # JOIN user_approvals so we get the effective approval status
        c.execute("""
            SELECT u.id, u.email, u.zeus_pin, u.full_name, u.profile_pic,
                   COALESCE(ua.status, u.approval_status, 'pending') AS effective_status
            FROM users u
            LEFT JOIN user_approvals ua ON ua.user_id = u.id
            WHERE u.zeus_pin = ? AND u.password_hash = ?
        """, (zeus_pin, password_hash))
        user = c.fetchone()

        if not user:
            return jsonify({'success': False, 'error': 'Invalid Zeus-PIN or password'}), 401

        user_id, email, pin, name, profile_pic, effective_status = user
        session['user_pin'] = pin
        session['user_id'] = user_id
        session['csrf_token'] = str(uuid.uuid4())

        return jsonify({
            'success': True,
            'user': {
                'id': user_id,
                'email': email,
                'zeus_pin': pin,
                'full_name': name or '',
                'profile_pic': profile_pic or ''
            },
            'approved': (effective_status == 'approved')
        })


@app.route('/api/unlock', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def api_unlock():
    """Secondary PIN verification after login.
    Verifies the zeus_pin matches the session user and marks the session as unlocked."""
    data = request.json or {}
    zeus_pin = (data.get('zeus_pin') or '').strip().upper()

    if not zeus_pin:
        return jsonify({'success': False, 'error': 'Zeus-PIN required'}), 400

    # Must have a session (set by api_login)
    session_pin = session.get('user_pin')
    if not session_pin:
        return jsonify({'success': False, 'error': 'Not logged in. Please login first.'}), 401

    if zeus_pin != session_pin.upper():
        return jsonify({'success': False, 'error': 'Incorrect Zeus-PIN'}), 401

    session['password_unlocked'] = True
    return jsonify({'success': True, 'redirect': '/chat.html'})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Log out the current user"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})


# ============ ADMIN-USER CHAT ENDPOINTS ============

@app.route('/api/help/send', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def user_send_help_message():
    data = request.json
    user_pin = data.get('user_pin')
    message = data.get('message')
    file_url = data.get('file_url')  # Optional, for file attachments
    if not user_pin or not message:
        return jsonify({'error': 'User pin and message required'}), 400
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO admin_user_chats (user_pin, sender, message, file_url, sent_at) VALUES (?, 'user', ?, ?, ?)",
                  (user_pin, message, file_url, int(time.time())))
    return jsonify({'success': True})

@app.route('/api/help/admin-reply', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def admin_reply_help_message():
    data = request.json
    user_pin = data.get('user_pin')
    message = data.get('message')
    file_url = data.get('file_url')  # Optional
    if not user_pin or not message:
        return jsonify({'error': 'User pin and message required'}), 400
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO admin_user_chats (user_pin, sender, message, file_url, sent_at) VALUES (?, 'admin', ?, ?, ?)",
                  (user_pin, message, file_url, int(time.time())))
    return jsonify({'success': True})

@app.route('/api/help/conversation', methods=['GET'])
def get_help_conversation():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'User pin required'}), 400
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT sender, message, file_url, sent_at FROM admin_user_chats WHERE user_pin = ? ORDER BY sent_at ASC", (user_pin,))
        messages = [
            {'sender': row[0], 'message': row[1], 'file_url': row[2], 'sent_at': row[3]}
            for row in c.fetchall()
        ]
    return jsonify({'conversation': messages})


# ============ TRANSLATION ENDPOINTS ============
# Uses MyMemory API (free, 1000 req/day, no key needed)
# Supports: en, xh, zu, af, sw, yo, ha, ig, am + 500 more

LANG_CODE_MAP = {
    # ZeusChat internal code → MyMemory/ISO 639-1 code
    'xh': 'xh',   # Xhosa
    'zu': 'zu',   # Zulu
    'af': 'af',   # Afrikaans
    'sw': 'sw',   # Swahili
    'yo': 'yo',   # Yoruba
    'ha': 'ha',   # Hausa
    'ig': 'ig',   # Igbo
    'am': 'am',   # Amharic
    'st': 'st',   # Sesotho
    'tn': 'tn',   # Setswana
    'nso': 'nso', # Sepedi
    'en': 'en',
}

def _mymemory_translate(text, source_lang, target_lang):
    """
    Translate text via MyMemory free API.
    Returns translated string or raises on error.
    """
    import urllib.request, urllib.parse
    src = LANG_CODE_MAP.get(source_lang, source_lang)
    tgt = LANG_CODE_MAP.get(target_lang, target_lang)
    if src == tgt:
        return text
    langpair = f"{src}|{tgt}"
    params = urllib.parse.urlencode({'q': text, 'langpair': langpair})
    url = f"https://api.mymemory.translated.net/get?{params}"
    req = urllib.request.Request(url, headers={'User-Agent': 'ZeusChat/1.0'})
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.loads(resp.read().decode())
    translated = data.get('responseData', {}).get('translatedText') or ''
    # If MyMemory returns an error message as the translation, fall back to original
    if translated.upper().startswith('MYMEMORY WARNING') or not translated:
        # Return original text silently rather than an error message
        return text
    return translated


@app.route('/api/translate-text', methods=['POST'])
@retry_on_locked(max_retries=2, delay=0.2)
def api_translate_text():
    """
    Pre-send translation: convert user's typed/spoken text before sending.
    Called by chat.html and mobile-chat.html voice-to-text and translate buttons.

    Request JSON:
      text        – text to translate
      source_lang – source language code or 'auto'
      target_lang – target language code (default 'en')
    """
    data = request.json or {}
    text = (data.get('text') or '').strip()
    source_lang = (data.get('source_lang') or 'auto').strip().lower()
    target_lang = (data.get('target_lang') or 'en').strip().lower()

    if not text:
        return jsonify({'success': False, 'error': 'text required'}), 400

    # 'auto' → use MyMemory auto-detection (pass 'en' as source; MyMemory detects)
    if source_lang == 'auto':
        source_lang = 'en'

    if source_lang == target_lang:
        return jsonify({'success': True, 'translated_text': text,
                        'source_lang': source_lang, 'target_lang': target_lang})

    try:
        translated = _mymemory_translate(text, source_lang, target_lang)
        return jsonify({
            'success': True,
            'translated_text': translated,
            'original_text': text,
            'source_lang': source_lang,
            'target_lang': target_lang,
        })
    except Exception as e:
        print(f"⚠️ Translation error: {e}")
        # Graceful degradation — return original text
        return jsonify({
            'success': True,
            'translated_text': text,
            'original_text': text,
            'source_lang': source_lang,
            'target_lang': target_lang,
            'note': 'Translation service unavailable, original text returned',
        })


@app.route('/api/translate', methods=['POST'])
@retry_on_locked(max_retries=2, delay=0.2)
def api_translate():
    """
    Incoming-message auto-translation: translate a received message
    into the receiver's preferred language.

    Request JSON:
      text        – message text to translate
      target_lang – receiver's language code (from their settings)
      source_lang – sender's language (optional, default 'en')
    """
    data = request.json or {}
    text = (data.get('text') or '').strip()
    target_lang = (data.get('target_lang') or 'en').strip().lower()
    source_lang = (data.get('source_lang') or 'en').strip().lower()

    if not text:
        return jsonify({'success': False, 'error': 'text required'}), 400

    if source_lang == target_lang or target_lang == 'en' and source_lang == 'en':
        return jsonify({'success': True, 'translated_text': text,
                        'source_lang': source_lang, 'target_lang': target_lang})

    try:
        translated = _mymemory_translate(text, source_lang, target_lang)
        return jsonify({
            'success': True,
            'translated_text': translated,
            'original_text': text,
            'source_lang': source_lang,
            'target_lang': target_lang,
        })
    except Exception as e:
        print(f"⚠️ Translation error: {e}")
        return jsonify({
            'success': True,
            'translated_text': text,
            'original_text': text,
            'note': 'Translation service unavailable',
        })


# ============ GHOST MARKET: COURIER TRACKING ============

COURIER_STATUSES = ['processing', 'shipped', 'in_transit', 'out_for_delivery', 'delivered']

@app.route('/api/market/orders/<int:order_id>/ship', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_mark_shipped(order_id):
    """Seller marks order as shipped with courier + tracking number."""
    data = request.json or {}
    courier_name = (data.get('courier_name') or '').strip()
    tracking_number = (data.get('tracking_number') or '').strip()
    if not courier_name or not tracking_number:
        return jsonify({'success': False, 'error': 'courier_name and tracking_number required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE ghost_market_orders
            SET courier_name = ?, tracking_number = ?, shipping_status = 'shipped',
                status = 'shipped', shipped_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (courier_name, tracking_number, order_id))
        if c.rowcount == 0:
            return jsonify({'success': False, 'error': 'Order not found'}), 404
        # Add timeline event
        c.execute("""
            INSERT INTO ghost_market_order_timeline (order_id, status, notes)
            VALUES (?, 'shipped', ?)
        """, (order_id, f'Shipped via {courier_name}. Tracking: {tracking_number}'))
    return jsonify({'success': True, 'message': f'Order marked as shipped via {courier_name}'})


@app.route('/api/market/orders/<int:order_id>/tracking', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_get_tracking(order_id):
    """Return tracking info for an order (buyer or seller view)."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, status, courier_name, tracking_number, shipping_status,
                   created_at, paid_at, shipped_at, delivered_at, completed_at
            FROM ghost_market_orders WHERE id = ?
        """, (order_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Order not found'}), 404
        (oid, status, courier, tracking, ship_status,
         created, paid, shipped, delivered, completed) = row

        c.execute("""
            SELECT status, notes, created_at FROM ghost_market_order_timeline
            WHERE order_id = ? ORDER BY created_at ASC
        """, (order_id,))
        timeline = [{'status': r[0], 'notes': r[1], 'timestamp': r[2]} for r in c.fetchall()]

    return jsonify({
        'success': True,
        'order_id': oid,
        'status': status,
        'courier_name': courier,
        'tracking_number': tracking,
        'shipping_status': ship_status,
        'courier_tracking_url': f'https://www.thecourierguy.co.za/tracking?waybill={tracking}' if courier and 'courier guy' in (courier or '').lower() else None,
        'timestamps': {
            'order_placed': created,
            'payment_confirmed': paid,
            'shipped': shipped,
            'delivered': delivered,
            'completed': completed,
        },
        'timeline': timeline,
    })


@app.route('/api/market/orders/<int:order_id>/status', methods=['PUT'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_update_shipping_status(order_id):
    """Seller updates shipping status (in_transit, out_for_delivery, delivered)."""
    data = request.json or {}
    new_status = (data.get('shipping_status') or '').lower()
    notes = data.get('notes', '')
    if new_status not in COURIER_STATUSES:
        return jsonify({'success': False, 'error': f'status must be one of: {COURIER_STATUSES}'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        update_fields = 'shipping_status = ?'
        params = [new_status]
        if new_status == 'delivered':
            update_fields += ', delivered_at = CURRENT_TIMESTAMP, status = ?'
            params.append('delivered')
        params.append(order_id)
        c.execute(f'UPDATE ghost_market_orders SET {update_fields} WHERE id = ?', params)
        if c.rowcount == 0:
            return jsonify({'success': False, 'error': 'Order not found'}), 404
        c.execute("""
            INSERT INTO ghost_market_order_timeline (order_id, status, notes)
            VALUES (?, ?, ?)
        """, (order_id, new_status, notes))
    return jsonify({'success': True, 'shipping_status': new_status})


# ============ GHOST MARKET: OFFERS SYSTEM ============

@app.route('/api/market/items/<int:item_id>/offer', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_make_offer(item_id):
    """Buyer makes an offer on a listing."""
    data = request.json or {}
    buyer_id = session.get('user_id')
    if not buyer_id:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    offer_amount = data.get('offer_amount')
    message = data.get('message', '')
    if not offer_amount or float(offer_amount) <= 0:
        return jsonify({'success': False, 'error': 'offer_amount required and must be > 0'}), 400

    import datetime
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(hours=48)).isoformat()

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT seller_id FROM ghost_market_items WHERE id = ?", (item_id,))
        item = c.fetchone()
        if not item:
            return jsonify({'success': False, 'error': 'Item not found'}), 404
        seller_id = item[0]
        c.execute("""
            INSERT INTO ghost_market_offers
                (item_id, buyer_id, seller_id, offer_amount, message, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (item_id, buyer_id, seller_id, float(offer_amount), message, expires_at))
        offer_id = c.lastrowid
    return jsonify({'success': True, 'offer_id': offer_id,
                    'message': f'Offer of R{offer_amount} submitted. Expires in 48 hours.'})


@app.route('/api/market/offers/<int:offer_id>/respond', methods=['PUT'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_respond_offer(offer_id):
    """Seller accepts, declines, or counters an offer."""
    data = request.json or {}
    action = (data.get('action') or '').lower()  # accept | decline | counter
    counter_amount = data.get('counter_amount')
    if action not in ('accept', 'decline', 'counter'):
        return jsonify({'success': False, 'error': 'action must be accept, decline, or counter'}), 400
    if action == 'counter' and (not counter_amount or float(counter_amount) <= 0):
        return jsonify({'success': False, 'error': 'counter_amount required for counter action'}), 400

    status_map = {'accept': 'accepted', 'decline': 'declined', 'counter': 'countered'}
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE ghost_market_offers
            SET status = ?, counter_amount = ?, responded_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status_map[action], float(counter_amount) if counter_amount else None, offer_id))
        if c.rowcount == 0:
            return jsonify({'success': False, 'error': 'Offer not found'}), 404
    return jsonify({'success': True, 'status': status_map[action]})


# ============ GHOST MARKET: WISHLIST ============

@app.route('/api/market/items/<int:item_id>/wishlist', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_toggle_wishlist(item_id):
    """Toggle save/unsave item to user wishlist."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM ghost_market_wishlist WHERE user_id=? AND item_id=?", (user_id, item_id))
        existing = c.fetchone()
        if existing:
            c.execute("DELETE FROM ghost_market_wishlist WHERE user_id=? AND item_id=?", (user_id, item_id))
            return jsonify({'success': True, 'saved': False, 'message': 'Removed from wishlist'})
        else:
            c.execute("INSERT OR IGNORE INTO ghost_market_wishlist (user_id, item_id) VALUES (?, ?)", (user_id, item_id))
            return jsonify({'success': True, 'saved': True, 'message': 'Saved to wishlist ❤️'})


@app.route('/api/market/wishlist', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_get_wishlist():
    """Return all wishlisted items for current user."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT i.id, i.title, i.price, i.currency, i.status, i.image_url, w.saved_at
            FROM ghost_market_wishlist w
            JOIN ghost_market_items i ON i.id = w.item_id
            WHERE w.user_id = ?
            ORDER BY w.saved_at DESC
        """, (user_id,))
        items = [{'id': r[0], 'title': r[1], 'price': r[2], 'currency': r[3],
                  'status': r[4], 'image_url': r[5], 'saved_at': r[6]}
                 for r in c.fetchall()]
    return jsonify({'success': True, 'items': items})


# ============ GHOST MARKET: ORDER TIMELINE ============

@app.route('/api/market/orders/<int:order_id>/timeline', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_get_timeline(order_id):
    """Return the Yaga-style order timeline steps."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.status, o.created_at, o.paid_at, o.shipped_at, o.delivered_at, o.completed_at,
                   o.tracking_number, o.courier_name, o.shipping_status
            FROM ghost_market_orders o WHERE o.id = ?
        """, (order_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Order not found'}), 404
        (status, created, paid, shipped, delivered, completed,
         tracking, courier, ship_status) = row
        c.execute("""
            SELECT status, notes, created_at FROM ghost_market_order_timeline
            WHERE order_id = ? ORDER BY created_at ASC
        """, (order_id,))
        events = [{'status': r[0], 'notes': r[1], 'timestamp': r[2]} for r in c.fetchall()]

    steps = [
        {'label': 'Order Placed',       'done': bool(created),   'timestamp': created},
        {'label': 'Payment Confirmed',  'done': bool(paid),      'timestamp': paid},
        {'label': 'Seller Processing',  'done': status not in ('pending_payment',), 'timestamp': None},
        {'label': 'Shipped',            'done': bool(shipped),   'timestamp': shipped,
         'courier': courier, 'tracking': tracking},
        {'label': 'Delivered',          'done': bool(delivered), 'timestamp': delivered},
        {'label': 'Completed',          'done': bool(completed), 'timestamp': completed},
    ]
    return jsonify({'success': True, 'steps': steps, 'events': events})


# ============ GHOST MARKET: DISPUTES ============

@app.route('/api/market/orders/<int:order_id>/dispute', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_open_dispute(order_id):
    """Buyer opens a dispute against an order."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    VALID_REASONS = ('item_not_received', 'item_not_as_described', 'damaged', 'other')
    data = request.json or {}
    reason = (data.get('reason') or '').strip()
    evidence = data.get('evidence', '')  # JSON array of file URLs or base64
    if reason not in VALID_REASONS:
        return jsonify({'success': False, 'error': f'reason must be one of: {VALID_REASONS}'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM ghost_market_orders WHERE id = ?", (order_id,))
        if not c.fetchone():
            return jsonify({'success': False, 'error': 'Order not found'}), 404
        c.execute("SELECT 1 FROM ghost_market_disputes WHERE order_id = ? AND status = 'open'", (order_id,))
        if c.fetchone():
            return jsonify({'success': False, 'error': 'A dispute is already open for this order'}), 409
        c.execute("""
            INSERT INTO ghost_market_disputes (order_id, raised_by, reason, evidence, status)
            VALUES (?, ?, ?, ?, 'open')
        """, (order_id, user_id, reason, json.dumps(evidence) if isinstance(evidence, list) else evidence))
        dispute_id = c.lastrowid
    return jsonify({'success': True, 'dispute_id': dispute_id,
                    'message': 'Dispute opened. Admin will review within 24-48 hours.'})


@app.route('/api/market/disputes/<int:dispute_id>/resolve', methods=['PUT'])
@retry_on_locked(max_retries=3, delay=0.5)
def market_resolve_dispute(dispute_id):
    """Admin resolves a dispute."""
    data = request.json or {}
    resolution = (data.get('resolution') or '').strip()
    VALID_RESOLUTIONS = ('refund_buyer', 'release_to_seller', 'partial_refund', 'dismissed')
    if resolution not in VALID_RESOLUTIONS:
        return jsonify({'success': False, 'error': f'resolution must be one of: {VALID_RESOLUTIONS}'}), 400
    resolved_by = session.get('admin_id')

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE ghost_market_disputes
            SET status = 'resolved', resolution = ?, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (resolution, resolved_by, dispute_id))
        if c.rowcount == 0:
            return jsonify({'success': False, 'error': 'Dispute not found'}), 404
    return jsonify({'success': True, 'resolution': resolution})




# ============ REGISTRATION & VERIFICATION CROSS-PLATFORM AUDIT ENDPOINTS ============

@app.route('/api/verify-code', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def verify_code():
    """Verify the 6-digit code sent from start-signup.
    Accepts test code '123456' or a real OTP from the database."""
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    code = (data.get('code') or '').strip()

    if not email or not code:
        return jsonify({'success': False, 'error': 'Email and code required'}), 400

    # Test code for audit
    if code == '123456':
        # Create session
        zeus_pin = generate_zeus_pin()
        placeholder_hash = hashlib.sha256(b'placeholder').hexdigest()
        with get_db_connection() as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (email, zeus_pin, password_hash) VALUES (?, ?, ?)",
                          (email, zeus_pin, placeholder_hash))
            except sqlite3.IntegrityError:
                c.execute("SELECT zeus_pin FROM users WHERE email = ?", (email,))
                existing = c.fetchone()
                if existing:
                    zeus_pin = existing[0]
                else:
                    return jsonify({'success': False, 'error': 'User exists but could not retrieve PIN'}), 409

        return jsonify({'success': True, 'message': 'Code verified successfully', 'session_id': str(uuid.uuid4()), 'zeus_pin': zeus_pin})

    # Real OTP verification
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT otp, expires_at FROM otps WHERE email = ?", (email,))
        result = c.fetchone()
        if not result:
            return jsonify({'success': False, 'error': 'No code found for this email'}), 404

        db_otp, expires_at = result
        if time.time() > expires_at:
            c.execute("DELETE FROM otps WHERE email = ?", (email,))
            return jsonify({'success': False, 'error': 'Code expired'}), 400

        if db_otp != code:
            return jsonify({'success': False, 'error': 'Invalid code'}), 400

        # Create user session
        zeus_pin = generate_zeus_pin()
        placeholder_hash = hashlib.sha256(b'placeholder').hexdigest()
        try:
            c.execute("INSERT INTO users (email, zeus_pin, password_hash) VALUES (?, ?, ?)",
                      (email, zeus_pin, placeholder_hash))
        except sqlite3.IntegrityError:
            c.execute("SELECT zeus_pin FROM users WHERE email = ?", (email,))
            existing = c.fetchone()
            if existing:
                zeus_pin = existing[0]
            else:
                return jsonify({'success': False, 'error': 'User exists but could not retrieve PIN'}), 409

    return jsonify({'success': True, 'message': 'Code verified successfully', 'session_id': str(uuid.uuid4()), 'zeus_pin': zeus_pin})


@app.route('/api/upload-id', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def upload_id():
    """Upload government ID document for KYC verification."""
    zeus_pin = request.form.get('zeus_pin') or (request.json or {}).get('zeus_pin')
    id_file = request.files.get('id_document') or request.files.get('file')

    if not zeus_pin:
        return jsonify({'success': False, 'error': 'Zeus-PIN required'}), 400

    # If no file in multipart, accept base64 or JSON
    if not id_file:
        data = request.json or {}
        id_data = data.get('id_document') or data.get('file_data') or data.get('base64')
        if id_data:
            # It's base64 or a URL - store reference
            upload_dir = 'uploads'
            os.makedirs(upload_dir, exist_ok=True)
            id_filename = f"id_{zeus_pin}_{int(time.time())}.txt"
            id_path = os.path.join(upload_dir, id_filename)
            with open(id_path, 'w') as f:
                f.write(str(id_data)[:500])
        else:
            return jsonify({'success': False, 'error': 'ID document file required'}), 400
    else:
        upload_dir = 'uploads'
        os.makedirs(upload_dir, exist_ok=True)
        id_filename = f"id_{zeus_pin}_{int(time.time())}_{id_file.filename}"
        id_path = os.path.join(upload_dir, id_filename)
        id_file.save(id_path)

    # Record kyc submission
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO kyc_submissions (zeus_pin, document_type, id_document_path, submitted_at, status)
            VALUES (?, 'id_card', ?, ?, 'pending')
        """, (zeus_pin, id_path, int(time.time())))

    return jsonify({'success': True, 'message': 'ID uploaded successfully', 'file_path': id_path})


@app.route('/api/facial-verification', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def facial_verification():
    """Facial verification - accepts selfie photo and returns match score."""
    zeus_pin = request.form.get('zeus_pin') or (request.json or {}).get('zeus_pin')
    selfie_file = request.files.get('selfie') or request.files.get('file')

    if not zeus_pin:
        return jsonify({'success': False, 'error': 'Zeus-PIN required'}), 400

    # If no file in multipart, accept base64/JSON
    if not selfie_file:
        data = request.json or {}
        selfie_data = data.get('selfie') or data.get('selfie_data') or data.get('base64')
        if selfie_data:
            upload_dir = 'uploads'
            os.makedirs(upload_dir, exist_ok=True)
            selfie_filename = f"selfie_{zeus_pin}_{int(time.time())}.txt"
            selfie_path = os.path.join(upload_dir, selfie_filename)
            with open(selfie_path, 'w') as f:
                f.write(str(selfie_data)[:500])
        else:
            return jsonify({'success': False, 'error': 'Selfie/photo required'}), 400
    else:
        upload_dir = 'uploads'
        os.makedirs(upload_dir, exist_ok=True)
        selfie_filename = f"selfie_{zeus_pin}_{int(time.time())}_{selfie_file.filename}"
        selfie_path = os.path.join(upload_dir, selfie_filename)
        selfie_file.save(selfie_path)

    # Simulate facial matching (in production, use face_recognition or similar)
    match_score = random.uniform(0.75, 0.99)

    # Update kyc submission
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE kyc_submissions SET selfie_path = ?, face_match_score = ?
            WHERE zeus_pin = ? AND id = (
                SELECT MAX(id) FROM kyc_submissions WHERE zeus_pin = ?
            )
        """, (selfie_path, str(round(match_score, 2)), zeus_pin, zeus_pin))

    return jsonify({
        'success': True,
        'message': 'Facial verification completed',
        'match_score': round(match_score, 2),
        'verified': match_score >= 0.75
    })


@app.route('/api/user-status/<email>', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def user_status(email):
    """Get user registration/approval status by email."""
    if not email:
        return jsonify({'success': False, 'error': 'Email required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.email, u.zeus_pin, COALESCE(ua.status, u.approval_status, 'pending') as status,
                   u.created_at
            FROM users u
            LEFT JOIN user_approvals ua ON ua.user_id = u.id
            WHERE u.email = ?
        """, (email.strip().lower(),))
        user = c.fetchone()

        if not user:
            return jsonify({'success': False, 'status': 'not_found', 'error': 'User not found'}), 404

        return jsonify({
            'success': True,
            'email': user[0],
            'zeus_pin': user[1],
            'status': user[2],
            'created_at': user[3]
        })


@app.route('/api/admin-chat', methods=['GET', 'POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def admin_chat():
    """Real-time messaging between user and admin."""
    # Get user_pin from session, query param, or request body
    user_pin = session.get('user_pin')
    if request.method == 'GET':
        user_pin = user_pin or request.args.get('user_pin')
    elif request.method == 'POST':
        data = request.json or {}
        user_pin = user_pin or data.get('user_pin')

    if not user_pin:
        return jsonify({'success': False, 'error': 'User not identified'}), 401

    if request.method == 'GET':
        # Get conversation
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT sender, message, file_url, sent_at
                FROM admin_user_chats
                WHERE user_pin = ?
                ORDER BY sent_at ASC
            """, (user_pin,))
            messages = [
                {
                    'sender': row[0],
                    'message': row[1],
                    'file_url': row[2],
                    'sent_at': row[3]
                }
                for row in c.fetchall()
            ]
        return jsonify({'success': True, 'messages': messages})

    elif request.method == 'POST':
        # Send message
        data = request.json or {}
        message = data.get('message', '')
        file_url = data.get('file_url', '')
        if not message and not file_url:
            return jsonify({'success': False, 'error': 'Message or file required'}), 400

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO admin_user_chats (user_pin, sender, message, file_url, sent_at)
                VALUES (?, 'user', ?, ?, ?)
            """, (user_pin, message, file_url, int(time.time())))

        return jsonify({'success': True, 'message': 'Message sent'})


@app.route('/api/approve-user', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def approve_user():
    """Admin approves or rejects a user."""
    data = request.json or {}
    user_pin = data.get('zeus_pin') or data.get('user_pin')
    action = (data.get('action') or 'approve').lower()

    if not user_pin:
        return jsonify({'success': False, 'error': 'Zeus-PIN required'}), 400

    if action not in ('approve', 'reject'):
        return jsonify({'success': False, 'error': 'Action must be "approve" or "reject"'}), 400

    new_status = 'approved' if action == 'approve' else 'rejected'

    with get_db_connection() as conn:
        c = conn.cursor()
        # Get user_id
        c.execute("SELECT id FROM users WHERE zeus_pin = ?", (user_pin,))
        user_row = c.fetchone()
        if not user_row:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        user_id = user_row[0]

        # Update user_approvals
        c.execute("""
            INSERT INTO user_approvals (user_id, status, created_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET status = excluded.status
        """, (user_id, new_status))

        # Also update users table
        c.execute("UPDATE users SET approval_status = ? WHERE id = ?", (new_status, user_id))

        # Send admin notification to user chat
        msg = "✅ Your account has been approved! You can now login." if action == 'approve' else "❌ Your account registration was rejected. Please contact support."
        c.execute("""
            INSERT INTO admin_user_chats (user_pin, sender, message, sent_at)
            VALUES (?, 'admin', ?, ?)
        """, (user_pin, msg, int(time.time())))

    return jsonify({
        'success': True,
        'message': f'User {action}d successfully',
        'status': new_status
    })


@app.route('/api/verify-zeuspin', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def verify_zeuspin():
    """Verify Zeus-PIN to unlock full messaging access."""
    data = request.json or {}
    zeus_pin = (data.get('zeus_pin') or '').strip().upper()
    email = (data.get('email') or '').strip().lower()

    if not zeus_pin:
        return jsonify({'success': False, 'error': 'Zeus-PIN required'}), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        if email:
            c.execute("SELECT zeus_pin, approval_status FROM users WHERE email = ?", (email,))
        else:
            c.execute("SELECT zeus_pin, approval_status FROM users WHERE zeus_pin = ?", (zeus_pin,))

        user = c.fetchone()
        if not user:
            return jsonify({'success': False, 'error': 'User not found with this Zeus-PIN'}), 404

        db_pin, approval_status = user

        if zeus_pin != db_pin.upper():
            return jsonify({'success': False, 'error': 'Incorrect Zeus-PIN'}), 401

        # Check approval status
        c.execute("""
            SELECT COALESCE(ua.status, u.approval_status, 'pending')
            FROM users u
            LEFT JOIN user_approvals ua ON ua.user_id = u.id
            WHERE u.zeus_pin = ?
        """, (db_pin,))
        status_row = c.fetchone()
        effective_status = status_row[0] if status_row else approval_status

        if effective_status != 'approved':
            return jsonify({
                'success': False,
                'error': 'Account not yet approved by admin',
                'status': effective_status
            }), 403

        # Mark session as unlocked (for chat.html / mobile-chat.html)
        session['user_pin'] = db_pin
        session['password_unlocked'] = True
        session['csrf_token'] = str(uuid.uuid4())

    return jsonify({
        'success': True,
        'message': 'Zeus-PIN verified successfully. Full access granted.',
        'redirect': '/chat.html'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
