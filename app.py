from flask import Flask, request, jsonify, send_from_directory, session, render_template, redirect
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, emit
from flask_compress import Compress
import sqlite3
import os
import secrets
import hashlib
import re
import bcrypt
from collections import defaultdict
from datetime import datetime, timedelta
import json
import sys
import flask
from contextlib import contextmanager
from functools import wraps
import time
import gzip
import base64
import threading
import io
import tempfile
import shutil
import subprocess
import requests as http_requests
from urllib import request as urllib_request
from werkzeug.utils import secure_filename
from PIL import Image
from admin_middleware import require_approved_user, user_has_unlock, user_has_feature_access, get_user_subscription_tier, log_admin_action, get_db_connection as admin_get_db
from admin_routes import admin_bp
from payment_routes import payment_bp, validate_payment_config
from pywebpush import webpush, WebPushException

# Startup logging for deployment verification
print("="*60)
print(f"🚀 ZeusChat Server Starting")
print(f"📦 Python Version: {sys.version}")
print(f"📦 Flask Version: {flask.__version__}")
print("="*60)

app = Flask(__name__, static_folder='.', static_url_path='')
app.permanent_session_lifetime = timedelta(days=30)

# ============ SESSION COOKIE SECURITY ============
# Always set HttpOnly and SameSite; only require HTTPS when the app is actually
# deployed behind HTTPS. Local human testing on http://localhost must keep
# secure cookies disabled or browsers will drop the session cookie entirely.
_environment = (os.environ.get('FLASK_ENV') or os.environ.get('ENV') or '').strip().lower()
_is_production = bool(os.environ.get('RENDER')) or _environment == 'production'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=_is_production,   # HTTPS-only in production
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_SECURE=_is_production,
)
print(f"🔒 Session cookie security: SECURE={'ON' if _is_production else 'OFF (dev mode)'} | HTTPONLY=ON | SAMESITE=Lax")
# ============================================
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'zeuschat.db')
BASE_URL = os.environ.get('BASE_URL', 'https://zeuschat1-0-ixax.onrender.com')
ALLOWED_HOSTS = [
    host.strip() for host in os.environ.get(
        'ALLOWED_HOSTS',
        'zeuschat1-0-ixax.onrender.com,zeustechafrica.com,www.zeustechafrica.com'
    ).split(',') if host.strip()
]

if '*' in ALLOWED_HOSTS:
    ALLOWED_ORIGINS = ['*']
else:
    ALLOWED_ORIGINS = []
    for host in ALLOWED_HOSTS:
        if host.startswith('http://') or host.startswith('https://'):
            ALLOWED_ORIGINS.append(host)
        else:
            ALLOWED_ORIGINS.append(f'https://{host}')
            ALLOWED_ORIGINS.append(f'http://{host}')

# VAPID keys for Web Push notifications
VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '')
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '')
VAPID_SUBJECT = os.environ.get('VAPID_SUBJECT', 'mailto:admin@zeuschat.com')

# ============ LOW-BANDWIDTH OPTIMIZATION ============
# Enable gzip compression for all responses
Compress(app)
app.config['COMPRESS_LEVEL'] = 9  # Maximum compression
app.config['COMPRESS_MIN_SIZE'] = 100  # Compress responses > 100 bytes

# Low-bandwidth configuration
LOW_BANDWIDTH_CONFIG = {
    "enable_compression": True,
    "gzip_level": 9,
    "max_message_batch_size": 10,
    "heartbeat_interval": 60,
    "retry_max_attempts": 15,
    "retry_base_delay": 1,
    "retry_max_delay": 1800,
    "queue_cleanup_interval": 3600,
    "api_response_limit": 2048,
}


def ghost_utc_now():
    """Return a naive UTC datetime for Ghost content expiry consistency."""
    return datetime.utcnow()

print(f"📦 Low-Bandwidth Optimization: ENABLED")
print(f"   - Gzip compression: Level {LOW_BANDWIDTH_CONFIG['gzip_level']}")
print(f"   - Max retries: {LOW_BANDWIDTH_CONFIG['retry_max_attempts']}")
print(f"   - Heartbeat: {LOW_BANDWIDTH_CONFIG['heartbeat_interval']}s")
# ============================================

# Use persistent secret key - generate once and store in .secret_key file
SECRET_KEY_FILE = '.secret_key'
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
    print(f"🔑 Loaded existing secret key from {SECRET_KEY_FILE}")
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)
    print(f"🔑 Generated new secret key and saved to {SECRET_KEY_FILE}")

# CORS Configuration
CORS(
    app,
    origins=ALLOWED_ORIGINS,
    supports_credentials=True,
    methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
)

# Socket.IO for realtime status updates - OPTIMIZED FOR LOW-BANDWIDTH
socketio = SocketIO(
    app, 
    cors_allowed_origins=ALLOWED_ORIGINS,
    async_mode="threading",
    
    # ℹ️ Low-bandwidth network optimization
    ping_interval=60,              # Reduce from 25s to 60s (fewer keepalive packets)
    ping_timeout=120,              # Increase timeout window for poor networks
    max_http_buffer_size=256,      # Limit buffer to trigger message batching
    transports=['websocket', 'polling'],  # Allow both, prefer websocket
    
    # Connection reliability
    reconnect_delay=[100, 200, 300, 500],  # Random backoff: 100-500ms
    reconnect_delay_max=5000,      # Max 5 seconds between reconnection attempts
    
    # Logging and debugging
    engineio_logger=False,         # Disable engineio logging to reduce overhead
    logger=False,                  # Disable socketio logging
)

# Track connected users in Socket.IO
connected_users = {}  # Maps user_id -> socket_id

@socketio.on('connect')
def handle_socket_connect():
    """Handle Socket.IO connection - user passes their ID from client"""
    try:
        print(f"🔌 Socket connection attempt from {request.sid}")
        # Don't reject connection - clients will authenticate themselves
        emit('socket_ready', {'success': True, 'socket_id': request.sid})
        print(f"✅ Socket connection accepted")
    except Exception as e:
        print(f"⚠️ Socket connect error: {e}")

@socketio.on('register_user')
def handle_register_user(data):
    """Register user with Socket.IO when they authenticate"""
    try:
        user_id = data.get('user_id')
        if not user_id:
            print(f"❌ register_user: No user_id provided in data: {data}")
            emit('error', {'message': 'No user_id provided'})
            return
        
        # Convert to int if string
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            print(f"❌ register_user: Invalid user_id format: {user_id}")
            emit('error', {'message': 'Invalid user_id format'})
            return
        
        # Map user to their socket
        connected_users[user_id] = request.sid
        join_room(f"user:{user_id}")
        
        print(f"✅ User {user_id} registered on Socket.IO (sid: {request.sid})")
        print(f"📋 Connected users: {list(connected_users.keys())}")
        print(f"🎯 User {user_id} joined room: user:{user_id}")
        
        emit('user_registered', {'success': True, 'user_id': user_id})
        
        # Flush any queued messages for this user
        flush_message_queue(user_id)
    except Exception as e:
        print(f"⚠️ register_user error: {e}")
        import traceback
        traceback.print_exc()

@socketio.on('disconnect')
def handle_socket_disconnect():
    """Handle Socket.IO disconnection"""
    try:
        # Find and remove user from connected_users
        for user_id, sid in list(connected_users.items()):
            if sid == request.sid:
                del connected_users[user_id]
                print(f"🔌 User {user_id} disconnected (sid: {request.sid})")
                break
    except Exception as e:
        print(f"⚠️ Socket disconnect error: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    """Handle typing indicator (user started typing)"""
    try:
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        if not sender_id or not receiver_id:
            return
        
        # Emit to receiver
        room = f"user:{receiver_id}"
        socketio.emit('user_typing', {'user_id': sender_id, 'typing': True}, room=room)
        print(f"⌨️ User {sender_id} typing to {receiver_id}")
    except Exception as e:
        print(f"⚠️ typing_start error: {e}")

@socketio.on('typing_stop')
def handle_typing_stop(data):
    """Handle typing indicator (user stopped typing)"""
    try:
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        if not sender_id or not receiver_id:
            return
        
        # Emit to receiver
        room = f"user:{receiver_id}"
        socketio.emit('user_typing', {'user_id': sender_id, 'typing': False}, room=room)
        print(f"🛑 User {sender_id} stopped typing to {receiver_id}")
    except Exception as e:
        print(f"⚠️ typing_stop error: {e}")

@socketio.on('ping')
def handle_ping():
    """Handle heartbeat ping from client"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

# ============ BBM FEATURE SOCKET.IO HANDLERS ============

@socketio.on('status_change')
def handle_status_change(data):
    """BBM Feature: Broadcast status change (available/away/busy) to all contacts"""
    try:
        user_id = data.get('user_id')
        status_state = data.get('status_state')  # 'available', 'away', 'busy'
        status_message = data.get('status_message', '')
        
        if not user_id or not status_state:
            return
        
        # Update database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET status_state = ?, status_message = ?
                WHERE id = ?
            ''', (status_state, status_message, user_id))
            conn.commit()
        
        # Broadcast to all contacts of this user
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT contact_user_id FROM contacts 
                WHERE user_id = ? AND status = 'accepted'
            ''', (user_id,))
            contacts = cursor.fetchall()
            
            for contact_row in contacts:
                contact_id = contact_row[0]
                room = f"user:{contact_id}"
                socketio.emit('contact_status_changed', {
                    'user_id': user_id,
                    'status_state': status_state,
                    'status_message': status_message,
                    'timestamp': datetime.now().isoformat()
                }, room=room)
        
        print(f"🎨 User {user_id} status changed to {status_state}")
    except Exception as e:
        print(f"⚠️ status_change error: {e}")

@socketio.on('send_ping')
def handle_send_ping(data):
    """BBM Feature: Send tactile PING nudge to a contact (Socket.IO alternative)"""
    try:
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        ping_type = data.get('ping_type', 'standard')  # 'standard' or 'urgent'
        
        # Type conversion and validation
        try:
            sender_id = int(sender_id)
            receiver_id = int(receiver_id)
        except (ValueError, TypeError):
            print(f"⚠️ send_ping: Invalid ID types - sender_id={sender_id}, receiver_id={receiver_id}")
            return
        
        if not sender_id or not receiver_id:
            print(f"⚠️ send_ping: Missing IDs - sender_id={sender_id}, receiver_id={receiver_id}")
            return
        
        # Get sender details
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT zeus_pin, full_name FROM users WHERE id = ?', (sender_id,))
            sender_row = cursor.fetchone()
            
            if not sender_row:
                print(f"⚠️ send_ping: Sender {sender_id} not found")
                return
            
            sender_pin = sender_row[0]
            sender_name = sender_row[1]
            
            # Verify they are contacts
            cursor.execute('''
                SELECT id FROM contacts 
                WHERE user_id = ? AND contact_user_id = ? AND status = 'accepted'
            ''', (sender_id, receiver_id))
            
            if not cursor.fetchone():
                print(f"⚠️ send_ping: Not authorized - {sender_id} and {receiver_id} not contacts")
                return
        
        # Emit PING with vibration pattern (using ping_incoming to match frontend listener)
        room = f"user:{receiver_id}"
        vibration = [100, 50, 100] if ping_type == 'standard' else [200, 100, 200, 100, 200]
        
        socketio.emit('ping_incoming', {
            'sender_id': sender_id,
            'sender_pin': sender_pin,
            'sender_name': sender_name,
            'ping_type': ping_type,
            'vibration_pattern': vibration,
            'timestamp': datetime.now().isoformat()
        }, room=room)
        
        print(f"📳 PING sent from {sender_pin} ({sender_id}) to user:{receiver_id} ({ping_type})")
    except Exception as e:
        print(f"❌ send_ping error: {str(e)}")

@socketio.on('message_deleted')
def handle_message_deleted(data):
    """BBM Feature: Sync message deletion (Delete Everywhere) via Socket.IO"""
    try:
        message_id = data.get('message_id')
        receiver_id = data.get('receiver_id')
        
        if not message_id or not receiver_id:
            return
        
        # Emit deletion to receiver
        room = f"user:{receiver_id}"
        socketio.emit('message_removed', {
            'message_id': message_id,
            'timestamp': datetime.now().isoformat()
        }, room=room)
        
        print(f"🗑️ Message {message_id} deletion synced to user {receiver_id}")
    except Exception as e:
        print(f"⚠️ message_deleted error: {e}")

def emit_message_status(sender_id, message_id, status, delivered_at=None, viewed_at=None):
    """
    Emit message status update to sender via Socket.IO with fallback
    
    WhatsApp-style approach:
    1. Try immediate Socket.IO emit (real-time)
    2. Store in database immediately (for polling)
    3. Client will fetch updates via polling if Socket misses them
    """
    if not sender_id or not message_id:
        print(f"⚠️ emit_message_status: Missing sender_id or message_id")
        return
    
    payload = {
        'message_id': message_id,
        'status': status,
        'timestamp': datetime.now().isoformat()
    }
    if delivered_at:
        payload['delivered_at'] = delivered_at
    if viewed_at:
        payload['viewed_at'] = viewed_at
    
    room = f"user:{sender_id}"
    
    # ALWAYS emit via Socket.IO for real-time (best-effort)
    try:
        print(f"📤 [WebSocket] Emitting {status} for message {message_id} to room {room}")
        socketio.emit('message_status', payload, room=room, skip_sid=None)
        print(f"✅ [WebSocket] Status event sent")
    except Exception as e:
        print(f"⚠️ [WebSocket] Emit failed: {e}")
    
    # NOTE: Database already updated in calling function
    # Sender can also poll for updates every 2 seconds as fallback
    print(f"💾 [Fallback] Message {message_id} status in DB: {status}")

def emit_new_message(receiver_id, message_data):
    """
    Emit new message to receiver via Socket.IO for instant delivery
    WhatsApp/Telegram-style: No polling needed
    """
    if not receiver_id or not message_data:
        print(f"⚠️ emit_new_message: Missing receiver_id or message_data")
        return
    
    room = f"user:{receiver_id}"
    
    # Check if user is online
    is_online = receiver_id in connected_users
    
    print(f"📨 [NEW MESSAGE] Attempting to deliver message {message_data.get('id')} to user {receiver_id}")
    print(f"   - Target room: {room}")
    print(f"   - Receiver online: {is_online}")
    print(f"   - Connected users: {list(connected_users.keys())}")
    
    if is_online:
        try:
            print(f"📨 [WebSocket] Emitting new message {message_data.get('id')} to {room}")
            socketio.emit('new_message', message_data, room=room)
            print(f"✅ [WebSocket] New message delivered instantly to user {receiver_id}")
            return True
        except Exception as e:
            print(f"⚠️ [WebSocket] New message emit failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    else:
        print(f"📪 [Offline] User {receiver_id} offline, message queued")
        queue_offline_message(receiver_id, message_data)
        return False

def queue_offline_message(user_id, message_data):
    """Queue message for offline user - will be delivered on reconnection"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO message_queue (user_id, message_id, message_data, created_at)
                VALUES (?, ?, ?, datetime('now'))
            ''', (user_id, message_data.get('id'), str(message_data)))
        print(f"📮 Message {message_data.get('id')} queued for offline user {user_id}")
    except Exception as e:
        print(f"⚠️ queue_offline_message error: {e}")

def flush_message_queue(user_id):
    """Flush queued messages when user reconnects (WhatsApp-style)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT message_id, message_data FROM message_queue
                WHERE user_id = ?
                ORDER BY created_at ASC
            ''', (user_id,))
            queued = cursor.fetchall()
            
            if queued:
                print(f"📬 Flushing {len(queued)} queued messages for user {user_id}")
                room = f"user:{user_id}"
                for msg_id, msg_data in queued:
                    try:
                        import json
                        message_dict = eval(msg_data)  # Convert string back to dict
                        socketio.emit('new_message', message_dict, room=room)
                    except Exception as e:
                        print(f"⚠️ Error flushing message {msg_id}: {e}")
                
                # Clear queue
                cursor.execute('DELETE FROM message_queue WHERE user_id = ?', (user_id,))
                conn.commit()
                print(f"✅ Message queue flushed for user {user_id}")
    except Exception as e:
        print(f"⚠️ flush_message_queue error: {e}")

# ============ DATABASE CONNECTION MANAGEMENT ============

@contextmanager
def get_db_connection():
    """Context manager for database connections with proper cleanup and WAL mode"""
    conn = None
    try:
        # Enable WAL mode for better concurrency
        conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA busy_timeout=30000')
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except sqlite3.OperationalError as e:
        if conn:
            conn.rollback()
        print(f"❌ Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def retry_on_locked(max_retries=3, delay=0.5):
    """Retry database operation if locked"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    last_error = e
                    if "locked" in str(e).lower() and attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)  # Exponential backoff
                        print(f"⚠️  Database locked, retrying ({attempt + 1}/{max_retries}) after {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    raise
            if last_error:
                raise last_error
        return wrapper
    return decorator


RATE_LIMITS = {
    'start-signup': {'max_requests': 5, 'window_seconds': 3600},
    'verify-otp': {'max_requests': 10, 'window_seconds': 3600},
    'login': {'max_requests': 10, 'window_seconds': 1800},
    'api/register': {'max_requests': 3, 'window_seconds': 3600},
    'forgot-password': {'max_requests': 3, 'window_seconds': 3600},
    'process-message-queue': {'max_requests': 60, 'window_seconds': 60},
}


class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key, max_requests, window_seconds):
        now = time.time()
        with self.lock:
            request_times = [t for t in self.requests[key] if t > now - window_seconds]
            self.requests[key] = request_times

            if len(request_times) >= max_requests:
                oldest_request = request_times[0]
                retry_after = max(1, int(window_seconds - (now - oldest_request)))
                return False, retry_after

            self.requests[key].append(now)
            return True, 0


rate_limiter = RateLimiter()


def _rate_limit_extra_identity(endpoint_key):
    """Add endpoint-specific identifiers to reduce brute-force effectiveness."""
    data = request.get_json(silent=True) or {}

    if endpoint_key in ('start-signup', 'verify-otp', 'api/register', 'forgot-password'):
        email = (data.get('email') or '').strip().lower()
        return hashlib.sha256(email.encode()).hexdigest() if email else 'no-email'

    if endpoint_key == 'login':
        zeus_pin = (data.get('zeus_pin') or '').strip().upper()
        return hashlib.sha256(zeus_pin.encode()).hexdigest() if zeus_pin else 'no-pin'

    return 'none'


def rate_limit(endpoint_key):
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if request.method == 'OPTIONS':
                return func(*args, **kwargs)

            limit = RATE_LIMITS.get(endpoint_key)
            if not limit:
                return func(*args, **kwargs)

            forwarded_for = request.headers.get('X-Forwarded-For', '')
            client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else (request.remote_addr or 'unknown')
            user_id = session.get('admin_id') or session.get('user_id') or 'anonymous'
            extra_identity = _rate_limit_extra_identity(endpoint_key)
            key = f"{endpoint_key}:{client_ip}:{user_id}:{extra_identity}"

            allowed, retry_after = rate_limiter.is_allowed(
                key,
                limit['max_requests'],
                limit['window_seconds'],
            )

            if not allowed:
                return jsonify({
                    'error': 'Too many requests. Please try again later.',
                    'retry_after': retry_after,
                }), 429

            return func(*args, **kwargs)
        return decorated_function
    return decorator


CSRF_SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}
PUBLIC_CSRF_EXEMPT_PATHS = {
    '/api/csrf-token',
    '/api/start-signup',
    '/api/verify-otp',
    '/api/register',
    '/api/complete-registration',
    '/api/complete-registration-with-kyc',
    '/api/complete-kyc',
    '/api/login',
}


def generate_csrf_token(force_refresh=False):
    if force_refresh or 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def validate_csrf_token():
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not token and request.is_json:
        token = (request.get_json(silent=True) or {}).get('csrf_token')
    return bool(token) and token == session.get('csrf_token')


def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method not in CSRF_SAFE_METHODS and not validate_csrf_token():
            return jsonify({'error': 'CSRF token validation failed'}), 403
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def enforce_admin_csrf_protection():
    """Apply CSRF checks to admin API mutating requests."""
    if not request.path.startswith('/admin/api/'):
        return None

    if request.path == '/admin/api/login':
        return None

    if request.method in CSRF_SAFE_METHODS:
        return None

    if not validate_csrf_token():
        return jsonify({'error': 'CSRF token validation failed'}), 403

    return None


@app.before_request
def enforce_user_api_csrf_protection():
    """Apply CSRF checks to non-admin mutating API requests by default."""
    if not request.path.startswith('/api/'):
        return None

    if request.path.startswith('/admin/api/'):
        return None

    if request.method in CSRF_SAFE_METHODS:
        return None

    if request.path in PUBLIC_CSRF_EXEMPT_PATHS:
        return None

    if not validate_csrf_token():
        return jsonify({'error': 'CSRF token validation failed'}), 403

    return None


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)


@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()})


DEFAULT_ADMIN_PERMISSIONS = json.dumps({
    'can_approve_users': True,
    'can_ban_users': True,
    'can_approve_payments': True,
    'can_manage_admins': True,
    'can_view_logs': True,
})


def bootstrap_first_admin(cursor):
    """Create the initial super admin only from environment variables."""
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    admin_count = cursor.fetchone()[0]
    if admin_count > 0:
        return

    first_admin_username = os.environ.get('FIRST_ADMIN_USERNAME', '').strip()
    first_admin_password = os.environ.get('FIRST_ADMIN_PASSWORD', '')
    first_admin_email = os.environ.get('FIRST_ADMIN_EMAIL', '').strip().lower()

    if not (first_admin_username and first_admin_password and first_admin_email):
        print('⚠️ No admin users exist and FIRST_ADMIN_* environment variables are not fully set; skipping admin bootstrap')
        return

    cursor.execute(
        '''
        INSERT INTO admin_users (username, password_hash, email, role, permissions)
        VALUES (?, ?, ?, 'super_admin', ?)
        ''',
        (first_admin_username, hash_password(first_admin_password), first_admin_email, DEFAULT_ADMIN_PERMISSIONS),
    )
    print('✅ First admin created from environment variables')

# Database initialization
def init_db():
    """Initialize SQLite database with WAL mode"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                zeus_pin TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                profile_pic TEXT,
                about TEXT,
                avatar_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP
            )
        ''')
        
        # Add about and avatar_url columns if they don't exist (migration)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN about TEXT")
            print("✅ Added 'about' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
            print("✅ Added 'avatar_url' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # BBM Feature: Status Colors
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN status_state TEXT DEFAULT 'available'")
            print("✅ Added 'status_state' column to users table (BBM Status Colors)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN status_message TEXT")
            print("✅ Added 'status_message' column to users table (BBM Status Colors)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # BBM Feature: "Now Playing" Music Status
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN now_playing_track TEXT")
            print("✅ Added 'now_playing_track' column to users table (BBM Now Playing)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN now_playing_artist TEXT")
            print("✅ Added 'now_playing_artist' column to users table (BBM Now Playing)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN now_playing_updated_at TIMESTAMP")
            print("✅ Added 'now_playing_updated_at' column to users table (BBM Now Playing)")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Data Saver preferences
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN data_saver_mode INTEGER DEFAULT 0")
            print("✅ Added 'data_saver_mode' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN auto_download_images INTEGER DEFAULT 0")
            print("✅ Added 'auto_download_images' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN auto_download_videos INTEGER DEFAULT 0")
            print("✅ Added 'auto_download_videos' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN image_quality TEXT DEFAULT 'medium'")
            print("✅ Added 'image_quality' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'")
            print("✅ Added 'language' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN ghost_banned INTEGER DEFAULT 0")
            print("✅ Added 'ghost_banned' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN ghost_ban_reason TEXT")
            print("✅ Added 'ghost_ban_reason' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN ghost_ban_expires TIMESTAMP")
            print("✅ Added 'ghost_ban_expires' column to users table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
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
                status TEXT DEFAULT 'sent',
                delivered_at TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        
        # Add status and delivered_at columns if they don't exist (migration)
        try:
            cursor.execute("ALTER TABLE messages ADD COLUMN status TEXT DEFAULT 'sent'")
            print("✅ Added 'status' column to messages table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE messages ADD COLUMN delivered_at TIMESTAMP")
            print("✅ Added 'delivered_at' column to messages table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Add read_timer_started_at column if it doesn't exist (TTL timer fix)
        try:
            cursor.execute("ALTER TABLE messages ADD COLUMN read_timer_started_at TIMESTAMP")
            print("✅ Added 'read_timer_started_at' column to messages table (TTL fix)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # BBM Feature: PING and Delete Everywhere
        try:
            cursor.execute("ALTER TABLE messages ADD COLUMN is_ping INTEGER DEFAULT 0")
            print("✅ Added 'is_ping' column to messages table (BBM PING Feature)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE messages ADD COLUMN is_deleted INTEGER DEFAULT 0")
            print("✅ Added 'is_deleted' column to messages table (BBM Delete Everywhere)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # BBM Feature: High-Priority PING Delivery
        try:
            cursor.execute("ALTER TABLE messages ADD COLUMN is_high_priority INTEGER DEFAULT 0")
            print("✅ Added 'is_high_priority' column to messages table (High-Priority PING)")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Privacy/Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                last_seen_visibility TEXT DEFAULT 'myContacts',
                profile_photo_visibility TEXT DEFAULT 'myContacts',
                about_visibility TEXT DEFAULT 'myContacts',
                status_visibility TEXT DEFAULT 'myContacts',
                groups_visibility TEXT DEFAULT 'everyone',
                pin_to_view_enabled INTEGER DEFAULT 0,
                auto_delete_ttl INTEGER DEFAULT 0,
                notification_type TEXT DEFAULT 'both',
                show_online_status INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Message Queue table (WhatsApp/Telegram-style offline message queue)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message_id INTEGER,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                ttl_seconds INTEGER DEFAULT 3600,
                
                queue_status TEXT DEFAULT 'pending',
                send_attempts INTEGER DEFAULT 0,
                last_attempt_at TIMESTAMP,
                next_retry_at TIMESTAMP,
                backoff_multiplier REAL DEFAULT 1.0,
                
                message_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id),
                FOREIGN KEY (message_id) REFERENCES messages(id)
            )
        ''')
        
        # Low-bandwidth metrics table for monitoring
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                packet_size INTEGER,
                compressed_size INTEGER,
                delivery_time_ms INTEGER,
                network_quality TEXT,
                retry_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (message_id) REFERENCES messages(id)
            )
        ''')
        
        # BBM Feature: "Updates" Feed (Activity Log)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_feed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                activity_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # BBM Feature: Groups
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_name TEXT NOT NULL,
                group_avatar TEXT,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')
        
        # BBM Feature: Group Members
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # BBM Feature: Group To-Do Lists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                task_title TEXT NOT NULL,
                task_description TEXT,
                is_completed INTEGER DEFAULT 0,
                assigned_to INTEGER,
                created_by INTEGER NOT NULL,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id),
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (assigned_to) REFERENCES users(id)
            )
        ''')
        
        # BBM Feature: Group Calendar Events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_calendar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                event_title TEXT NOT NULL,
                event_description TEXT,
                event_location TEXT,
                event_start TIMESTAMP NOT NULL,
                event_end TIMESTAMP,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id),
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')

        # Admin control room tables (non-breaking additive migration)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                reviewed_by INTEGER,
                reviewed_at TIMESTAMP,
                rejection_reason TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'moderator',
                permissions TEXT,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                admin_id INTEGER,
                message TEXT NOT NULL,
                is_from_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (admin_id) REFERENCES admin_users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS one_off_payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                payment_type TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'ZAR',
                payfast_payment_id TEXT,
                payfast_token TEXT,
                status TEXT NOT NULL DEFAULT 'pending_approval',
                approved_by INTEGER,
                approved_at TIMESTAMP,
                rejection_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (approved_by) REFERENCES admin_users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_unlocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                feature_name TEXT NOT NULL,
                unlock_type TEXT NOT NULL,
                payment_id INTEGER,
                expires_at TIMESTAMP,
                granted_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (payment_id) REFERENCES one_off_payments(id),
                FOREIGN KEY (granted_by) REFERENCES admin_users(id),
                UNIQUE(user_id, feature_name)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT NOT NULL,
                target_user_id INTEGER,
                target_payment_id INTEGER,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admin_users(id)
            )
        ''')

        bootstrap_first_admin(cursor)

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_approvals_status ON user_approvals(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_approvals_user_id ON user_approvals(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_messages_user_id ON admin_messages(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_one_off_payments_status ON one_off_payments(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_unlocks_user_id ON user_unlocks(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log(created_at)')

        cursor.execute('''
            INSERT OR IGNORE INTO user_approvals (user_id, status, reviewed_at)
            SELECT id, 'approved', CURRENT_TIMESTAMP FROM users
        ''')
        
        print("✅ Privacy settings table initialized")
        print("✅ Message queue table initialized (offline delivery system)")
        print("✅ Network metrics table initialized (low-bandwidth monitoring)")
        print("✅ Activity feed table initialized (BBM Updates)")
        print("✅ Groups tables initialized (BBM Group Workspaces)")
    
    print("✅ Database initialized with WAL mode enabled")

# Initialize DB on startup
init_db()


def run_migrations():
    """Run pending SQL migrations in version order."""
    migration_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'migrations')
    migrations = [
        (1, '001_initial_schema.sql'),
        (2, '002_ghost_market_tables.sql'),
        (3, '003_add_indexes.sql'),
        (4, '004_ghost_forums.sql'),
        (5, '005_ghost_ultimate.sql'),
    ]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('SELECT version FROM schema_migrations ORDER BY version')
        applied_versions = {row['version'] for row in cursor.fetchall()}

        for version, filename in migrations:
            if version in applied_versions:
                continue

            path = os.path.join(migration_dir, filename)
            if not os.path.exists(path):
                print(f"⚠️ Migration file missing, skipping version {version}: {filename}")
                continue

            print(f"🔄 Applying migration {version}: {filename}")
            with open(path, 'r') as f:
                sql = f.read()

            cursor.executescript(sql)
            cursor.execute(
                'INSERT INTO schema_migrations (version, name) VALUES (?, ?)',
                (version, filename),
            )
            conn.commit()
            print(f"✅ Migration {version} applied")

def run_admin_migrations():
    """Auto-create admin tables on app startup (for free tier deployment)."""
    # First run versioned migrations; keep inline creation below for compatibility.
    run_migrations()

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if admin_users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_users'")
        admin_users_exists = bool(cursor.fetchone())
        if admin_users_exists:
            print("✅ Admin tables already exist - ensuring latest schema...")
        else:
            print("🔄 Running admin migrations...")

        # Data saver columns on users table
        for ddl in [
            "ALTER TABLE users ADD COLUMN data_saver_mode INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN auto_download_images INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN auto_download_videos INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN image_quality TEXT DEFAULT 'medium'",
            "ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'",
            "ALTER TABLE users ADD COLUMN ghost_banned INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN ghost_ban_reason TEXT",
            "ALTER TABLE users ADD COLUMN ghost_ban_expires TIMESTAMP",
        ]:
            try:
                cursor.execute(ddl)
            except sqlite3.OperationalError:
                pass

        # Create user_approvals table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP,
            rejection_reason TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        # Create admin_users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'moderator',
            permissions TEXT,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create admin_messages table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            admin_id INTEGER,
            message TEXT NOT NULL,
            is_from_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (admin_id) REFERENCES admin_users(id)
        )
        ''')

        # Create one_off_payments table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS one_off_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            payment_type TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'ZAR',
            payfast_payment_id TEXT,
            payfast_token TEXT,
            status TEXT NOT NULL DEFAULT 'pending_approval',
            approved_by INTEGER,
            approved_at TIMESTAMP,
            rejection_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES admin_users(id)
        )
        ''')

        # Create user_unlocks table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_unlocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            feature_name TEXT NOT NULL,
            unlock_type TEXT NOT NULL,
            payment_id INTEGER,
            expires_at TIMESTAMP,
            granted_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (payment_id) REFERENCES one_off_payments(id),
            FOREIGN KEY (granted_by) REFERENCES admin_users(id),
            UNIQUE(user_id, feature_name)
        )
        ''')

        # Create admin_audit_log table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT NOT NULL,
            target_user_id INTEGER,
            target_payment_id INTEGER,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admin_users(id)
        )
        ''')

        # Create kyc_documents table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS kyc_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            id_document_path TEXT NOT NULL,
            selfie_path TEXT NOT NULL,
            document_type TEXT NOT NULL,
            face_match_score REAL,
            auto_verified INTEGER DEFAULT 0,
            admin_review_status TEXT DEFAULT 'pending',
            admin_review_notes TEXT,
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (reviewed_by) REFERENCES admin_users(id)
        )
        ''')

        # Create profile_picture_locks table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS profile_picture_locks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            is_locked INTEGER DEFAULT 1,
            remaining_changes INTEGER DEFAULT 0,
            subscription_tier TEXT DEFAULT 'free',
            last_change_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        # Create profile_pic_payments table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS profile_pic_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            payment_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending_approval',
            approved_by INTEGER,
            approved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (payment_id) REFERENCES one_off_payments(id),
            FOREIGN KEY (approved_by) REFERENCES admin_users(id)
        )
        ''')

        # Create subscriptions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            tier TEXT NOT NULL DEFAULT 'free',
            status TEXT NOT NULL DEFAULT 'active',
            payfast_subscription_id TEXT,
            current_period_start TIMESTAMP,
            current_period_end TIMESTAMP,
            cancelled_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        # Create subscription payment history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscription_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subscription_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'ZAR',
            payfast_payment_id TEXT,
            payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'success',
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
        )
        ''')

        # Create feature mapping table for subscription tiers
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscription_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tier TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            UNIQUE(tier, feature_name)
        )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_approvals_status ON user_approvals(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_approvals_user_id ON user_approvals(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_messages_user_id ON admin_messages(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_one_off_payments_status ON one_off_payments(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_unlocks_user_id ON user_unlocks(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_kyc_documents_review_status ON kyc_documents(admin_review_status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_profile_pic_payments_status ON profile_pic_payments(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_profile_picture_locks_user_id ON profile_picture_locks(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_subscription_payments_subscription_id ON subscription_payments(subscription_id)')

        # User feedback table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            feedback_type TEXT NOT NULL,
            message TEXT NOT NULL,
            contact_email TEXT,
            status TEXT DEFAULT 'pending',
            admin_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_feedback_status ON user_feedback(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_feedback_user_id ON user_feedback(user_id)')

        # Message queue indexes (faster queue processing)
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_message_queue_status ON message_queue(queue_status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_message_queue_next_retry ON message_queue(next_retry_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_message_queue_user_id ON message_queue(user_id)')

        # Messages indexes (schema uses sender_id/receiver_id/created_at/viewed_at)
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_id, receiver_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp_desc ON messages(created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_is_read ON messages(viewed_at)')

        # Contacts and contact request lookup indexes (requests are stored in contacts)
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contacts_user_contact ON contacts(user_id, contact_user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contact_requests_receiver_pending ON contacts(contact_user_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contact_requests_sender ON contacts(user_id)')

        # Users and subscriptions indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_zeus_pin ON users(zeus_pin)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_subscriptions_user_tier ON subscriptions(user_id, tier)')

        bootstrap_first_admin(cursor)

        # Migrate existing users to approved status
        cursor.execute('''
        INSERT OR IGNORE INTO user_approvals (user_id, status, reviewed_at)
        SELECT id, 'approved', CURRENT_TIMESTAMP FROM users
        ''')

        # Existing users remain unlocked for profile picture changes
        cursor.execute('''
        INSERT OR IGNORE INTO profile_picture_locks (user_id, is_locked, subscription_tier)
        SELECT id, 0, 'free' FROM users
        ''')

        # Default feature mappings: free tier
        cursor.executemany(
            '''
            INSERT OR IGNORE INTO subscription_features (tier, feature_name, is_enabled)
            VALUES (?, ?, ?)
            ''',
            [
                ('free', 'messaging', 1),
                ('free', 'basic_ttl_1hour', 1),
                ('free', 'pin_to_view', 1),
                ('free', 'blocking', 1),
                ('free', 'delete_everywhere', 1),
                ('free', 'profile_name_bio', 1),
            ],
        )

        # Default feature mappings: pro tier
        cursor.executemany(
            '''
            INSERT OR IGNORE INTO subscription_features (tier, feature_name, is_enabled)
            VALUES (?, ?, ?)
            ''',
            [
                ('pro', 'custom_ttl', 1),
                ('pro', 'profile_picture_unlimited', 1),
                ('pro', 'file_sharing', 1),
                ('pro', 'voice_notes', 1),
                ('pro', 'cloud_backup_10gb', 1),
                ('pro', 'export_chat_history', 1),
                ('pro', 'message_scheduling', 1),
                ('pro', 'priority_support', 1),
                ('pro', 'pin_retention_permanent', 1),
            ],
        )

        # Default feature mappings: teams tier
        cursor.executemany(
            '''
            INSERT OR IGNORE INTO subscription_features (tier, feature_name, is_enabled)
            VALUES (?, ?, ?)
            ''',
            [
                ('teams', 'group_workspaces', 1),
                ('teams', 'admin_dashboard', 1),
                ('teams', 'audit_logs', 1),
                ('teams', 'team_cloud_storage_100gb', 1),
                ('teams', 'sso_integration', 1),
            ],
        )

        # Create push subscriptions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL UNIQUE,
            keys_auth TEXT NOT NULL,
            keys_p256dh TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id)')

        # ============================================
        # GHOST MARKET TABLES
        # ============================================

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ghost_market_sellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            application_status TEXT DEFAULT 'pending',
            store_name TEXT,
            store_description TEXT,
            approved_by INTEGER,
            approved_at TIMESTAMP,
            rejection_reason TEXT,
            total_sales INTEGER DEFAULT 0,
            total_earnings REAL DEFAULT 0,
            rating REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES admin_users(id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ghost_market_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            currency TEXT DEFAULT 'ZAR',
            images TEXT,
            category TEXT,
            condition TEXT,
            status TEXT DEFAULT 'pending_approval',
            admin_notes TEXT,
            approved_by INTEGER,
            approved_at TIMESTAMP,
            rejection_reason TEXT,
            view_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES ghost_market_sellers(user_id),
            FOREIGN KEY (approved_by) REFERENCES admin_users(id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ghost_market_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending_payment',
            pudo_locker_location TEXT,
            pudo_pickup_code TEXT,
            buyer_pin_half TEXT,
            seller_pin_half TEXT,
            tracking_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            paid_at TIMESTAMP,
            shipped_at TIMESTAMP,
            delivered_at TIMESTAMP,
            completed_at TIMESTAMP,
            cancelled_at TIMESTAMP,
            FOREIGN KEY (item_id) REFERENCES ghost_market_items(id),
            FOREIGN KEY (buyer_id) REFERENCES users(id),
            FOREIGN KEY (seller_id) REFERENCES ghost_market_sellers(user_id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ghost_market_escrow (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'held',
            held_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            released_at TIMESTAMP,
            refunded_at TIMESTAMP,
            FOREIGN KEY (order_id) REFERENCES ghost_market_orders(id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ghost_market_disputes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            raised_by INTEGER NOT NULL,
            reason TEXT NOT NULL,
            evidence TEXT,
            status TEXT DEFAULT 'open',
            resolution TEXT,
            resolved_by INTEGER,
            resolved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (order_id) REFERENCES ghost_market_orders(id),
            FOREIGN KEY (raised_by) REFERENCES users(id),
            FOREIGN KEY (resolved_by) REFERENCES admin_users(id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ghost_market_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (item_id) REFERENCES ghost_market_items(id),
            FOREIGN KEY (buyer_id) REFERENCES users(id),
            FOREIGN KEY (seller_id) REFERENCES ghost_market_sellers(user_id),
            UNIQUE(item_id, buyer_id)
        )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmi_status ON ghost_market_items(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmi_category ON ghost_market_items(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmo_status ON ghost_market_orders(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmo_buyer ON ghost_market_orders(buyer_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmo_seller ON ghost_market_orders(seller_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmi_seller_status ON ghost_market_items(seller_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmi_approved ON ghost_market_items(status, created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmo_buyer_status ON ghost_market_orders(buyer_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_gmo_seller_status ON ghost_market_orders(seller_id, status)')

        conn.commit()
        print("✅ Admin migrations completed successfully!")

# Call the function
run_admin_migrations()

def optimize_database():
    """Add runtime indexes and tuning pragmas for faster messaging queries."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver_created ON messages(sender_id, receiver_id, created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver_created ON messages(receiver_id, created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_viewed_at ON messages(viewed_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contacts_user_contact_status ON contacts(user_id, contact_user_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_contacts_contact_user ON contacts(contact_user_id, user_id)')

        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA synchronous=NORMAL')
        cursor.execute('PRAGMA cache_size=-20000')
        cursor.execute('PRAGMA temp_store=MEMORY')

    print('✅ Database optimization complete - indexes added, WAL mode enabled')

optimize_database()

# Validate payment settings before exposing payment routes.
validate_payment_config()

# Register additive blueprints (no existing route removal)
app.register_blueprint(admin_bp)
app.register_blueprint(payment_bp)
print("✅ Admin and payment routes registered")

# Helper functions
def generate_zeus_pin():
    """Generate unique Zeus PIN in format ZT-XXXX-XXXX"""
    return f"ZT-{secrets.randbelow(9000) + 1000}-{secrets.randbelow(9000) + 1000}"

def hash_password(password):
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def is_legacy_sha256_hash(stored_hash):
    """Identify legacy unsalted SHA-256 hashes (64 lowercase hex chars)."""
    return bool(stored_hash and re.fullmatch(r'[a-f0-9]{64}', stored_hash))


def verify_password(password, stored_hash):
    """Verify a password against bcrypt or legacy SHA-256 hash formats."""
    if not stored_hash:
        return False

    if stored_hash.startswith('$2a$') or stored_hash.startswith('$2b$') or stored_hash.startswith('$2y$'):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except ValueError:
            return False

    if is_legacy_sha256_hash(stored_hash):
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash

    return False


def require_password_unlock(f):
    """Require an additional password unlock step for sensitive pages."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            if request.path.endswith('.html'):
                return redirect('/login')
            return jsonify({'error': 'Not authenticated', 'redirect': '/login'}), 401

        if not session.get('password_unlocked', False):
            session['intended_url'] = request.path
            if request.path.endswith('.html'):
                return redirect('/unlock')
            return jsonify({'error': 'Password unlock required', 'redirect': '/unlock'}), 401

        return f(*args, **kwargs)

    return decorated_function

def ensure_user_profile_columns(conn):
    """Ensure profile-related columns exist on users table."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = {row[1] for row in cursor.fetchall()}
    if 'about' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN about TEXT")
        conn.commit()
        print("✅ Added 'about' column to users table")
    if 'avatar_url' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
        conn.commit()
        print("✅ Added 'avatar_url' column to users table")

# ============ LOW-BANDWIDTH OPTIMIZATION: QUEUE & RETRY SYSTEM ============

def calculate_message_size(message_data):
    """Calculate message size in bytes"""
    return len(json.dumps(message_data).encode('utf-8'))

def compress_payload(data):
    """Compress JSON payload with gzip"""
    try:
        json_str = json.dumps(data)
        compressed = gzip.compress(json_str.encode('utf-8'), compresslevel=9)
        return base64.b64encode(compressed).decode('utf-8'), len(compressed)
    except Exception as e:
        print(f"⚠️ Compression error: {e}")
        return None, len(json.dumps(data).encode('utf-8'))


def compress_image(image_data, quality='medium'):
    """Compress image bytes using data saver quality profile."""
    quality_map = {
        'low': 30,
        'medium': 60,
        'high': 85,
    }
    selected_quality = quality if quality in quality_map else 'medium'

    try:
        img = Image.open(io.BytesIO(image_data))

        if img.mode in ('RGBA', 'LA', 'P'):
            rgb_img = Image.new('RGB', img.size, (255, 255, 255))
            alpha_mask = img.split()[-1] if img.mode in ('RGBA', 'LA') else None
            rgb_img.paste(img, mask=alpha_mask)
            img = rgb_img

        if selected_quality == 'low':
            img.thumbnail((480, 480))
        elif selected_quality == 'medium':
            img.thumbnail((800, 800))

        output = io.BytesIO()
        img.save(output, format='JPEG', quality=quality_map[selected_quality], optimize=True)
        return output.getvalue()
    except Exception as e:
        print(f"Image compression error: {e}")
        return image_data


def compress_base64_image_data_url(data_url, quality='medium'):
    """Compress base64 image data-url and return JPEG data-url."""
    if not isinstance(data_url, str) or not data_url.startswith('data:image') or ',' not in data_url:
        return data_url

    try:
        encoded = data_url.split(',', 1)[1]
        raw = base64.b64decode(encoded)
        compressed = compress_image(raw, quality=quality)
        return 'data:image/jpeg;base64,' + base64.b64encode(compressed).decode('utf-8')
    except Exception as e:
        print(f"Base64 image compression error: {e}")
        return data_url


def get_data_saver_preferences(user_id):
    """Fetch user-level data saver preferences from users table."""
    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT data_saver_mode, auto_download_images, auto_download_videos, image_quality
            FROM users
            WHERE id = ?
            ''',
            (user_id,),
        )
        row = cursor.fetchone()

    if not row:
        return {
            'data_saver_mode': False,
            'auto_download_images': False,
            'auto_download_videos': False,
            'image_quality': 'medium',
        }

    image_quality = row['image_quality'] if row['image_quality'] in ('low', 'medium', 'high') else 'medium'
    return {
        'data_saver_mode': bool(row['data_saver_mode']),
        'auto_download_images': bool(row['auto_download_images']),
        'auto_download_videos': bool(row['auto_download_videos']),
        'image_quality': image_quality,
    }

def queue_message_for_retry(user_id, receiver_id, content, ttl_seconds=3600):
    """Queue message in database for retry with exponential backoff"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Insert into message_queue
            cursor.execute('''
                INSERT INTO message_queue (user_id, receiver_id, content, ttl_seconds, queue_status, next_retry_at)
                VALUES (?, ?, ?, ?, 'pending', datetime('now'))
            ''', (user_id, receiver_id, content, ttl_seconds))
            
            queue_id = cursor.lastrowid
            print(f"📬 Message queued for retry: queue_id={queue_id}, user={user_id} → {receiver_id}")
            return queue_id
    except Exception as e:
        print(f"❌ Queue message error: {e}")
        return None

def calculate_next_retry_time(attempt_number):
    """Calculate next retry time using exponential backoff"""
    base_delay = LOW_BANDWIDTH_CONFIG["retry_base_delay"]
    max_delay = LOW_BANDWIDTH_CONFIG["retry_max_delay"]
    
    # Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s...
    delay = min(base_delay * (2 ** (attempt_number - 1)), max_delay)
    
    return delay

def process_message_queue():
    """Process queued messages with exponential backoff retries"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find messages ready to retry
            cursor.execute('''
                SELECT id, user_id, receiver_id, content, ttl_seconds, send_attempts
                FROM message_queue
                WHERE queue_status = 'pending' 
                AND (next_retry_at IS NULL OR next_retry_at <= datetime('now'))
                AND send_attempts < ?
                ORDER BY created_at ASC
                LIMIT 50
            ''', (LOW_BANDWIDTH_CONFIG["retry_max_attempts"],))
            
            queued_messages = cursor.fetchall()
            
            if queued_messages:
                print(f"⏳ Processing {len(queued_messages)} queued messages for retry...")
            
            successful = 0
            failed = 0
            
            for queue_id, user_id, receiver_id, content, ttl_seconds, attempt in queued_messages:
                try:
                    # Get sender and receiver details
                    cursor.execute('SELECT zeus_pin, full_name FROM users WHERE id = ?', (user_id,))
                    sender_row = cursor.fetchone()
                    if not sender_row:
                        continue
                    
                    sender_pin, sender_name = sender_row
                    
                    # Try to send message via normal flow
                    cursor.execute('''
                        INSERT INTO messages (sender_id, receiver_id, content, file_url, ttl_seconds, status)
                        VALUES (?, ?, ?, '', ?, 'sent')
                    ''', (user_id, receiver_id, content, ttl_seconds))
                    
                    message_id = cursor.lastrowid
                    
                    # Prepare message data
                    message_data = {
                        'id': message_id,
                        'sender_id': user_id,
                        'receiver_id': receiver_id,
                        'content': content,
                        'file_url': '',
                        'ttl_seconds': ttl_seconds,
                        'created_at': datetime.now().isoformat(),
                        'viewed_at': None,
                        'status': 'sent',
                        'delivered_at': None,
                        'sender_pin': sender_pin,
                        'sender_name': sender_name,
                        'is_unread': True
                    }
                    
                    # Try to emit via Socket.IO
                    emit_new_message(receiver_id, message_data)
                    
                    # Mark as sent in queue
                    cursor.execute('''
                        UPDATE message_queue SET queue_status = 'sent', message_id = ? WHERE id = ?
                    ''', (message_id, queue_id))
                    
                    successful += 1
                    print(f"✅ Queued message {queue_id} successfully sent (attempt {attempt + 1})")
                    
                except Exception as e:
                    # Update retry count and calculate next retry time
                    next_attempt = attempt + 1
                    next_delay = calculate_next_retry_time(next_attempt)
                    
                    cursor.execute('''
                        UPDATE message_queue 
                        SET send_attempts = ?, 
                            last_attempt_at = datetime('now'),
                            next_retry_at = datetime('now', ? || ' seconds')
                        WHERE id = ?
                    ''', (next_attempt, next_delay, queue_id))
                    
                    failed += 1
                    print(f"⚠️ Queued message {queue_id} failed (attempt {next_attempt}), retrying in {next_delay}s")
            
            conn.commit()
            
            if successful > 0 or failed > 0:
                print(f"📊 Queue processing: {successful} successful, {failed} will retry")
            
            return successful, failed
    except Exception as e:
        print(f"❌ process_message_queue error: {e}")
        return 0, 0

def get_network_quality():
    """Detect and return current network quality estimate"""
    # This would be called from frontend to determine send strategy
    return {
        "quality": "unknown",
        "recommended_strategy": "normal",
        "should_queue": False,
        "compression_level": 9
    }

# ============ API ENDPOINTS ============

@app.route('/api/start-signup', methods=['POST', 'OPTIONS'])
@rate_limit('start-signup')
@retry_on_locked(max_retries=3, delay=0.5)
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
        
        # Check if user already exists using context manager
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return jsonify({'error': 'Email already registered'}), 409
        
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
@rate_limit('verify-otp')
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

@app.route('/api/register', methods=['POST', 'OPTIONS'])
@app.route('/api/complete-registration', methods=['POST', 'OPTIONS'])
@rate_limit('api/register')
@retry_on_locked(max_retries=3, delay=0.5)
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
        
        password_hash = hash_password(password)
        
        # Clear any existing session before registration
        session.clear()
        
        # Use context manager for database connection
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (email, zeus_pin, password_hash, full_name, profile_pic)
                VALUES (?, ?, ?, ?, ?)
            ''', (email, zeus_pin, password_hash, full_name, profile_pic))
            user_id = cursor.lastrowid

        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO user_approvals (user_id, status)
                VALUES (?, 'pending')
            ''', (user_id,))
            conn.commit()
        
        # Set session for newly registered user - automatically logs them in
        session['user_id'] = user_id
        session['zeus_pin'] = zeus_pin
        
        print(f"✅ User registered: {email} (ID: {user_id}, PIN: {zeus_pin})")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful. Account pending admin approval.',
            'redirect': '/pending-approval',
            'user_id': user_id,
            'approved': False
        }), 201
        
    except sqlite3.IntegrityError as e:
        print(f"❌ Integrity error: {str(e)}")
        return jsonify({'error': 'Email or PIN already exists'}), 409
    except Exception as e:
        print(f"❌ complete-registration error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/complete-registration-with-kyc', methods=['POST'])
@rate_limit('api/register')
@retry_on_locked(max_retries=3, delay=0.5)
def complete_registration_with_kyc():
    """Handle registration with KYC document upload and face-match metadata."""
    try:
        full_name = (request.form.get('full_name') or '').strip()
        email = (request.form.get('email') or '').lower().strip()
        zeus_pin = (request.form.get('zeus_pin') or '').strip()
        password = request.form.get('password') or ''
        profile_pic = request.form.get('profile_pic', '')
        face_match_score = request.form.get('face_match_score')
        auto_verified = request.form.get('auto_verified', '0')
        document_type = (request.form.get('document_type') or 'national_id').strip().lower()

        id_document = request.files.get('id_document')
        selfie = request.files.get('selfie')

        if not all([full_name, email, zeus_pin, password, id_document, selfie]):
            return jsonify({'error': 'All fields and KYC documents are required'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if document_type not in ('passport', 'national_id'):
            document_type = 'national_id'

        password_hash = hash_password(password)

        with admin_get_db() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT id FROM users WHERE email = ? OR zeus_pin = ?', (email, zeus_pin))
            if cursor.fetchone():
                return jsonify({'error': 'Email or PIN already exists'}), 409

            cursor.execute(
                '''
                INSERT INTO users (email, zeus_pin, password_hash, full_name, profile_pic)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (email, zeus_pin, password_hash, full_name, profile_pic),
            )
            user_id = cursor.lastrowid

            os.makedirs('uploads/kyc', exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            id_ext = os.path.splitext(secure_filename(id_document.filename or 'id_document'))[1] or '.bin'
            id_filename = f'user_{user_id}_id_{timestamp}{id_ext}'
            id_path = os.path.join('uploads', 'kyc', id_filename)
            id_document.save(id_path)

            selfie_ext = os.path.splitext(secure_filename(selfie.filename or 'selfie.jpg'))[1] or '.jpg'
            selfie_filename = f'user_{user_id}_selfie_{timestamp}{selfie_ext}'
            selfie_path = os.path.join('uploads', 'kyc', selfie_filename)
            selfie.save(selfie_path)

            parsed_score = None
            if face_match_score not in (None, ''):
                try:
                    parsed_score = float(face_match_score)
                except (TypeError, ValueError):
                    parsed_score = None

            cursor.execute(
                '''
                INSERT INTO kyc_documents (
                    user_id, id_document_path, selfie_path, document_type,
                    face_match_score, auto_verified, admin_review_status
                )
                VALUES (?, ?, ?, ?, ?, ?, 'pending')
                ''',
                (user_id, id_path, selfie_path, document_type, parsed_score, 1 if str(auto_verified) == '1' else 0),
            )

            cursor.execute(
                '''
                INSERT OR IGNORE INTO user_approvals (user_id, status)
                VALUES (?, 'pending')
                ''',
                (user_id,),
            )

            cursor.execute(
                '''
                INSERT OR IGNORE INTO profile_picture_locks (user_id, is_locked, remaining_changes, subscription_tier)
                VALUES (?, 1, 0, 'free')
                ''',
                (user_id,),
            )

            welcome_message = (
                "Welcome to ZeusChat!\n\n"
                "Your registration is pending admin approval while we review your KYC documents.\n"
                "We will notify you as soon as your account is approved."
            )
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, (SELECT id FROM admin_users WHERE role = 'super_admin' LIMIT 1))
                ''',
                (user_id, welcome_message),
            )

            conn.commit()

        session.clear()
        session['user_id'] = user_id
        session['zeus_pin'] = zeus_pin
        session['user_email'] = email
        session['user_full_name'] = full_name

        log_admin_action(
            None,
            'user_registered_with_kyc',
            target_user_id=user_id,
            details={
                'document_type': document_type,
                'face_match_score': face_match_score,
                'auto_verified': str(auto_verified) == '1',
            },
            ip_address=request.remote_addr,
        )

        return jsonify(
            {
                'success': True,
                'message': 'Registration successful. Account pending admin approval.',
                'redirect': '/pending-approval',
                'user_id': user_id,
                'approved': False,
            }
        ), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email or PIN already exists'}), 409
    except Exception as e:
        print(f"❌ complete-registration-with-kyc error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/complete-kyc', methods=['POST'])
@retry_on_locked(max_retries=3, delay=0.5)
def complete_kyc():
    """Handle KYC submission after profile creation."""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Not authenticated'}), 401

        zeus_pin = (request.form.get('zeus_pin') or '').strip()
        session_pin = (session.get('zeus_pin') or '').strip()
        if not zeus_pin or zeus_pin != session_pin:
            return jsonify({'error': 'Invalid PIN context'}), 400

        face_match_score = request.form.get('face_match_score')
        auto_verified = request.form.get('auto_verified', '0')
        document_type = (request.form.get('document_type') or 'national_id').strip().lower()
        if document_type not in ('passport', 'national_id'):
            document_type = 'national_id'

        id_document = request.files.get('id_document')
        selfie = request.files.get('selfie')
        if not id_document or not selfie:
            return jsonify({'error': 'Documents required'}), 400

        os.makedirs('uploads/kyc', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        id_ext = os.path.splitext(secure_filename(id_document.filename or 'id_document'))[1] or '.bin'
        id_filename = f'user_{user_id}_id_{timestamp}{id_ext}'
        id_path = os.path.join('uploads', 'kyc', id_filename)
        id_document.save(id_path)

        selfie_ext = os.path.splitext(secure_filename(selfie.filename or 'selfie.jpg'))[1] or '.jpg'
        selfie_filename = f'user_{user_id}_selfie_{timestamp}{selfie_ext}'
        selfie_path = os.path.join('uploads', 'kyc', selfie_filename)
        selfie.save(selfie_path)

        parsed_score = None
        if face_match_score not in (None, ''):
            try:
                parsed_score = float(face_match_score)
            except (TypeError, ValueError):
                parsed_score = None

        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM kyc_documents WHERE user_id = ?', (user_id,))
            if cursor.fetchone():
                cursor.execute(
                    '''
                    UPDATE kyc_documents
                    SET id_document_path = ?,
                        selfie_path = ?,
                        document_type = ?,
                        face_match_score = ?,
                        auto_verified = ?,
                        admin_review_status = 'pending',
                        admin_review_notes = NULL,
                        reviewed_by = NULL,
                        reviewed_at = NULL,
                        created_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                    ''',
                    (id_path, selfie_path, document_type, parsed_score, 1 if str(auto_verified) == '1' else 0, user_id),
                )
            else:
                cursor.execute(
                    '''
                    INSERT INTO kyc_documents (
                        user_id, id_document_path, selfie_path, document_type,
                        face_match_score, auto_verified, admin_review_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'pending')
                    ''',
                    (user_id, id_path, selfie_path, document_type, parsed_score, 1 if str(auto_verified) == '1' else 0),
                )

            cursor.execute(
                '''
                INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, notes)
                VALUES (?, 'pending', NULL, NULL, 'Awaiting KYC review')
                ON CONFLICT(user_id) DO UPDATE SET
                    status = 'pending',
                    reviewed_by = NULL,
                    reviewed_at = NULL,
                    notes = 'Awaiting KYC review'
                ''',
                (user_id,),
            )
            conn.commit()

        return jsonify({'success': True, 'message': 'KYC submitted for review'}), 200
    except Exception as e:
        print(f"❌ complete-kyc error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
@rate_limit('login')
@retry_on_locked(max_retries=3, delay=0.5)
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
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, email, full_name, profile_pic, password_hash FROM users
                WHERE zeus_pin = ?
            ''', (zeus_pin,))
            
            user = cursor.fetchone()

            if not user or not verify_password(password, user['password_hash']):
                return jsonify({'error': 'Invalid PIN or password'}), 401

            # Migrate legacy SHA-256 hashes to bcrypt after successful login.
            if is_legacy_sha256_hash(user['password_hash']):
                cursor.execute('''
                    UPDATE users
                    SET password_hash = ?
                    WHERE id = ?
                ''', (hash_password(password), user['id']))
                conn.commit()

        subscription_tier = get_user_subscription_tier(user[0])

        # Rotate CSRF token on successful authentication.
        generate_csrf_token(force_refresh=True)
        
        # Set session
        session['user_id'] = user[0]
        session['zeus_pin'] = zeus_pin
        session['full_name'] = user[2]
        session['email'] = user[1]
        session['user_email'] = user[1]
        session['user_full_name'] = user[2]
        session['subscription_tier'] = subscription_tier
        session['password_unlocked'] = False
        session.permanent = True

        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT status FROM user_approvals WHERE user_id = ?', (user[0],))
            approval = cursor.fetchone()
            approval_status = approval['status'] if approval else 'pending'
        
        print(f"✅ User logged in: {user[1]}")

        if approval_status != 'approved':
            session['is_approved'] = False
            return jsonify({
                'success': True,
                'message': 'Account pending approval',
                'redirect': '/pending-approval',
                'approved': False,
                'is_approved': False,
                'user_id': user[0],
                'subscription_tier': subscription_tier,
                'approval_status': approval_status,
                'pending_approval': True,
                'requires_password_unlock': True,
                'user': {
                    'id': user[0],
                    'email': user[1],
                    'full_name': user[2],
                    'profile_pic': user[3],
                    'zeus_pin': zeus_pin,
                    'subscription_tier': subscription_tier
                }
            }), 200
        
        session['is_approved'] = True
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': '/dashboard',
            'approved': True,
            'is_approved': True,
            'user_id': user[0],
            'subscription_tier': subscription_tier,
            'approval_status': approval_status,
            'pending_approval': False,
            'requires_password_unlock': True,
            'user': {
                'id': user[0],
                'email': user[1],
                'full_name': user[2],
                'profile_pic': user[3],
                'zeus_pin': zeus_pin,
                'subscription_tier': subscription_tier
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


@app.route('/unlock')
def unlock_page():
    """Password unlock page."""
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('password_unlocked'):
        return redirect(session.get('intended_url', '/chat.html'))
    return render_template('unlock.html')


@app.route('/api/check-unlock', methods=['GET'])
def check_unlock_status():
    """Return whether password unlock is required for current session."""
    if 'user_id' not in session:
        return jsonify({'requires_unlock': False, 'authenticated': False}), 200
    return jsonify({
        'requires_unlock': not session.get('password_unlocked', False),
        'authenticated': True,
    }), 200


@app.route('/api/unlock', methods=['POST'])
def unlock():
    """Verify password and unlock current session."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json() or {}
    password = (data.get('password') or '').strip()
    if not password:
        return jsonify({'error': 'Password required'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Incorrect password'}), 401

    session['password_unlocked'] = True
    session.permanent = True
    intended_url = session.pop('intended_url', '/chat.html')
    return jsonify({'success': True, 'redirect': intended_url}), 200


@app.route('/api/biometric/request', methods=['GET'])
def biometric_request():
    """Placeholder biometric challenge endpoint."""
    return jsonify({'error': 'Biometric authentication is not configured yet'}), 501


@app.route('/api/biometric/verify', methods=['POST'])
def biometric_verify():
    """Placeholder biometric verify endpoint."""
    return jsonify({'error': 'Biometric authentication is not configured yet'}), 501


@app.route('/chat.html')
@require_approved_user
@require_password_unlock
def chat_page():
    """Protected chat page route with unlock guard."""
    return send_from_directory('.', 'chat.html')


@app.route('/login')
def login_redirect():
    """Compatibility route for app redirects expecting /login."""
    return redirect('/login.html')


@app.route('/dashboard')
def dashboard_redirect():
    """Compatibility route for app redirects expecting /dashboard."""
    if 'user_id' not in session:
        return redirect('/login')
    return redirect('/chat.html')


@app.route('/pending-approval')
def pending_approval():
    """Show pending approval page for unapproved users"""
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT status FROM user_approvals WHERE user_id = ?', (user_id,))
        approval = cursor.fetchone()

        if approval and approval['status'] == 'approved':
            return redirect('/dashboard')

    return render_template('pending-approval.html')


@app.route('/kyc-upload')
def kyc_upload():
    """Show dedicated KYC upload page."""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('kyc-upload.html')


@app.route('/subscription')
def subscription_page():
    """Subscription management page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('subscription.html')


@app.route('/subscription/success')
def subscription_success():
    """PayFast subscription return success route"""
    return redirect('/subscription?status=success')


@app.route('/subscription/cancel')
def subscription_cancel():
    """PayFast subscription cancel route"""
    return redirect('/subscription?status=cancel')


@app.route('/api/user/subscription', methods=['GET'])
def get_user_subscription():
    """Get current user's subscription details"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT tier, status, current_period_start, current_period_end
            FROM subscriptions
            WHERE user_id = ?
            ''',
            (user_id,),
        )
        sub = cursor.fetchone()

    if not sub:
        return jsonify({'success': True, 'tier': 'free', 'status': 'active'}), 200

    return jsonify(
        {
            'success': True,
            'tier': sub['tier'],
            'status': sub['status'],
            'current_period_start': sub['current_period_start'],
            'current_period_end': sub['current_period_end'],
        }
    ), 200


@app.route('/api/user/subscription/cancel', methods=['POST'])
def cancel_subscription():
    """Cancel user's subscription"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE subscriptions
            SET status = 'cancelled', cancelled_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND status = 'active'
            ''',
            (user_id,),
        )
        conn.commit()

    return jsonify({'success': True, 'message': 'Subscription cancelled'}), 200


@app.route('/api/user/has-feature/<feature_name>', methods=['GET'])
def has_feature(feature_name):
    """Check if current user has access to a named feature."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    has_access = user_has_feature_access(user_id, feature_name)
    return jsonify({'success': True, 'feature': feature_name, 'has_access': bool(has_access)}), 200


# ============ PUSH NOTIFICATION ENDPOINTS ============

def send_push_notification(user_id, title, body, url='/'):
    """Send a push notification to all registered subscriptions for a user."""
    if not VAPID_PRIVATE_KEY:
        return  # Skip if VAPID not configured

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT endpoint, keys_auth, keys_p256dh FROM push_subscriptions WHERE user_id = ?',
            (user_id,)
        )
        subscriptions = cursor.fetchall()

    for sub in subscriptions:
        try:
            webpush(
                subscription_info={
                    'endpoint': sub['endpoint'],
                    'keys': {
                        'auth': sub['keys_auth'],
                        'p256dh': sub['keys_p256dh'],
                    }
                },
                data=json.dumps({'title': title, 'body': body, 'url': url}),
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims={'sub': VAPID_SUBJECT}
            )
            print(f"✅ Push sent to user {user_id}")
        except WebPushException as e:
            print(f"❌ Push failed for user {user_id}: {e}")
            # Remove subscription if server reports it as gone (HTTP 410)
            if hasattr(e, 'response') and e.response and e.response.status_code == 410:
                with admin_get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'DELETE FROM push_subscriptions WHERE endpoint = ?',
                        (sub['endpoint'],)
                    )
                    conn.commit()


@app.route('/api/push/subscribe', methods=['POST'])
@csrf_protect
@require_approved_user
def subscribe_push():
    """Save or update a push subscription for the current user."""
    user_id = session['user_id']
    data = request.get_json()

    endpoint = data.get('endpoint')
    keys_auth = data.get('keys', {}).get('auth')
    keys_p256dh = data.get('keys', {}).get('p256dh')

    if not all([endpoint, keys_auth, keys_p256dh]):
        return jsonify({'error': 'Invalid subscription data'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO push_subscriptions
                (user_id, endpoint, keys_auth, keys_p256dh, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, endpoint, keys_auth, keys_p256dh))
        conn.commit()

    return jsonify({'success': True}), 200


@app.route('/api/push/unsubscribe', methods=['POST'])
@csrf_protect
@require_approved_user
def unsubscribe_push():
    """Remove a push subscription for the current user."""
    user_id = session['user_id']
    data = request.get_json()
    endpoint = data.get('endpoint')

    if endpoint:
        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?',
                (user_id, endpoint)
            )
            conn.commit()

    return jsonify({'success': True}), 200


@app.route('/api/push/vapid-public-key', methods=['GET'])
def get_vapid_public_key():
    """Return the VAPID public key so the frontend can subscribe."""
    return jsonify({'publicKey': VAPID_PUBLIC_KEY}), 200


# ============ END PUSH NOTIFICATION ENDPOINTS ============

@app.route('/api/user/approval-status', methods=['GET'])
def get_approval_status():
    """Check current user's approval status"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT status, reviewed_at, rejection_reason
            FROM user_approvals WHERE user_id = ?
        ''', (user_id,))
        approval = cursor.fetchone()

        if not approval:
            status = 'pending'
            reviewed_at = None
            rejection_reason = None
        else:
            status = approval['status']
            reviewed_at = approval['reviewed_at']
            rejection_reason = approval['rejection_reason']

        return jsonify({
            'success': True,
            'status': status,
            'reviewed_at': reviewed_at,
            'rejection_reason': rejection_reason,
            'is_approved': status == 'approved'
        }), 200


@app.route('/api/user/admin-messages', methods=['GET', 'POST'])
def user_admin_messages():
    """User sends/receives messages to/from admin (works even for pending users)"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    if request.method == 'GET':
        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, message, is_from_admin, created_at, read_at
                FROM admin_messages
                WHERE user_id = ?
                ORDER BY created_at ASC
            ''', (user_id,))
            messages = cursor.fetchall()

            # Mark unread admin messages as read
            cursor.execute('''
                UPDATE admin_messages SET read_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND is_from_admin = 1 AND read_at IS NULL
            ''', (user_id,))
            conn.commit()

            return jsonify({
                'success': True,
                'messages': [
                    {
                        'id': m['id'],
                        'message': m['message'],
                        'is_from_admin': bool(m['is_from_admin']),
                        'created_at': m['created_at'],
                        'read_at': m['read_at']
                    }
                    for m in messages
                ]
            }), 200

    elif request.method == 'POST':
        data = request.get_json() or {}
        message = data.get('message', '').strip()

        if not message:
            return jsonify({'error': 'Message cannot be empty'}), 400

        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO admin_messages (user_id, message, is_from_admin)
                VALUES (?, ?, 0)
            ''', (user_id, message))
            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Message sent to admin'
            }), 201

@app.route('/api/delete-account', methods=['POST', 'OPTIONS'])
@csrf_protect
@retry_on_locked(max_retries=3, delay=0.5)
def delete_account():
    """Delete account and related data"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200

    try:
        data = request.get_json()
        zeus_pin = data.get('zeus_pin', '').strip()
        password = data.get('password', '').strip()

        if not zeus_pin or not password:
            return jsonify({'error': 'PIN and password required'}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, password_hash FROM users
                WHERE zeus_pin = ?
            ''', (zeus_pin,))

            user = cursor.fetchone()

            if not user or not verify_password(password, user['password_hash']):
                return jsonify({'error': 'Invalid credentials'}), 401

            user_id = user[0]

            cursor.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?',
                           (user_id, user_id))
            cursor.execute('''
                DELETE FROM contacts
                WHERE user_id = ? OR contact_user_id = ?
            ''', (user_id, user_id))
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

        print(f"✅ Account deleted: {zeus_pin}")

        return jsonify({
            'success': True,
            'message': 'Account deleted successfully'
        }), 200

    except Exception as e:
        print(f"❌ delete-account error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_user_profile():
    """Get current user profile"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, email, full_name, profile_pic, zeus_pin, created_at, about, avatar_url
            FROM users WHERE id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
    
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
            'created_at': user[5],
            'about': user[6],
            'avatar_url': user[7]
        }
    }), 200

@app.route('/api/user/update-profile', methods=['POST', 'OPTIONS'])
@csrf_protect
@retry_on_locked(max_retries=3, delay=0.5)
def update_profile():
    """Update user profile including bio/about field"""
    if request.method == 'OPTIONS':
        response = jsonify({'success': True})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response, 200
    
    try:
        data = request.get_json()
        print(f"📝 Update profile request received: {data}")
        
        if not data:
            print("❌ No JSON data provided")
            return jsonify({'error': 'No data provided'}), 400
        
        zeus_pin = data.get('zeus_pin', '').strip()
        full_name = data.get('full_name', '').strip()
        about = data.get('about', '').strip()
        avatar_url = data.get('avatar_url', '').strip()
        profile_pic = data.get('profile_pic', '')

        if profile_pic and profile_pic.startswith('data:image'):
            session_user_id = session.get('user_id')
            if session_user_id:
                saver_settings = get_data_saver_preferences(session_user_id)
                if saver_settings['data_saver_mode']:
                    profile_pic = compress_base64_image_data_url(profile_pic, saver_settings['image_quality'])
        
        print(f"📝 Parsed fields: PIN={zeus_pin}, Name={full_name}, About={about[:50] if about else 'EMPTY'}...")
        
        if not full_name:
            print(f"❌ Missing required field: full_name")
            return jsonify({'error': 'Full name required'}), 400
        
        print(f"✅ Validation passed. Attempting database update...")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Ensure columns exist
            print("🔧 Checking if profile columns exist...")
            ensure_user_profile_columns(conn)
            
            if not zeus_pin:
                user_id = session.get('user_id')
                print(f"🔍 No PIN provided, checking session for user_id: {user_id}")
                if not user_id:
                    print("❌ Missing zeus_pin and no session user_id")
                    return jsonify({'error': 'Zeus-PIN or session required'}), 401
                cursor.execute('SELECT zeus_pin FROM users WHERE id = ?', (user_id,))
                row = cursor.fetchone()
                if not row:
                    print(f"❌ User not found in database: ID={user_id}")
                    return jsonify({'error': 'User not found'}), 404
                zeus_pin = row[0]
                print(f"✅ Retrieved PIN from session: {zeus_pin}")
            
            # First check if user exists
            print(f"🔍 Checking if user exists with PIN: {zeus_pin}")
            cursor.execute('SELECT id, full_name, profile_pic FROM users WHERE zeus_pin = ?', (zeus_pin,))
            user_row = cursor.fetchone()
            
            if not user_row:
                print(f"❌ User not found with PIN: {zeus_pin}")
                return jsonify({'error': 'User not found'}), 404
            
            user_id = user_row[0]
            print(f"✅ User found: ID={user_id}, Current Name={user_row[1]}")

            current_profile_pic = user_row[2] or ''
            profile_pic_changed = bool(profile_pic) and profile_pic != current_profile_pic

            can_use_one_time_picture_change = False
            if profile_pic_changed:
                tier = get_user_subscription_tier(user_id)

                if tier == 'free':
                    cursor.execute(
                        '''
                        SELECT remaining_changes
                        FROM profile_picture_locks
                        WHERE user_id = ? AND is_locked = 0 AND remaining_changes > 0
                        ''',
                        (user_id,),
                    )
                    one_time = cursor.fetchone()

                    if not one_time:
                        return jsonify({
                            'error': 'Profile picture changes require Pro subscription or one-time payment',
                            'requires_upgrade': True,
                            'tier': 'free',
                            'payment_endpoint': '/api/user/request-profile-picture',
                        }), 403

                    can_use_one_time_picture_change = True
            
            # Update ALL fields including 'about' and 'avatar_url'
            print(f"📝 Executing UPDATE for user {user_id}...")
            cursor.execute('''
                UPDATE users 
                SET full_name = ?, 
                    about = ?,
                    profile_pic = ?,
                    avatar_url = ?
                WHERE id = ?
            ''', (full_name, about, profile_pic, avatar_url, user_id))
            
            rows_affected = cursor.rowcount
            print(f"✅ UPDATE executed: {rows_affected} row(s) affected")

            if profile_pic_changed:
                if can_use_one_time_picture_change:
                    cursor.execute(
                        '''
                        UPDATE profile_picture_locks
                        SET remaining_changes = remaining_changes - 1,
                            is_locked = CASE WHEN remaining_changes - 1 <= 0 THEN 1 ELSE 0 END,
                            last_change_at = CURRENT_TIMESTAMP
                        WHERE user_id = ?
                        ''',
                        (user_id,),
                    )
                else:
                    cursor.execute(
                        '''
                        UPDATE profile_picture_locks
                        SET is_locked = 0,
                            last_change_at = CURRENT_TIMESTAMP,
                            subscription_tier = ?
                        WHERE user_id = ?
                        ''',
                        (tier, user_id),
                    )
            
            conn.commit()
            print(f"✅ Database committed successfully")
            
            # Verify the update worked
            cursor.execute('SELECT full_name, about, avatar_url FROM users WHERE id = ?', (user_id,))
            updated_user = cursor.fetchone()
            
            if not updated_user:
                print(f"❌ Verification failed - user not found after update")
                return jsonify({'error': 'Update verification failed'}), 500
            
            print(f"✅ Verification successful - Name: {updated_user[0]}, About: {updated_user[1][:50] if updated_user[1] else 'EMPTY'}...")
        
        response = jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'updated_name': updated_user[0],
            'updated_about': updated_user[1],
            'updated_avatar': updated_user[2]
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response, 200
        
    except Exception as e:
        print(f"❌ update-profile error: {str(e)}")
        import traceback
        traceback.print_exc()
        response = jsonify({'error': f'Server error: {str(e)}'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response, 500


@app.route('/api/user/profile-picture', methods=['POST'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def update_profile_picture():
    """Update current user's profile picture with free-tier lock enforcement."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json(silent=True) or {}
    profile_pic = data.get('profile_pic', '')
    if not profile_pic:
        return jsonify({'error': 'profile_pic is required'}), 400

    saver_settings = get_data_saver_preferences(user_id)
    if saver_settings['data_saver_mode'] and profile_pic.startswith('data:image'):
        profile_pic = compress_base64_image_data_url(profile_pic, saver_settings['image_quality'])

    tier = get_user_subscription_tier(user_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        can_use_one_time_picture_change = False
        if tier == 'free':
            cursor.execute(
                '''
                SELECT remaining_changes
                FROM profile_picture_locks
                WHERE user_id = ? AND is_locked = 0 AND remaining_changes > 0
                ''',
                (user_id,),
            )
            one_time = cursor.fetchone()
            if not one_time:
                return jsonify({
                    'error': 'Profile picture changes require Pro subscription or one-time payment',
                    'requires_upgrade': True,
                    'tier': 'free'
                }), 403
            can_use_one_time_picture_change = True

        cursor.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (profile_pic, user_id))
        if cursor.rowcount == 0:
            return jsonify({'error': 'User not found'}), 404

        if can_use_one_time_picture_change:
            cursor.execute(
                '''
                UPDATE profile_picture_locks
                SET remaining_changes = remaining_changes - 1,
                    is_locked = CASE WHEN remaining_changes - 1 <= 0 THEN 1 ELSE 0 END,
                    last_change_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                ''',
                (user_id,),
            )
        else:
            cursor.execute(
                '''
                INSERT INTO profile_picture_locks (user_id, is_locked, remaining_changes, subscription_tier, last_change_at)
                VALUES (?, 0, 0, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    is_locked = 0,
                    subscription_tier = excluded.subscription_tier,
                    last_change_at = CURRENT_TIMESTAMP
                ''',
                (user_id, tier),
            )

    return jsonify({'success': True, 'message': 'Profile picture updated'}), 200

# ============ MESSAGING SYSTEM ENDPOINTS ============

@app.route('/api/send-message', methods=['POST', 'OPTIONS'])
@csrf_protect
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def send_message():
    """Send a message to a contact (requires accepted handshake)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        start_time = time.perf_counter()

        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        sender_id = session['user_id']
        receiver_zeus_pin = data.get('receiver_pin', '').strip()
        content = data.get('content', '').strip()
        ttl_seconds = data.get('ttl', 3600)  # Default 1 hour
        is_ping = data.get('is_ping', 0)  # BBM PING feature
        is_high_priority = data.get('is_high_priority', 0)  # High-priority delivery
        
        if not receiver_zeus_pin or not content:
            return jsonify({'error': 'Missing receiver_pin or content'}), 400
        
        # Use context manager for database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get sender details for message payload
            cursor.execute('SELECT zeus_pin, full_name FROM users WHERE id = ?', (sender_id,))
            sender_row = cursor.fetchone()
            if not sender_row:
                return jsonify({'error': 'Sender not found'}), 404
            sender_pin = sender_row[0]
            sender_name = sender_row[1]
            
            # Find receiver by Zeus PIN
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (receiver_zeus_pin,))
            receiver = cursor.fetchone()
            if not receiver:
                return jsonify({'error': 'Receiver not found'}), 404
            
            receiver_id = receiver[0]
            
            # Check contact handshake (CRITICAL: contacts must be accepted)
            cursor.execute('''
                SELECT status FROM contacts 
                WHERE user_id = ? AND contact_user_id = ? AND status = 'accepted'
            ''', (sender_id, receiver_id))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Contact not accepted. Cannot send message.'}), 403
            
            # Insert message
            cursor.execute('''
                INSERT INTO messages (sender_id, receiver_id, content, file_url, ttl_seconds, status, is_ping, is_high_priority)
                VALUES (?, ?, ?, ?, ?, 'sent', ?, ?)
            ''', (sender_id, receiver_id, content, '', ttl_seconds, is_ping, is_high_priority))
            
            message_id = cursor.lastrowid
            created_at = datetime.now().isoformat()
        
        print(f"✅ Message sent from user {sender_id} to {receiver_id}, message_id: {message_id}")
        
        # Prepare message data for Socket.IO (WhatsApp/Telegram-style instant delivery)
        message_data = {
            'id': message_id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'content': content,
            'file_url': '',
            'ttl_seconds': ttl_seconds,
            'created_at': created_at,
            'viewed_at': None,
            'status': 'sent',
            'delivered_at': None,
            'read_timer_started_at': None,
            'sender_pin': sender_pin,
            'sender_name': sender_name,
            'is_unread': True,
            'is_ping': is_ping,
            'is_high_priority': is_high_priority
        }
        
        # High-priority messages (PING) bypass standard queue
        if is_high_priority or is_ping:
            print(f"🚨 HIGH-PRIORITY message {message_id} - bypassing queue")
            # Emit with high priority flag to ensure immediate delivery
            socketio.emit('high_priority_message', message_data, room=f"user:{receiver_id}")
        else:
            # Emit new message to receiver via Socket.IO (instant delivery, no polling)
            emit_new_message(receiver_id, message_data)
        
        # Emit acknowledgment to sender (message sent confirmation)
        emit_message_status(sender_id, message_id, 'sent')

        # Send push notification if receiver is not connected via Socket.IO
        if receiver_id not in connected_users:
            message_preview = content[:100] if len(content) > 100 else content
            send_push_notification(
                receiver_id,
                f'New message from {sender_name}',
                message_preview,
                '/chat.html'
            )

        delivery_ms = (time.perf_counter() - start_time) * 1000
        print(f"⚡ Message delivered in {delivery_ms:.2f}ms (id={message_id})")
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'message': 'Message sent successfully',
            'status': 'sent'
        }), 200
        
    except Exception as e:
        print(f"❌ send_message error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-messages', methods=['GET'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def get_messages():
    """Get messages between current user and a specific contact (auto-delete expired)"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        contact_pin = request.args.get('contact_pin', '').strip()
        
        # Contact PIN is optional - if not provided, return all messages
        contact_id = None
        if contact_pin:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (contact_pin,))
                contact = cursor.fetchone()
                if contact:
                    contact_id = contact[0]
        
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Find messages that just expired for this receiver (to notify sender)
            cursor.execute('''
                SELECT id, sender_id
                FROM messages
                WHERE receiver_id = ?
                AND viewed_at IS NOT NULL
                AND read_timer_started_at IS NOT NULL
                AND datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
            ''', (user_id,))
            expired_rows = cursor.fetchall()

            # CRITICAL FIX: DELETE (not just mark) expired messages with TTL countdown
            cursor.execute('''
                DELETE FROM messages
                WHERE receiver_id = ?
                AND viewed_at IS NOT NULL
                AND read_timer_started_at IS NOT NULL
                AND datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
            ''', (user_id,))

            total_expired = cursor.rowcount
            if total_expired > 0:
                print(f"🗑️ TTL AUTO-DELETE: DELETED {total_expired} expired message(s) for user {user_id}")
                print(f"   - Messages deleted after their TTL timer ran out")
                print(f"📡 Notifying {len(expired_rows)} sender(s) about expired messages...")
                # Emit 'expired' status to all senders whose messages expired after being viewed
                for msg_id, sender_id in expired_rows:
                    emit_message_status(sender_id, msg_id, 'expired')
            
            # CRITICAL FIX: Get sender IDs BEFORE deleting 24h old unread messages
            # So we can notify senders that their messages failed to deliver
            cursor.execute('''
                SELECT id, sender_id
                FROM messages
                WHERE receiver_id = ?
                AND viewed_at IS NULL
                AND status NOT IN ('failed', 'expired', 'seen')
                AND created_at < datetime('now', '-1 days')
            ''', (user_id,))
            failed_messages = cursor.fetchall()
            
            # Also DELETE very old unread messages (>24h) as backup safety
            cursor.execute('''
                DELETE FROM messages
                WHERE receiver_id = ?
                AND viewed_at IS NULL
                AND status NOT IN ('failed', 'expired', 'seen')
                AND created_at < datetime('now', '-1 days')
            ''', (user_id,))
            
            backup_expired = cursor.rowcount
            if backup_expired > 0:
                print(f"🗑️ TTL AUTO-DELETE: DELETED {backup_expired} old unread message(s) (24h backup)")
                print(f"📡 Notifying {len(failed_messages)} sender(s) about failed delivery...")
                # Emit 'failed' status to all senders whose messages were never delivered
                for msg_id, sender_id in failed_messages:
                    emit_message_status(sender_id, msg_id, 'failed')
            
            total_expired += backup_expired

            # Find messages that are being delivered now (first fetch)
            # Only include messages that haven't expired yet
            cursor.execute('''
                SELECT id, sender_id
                FROM messages
                WHERE receiver_id = ?
                AND delivered_at IS NULL
                AND status IN ('sent', 'delivered')
                AND (read_timer_started_at IS NULL OR datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') > datetime('now'))
            ''', (user_id,))
            delivered_rows = cursor.fetchall()

            # Mark delivered for messages fetched by receiver
            cursor.execute('''
                UPDATE messages
                SET delivered_at = datetime('now'),
                    status = 'delivered'
                WHERE receiver_id = ?
                AND delivered_at IS NULL
                AND (read_timer_started_at IS NULL OR datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') > datetime('now'))
                AND status NOT IN ('failed', 'expired', 'seen')
            ''', (user_id,))
            
            # Get messages - filter by contact if specified
            if contact_id:
                # Get messages between user and specific contact (both directions)
                # BBM Feature: Exclude deleted messages (is_deleted=1)
                cursor.execute('''
                    SELECT m.id, m.sender_id, m.receiver_id, m.content, m.file_url,
                           m.ttl_seconds, m.created_at, m.viewed_at, m.status, m.delivered_at,
                           u.zeus_pin, u.full_name, m.read_timer_started_at
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE (
                        (m.receiver_id = ? AND m.sender_id = ?
                         AND m.status NOT IN ('expired', 'failed')
                         AND m.is_deleted = 0
                         AND (m.read_timer_started_at IS NULL OR datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds') > datetime('now')))
                        OR (m.sender_id = ? AND m.receiver_id = ? 
                            AND m.is_deleted = 0
                            AND m.status NOT IN ('expired', 'failed')
                            AND (m.read_timer_started_at IS NULL OR datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds') > datetime('now')))
                    )
                    ORDER BY m.created_at DESC
                ''', (user_id, contact_id, user_id, contact_id))
                print(f"📬 Getting messages between user {user_id} and contact {contact_id}")
            else:
                # Get all messages for user (no filter)
                # BBM Feature: Exclude deleted messages (is_deleted=1)
                cursor.execute('''
                    SELECT m.id, m.sender_id, m.receiver_id, m.content, m.file_url,
                           m.ttl_seconds, m.created_at, m.viewed_at, m.status, m.delivered_at,
                           u.zeus_pin, u.full_name, m.read_timer_started_at
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE m.receiver_id = ? 
                    AND m.status NOT IN ('expired', 'failed')
                    AND m.is_deleted = 0
                    AND (m.read_timer_started_at IS NULL OR datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds') > datetime('now'))
                    ORDER BY m.created_at DESC
                ''', (user_id,))
                print(f"📬 Getting all messages for user {user_id}")
            
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
                    'viewed_at': row[7],
                    'status': row[8],
                    'delivered_at': row[9],
                    'read_timer_started_at': row[12] if len(row) > 12 else None,
                    'sender_pin': row[10],  # Zeus PIN for badge matching
                    'sender_name': row[11],  # Full name for notifications
                    'is_unread': row[7] is None  # True if not yet read
                })
            
            print(f"✅ Retrieved {len(messages)} message(s) for user {user_id}")

        # Emit status updates AFTER DB commit  
        print(f"📡 Emitting {len(delivered_rows)} delivered status updates...")
        for message_id, sender_id in delivered_rows:
            emit_message_status(sender_id, message_id, 'delivered')

        print(f"📡 Emitting {len(expired_rows)} expired status updates...")
        for message_id, sender_id in expired_rows:
            emit_message_status(sender_id, message_id, 'expired')
        
        return jsonify({
            'success': True,
            'messages': messages,
            'count': len(messages)
        }), 200
        
    except Exception as e:
        print(f"❌ get_messages error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-unread-counts', methods=['GET'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def get_unread_counts():
    """Get unread message counts for all contacts"""
    try:
        user_pin = request.args.get('user_pin', '').strip()
        
        if not user_pin:
            return jsonify({'error': 'User PIN required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (user_pin,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            user_id = user[0]
            
            # Get unread counts for all contacts
            cursor.execute('''
                SELECT u.zeus_pin, COUNT(m.id) as unread_count
                FROM contacts c
                JOIN users u ON c.user_id = u.id
                LEFT JOIN messages m ON m.sender_id = u.id 
                    AND m.receiver_id = ? 
                    AND m.viewed_at IS NULL
                    AND m.status NOT IN ('failed', 'expired')
                    AND (m.read_timer_started_at IS NULL OR datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds') > datetime('now'))
                WHERE c.contact_user_id = ? AND c.status = 'accepted'
                GROUP BY u.zeus_pin
            ''', (user_id, user_id))
            
            contacts = cursor.fetchall()
            
            counts = {contact[0]: contact[1] for contact in contacts}
        
        return jsonify({
            'success': True,
            'counts': counts
        }), 200
        
    except Exception as e:
        print(f"❌ get-unread-counts error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mark-message-viewed', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def mark_message_viewed():
    """Mark specific messages as viewed by the user"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        message_ids = data.get('message_ids', [])
        
        if not message_ids:
            # Mark ALL unviewed messages as viewed for this user
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, sender_id
                    FROM messages
                    WHERE receiver_id = ? AND viewed_at IS NULL
                ''', (user_id,))
                seen_rows = cursor.fetchall()

                # CRITICAL FIX: ALWAYS set read_timer_started_at when marking viewed
                # This ensures TTL countdown starts when receiver opens the message
                cursor.execute('''
                    UPDATE messages 
                    SET viewed_at = datetime('now'),
                        delivered_at = COALESCE(delivered_at, datetime('now')),
                        read_timer_started_at = datetime('now'),
                        status = 'seen'
                    WHERE receiver_id = ? AND viewed_at IS NULL
                ''', (user_id,))
                count = cursor.rowcount
            
            print(f"✅ Marked {count} messages as viewed for user {user_id}")
            if count > 0:
                print(f"⏰ TTL TIMER STARTED: {count} message(s) will auto-delete after their TTL expires")
            print(f"📡 Emitting {len(seen_rows)} seen status updates...")
            viewed_at = datetime.now().isoformat()
            for message_id, sender_id in seen_rows:
                emit_message_status(sender_id, message_id, 'seen', viewed_at=viewed_at)

            return jsonify({
                'success': True,
                'marked_count': count
            }), 200
        else:
            # Mark specific messages as viewed
            with get_db_connection() as conn:
                cursor = conn.cursor()
                placeholders = ','.join('?' * len(message_ids))
                
                # Get TTL info BEFORE updating
                cursor.execute(f'''
                    SELECT ttl_seconds FROM messages WHERE id IN ({placeholders}) LIMIT 1
                ''', message_ids)
                ttl_row = cursor.fetchone()
                ttl_seconds = ttl_row[0] if ttl_row else None
                
                cursor.execute(f'''
                    SELECT id, sender_id
                    FROM messages
                    WHERE id IN ({placeholders}) AND receiver_id = ? AND viewed_at IS NULL
                ''', message_ids + [user_id])
                seen_rows = cursor.fetchall()

                cursor.execute(f'''
                    UPDATE messages 
                    SET viewed_at = datetime('now'),
                        delivered_at = COALESCE(delivered_at, datetime('now')),
                        read_timer_started_at = datetime('now'),
                        status = 'seen'
                    WHERE id IN ({placeholders}) AND receiver_id = ? AND viewed_at IS NULL
                ''', message_ids + [user_id])
                count = cursor.rowcount
            
            print(f"✅ Marked {count} specific messages as viewed for user {user_id}")
            if count > 0 and ttl_seconds:
                print(f"⏰ TTL TIMER STARTED: Messages will auto-delete in {ttl_seconds}s")
            
            print(f"📡 Emitting {len(seen_rows)} seen status updates...")
            viewed_at = datetime.now().isoformat()
            for message_id, sender_id in seen_rows:
                emit_message_status(sender_id, message_id, 'seen', viewed_at=viewed_at)

            return jsonify({
                'success': True,
                'marked_count': count
            }), 200
        
    except Exception as e:
        print(f"❌ mark-message-viewed error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-ttl-expiring', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_ttl_expiring():
    """Get unread messages expiring soon (TTL tracking before expiration)"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        # Get threshold from query param (minutes until expiration) - default 5 minutes
        expiration_threshold_seconds = int(request.args.get('threshold_seconds', 300))
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get unread messages that will expire within the threshold
            # Calculate expiration time and time remaining
            cursor.execute('''
                SELECT m.id, m.sender_id, m.receiver_id, m.content, m.file_url,
                       m.ttl_seconds, m.created_at, m.viewed_at, u.zeus_pin, u.full_name,
                       datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds') as expiration_time,
                       CAST((julianday(datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds')) 
                             - julianday('now')) * 86400 as INTEGER) as seconds_remaining
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.receiver_id = ? 
                AND m.viewed_at IS NOT NULL
                AND m.read_timer_started_at IS NOT NULL
                AND datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds') > datetime('now')
                AND CAST((julianday(datetime(m.read_timer_started_at, '+' || m.ttl_seconds || ' seconds')) 
                         - julianday('now')) * 86400 as INTEGER) <= ?
                ORDER BY expiration_time ASC
            ''', (user_id, expiration_threshold_seconds))
            
            expiring_messages = []
            for row in cursor.fetchall():
                seconds_remaining = row[11] if row[11] is not None else 0
                expiring_messages.append({
                    'id': row[0],
                    'sender_id': row[1],
                    'receiver_id': row[2],
                    'content': row[3],
                    'file_url': row[4],
                    'ttl_seconds': row[5],
                    'created_at': row[6],
                    'viewed_at': row[7],
                    'sender_pin': row[8],
                    'sender_name': row[9],
                    'expiration_time': row[10],
                    'seconds_remaining': max(0, seconds_remaining),  # Ensure non-negative
                    'minutes_remaining': max(0, seconds_remaining // 60),
                    'is_unread': row[7] is None,
                    'expiring_soon': seconds_remaining <= 60  # Flag if less than 1 minute
                })
            
            print(f"⏳ Retrieved {len(expiring_messages)} message(s) expiring soon for user {user_id}")
        
        return jsonify({
            'success': True,
            'expiring_messages': expiring_messages,
            'count': len(expiring_messages),
            'threshold_seconds': expiration_threshold_seconds
        }), 200
        
    except Exception as e:
        print(f"❌ get-ttl-expiring error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-ttl-statistics', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_ttl_statistics():
    """Get TTL expiration statistics for current user (unread tracking)"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Total unread count (including those about to expire)
            cursor.execute('''
                SELECT COUNT(*) as total_unread
                FROM messages
                WHERE receiver_id = ? 
                AND viewed_at IS NULL
                AND (read_timer_started_at IS NULL OR datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') > datetime('now'))
            ''', (user_id,))
            total_unread = cursor.fetchone()[0]
            
            # Unread messages expiring within different timeframes
            cursor.execute('''
                SELECT 
                    COUNT(CASE WHEN CAST((julianday(datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds')) 
                                         - julianday('now')) * 86400 as INTEGER) <= 60 THEN 1 END) as expiring_1min,
                    COUNT(CASE WHEN CAST((julianday(datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds')) 
                                         - julianday('now')) * 86400 as INTEGER) <= 300 THEN 1 END) as expiring_5min,
                    COUNT(CASE WHEN CAST((julianday(datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds')) 
                                         - julianday('now')) * 86400 as INTEGER) <= 3600 THEN 1 END) as expiring_1hour,
                    COUNT(*) as total_unread_count
                FROM messages
                WHERE receiver_id = ? 
                AND viewed_at IS NOT NULL
                AND read_timer_started_at IS NOT NULL
                AND datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') > datetime('now')
            ''', (user_id,))
            
            stats = cursor.fetchone()
            
            # Get average TTL for unread messages
            cursor.execute('''
                SELECT AVG(ttl_seconds) as avg_ttl, MIN(ttl_seconds) as min_ttl, MAX(ttl_seconds) as max_ttl
                FROM messages
                WHERE receiver_id = ? 
                AND viewed_at IS NULL
                AND (read_timer_started_at IS NULL OR datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') > datetime('now'))
            ''', (user_id,))
            
            ttl_info = cursor.fetchone()
            
            statistics = {
                'total_unread': total_unread,
                'expiring_within_1min': stats[0] if stats[0] else 0,
                'expiring_within_5min': stats[1] if stats[1] else 0,
                'expiring_within_1hour': stats[2] if stats[2] else 0,
                'average_ttl_seconds': int(ttl_info[0]) if ttl_info[0] else 0,
                'min_ttl_seconds': ttl_info[1] if ttl_info[1] else 0,
                'max_ttl_seconds': ttl_info[2] if ttl_info[2] else 0
            }
            
            print(f"📊 TTL Statistics for user {user_id}: {statistics}")
        
        return jsonify({
            'success': True,
            'statistics': statistics
        }), 200
        
    except Exception as e:
        print(f"❌ get-ttl-statistics error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/record-message-missed', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def record_message_missed():
    """Record when an unread message expires before being viewed"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        message_ids = data.get('message_ids', [])
        
        if not message_ids:
            return jsonify({'error': 'No message IDs provided'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get details of expired messages for logging
            placeholders = ','.join('?' * len(message_ids))
            cursor.execute(f'''
                SELECT id, sender_id, content, ttl_seconds, created_at
                FROM messages
                WHERE id IN ({placeholders}) AND receiver_id = ? AND viewed_at IS NULL
            ''', message_ids + [user_id])
            
            missed_messages = cursor.fetchall()
            
            # Log the missed messages
            for msg in missed_messages:
                print(f"⏰ MISSED MESSAGE: ID={msg[0]}, Sender={msg[1]}, TTL={msg[3]}s, Created={msg[4]}")
            
            # Mark only the specified messages as missed/expired (constrained to caller's receiver_id)
            if missed_messages:
                missed_ids = [msg[0] for msg in missed_messages]
                id_placeholders = ','.join('?' * len(missed_ids))
                cursor.execute(f'''
                    UPDATE messages
                    SET viewed_at = datetime('now'),
                        delivered_at = COALESCE(delivered_at, datetime('now')),
                        read_timer_started_at = datetime('now'),
                        status = 'seen'
                    WHERE id IN ({id_placeholders}) AND receiver_id = ?
                ''', (*missed_ids, user_id))

            updated_count = cursor.rowcount

        return jsonify({
            'success': True,
            'missed_count': updated_count,
            'message_count': len(missed_messages)
        }), 200
        
    except Exception as e:
        print(f"❌ record-message-missed error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-message', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def delete_message():
    """Delete a message (by sender or receiver) - BBM-style Delete Everywhere"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        data = request.get_json()
        message_id = data.get('message_id')
        delete_mode = data.get('delete_mode', 'delete_everywhere')  # delete_everywhere or delete_for_me
        
        if not message_id:
            return jsonify({'error': 'Missing message_id'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get message details
            cursor.execute('''
                SELECT sender_id, receiver_id FROM messages 
                WHERE id = ? AND (sender_id = ? OR receiver_id = ?)
            ''', (message_id, user_id, user_id))
            
            msg_row = cursor.fetchone()
            if not msg_row:
                return jsonify({'error': 'Message not found or not authorized'}), 404
            
            sender_id, receiver_id = msg_row[0], msg_row[1]
            
            if delete_mode == 'delete_everywhere':
                # BBM Feature: Mark as deleted for both users (no soft delete, true removal)
                cursor.execute('''
                    UPDATE messages 
                    SET is_deleted = 1
                    WHERE id = ?
                ''', (message_id,))
                
                # Determine who the other party is
                other_user_id = receiver_id if user_id == sender_id else sender_id
                
                # Sync deletion via Socket.IO to other party (BBM-style)
                socketio.emit('message_deleted', {
                    'message_id': message_id,
                    'deleted_by': user_id,
                    'timestamp': datetime.now().isoformat()
                }, room=f"user:{other_user_id}")
                
                print(f"🗑️ Message {message_id} deleted everywhere (BBM Delete feature)")
            else:
                # Delete just for this user (soft delete)
                cursor.execute('''
                    DELETE FROM messages 
                    WHERE id = ? AND (sender_id = ? OR receiver_id = ?)
                ''', (message_id, user_id, user_id))
                
                print(f"✅ Message {message_id} deleted locally by user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Message deleted successfully',
            'delete_mode': delete_mode
        }), 200
        
    except Exception as e:
        print(f"❌ delete_message error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-message-security', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def delete_message_security():
    """Delete a message due to PIN-to-view security (wrong PIN)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        message_id = data.get('message_id')
        reason = data.get('reason', 'Wrong PIN')
        
        if not message_id:
            return jsonify({'error': 'Missing message_id'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Mark message as failed for security (keep sender history)
            cursor.execute('''
                UPDATE messages
                SET status = 'failed'
                WHERE id = ?
            ''', (message_id,))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Message not found'}), 404

            cursor.execute('SELECT sender_id FROM messages WHERE id = ?', (message_id,))
            row = cursor.fetchone()
            sender_id = row[0] if row else None
        
        print(f"⚠️ Message {message_id} marked failed for security: {reason}")

        if sender_id:
            print(f"📡 Emitting failed status for message {message_id}")
            emit_message_status(sender_id, message_id, 'failed')
        
        return jsonify({
            'success': True,
            'message': 'Message deleted for security'
        }), 200
        
    except Exception as e:
        print(f"❌ delete_message_security error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notify-delivery-failed', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def notify_delivery_failed():
    """Notify sender that message delivery failed"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        sender_pin = data.get('sender_pin')
        receiver_pin = data.get('receiver_pin')
        message_id = data.get('message_id')
        reason = data.get('reason', 'Unknown')
        
        print(f"⚠️ DELIVERY FAILED: Message {message_id}")
        print(f"   From: {sender_pin}")
        print(f"   To: {receiver_pin}")
        print(f"   Reason: {reason}")

        # Persist status for sender visibility
        if message_id:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE messages
                    SET status = 'failed'
                    WHERE id = ?
                ''', (message_id,))

                cursor.execute('SELECT sender_id FROM messages WHERE id = ?', (message_id,))
                row = cursor.fetchone()
                sender_id = row[0] if row else None

            if sender_id:
                print(f"📡 Emitting failed status for message {message_id}")
                emit_message_status(sender_id, message_id, 'failed')
        
        # In production, send real-time notification via WebSocket
        # For now, just log it (could add to notifications table in future)
        
        return jsonify({
            'success': True,
            'message': 'Sender will be notified'
        }), 200
        
    except Exception as e:
        print(f"❌ notify_delivery_failed error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ CONTACT MANAGEMENT SYSTEM ENDPOINTS ============

@app.route('/api/add-contact', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def add_contact():
    """Send contact request to another user"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        sender_id = session['user_id']
        target_zeus_pin = data.get('zeus_pin', '').strip().upper()
        
        if not target_zeus_pin:
            return jsonify({'error': 'Zeus PIN required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find target user by Zeus PIN
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (target_zeus_pin,))
            target = cursor.fetchone()
            
            if not target:
                return jsonify({'error': 'User not found'}), 404
            
            target_id = target[0]
            
            # Prevent self-contact
            if sender_id == target_id:
                return jsonify({'error': 'Cannot add yourself as contact'}), 400
            
            # Check if already contacted
            cursor.execute('''
                SELECT status FROM contacts 
                WHERE user_id = ? AND contact_user_id = ?
            ''', (sender_id, target_id))
            
            existing = cursor.fetchone()
            if existing:
                if existing[0] == 'pending':
                    return jsonify({'error': 'Contact request already pending'}), 409
                elif existing[0] == 'accepted':
                    return jsonify({'error': 'Already connected'}), 409
                else:
                    return jsonify({'error': 'Contact already blocked'}), 409
            
            # Create contact request
            cursor.execute('''
                INSERT INTO contacts (user_id, contact_user_id, status)
                VALUES (?, ?, 'pending')
            ''', (sender_id, target_id))
        
        print(f"✅ Contact request from {sender_id} to {target_id}")
        
        return jsonify({
            'success': True,
            'message': 'Contact request sent'
        }), 200
        
    except Exception as e:
        print(f"❌ add_contact error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-contact-requests', methods=['GET'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def get_contact_requests():
    """Get pending contact requests for current user"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get pending contact requests where I'm the target
            cursor.execute('''
                SELECT c.id, u.id, u.full_name, u.zeus_pin, u.profile_pic, c.created_at
                FROM contacts c
                JOIN users u ON c.user_id = u.id
                WHERE c.contact_user_id = ? AND c.status = 'pending'
                ORDER BY c.created_at DESC
            ''', (user_id,))
            
            requests = []
            for row in cursor.fetchall():
                requests.append({
                    'contact_id': row[0],
                    'user_id': row[1],
                    'full_name': row[2],
                    'zeus_pin': row[3],
                    'profile_pic': row[4],
                    'created_at': row[5]
                })
        
        return jsonify({
            'success': True,
            'requests': requests,
            'count': len(requests)
        }), 200
        
    except Exception as e:
        print(f"❌ get_contact_requests error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/accept-contact', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def accept_contact():
    """Accept a contact request (complete handshake)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        contact_id = data.get('contact_id')
        
        if not contact_id:
            return jsonify({'error': 'Contact ID required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get the contact request
            cursor.execute('''
                SELECT user_id FROM contacts 
                WHERE id = ? AND contact_user_id = ? AND status = 'pending'
            ''', (contact_id, user_id))
            
            request_data = cursor.fetchone()
            if not request_data:
                return jsonify({'error': 'Contact request not found'}), 404
            
            requester_id = request_data[0]
            
            # Update to accepted
            cursor.execute('''
                UPDATE contacts 
                SET status = 'accepted'
                WHERE id = ?
            ''', (contact_id,))
            
            # Create bi-directional contact
            cursor.execute('''
                INSERT OR IGNORE INTO contacts (user_id, contact_user_id, status)
                VALUES (?, ?, 'accepted')
            ''', (user_id, requester_id))
            
            # Get accepter's details to send back to requester
            cursor.execute('SELECT zeus_pin, full_name FROM users WHERE id = ?', (user_id,))
            accepter_row = cursor.fetchone()
            accepter_pin = accepter_row[0]
            accepter_name = accepter_row[1]
        
        print(f"✅ Contact request {contact_id} accepted: {user_id} <-> {requester_id}")
        
        # ⭐ REAL-TIME UPDATE: Notify the requester that their contact request was accepted
        socketio.emit('contact_request_accepted', {
            'accepter_id': user_id,
            'accepter_pin': accepter_pin,
            'accepter_name': accepter_name,
            'contact_id': contact_id,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{requester_id}")
        
        return jsonify({
            'success': True,
            'message': 'Contact request accepted',
            'accepter_name': accepter_name,
            'accepter_pin': accepter_pin
        }), 200
        
    except Exception as e:
        print(f"❌ accept_contact error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/decline-contact', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def decline_contact():
    """Decline/reject a contact request or Ignore it (BBM Feature)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        contact_id = data.get('contact_id')
        action = data.get('action', 'decline')  # 'decline' or 'ignore' (BBM Feature)
        
        if not contact_id:
            return jsonify({'error': 'Contact ID required'}), 400
        
        if action not in ['decline', 'ignore']:
            return jsonify({'error': 'Invalid action (decline or ignore)'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if action == 'ignore':
                # BBM Feature: Ignore - mark as ignored so sender can't see pending request
                # Sender will never know they were ignored (stays "pending" in their view)
                cursor.execute('''
                    UPDATE contacts 
                    SET status = 'ignored'
                    WHERE id = ? AND contact_user_id = ? AND status = 'pending'
                ''', (contact_id, user_id))
                
                if cursor.rowcount == 0:
                    return jsonify({'error': 'Contact request not found'}), 404
                
                print(f"🤐 User {user_id} ignored contact request {contact_id} (sender won't know)")
                return jsonify({
                    'success': True,
                    'message': 'Contact request ignored (sender not notified)',
                    'action': 'ignore'
                }), 200
            
            else:
                # Standard decline - delete the pending contact request
                cursor.execute('''
                    DELETE FROM contacts 
                    WHERE id = ? AND contact_user_id = ? AND status = 'pending'
                ''', (contact_id, user_id))
                
                if cursor.rowcount == 0:
                    return jsonify({'error': 'Contact request not found'}), 404
                
                print(f"✅ Contact request {contact_id} declined by user {user_id}")
                return jsonify({
                    'success': True,
                    'message': 'Contact request declined',
                    'action': 'decline'
                }), 200
        
    except Exception as e:
        print(f"❌ decline_contact error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/block-contact', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def block_contact():
    """Block a contact - BBM style bidirectional blocking"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        target_zeus_pin = data.get('zeus_pin', '').strip().upper()
        
        if not target_zeus_pin:
            return jsonify({'error': 'Zeus PIN required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find target user
            cursor.execute('SELECT id, full_name FROM users WHERE zeus_pin = ?', (target_zeus_pin,))
            target = cursor.fetchone()
            
            if not target:
                return jsonify({'error': 'User not found'}), 404
            
            target_id = target[0]
            target_name = target[1]
            
            # ============================================
            # BBM BIDIRECTIONAL BLOCKING
            # ============================================
            
            # Block direction 1: User → Target (user blocks target)
            cursor.execute('''
                SELECT id FROM contacts 
                WHERE user_id = ? AND contact_user_id = ?
            ''', (user_id, target_id))
            
            existing_1 = cursor.fetchone()
            
            if existing_1:
                cursor.execute('''
                    UPDATE contacts 
                    SET status = 'blocked'
                    WHERE user_id = ? AND contact_user_id = ?
                ''', (user_id, target_id))
            else:
                cursor.execute('''
                    INSERT INTO contacts (user_id, contact_user_id, status)
                    VALUES (?, ?, 'blocked')
                ''', (user_id, target_id))
            
            # Block direction 2: Target → User (mutual blocking - user disappears from target's list)
            cursor.execute('''
                SELECT id FROM contacts 
                WHERE user_id = ? AND contact_user_id = ?
            ''', (target_id, user_id))
            
            existing_2 = cursor.fetchone()
            
            if existing_2:
                cursor.execute('''
                    UPDATE contacts 
                    SET status = 'blocked'
                    WHERE user_id = ? AND contact_user_id = ?
                ''', (target_id, user_id))
            else:
                cursor.execute('''
                    INSERT INTO contacts (user_id, contact_user_id, status)
                    VALUES (?, ?, 'blocked')
                ''', (target_id, user_id))
            
            conn.commit()
        
        print(f"✅ BBM BIDIRECTIONAL BLOCK: User {user_id} blocked {target_id} ({target_name})")
        print(f"   - {target_name} removed from User {user_id}'s contact list")
        print(f"   - User {user_id} removed from {target_name}'s contact list")
        
        # Emit Socket.IO event to notify both users (NOT broadcast to all)
        # Only notify the user and the blocked user
        socketio.emit('contact_blocked', {
            'user_id': user_id,
            'blocked_user_id': target_id,
            'blocked_user_name': target_name,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{user_id}")
        socketio.emit('contact_blocked', {
            'user_id': user_id,
            'blocked_user_id': target_id,
            'blocked_user_name': target_name,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{target_id}")
        
        return jsonify({
            'success': True,
            'message': 'Contact blocked',
            'blocked_user': target_name,
            'note': 'You have been mutually blocked. This contact will no longer appear in either contact list.'
        }), 200
        
    except Exception as e:
        print(f"❌ block_contact error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-contact', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def unblock_contact():
    """Unblock a contact - BBM style bidirectional unblocking"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        target_zeus_pin = data.get('zeus_pin', '').strip().upper()
        
        if not target_zeus_pin:
            return jsonify({'error': 'Zeus PIN required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find target user
            cursor.execute('SELECT id, full_name FROM users WHERE zeus_pin = ?', (target_zeus_pin,))
            target = cursor.fetchone()
            
            if not target:
                return jsonify({'error': 'User not found'}), 404
            
            target_id = target[0]
            target_name = target[1]
            
            # ============================================
            # BBM BIDIRECTIONAL UNBLOCKING
            # ============================================
            
            # Delete block direction 1: User → Target
            cursor.execute('''
                DELETE FROM contacts 
                WHERE user_id = ? AND contact_user_id = ? AND status = 'blocked'
            ''', (user_id, target_id))
            
            count_1 = cursor.rowcount
            
            # Delete block direction 2: Target → User (remove mutual block)
            cursor.execute('''
                DELETE FROM contacts 
                WHERE user_id = ? AND contact_user_id = ? AND status = 'blocked'
            ''', (target_id, user_id))
            
            count_2 = cursor.rowcount
            
            if count_1 == 0 and count_2 == 0:
                return jsonify({'error': 'Contact not blocked'}), 404
            
            conn.commit()
        
        print(f"✅ BBM BIDIRECTIONAL UNBLOCK: User {user_id} unblocked {target_id} ({target_name})")
        print(f"   - {target_name} can be re-added to User {user_id}'s contact list")
        print(f"   - User {user_id} can be re-added to {target_name}'s contact list")
        
        # Emit Socket.IO event to notify both users (NOT broadcast to all)
        # Only notify the user and the unblocked user
        socketio.emit('contact_unblocked', {
            'user_id': user_id,
            'unblocked_user_id': target_id,
            'unblocked_user_name': target_name,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{user_id}")
        socketio.emit('contact_unblocked', {
            'user_id': user_id,
            'unblocked_user_id': target_id,
            'unblocked_user_name': target_name,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{target_id}")
        
        return jsonify({
            'success': True,
            'message': 'Contact unblocked',
            'unblocked_user': target_name,
            'note': 'You can now re-add this contact to your contact list.'
        }), 200
        
    except Exception as e:
        print(f"❌ unblock_contact error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-contacts', methods=['GET'])
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def get_contacts():
    """Get list of accepted contacts"""
    try:
        print("\n" + "="*70)
        print("🔍 GET-CONTACTS API CALLED")
        print("="*70)
        print(f"Session keys: {list(session.keys())}")
        print(f"Session data: {dict(session)}")
        
        if 'user_id' not in session:
            print("❌ ERROR: user_id NOT in session!")
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_id = session['user_id']
        print(f"✅ user_id from session: {user_id}")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # First, get user info for debug
            cursor.execute('SELECT id, full_name, zeus_pin FROM users WHERE id = ?', (user_id,))
            user_info = cursor.fetchone()
            if user_info:
                print(f"✅ User found: {user_info[1]} (PIN: {user_info[2]}, ID: {user_info[0]})")
            else:
                print(f"❌ User ID {user_id} not found in database!")
            
            # Get all contacts for this user (regardless of status)
            cursor.execute('''
                SELECT c.id, c.contact_user_id, u.full_name, u.zeus_pin, c.status
                FROM contacts c
                JOIN users u ON c.contact_user_id = u.id
                WHERE c.user_id = ?
                ORDER BY c.status DESC
            ''', (user_id,))
            
            all_contacts = cursor.fetchall()
            print(f"\n📋 Total contact relationships for user {user_id}: {len(all_contacts)}")
            for row in all_contacts:
                print(f"   - {row[2]} ({row[3]}) - Status: {row[4]}")
            
            # Get accepted contacts only
            cursor.execute('''
                SELECT u.id, u.full_name, u.zeus_pin, u.profile_pic, u.email
                FROM contacts c
                JOIN users u ON c.contact_user_id = u.id
                WHERE c.user_id = ? AND c.status = 'accepted'
                ORDER BY u.full_name
            ''', (user_id,))
            
            contacts = []
            for row in cursor.fetchall():
                contacts.append({
                    'user_id': row[0],
                    'full_name': row[1],
                    'zeus_pin': row[2],
                    'profile_pic': row[3],
                    'email': row[4]
                })
        
        print(f"\n✅ Returning {len(contacts)} accepted contacts to frontend")
        print("="*70 + "\n")
        
        return jsonify({
            'success': True,
            'contacts': contacts,
            'count': len(contacts)
        }), 200
        
    except Exception as e:
        print(f"❌ get_contacts error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/remove-contact', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def remove_contact():
    """Remove/unfriend a contact"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        target_zeus_pin = data.get('zeus_pin', '').strip().upper()
        
        if not target_zeus_pin:
            return jsonify({'error': 'Zeus PIN required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find target user
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (target_zeus_pin,))
            target = cursor.fetchone()
            
            if not target:
                return jsonify({'error': 'User not found'}), 404
            
            target_id = target[0]
            
            # Remove bidirectional contact
            cursor.execute('''
                DELETE FROM contacts 
                WHERE (user_id = ? AND contact_user_id = ?) 
                   OR (user_id = ? AND contact_user_id = ?)
            ''', (user_id, target_id, target_id, user_id))
            
            if cursor.rowcount == 0:
                return jsonify({'error': 'Contact not found'}), 404
        
        print(f"✅ User {user_id} removed contact {target_id}")
        
        return jsonify({
            'success': True,
            'message': 'Contact removed'
        }), 200
        
    except Exception as e:
        print(f"❌ remove_contact error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def health():
    """Health check endpoint"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
        
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


@app.route('/offline.html', methods=['GET'])
def offline_page():
    """Serve PWA offline fallback page."""
    return render_template('offline.html')


@app.route('/mobile')
def mobile_welcome():
    """Mobile-optimized welcome page for PWA installation."""
    return render_template('mobile-welcome.html')


def keep_alive():
    """Prevent free-tier cold starts by pinging health endpoint periodically."""
    while True:
        time.sleep(480)
        try:
            base_url = BASE_URL.rstrip('/')
            urllib_request.urlopen(f'{base_url}/health', timeout=10)
            print(f"✅ Keep-alive ping at {datetime.now().isoformat()}")
        except Exception as e:
            print(f"❌ Keep-alive failed: {e}")


def cleanup_expired_ghost_content_once():
    """Delete expired ghost posts/comments and orphaned votes once."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM ghost_posts WHERE expires_at < datetime("now")')
        expired_post_ids = [row['id'] for row in cursor.fetchall()]

        cursor.execute('SELECT id FROM ghost_comments WHERE expires_at < datetime("now")')
        expired_comment_ids = [row['id'] for row in cursor.fetchall()]

        deleted_posts = 0
        deleted_comments = 0

        if expired_post_ids:
            post_placeholders = ','.join('?' * len(expired_post_ids))
            cursor.execute(f'DELETE FROM ghost_votes WHERE post_id IN ({post_placeholders})', expired_post_ids)
            cursor.execute(f'DELETE FROM ghost_reports WHERE post_id IN ({post_placeholders})', expired_post_ids)
            cursor.execute(f'DELETE FROM ghost_purchases WHERE post_id IN ({post_placeholders})', expired_post_ids)
            cursor.execute(f'DELETE FROM moderation_queue WHERE post_id IN ({post_placeholders})', expired_post_ids)
            cursor.execute(f'DELETE FROM ghost_comments WHERE post_id IN ({post_placeholders})', expired_post_ids)
            cursor.execute(f'DELETE FROM ghost_posts WHERE id IN ({post_placeholders})', expired_post_ids)
            deleted_posts = cursor.rowcount

        if expired_comment_ids:
            comment_placeholders = ','.join('?' * len(expired_comment_ids))
            cursor.execute(f'DELETE FROM ghost_votes WHERE comment_id IN ({comment_placeholders})', expired_comment_ids)
            cursor.execute(f'DELETE FROM ghost_comments WHERE id IN ({comment_placeholders})', expired_comment_ids)
            deleted_comments = cursor.rowcount

        cursor.execute('''
            DELETE FROM ghost_votes
            WHERE (post_id IS NOT NULL AND post_id NOT IN (SELECT id FROM ghost_posts))
               OR (comment_id IS NOT NULL AND comment_id NOT IN (SELECT id FROM ghost_comments))
        ''')

        conn.commit()

    if deleted_posts > 0 or deleted_comments > 0:
        print(f"🧹 Cleaned up {deleted_posts} expired posts and {deleted_comments} comments")

    return deleted_posts, deleted_comments


def cleanup_expired_ghost_content():
    """Run every hour to delete expired ghost posts/comments and orphaned votes."""
    while True:
        time.sleep(3600)
        try:
            cleanup_expired_ghost_content_once()
        except Exception as e:
            print(f"❌ Ghost cleanup failed: {e}")


if os.environ.get('RENDER'):
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
    cleanup_thread = threading.Thread(target=cleanup_expired_ghost_content, daemon=True)
    cleanup_thread.start()
    print("🔄 Ghost content cleanup thread started")

# Message status tracking
@app.route('/api/message-status/<int:message_id>', methods=['GET'])
@retry_on_locked()
def get_message_status(message_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT status, viewed_at, delivered_at
                FROM messages
                WHERE id = ? AND sender_id = ?
            ''', (message_id, session['user_id']))
            
            row = cursor.fetchone()
            if not row:
                return jsonify({'error': 'Message not found'}), 404
            
            status = row[0] if row[0] else 'sent'
            viewed_at = row[1]
            delivered_at = row[2]
            
            return jsonify({
                'success': True,
                'status': status,
                'viewed_at': viewed_at,
                'delivered_at': delivered_at
            }), 200
    except Exception as e:
        print(f"Error fetching message status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-all-messages', methods=['POST'])
@retry_on_locked()
def delete_all_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    contact_pin = data.get('contact_pin')
    
    if not contact_pin:
        return jsonify({'error': 'Contact PIN required'}), 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get contact user ID
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (contact_pin,))
            contact = cursor.fetchone()
            if not contact:
                return jsonify({'error': 'Contact not found'}), 404
            
            contact_id = contact[0]
            
            # Delete all messages between users
            cursor.execute('''
                DELETE FROM messages
                WHERE (sender_id = ? AND receiver_id = ?)
                   OR (sender_id = ? AND receiver_id = ?)
            ''', (session['user_id'], contact_id, contact_id, session['user_id']))
            
            deleted_count = cursor.rowcount
            print(f"🗑️ Deleted {deleted_count} messages between users")
            
            return jsonify({
                'success': True,
                'deleted': deleted_count
            }), 200
    except Exception as e:
        print(f"Error deleting messages: {e}")
        return jsonify({'error': str(e)}), 500

# ========================================
# ONLINE STATUS ENDPOINTS
# ========================================

@app.route('/api/update-online-status', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked()
def update_online_status():
    """Update user's online status"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        data = request.get_json() or {}
        user_id = session['user_id']
        is_online = data.get('is_online', False)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if is_online:
                cursor.execute('''
                    UPDATE users SET last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id,))
            else:
                # Set last_seen to past time to appear offline
                cursor.execute('''
                    UPDATE users SET last_seen = datetime('now', '-1 hour')
                    WHERE id = ?
                ''', (user_id,))
        
        print(f"✅ Online status updated for user_id={user_id}: {'online' if is_online else 'offline'}")
        
        return jsonify({
            'success': True,
            'message': 'Status updated'
        }), 200
        
    except Exception as e:
        print(f"❌ update-online-status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-user-status/<zeus_pin>', methods=['GET'])
@retry_on_locked()
def get_user_status(zeus_pin):
    """Get user's online/last seen status"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT last_seen FROM users WHERE zeus_pin = ?
            ''', (zeus_pin,))
            
            user = cursor.fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            last_seen = user[0]
            
            if last_seen:
                from datetime import datetime, timedelta
                last_seen_dt = datetime.fromisoformat(last_seen)
                now = datetime.now()
                
                # If last seen within 5 minutes, consider online
                if (now - last_seen_dt).total_seconds() < 300:
                    return jsonify({
                        'success': True,
                        'status': 'online',
                        'last_seen': last_seen
                    })
                else:
                    return jsonify({
                        'success': True,
                        'status': 'offline',
                        'last_seen': last_seen,
                        'last_seen_formatted': last_seen_dt.strftime('%Y-%m-%d %H:%M')
                    })
            else:
                return jsonify({
                    'success': True,
                    'status': 'unknown',
                    'last_seen': None
                })
                
    except Exception as e:
        print(f"❌ get-user-status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ========================================
# BBM FEATURE ENDPOINTS (STATUS COLORS, PING, DELETE EVERYWHERE)
# ========================================

@app.route('/api/bbm-update-status', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def bbm_update_status():
    """BBM Feature: Update user's presence status (available/away/busy) + custom message"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        status_state = data.get('status_state', 'available')  # available, away, busy
        status_message = data.get('status_message', '')
        
        if status_state not in ['available', 'away', 'busy']:
            return jsonify({'error': 'Invalid status_state'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET status_state = ?, status_message = ?, last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status_state, status_message, user_id))
            conn.commit()
        
        # Emit status change to user's own room (NOT broadcast to all)
        # User's contacts will see status when they poll/fetch contacts
        socketio.emit('status_change', {
            'user_id': user_id,
            'status_state': status_state,
            'status_message': status_message,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{user_id}")
        
        print(f"🎨 User {user_id} status updated to {status_state}")
        
        return jsonify({
            'success': True,
            'message': 'Status updated',
            'status_state': status_state,
            'status_message': status_message
        }), 200
        
    except Exception as e:
        print(f"❌ bbm_update_status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bbm-get-contacts-status', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def bbm_get_contacts_status():
    """BBM Feature: Get status (availability + custom message) of all contacts"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get all accepted contacts with their status
            cursor.execute('''
                SELECT u.id, u.zeus_pin, u.full_name, u.status_state, u.status_message
                FROM users u
                JOIN contacts c ON u.id = c.contact_user_id
                WHERE c.user_id = ? AND c.status = 'accepted'
                ORDER BY u.full_name ASC
            ''', (user_id,))
            
            contacts = cursor.fetchall()
            contacts_data = []
            
            for contact in contacts:
                contacts_data.append({
                    'user_id': contact[0],
                    'zeus_pin': contact[1],
                    'full_name': contact[2],
                    'status_state': contact[3] or 'available',
                    'status_message': contact[4] or ''
                })
        
        return jsonify({
            'success': True,
            'contacts': contacts_data
        }), 200
        
    except Exception as e:
        print(f"❌ bbm_get_contacts_status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug-socket-io', methods=['GET'])
def debug_socket_io():
    """Debug Socket.IO connection info — admin-only, disabled in production."""
    # Disabled outside of debug mode to prevent socket session data leakage.
    if not app.debug:
        return jsonify({'error': 'Not found'}), 404

    if 'admin_id' not in session:
        return jsonify({'error': 'Admin authentication required'}), 401

    return jsonify({
        'success': True,
        'total_connected': len(connected_users),
    }), 200

@app.route('/api/cleanup-old-messages', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def cleanup_old_messages():
    """CRITICAL FIX: Delete ALL expired messages from database"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 1. DELETE messages that have expired TTL (already viewed and timer ran out)
            cursor.execute('''
                DELETE FROM messages
                WHERE viewed_at IS NOT NULL
                AND read_timer_started_at IS NOT NULL
                AND datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
            ''')
            deleted_expired = cursor.rowcount
            
            # 2. DELETE messages marked as expired
            cursor.execute('''
                DELETE FROM messages
                WHERE status = 'expired'
            ''')
            deleted_marked = cursor.rowcount
            
            # 3. DELETE very old unread messages (>24 hours)
            cursor.execute('''
                DELETE FROM messages
                WHERE viewed_at IS NULL
                AND created_at < datetime('now', '-1 days')
            ''')
            deleted_old = cursor.rowcount
            
            # 4. DELETE old seen messages without proper TTL tracking (>1 hour)
            cursor.execute('''
                DELETE FROM messages
                WHERE viewed_at IS NOT NULL
                AND read_timer_started_at IS NULL
                AND viewed_at < datetime('now', '-1 hours')
            ''')
            deleted_legacy = cursor.rowcount
            
            total_deleted = deleted_expired + deleted_marked + deleted_old + deleted_legacy
            
            print(f"🗑️ [CLEANUP] Deleted {total_deleted} old messages:")
            print(f"   - {deleted_expired} expired TTL messages")
            print(f"   - {deleted_marked} marked as expired")
            print(f"   - {deleted_old} old unread messages")
            print(f"   - {deleted_legacy} legacy seen messages")
            
            conn.commit()
        
        return jsonify({
            'success': True,
            'deleted_count': total_deleted,
            'breakdown': {
                'expired_ttl': deleted_expired,
                'marked_expired': deleted_marked,
                'old_unread': deleted_old,
                'legacy_seen': deleted_legacy
            }
        }), 200
        
    except Exception as e:
        print(f"❌ cleanup_old_messages error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/bbm-send-ping', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def bbm_send_ping():
    """BBM Feature: Send PING (tactile nudge) to a contact"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        sender_id = session['user_id']
        receiver_pin = data.get('receiver_pin', '').strip()
        ping_type = data.get('ping_type', 'standard')  # standard or urgent
        
        if not receiver_pin:
            return jsonify({'error': 'receiver_pin required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get receiver ID from PIN
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (receiver_pin,))
            receiver_row = cursor.fetchone()
            
            if not receiver_row:
                return jsonify({'error': 'Receiver not found'}), 404
            
            receiver_id = receiver_row[0]
            
            # Verify they are contacts
            cursor.execute('''
                SELECT id FROM contacts 
                WHERE user_id = ? AND contact_user_id = ? AND status = 'accepted'
            ''', (sender_id, receiver_id))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Not a contact or not accepted'}), 403
        
        # Get sender details
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT zeus_pin, full_name FROM users WHERE id = ?', (sender_id,))
            sender_row = cursor.fetchone()
            sender_pin = sender_row[0]
            sender_name = sender_row[1]
        
        # Emit PING via Socket.IO with vibration info
        room = f"user:{receiver_id}"
        is_online = receiver_id in connected_users
        
        ping_data = {
            'sender_id': sender_id,
            'sender_pin': sender_pin,
            'sender_name': sender_name,
            'ping_type': ping_type,
            'vibration_pattern': [100, 50, 100] if ping_type == 'standard' else [200, 100, 200, 100, 200],
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"📳 [PING] Attempting to send PING from {sender_pin} to {receiver_pin}")
        print(f"   - Receiver ID: {receiver_id}")
        print(f"   - Receiver online: {is_online}")
        print(f"   - Target room: {room}")
        print(f"   - Connected users: {list(connected_users.keys())}")
        
        ping_delivered = False
        try:
            socketio.emit('ping_incoming', ping_data, room=room)
            print(f"✅ [PING-WebSocket] PING delivered via Socket.IO to {receiver_pin}")
            ping_delivered = True
        except Exception as emit_error:
            print(f"⚠️ [PING-WebSocket] Emit failed: {emit_error}")
            import traceback
            traceback.print_exc()
        
        # FALLBACK: If Socket.IO fails or receiver offline, save PING as a special message
        if not ping_delivered or not is_online:
            try:
                print(f"📮 [PING-Fallback] Saving PING for fallback delivery via polling")
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    # Save PING as a special system message
                    cursor.execute('''
                        INSERT INTO messages (sender_id, receiver_id, content, status, is_ping, ttl_seconds)
                        VALUES (?, ?, ?, 'sent', 1, 3600)
                    ''', (sender_id, receiver_id, 'PING!'))
                    conn.commit()
                print(f"✅ [PING-Fallback] PING saved to database for polling delivery")
            except Exception as db_error:
                print(f"⚠️ [PING-Fallback] Database save failed: {db_error}")
        
        return jsonify({
            'success': True,
            'message': 'PING sent',
            'ping_type': ping_type,
            'receiver_pin': receiver_pin
        }), 200
        
    except Exception as e:
        print(f"❌ bbm_send_ping error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ========================================
# BBM FEATURE: NOW PLAYING MUSIC STATUS
# ========================================

@app.route('/api/update-now-playing', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def update_now_playing():
    """BBM Feature: Update user's "Now Playing" music status"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        track = data.get('track', '').strip()
        artist = data.get('artist', '').strip()
        
        # If empty, clear Now Playing
        if not track and not artist:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE users 
                    SET now_playing_track = NULL, 
                        now_playing_artist = NULL, 
                        now_playing_updated_at = NULL
                    WHERE id = ?
                ''', (user_id,))
            
            # Emit clear to user's own room (NOT broadcast to all)
            socketio.emit('now_playing_update', {
                'user_id': user_id,
                'track': None,
                'artist': None,
                'timestamp': None
            }, room=f"user:{user_id}")
            
            return jsonify({'success': True, 'message': 'Now Playing cleared'}), 200
        
        # Update Now Playing
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET now_playing_track = ?, 
                    now_playing_artist = ?, 
                    now_playing_updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (track, artist, user_id))
        
        # Emit update to user's own room (NOT broadcast to all)
        socketio.emit('now_playing_update', {
            'user_id': user_id,
            'track': track,
            'artist': artist,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{user_id}")
        
        # Log to activity feed
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO activity_feed (user_id, activity_type, activity_data)
                VALUES (?, 'now_playing', ?)
            ''', (user_id, json.dumps({'track': track, 'artist': artist})))
        
        print(f"🎵 User {user_id} Now Playing: {track} by {artist}")
        
        return jsonify({
            'success': True,
            'message': 'Now Playing updated',
            'track': track,
            'artist': artist
        }), 200
        
    except Exception as e:
        print(f"❌ update_now_playing error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-now-playing', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_now_playing():
    """BBM Feature: Get Now Playing status of all contacts"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get contacts with Now Playing music
            cursor.execute('''
                SELECT u.id, u.zeus_pin, u.full_name, u.now_playing_track, 
                       u.now_playing_artist, u.now_playing_updated_at
                FROM users u
                JOIN contacts c ON u.id = c.contact_user_id
                WHERE c.user_id = ? AND c.status = 'accepted'
                  AND u.now_playing_track IS NOT NULL
                ORDER BY u.now_playing_updated_at DESC
            ''', (user_id,))
            
            contacts = cursor.fetchall()
            now_playing_data = []
            
            for contact in contacts:
                now_playing_data.append({
                    'user_id': contact[0],
                    'zeus_pin': contact[1],
                    'full_name': contact[2],
                    'track': contact[3],
                    'artist': contact[4],
                    'updated_at': contact[5]
                })
        
        return jsonify({
            'success': True,
            'now_playing': now_playing_data
        }), 200
        
    except Exception as e:
        print(f"❌ get_now_playing error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ========================================
# BBM FEATURE: ACTIVITY FEED ("UPDATES")
# ========================================

@app.route('/api/get-activity-feed', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_activity_feed():
    """BBM Feature: Get activity feed (Updates) from all contacts"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        limit = request.args.get('limit', 50, type=int)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get activity from contacts only
            cursor.execute('''
                SELECT af.id, af.user_id, u.zeus_pin, u.full_name, u.avatar_url,
                       af.activity_type, af.activity_data, af.created_at
                FROM activity_feed af
                JOIN users u ON af.user_id = u.id
                JOIN contacts c ON (c.contact_user_id = af.user_id AND c.user_id = ?)
                WHERE c.status = 'accepted'
                ORDER BY af.created_at DESC
                LIMIT ?
            ''', (user_id, limit))
            
            activities = cursor.fetchall()
            feed_data = []
            
            for activity in activities:
                feed_data.append({
                    'id': activity[0],
                    'user_id': activity[1],
                    'zeus_pin': activity[2],
                    'full_name': activity[3],
                    'avatar_url': activity[4],
                    'activity_type': activity[5],
                    'activity_data': json.loads(activity[6]) if activity[6] else {},
                    'created_at': activity[7]
                })
        
        return jsonify({
            'success': True,
            'feed': feed_data
        }), 200
        
    except Exception as e:
        print(f"❌ get_activity_feed error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/log-activity', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def log_activity():
    """Log activity to feed (profile pic change, bio update, etc.)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        activity_type = data.get('activity_type')  # profile_pic, bio, status, etc.
        activity_data = data.get('activity_data', {})
        
        if not activity_type:
            return jsonify({'error': 'activity_type required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO activity_feed (user_id, activity_type, activity_data)
                VALUES (?, ?, ?)
            ''', (user_id, activity_type, json.dumps(activity_data)))
        
        # Emit to user's own room (NOT broadcast to all)
        socketio.emit('new_activity', {
            'user_id': user_id,
            'activity_type': activity_type,
            'activity_data': activity_data,
            'timestamp': datetime.now().isoformat()
        }, room=f"user:{user_id}")
        
        print(f"📰 Activity logged: {user_id} - {activity_type}")
        
        return jsonify({'success': True, 'message': 'Activity logged'}), 200
        
    except Exception as e:
        print(f"❌ log_activity error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ========================================
# BBM FEATURE: GROUP WORKSPACES
# ========================================

@app.route('/api/create-group', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def create_group():
    """BBM Feature: Create a group workspace"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        group_name = data.get('group_name', '').strip()
        group_avatar = data.get('group_avatar', '')
        member_ids = data.get('member_ids', [])  # List of user IDs to add
        
        if not group_name:
            return jsonify({'error': 'group_name required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create group
            cursor.execute('''
                INSERT INTO groups (group_name, group_avatar, created_by)
                VALUES (?, ?, ?)
            ''', (group_name, group_avatar, user_id))
            
            group_id = cursor.lastrowid
            
            # Add creator as admin
            cursor.execute('''
                INSERT INTO group_members (group_id, user_id, role)
                VALUES (?, ?, 'admin')
            ''', (group_id, user_id))
            
            # Add other members
            for member_id in member_ids:
                cursor.execute('''
                    INSERT INTO group_members (group_id, user_id, role)
                    VALUES (?, ?, 'member')
                ''', (group_id, member_id))
        
        print(f"👥 Group created: {group_name} (ID: {group_id}) by user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Group created',
            'group_id': group_id,
            'group_name': group_name
        }), 200
        
    except Exception as e:
        print(f"❌ create_group error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-groups', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_groups():
    """Get all groups user is a member of"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT g.id, g.group_name, g.group_avatar, g.created_at,
                       gm.role, u.full_name as creator_name
                FROM groups g
                JOIN group_members gm ON g.id = gm.group_id
                LEFT JOIN users u ON g.created_by = u.id
                WHERE gm.user_id = ?
                ORDER BY g.created_at DESC
            ''', (user_id,))
            
            groups = cursor.fetchall()
            groups_data = []
            
            for group in groups:
                groups_data.append({
                    'group_id': group[0],
                    'group_name': group[1],
                    'group_avatar': group[2],
                    'created_at': group[3],
                    'role': group[4],
                    'creator_name': group[5]
                })
        
        return jsonify({
            'success': True,
            'groups': groups_data
        }), 200
        
    except Exception as e:
        print(f"❌ get_groups error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-group-todo', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def add_group_todo():
    """BBM Feature: Add to-do item to group"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        group_id = data.get('group_id')
        task_title = data.get('task_title', '').strip()
        task_description = data.get('task_description', '')
        assigned_to = data.get('assigned_to')  # Optional user_id
        
        if not group_id or not task_title:
            return jsonify({'error': 'group_id and task_title required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verify user is member of group
            cursor.execute('''
                SELECT id FROM group_members
                WHERE group_id = ? AND user_id = ?
            ''', (group_id, user_id))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Not a member of this group'}), 403
            
            # Add to-do
            cursor.execute('''
                INSERT INTO group_todos (group_id, task_title, task_description, assigned_to, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (group_id, task_title, task_description, assigned_to, user_id))
            
            todo_id = cursor.lastrowid
        
        # Broadcast to group members via Socket.IO
        socketio.emit('group_todo_added', {
            'group_id': group_id,
            'todo_id': todo_id,
            'task_title': task_title,
            'created_by': user_id
        }, room=f"group:{group_id}")
        
        print(f"✅ To-do added to group {group_id}: {task_title}")
        
        return jsonify({
            'success': True,
            'message': 'To-do added',
            'todo_id': todo_id
        }), 200
        
    except Exception as e:
        print(f"❌ add_group_todo error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-group-todos', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_group_todos():
    """Get all to-do items for a group"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        group_id = request.args.get('group_id', type=int)
        
        if not group_id:
            return jsonify({'error': 'group_id required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verify membership
            cursor.execute('''
                SELECT id FROM group_members
                WHERE group_id = ? AND user_id = ?
            ''', (group_id, user_id))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Not a member of this group'}), 403
            
            # Get to-dos
            cursor.execute('''
                SELECT gt.id, gt.task_title, gt.task_description, gt.is_completed,
                       gt.assigned_to, gt.created_by, gt.completed_at, gt.created_at,
                       u1.full_name as assigned_to_name, u2.full_name as created_by_name
                FROM group_todos gt
                LEFT JOIN users u1 ON gt.assigned_to = u1.id
                LEFT JOIN users u2 ON gt.created_by = u2.id
                WHERE gt.group_id = ?
                ORDER BY gt.is_completed ASC, gt.created_at DESC
            ''', (group_id,))
            
            todos = cursor.fetchall()
            todos_data = []
            
            for todo in todos:
                todos_data.append({
                    'todo_id': todo[0],
                    'task_title': todo[1],
                    'task_description': todo[2],
                    'is_completed': bool(todo[3]),
                    'assigned_to': todo[4],
                    'created_by': todo[5],
                    'completed_at': todo[6],
                    'created_at': todo[7],
                    'assigned_to_name': todo[8],
                    'created_by_name': todo[9]
                })
        
        return jsonify({
            'success': True,
            'todos': todos_data
        }), 200
        
    except Exception as e:
        print(f"❌ get_group_todos error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/complete-group-todo', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def complete_group_todo():
    """Mark a group to-do as completed"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        todo_id = data.get('todo_id')
        is_completed = data.get('is_completed', True)
        
        if not todo_id:
            return jsonify({'error': 'todo_id required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Update completion status
            cursor.execute('''
                UPDATE group_todos
                SET is_completed = ?, 
                    completed_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (1 if is_completed else 0, 1 if is_completed else 0, todo_id))
            
            # Get group_id for broadcast
            cursor.execute('SELECT group_id FROM group_todos WHERE id = ?', (todo_id,))
            result = cursor.fetchone()
            group_id = result[0] if result else None
        
        if group_id:
            # Broadcast to group
            socketio.emit('group_todo_updated', {
                'group_id': group_id,
                'todo_id': todo_id,
                'is_completed': is_completed,
                'updated_by': user_id
            }, room=f"group:{group_id}")
        
        print(f"✅ To-do {todo_id} marked as {'completed' if is_completed else 'incomplete'}")
        
        return jsonify({
            'success': True,
            'message': 'To-do updated'
        }), 200
        
    except Exception as e:
        print(f"❌ complete_group_todo error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/add-group-event', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def add_group_event():
    """BBM Feature: Add calendar event to group"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        user_id = session['user_id']
        group_id = data.get('group_id')
        event_title = data.get('event_title', '').strip()
        event_description = data.get('event_description', '')
        event_location = data.get('event_location', '')
        event_start = data.get('event_start')  # ISO timestamp
        event_end = data.get('event_end')  # ISO timestamp
        
        if not group_id or not event_title or not event_start:
            return jsonify({'error': 'group_id, event_title, and event_start required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verify membership
            cursor.execute('''
                SELECT id FROM group_members
                WHERE group_id = ? AND user_id = ?
            ''', (group_id, user_id))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Not a member of this group'}), 403
            
            # Add event
            cursor.execute('''
                INSERT INTO group_calendar (group_id, event_title, event_description, 
                                           event_location, event_start, event_end, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (group_id, event_title, event_description, event_location, 
                  event_start, event_end, user_id))
            
            event_id = cursor.lastrowid
        
        # Broadcast to group
        socketio.emit('group_event_added', {
            'group_id': group_id,
            'event_id': event_id,
            'event_title': event_title,
            'event_start': event_start,
            'created_by': user_id
        }, room=f"group:{group_id}")
        
        print(f"📅 Event added to group {group_id}: {event_title}")
        
        return jsonify({
            'success': True,
            'message': 'Event added',
            'event_id': event_id
        }), 200
        
    except Exception as e:
        print(f"❌ add_group_event error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-group-calendar', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_group_calendar():
    """Get all calendar events for a group"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        group_id = request.args.get('group_id', type=int)
        
        if not group_id:
            return jsonify({'error': 'group_id required'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verify membership
            cursor.execute('''
                SELECT id FROM group_members
                WHERE group_id = ? AND user_id = ?
            ''', (group_id, user_id))
            
            if not cursor.fetchone():
                return jsonify({'error': 'Not a member of this group'}), 403
            
            # Get calendar events
            cursor.execute('''
                SELECT gc.id, gc.event_title, gc.event_description, gc.event_location,
                       gc.event_start, gc.event_end, gc.created_by, gc.created_at,
                       u.full_name as created_by_name
                FROM group_calendar gc
                LEFT JOIN users u ON gc.created_by = u.id
                WHERE gc.group_id = ?
                ORDER BY gc.event_start ASC
            ''', (group_id,))
            
            events = cursor.fetchall()
            events_data = []
            
            for event in events:
                events_data.append({
                    'event_id': event[0],
                    'event_title': event[1],
                    'event_description': event[2],
                    'event_location': event[3],
                    'event_start': event[4],
                    'event_end': event[5],
                    'created_by': event[6],
                    'created_at': event[7],
                    'created_by_name': event[8]
                })
        
        return jsonify({
            'success': True,
            'events': events_data
        }), 200
        
    except Exception as e:
        print(f"❌ get_group_calendar error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ========================================
# USER SETTINGS ENDPOINTS
# ========================================

@app.route('/api/save-user-settings', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def save_user_settings():
    """Save user privacy and notification settings"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if settings record exists
            cursor.execute('SELECT id FROM user_settings WHERE user_id = ?', (user_id,))
            existing = cursor.fetchone()

            # Load current values if they exist, otherwise defaults
            current = {
                'last_seen_visibility': 'myContacts',
                'profile_photo_visibility': 'myContacts',
                'about_visibility': 'myContacts',
                'status_visibility': 'myContacts',
                'groups_visibility': 'everyone',
                'pin_to_view_enabled': 0,
                'auto_delete_ttl': 0,
                'notification_type': 'both',
                'show_online_status': 1
            }

            if existing:
                cursor.execute('''
                    SELECT last_seen_visibility, profile_photo_visibility, about_visibility,
                           status_visibility, groups_visibility, pin_to_view_enabled,
                           auto_delete_ttl, notification_type, show_online_status
                    FROM user_settings WHERE user_id = ?
                ''', (user_id,))
                row = cursor.fetchone()
                if row:
                    current = {
                        'last_seen_visibility': row[0],
                        'profile_photo_visibility': row[1],
                        'about_visibility': row[2],
                        'status_visibility': row[3],
                        'groups_visibility': row[4],
                        'pin_to_view_enabled': row[5],
                        'auto_delete_ttl': row[6],
                        'notification_type': row[7],
                        'show_online_status': row[8]
                    }

            # Merge incoming data over current values
            def merged_value(key, default):
                return data[key] if key in data else default

            last_seen_visibility = merged_value('last_seen_visibility', current['last_seen_visibility'])
            profile_photo_visibility = merged_value('profile_photo_visibility', current['profile_photo_visibility'])
            about_visibility = merged_value('about_visibility', current['about_visibility'])
            status_visibility = merged_value('status_visibility', current['status_visibility'])
            groups_visibility = merged_value('groups_visibility', current['groups_visibility'])
            pin_to_view_enabled = 1 if merged_value('pin_to_view_enabled', current['pin_to_view_enabled']) else 0
            auto_delete_ttl = merged_value('auto_delete_ttl', current['auto_delete_ttl']) or 0
            notification_type = merged_value('notification_type', current['notification_type'])
            show_online_status = 1 if merged_value('show_online_status', current['show_online_status']) else 0

            if existing:
                # Update existing settings
                cursor.execute('''
                    UPDATE user_settings SET
                        last_seen_visibility = ?,
                        profile_photo_visibility = ?,
                        about_visibility = ?,
                        status_visibility = ?,
                        groups_visibility = ?,
                        pin_to_view_enabled = ?,
                        auto_delete_ttl = ?,
                        notification_type = ?,
                        show_online_status = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                ''', (
                    last_seen_visibility,
                    profile_photo_visibility,
                    about_visibility,
                    status_visibility,
                    groups_visibility,
                    pin_to_view_enabled,
                    int(auto_delete_ttl) if auto_delete_ttl else 0,
                    notification_type,
                    show_online_status,
                    user_id
                ))
            else:
                # Insert new settings
                cursor.execute('''
                    INSERT INTO user_settings (
                        user_id, last_seen_visibility, profile_photo_visibility,
                        about_visibility, status_visibility, groups_visibility,
                        pin_to_view_enabled, auto_delete_ttl, notification_type,
                        show_online_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    last_seen_visibility,
                    profile_photo_visibility,
                    about_visibility,
                    status_visibility,
                    groups_visibility,
                    pin_to_view_enabled,
                    int(auto_delete_ttl) if auto_delete_ttl else 0,
                    notification_type,
                    show_online_status
                ))
            
            print(f"✅ Settings saved for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Settings saved successfully'
        }), 200
    
    except Exception as e:
        print(f"❌ save-user-settings error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-user-settings', methods=['GET'])
@retry_on_locked(max_retries=3, delay=0.5)
def get_user_settings():
    """Get user's privacy and notification settings"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    last_seen_visibility, profile_photo_visibility,
                    about_visibility, status_visibility, groups_visibility,
                    pin_to_view_enabled, auto_delete_ttl, notification_type,
                    show_online_status
                FROM user_settings
                WHERE user_id = ?
            ''', (user_id,))
            
            settings = cursor.fetchone()
            
            if not settings:
                # Return defaults if no settings saved
                defaults = {
                    'last_seen_visibility': 'myContacts',
                    'profile_photo_visibility': 'myContacts',
                    'about_visibility': 'myContacts',
                    'status_visibility': 'myContacts',
                    'groups_visibility': 'everyone',
                    'pin_to_view_enabled': False,
                    'auto_delete_ttl': 0,
                    'notification_type': 'both',
                    'show_online_status': True
                }
                return jsonify({'success': True, 'settings': defaults}), 200
            
            settings_dict = {
                'last_seen_visibility': settings[0] or 'myContacts',
                'profile_photo_visibility': settings[1] or 'myContacts',
                'about_visibility': settings[2] or 'myContacts',
                'status_visibility': settings[3] or 'myContacts',
                'groups_visibility': settings[4] or 'everyone',
                'pin_to_view_enabled': bool(settings[5]),
                'auto_delete_ttl': int(settings[6]) if settings[6] else 0,
                'notification_type': settings[7] or 'both',
                'show_online_status': bool(settings[8])
            }
            
            print(f"✅ Retrieved settings for user {user_id}")
            return jsonify({'success': True, 'settings': settings_dict}), 200
    
    except Exception as e:
        print(f"❌ get-user-settings error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/data-saver-settings', methods=['GET', 'POST'])
@csrf_protect
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def data_saver_settings():
    """Get and update user data saver preferences."""
    user_id = session['user_id']

    if request.method == 'GET':
        settings = get_data_saver_preferences(user_id)
        return jsonify({'success': True, **settings}), 200

    data = request.get_json(silent=True) or {}
    image_quality = data.get('image_quality', 'medium')
    if image_quality not in ('low', 'medium', 'high'):
        image_quality = 'medium'

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE users
            SET data_saver_mode = ?,
                auto_download_images = ?,
                auto_download_videos = ?,
                image_quality = ?
            WHERE id = ?
            ''',
            (
                1 if data.get('data_saver_mode') else 0,
                1 if data.get('auto_download_images') else 0,
                1 if data.get('auto_download_videos') else 0,
                image_quality,
                user_id,
            ),
        )
        conn.commit()

    return jsonify({'success': True}), 200


@app.route('/api/user/language', methods=['GET', 'POST'])
@csrf_protect
@require_approved_user
@retry_on_locked(max_retries=3, delay=0.5)
def user_language():
    """Get and update the user's preferred interface language."""
    user_id = session['user_id']
    valid_languages = {'en', 'sw', 'yo', 'zu', 'ha', 'ig', 'am'}

    if request.method == 'GET':
        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT language FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            language = (row['language'] if row and row['language'] else 'en')
            if language not in valid_languages:
                language = 'en'
            return jsonify({'success': True, 'language': language}), 200

    data = request.get_json(silent=True) or {}
    language = data.get('language', 'en')
    if language not in valid_languages:
        return jsonify({'error': 'Invalid language'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET language = ? WHERE id = ?', (language, user_id))
        conn.commit()

    return jsonify({'success': True, 'language': language}), 200


@app.route('/api/transcribe-voice', methods=['POST'])
@csrf_protect
@require_approved_user
def transcribe_voice():
    """Transcribe a recorded voice note into text."""
    audio_file = request.files.get('audio')
    if not audio_file:
        return jsonify({'error': 'Missing audio file'}), 400

    language = (request.form.get('language') or 'en').strip().lower()
    lang_map = {
        'sw': 'sw-KE',
        'yo': 'yo-NG',
        'zu': 'zu-ZA',
        'ha': 'ha-NG',
        'ig': 'ig-NG',
        'am': 'am-ET',
        'en': 'en-US',
    }

    ffmpeg_bin = shutil.which('ffmpeg')
    if not ffmpeg_bin:
        return jsonify({'error': 'Voice transcription requires ffmpeg on the server'}), 503

    try:
        import speech_recognition as sr
    except Exception:
        return jsonify({'error': 'SpeechRecognition package is not available'}), 500

    temp_webm = tempfile.NamedTemporaryFile(delete=False, suffix='.webm')
    temp_webm_path = temp_webm.name
    temp_webm.close()
    temp_wav_path = temp_webm_path.replace('.webm', '.wav')

    try:
        audio_file.save(temp_webm_path)

        convert = subprocess.run(
            [
                ffmpeg_bin,
                '-y',
                '-i',
                temp_webm_path,
                '-acodec',
                'pcm_s16le',
                '-ar',
                '16000',
                temp_wav_path,
            ],
            capture_output=True,
            text=True,
        )
        if convert.returncode != 0:
            return jsonify({'error': 'Failed to process voice note'}), 400

        recognizer = sr.Recognizer()
        with sr.AudioFile(temp_wav_path) as source:
            audio_data = recognizer.record(source)

        try:
            text = recognizer.recognize_google(audio_data, language=lang_map.get(language, 'en-US'))
        except (sr.UnknownValueError, sr.RequestError):
            text = ''

        return jsonify({'success': True, 'text': text}), 200
    finally:
        for path in (temp_webm_path, temp_wav_path):
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass


@app.route('/api/translate', methods=['POST'])
@csrf_protect
@require_approved_user
def translate_message():
    """Translate a message into the user's target language."""
    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Text is required'}), 400

    valid_languages = {'sw', 'yo', 'zu', 'ha', 'ig', 'am', 'en'}
    target_lang = (data.get('target_lang') or '').strip().lower()

    if not target_lang:
        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT language FROM users WHERE id = ?', (session['user_id'],))
            row = cursor.fetchone()
            target_lang = (row['language'] if row and row['language'] else 'en')

    if target_lang not in valid_languages:
        target_lang = 'en'

    translated = None

    # First try self-hosted LibreTranslate if available.
    try:
        libre_response = http_requests.post(
            'http://localhost:5000/translate',
            json={
                'q': text,
                'source': 'auto',
                'target': target_lang,
                'format': 'text',
            },
            timeout=4,
        )
        if libre_response.ok:
            translated = (libre_response.json() or {}).get('translatedText')
    except Exception:
        translated = None

    # Fallback to MyMemory public API.
    if not translated:
        try:
            mymemory_response = http_requests.get(
                'https://api.mymemory.translated.net/get',
                params={
                    'q': text,
                    'langpair': f'auto|{target_lang}',
                },
                timeout=8,
            )
            if mymemory_response.ok:
                payload = mymemory_response.json() or {}
                translated = (payload.get('responseData') or {}).get('translatedText')
        except Exception:
            translated = None

    if not translated:
        return jsonify({'error': 'Translation service unavailable'}), 502

    return jsonify({'success': True, 'translated_text': translated}), 200

# ========================================
# CONTACT PROFILE ENDPOINT - PRIVACY AWARE
# ========================================

@app.route('/api/get-contact-profile', methods=['GET'])
@require_approved_user
@retry_on_locked()
def get_contact_profile():
    """Get contact's profile information for viewing (respects privacy settings)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    viewer_id = session['user_id']
    contact_pin = request.args.get('contact_pin', '').strip()
    
    if not contact_pin:
        print("❌ get-contact-profile: No contact_pin provided")
        return jsonify({'error': 'Contact PIN required'}), 400
    
    try:
        print(f"🔍 Fetching profile for contact: {contact_pin}")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, zeus_pin, full_name, profile_pic, about, created_at, last_seen
                FROM users
                WHERE zeus_pin = ?
            ''', (contact_pin,))
            
            contact = cursor.fetchone()
            
            if not contact:
                print(f"❌ Contact not found: {contact_pin}")
                return jsonify({'error': 'Contact not found'}), 404
            
            contact_id = contact[0]

            # Enforce contact relationship from authenticated viewer server-side.
            cursor.execute('''
                SELECT 1 FROM contacts
                WHERE user_id = ? AND contact_user_id = ? AND status = 'accepted'
                LIMIT 1
            ''', (viewer_id, contact_id))
            viewer_has_contact = cursor.fetchone() is not None

            cursor.execute('''
                SELECT 1 FROM contacts
                WHERE user_id = ? AND contact_user_id = ? AND status = 'accepted'
                LIMIT 1
            ''', (contact_id, viewer_id))
            contact_has_viewer = cursor.fetchone() is not None

            if not (viewer_has_contact or contact_has_viewer):
                return jsonify({'error': 'Not authorized to view this profile'}), 403
            
            # Get contact's privacy settings
            cursor.execute('''
                SELECT 
                    last_seen_visibility, profile_photo_visibility,
                    about_visibility, status_visibility, show_online_status
                FROM user_settings
                WHERE user_id = ?
            ''', (contact_id,))
            
            privacy_settings = cursor.fetchone()
            
            # Default visibility if not set
            if not privacy_settings:
                privacy_settings = ('myContacts', 'myContacts', 'myContacts', 'myContacts', 1)
            
            # Viewer relationship already enforced server-side above.
            is_contact = True
            
            # Helper function to check visibility
            def should_show(visibility_setting):
                if visibility_setting == 'everyone':
                    return True
                elif visibility_setting == 'myContacts':
                    return is_contact
                elif visibility_setting == 'nobody':
                    return False
                return False
            
            # Get online status with privacy respect
            from datetime import datetime
            last_seen = contact[6]
            status = 'offline'
            last_seen_formatted = None
            show_online = privacy_settings[4] if privacy_settings else 1
            
            if show_online and last_seen:
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen)
                    now = datetime.now()
                    
                    if (now - last_seen_dt).total_seconds() < 300:
                        status = 'online'
                    else:
                        last_seen_formatted = last_seen_dt.strftime('%Y-%m-%d %H:%M')
                except Exception as e:
                    print(f"⚠️ Date parsing error: {e}")
                    last_seen_formatted = 'Recently'
            
            # Apply privacy settings to returned data
            profile_pic = contact[3] if should_show(privacy_settings[1]) else None
            about = contact[4] if should_show(privacy_settings[2]) else None
            last_seen_value = contact[6] if should_show(privacy_settings[0]) else None
            
            print(f"✅ Profile found: {contact[2]} ({contact[1]})")
            
            return jsonify({
                'success': True,
                'contact': {
                    'zeus_pin': contact[1],
                    'full_name': contact[2] or 'Unknown',
                    'profile_pic': profile_pic or '',
                    'about': about or '',
                    'created_at': contact[5],
                    'last_seen': last_seen_value
                },
                'status': status if show_online else 'unknown',
                'last_seen_formatted': last_seen_formatted,
                'privacy_settings': {
                    'last_seen_visible': should_show(privacy_settings[0]),
                    'profile_photo_visible': should_show(privacy_settings[1]),
                    'about_visible': should_show(privacy_settings[2]),
                    'status_visible': should_show(privacy_settings[3])
                }
            }), 200
            
    except Exception as e:
        print(f"❌ get-contact-profile error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ========================================
# BLOCKED CONTACTS & FEEDBACK ENDPOINTS
# ========================================

@app.route('/api/get-blocked-contacts', methods=['GET', 'OPTIONS'])
@retry_on_locked()
def get_blocked_contacts():
    """Get list of blocked contacts for the current user"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get blocked contacts
            cursor.execute('''
                SELECT u.zeus_pin, u.full_name
                FROM contacts c
                JOIN users u ON c.contact_user_id = u.id
                WHERE c.user_id = ? AND c.status = 'blocked'
                ORDER BY c.created_at DESC
            ''', (user_id,))
            
            blocked = cursor.fetchall()
            blocked_list = [{'zeus_pin': row[0], 'full_name': row[1] or 'Unknown'} for row in blocked]
            
            print(f"✅ Retrieved {len(blocked_list)} blocked contacts for user {user_id}")
            
            return jsonify({
                'success': True,
                'count': len(blocked_list),
                'blocked_contacts': blocked_list
            }), 200
            
    except Exception as e:
        print(f"❌ get-blocked-contacts error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/unblock-from-settings', methods=['POST', 'OPTIONS'])
@retry_on_locked(max_retries=3, delay=0.5)
def unblock_from_settings():
    """Unblock a contact from settings page - BBM style bidirectional"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        contact_pin = data.get('contact_pin', '').strip()
        
        if not contact_pin:
            return jsonify({'error': 'Contact PIN required'}), 400
        
        user_id = session['user_id']
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get contact user ID and name
            cursor.execute('SELECT id, full_name FROM users WHERE zeus_pin = ?', (contact_pin,))
            contact = cursor.fetchone()
            
            if not contact:
                return jsonify({'error': 'Contact not found'}), 404
            
            contact_id = contact[0]
            contact_name = contact[1]
            
            # ============================================
            # BBM BIDIRECTIONAL UNBLOCKING
            # ============================================
            
            # Delete block direction 1: User → Contact
            cursor.execute('''
                DELETE FROM contacts
                WHERE user_id = ? AND contact_user_id = ? AND status = 'blocked'
            ''', (user_id, contact_id))
            
            count_1 = cursor.rowcount
            
            # Delete block direction 2: Contact → User (remove mutual block)
            cursor.execute('''
                DELETE FROM contacts
                WHERE user_id = ? AND contact_user_id = ? AND status = 'blocked'
            ''', (contact_id, user_id))
            
            count_2 = cursor.rowcount
            
            if count_1 == 0 and count_2 == 0:
                return jsonify({'error': 'Contact not blocked'}), 404
            
            conn.commit()
            
            print(f"✅ Unblocked from settings: User {user_id} unblocked {contact_name}")
            
            # Emit Socket.IO event (NOT broadcast to all)
            # Only notify the user and the unblocked user
            socketio.emit('contact_unblocked', {
                'user_id': user_id,
                'unblocked_user_id': contact_id,
                'unblocked_user_name': contact_name,
                'timestamp': datetime.now().isoformat()
            }, room=f"user:{user_id}")
            socketio.emit('contact_unblocked', {
                'user_id': user_id,
                'unblocked_user_id': contact_id,
                'unblocked_user_name': contact_name,
                'timestamp': datetime.now().isoformat()
            }, room=f"user:{contact_id}")
            
            return jsonify({
                'success': True,
                'message': f'{contact_name} has been unblocked'
            }), 200
            
    except Exception as e:
        print(f"❌ unblock-from-settings error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/submit-feedback', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked()
def submit_feedback():
    """Submit user feedback — persisted to database and notified to admin room."""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200

    try:
        data = request.get_json() or {}
        feedback_type = data.get('feedback_type', 'general').strip()
        message = data.get('message', '').strip()
        contact_email = data.get('contact_email', '').strip()

        if not feedback_type or not message:
            return jsonify({'error': 'Feedback type and message required'}), 400

        if len(message) < 5:
            return jsonify({'error': 'Message must be at least 5 characters'}), 400

        if len(message) > 1000:
            return jsonify({'error': 'Message must be less than 1000 characters'}), 400

        valid_types = {'bug', 'feature', 'general', 'complaint'}
        if feedback_type not in valid_types:
            feedback_type = 'general'

        user_id = session.get('user_id')

        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_feedback (user_id, feedback_type, message, contact_email, status)
                VALUES (?, ?, ?, ?, 'pending')
            ''', (user_id, feedback_type, message, contact_email))
            conn.commit()

        socketio.emit('new_feedback', {
            'user_id': user_id,
            'type': feedback_type,
            'message': message[:100]
        }, room='admins')

        print(f"📧 Feedback saved: type={feedback_type}, user={user_id}")

        return jsonify({
            'success': True,
            'message': 'Thank you! Your feedback has been received.'
        }), 200

    except Exception as e:
        print(f"❌ submit-feedback error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ========================================
# TYPING INDICATORS ENDPOINT
# ========================================

@app.route('/api/typing-indicator', methods=['POST', 'OPTIONS'])
@require_approved_user
@retry_on_locked()
def typing_indicator():
    """Update typing status (for future WebSocket implementation)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        data = request.get_json() or {}
        user_id = session['user_id']
        contact_pin = data.get('contact_pin', '').strip()
        is_typing = data.get('is_typing', False)

        if not contact_pin:
            return jsonify({'error': 'contact_pin required'}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT zeus_pin FROM users WHERE id = ?', (user_id,))
            user_row = cursor.fetchone()
            if not user_row:
                return jsonify({'error': 'User not found'}), 404
            user_pin = user_row[0]
        
        # For now, just log it. In production, use WebSocket or Redis pub/sub
        print(f"{'⌨️' if is_typing else '✅'} {user_pin} typing to {contact_pin}: {is_typing}")
        
        return jsonify({
            'success': True,
            'message': 'Typing status updated'
        }), 200
        
    except Exception as e:
        print(f"❌ typing-indicator error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ LOW-BANDWIDTH OPTIMIZATION ENDPOINTS ============

@app.route('/api/check-network-quality', methods=['GET', 'OPTIONS'])
def check_network_quality():
    """Check network quality and recommend compression/queuing strategy"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        # Returns network quality estimation
        quality = get_network_quality()
        return jsonify({
            'success': True,
            'network': quality
        }), 200
    except Exception as e:
        print(f"❌ check_network_quality error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-message-queue', methods=['POST', 'OPTIONS'])
@rate_limit('process-message-queue')
def process_queue_endpoint():
    """Process queued messages with exponential backoff retries"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        # Allow authenticated standard users and admin sessions only.
        if 'user_id' not in session and 'admin_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        successful, failed = process_message_queue()
        return jsonify({
            'success': True,
            'successful': successful,
            'failed': failed,
            'message': f'{successful} messages sent, {failed} will retry'
        }), 200
    except Exception as e:
        print(f"❌ process_queue_endpoint error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/queue-message', methods=['POST', 'OPTIONS'])
def queue_message_endpoint():
    """Queue a message for later delivery (for offline scenarios)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        data = request.get_json()
        receiver_pin = data.get('receiver_pin', '').strip()
        content = data.get('content', '').strip()
        ttl_seconds = data.get('ttl', 3600)
        
        if not receiver_pin or not content:
            return jsonify({'error': 'Missing receiver_pin or content'}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find receiver
            cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (receiver_pin,))
            receiver = cursor.fetchone()
            if not receiver:
                return jsonify({'error': 'Receiver not found'}), 404
            
            receiver_id = receiver[0]
        
        # Queue the message
        queue_id = queue_message_for_retry(session['user_id'], receiver_id, content, ttl_seconds)
        
        if queue_id:
            return jsonify({
                'success': True,
                'queue_id': queue_id,
                'message': 'Message queued for delivery'
            }), 200
        else:
            return jsonify({'error': 'Failed to queue message'}), 500
    
    except Exception as e:
        print(f"❌ queue_message_endpoint error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-queued-messages', methods=['GET', 'OPTIONS'])
def get_queued_messages():
    """Get count of messages awaiting delivery"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) as count FROM message_queue
                WHERE user_id = ? AND queue_status = 'pending'
            ''', (session['user_id'],))
            
            result = cursor.fetchone()
            count = result[0] if result else 0
        
        return jsonify({
            'success': True,
            'queued_count': count,
            'message': f'{count} messages awaiting delivery'
        }), 200
    
    except Exception as e:
        print(f"❌ get_queued_messages error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================
# GHOST FORUMS - ANONYMOUS COMMUNITY DISCUSSIONS
# ============================================

def get_forum_with_access(cursor, forum_id, user_id=None):
    """Fetch a forum row with membership metadata for access checks."""
    cursor.execute(
        '''
        SELECT f.*,
               EXISTS(
                   SELECT 1 FROM forum_members fm
                   WHERE fm.forum_id = f.id AND fm.user_id = ?
               ) AS is_member,
               (
                   SELECT role FROM forum_members fm
                   WHERE fm.forum_id = f.id AND fm.user_id = ?
                   LIMIT 1
               ) AS member_role,
               (
                   SELECT COUNT(*) FROM forum_members fm
                   WHERE fm.forum_id = f.id
               ) AS live_member_count,
               (
                   SELECT COUNT(*) FROM forum_posts fp
                   WHERE fp.forum_id = f.id
               ) AS live_post_count
        FROM ghost_forums f
        WHERE f.id = ?
        ''',
        (user_id or 0, user_id or 0, forum_id),
    )
    return cursor.fetchone()


def ensure_forum_membership(cursor, forum_id, user_id, role='member'):
    """Insert forum membership if it does not exist and refresh counts."""
    cursor.execute(
        '''
        INSERT OR IGNORE INTO forum_members (forum_id, user_id, role)
        VALUES (?, ?, ?)
        ''',
        (forum_id, user_id, role),
    )
    cursor.execute(
        '''
        UPDATE ghost_forums
        SET member_count = (
                SELECT COUNT(*) FROM forum_members WHERE forum_id = ?
            ),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''',
        (forum_id, forum_id),
    )


@app.route('/ghost-forums')
def ghost_forums():
    """Ghost forums landing page."""
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('ghost-forums.html', forum_id=None)


@app.route('/ghost-forums/forum/<int:forum_id>')
def ghost_forum_detail_page(forum_id):
    """Ghost forums detail page using the shared template."""
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('ghost-forums.html', forum_id=forum_id)


@app.route('/api/forums', methods=['GET'])
@require_approved_user
def get_forums():
    """List public forums plus private forums the user belongs to."""
    user_id = session['user_id']

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT f.*,
                   (
                       SELECT COUNT(*) FROM forum_members fm
                       WHERE fm.forum_id = f.id
                   ) AS live_member_count,
                   (
                       SELECT COUNT(*) FROM forum_posts fp
                       WHERE fp.forum_id = f.id
                   ) AS live_post_count,
                   EXISTS(
                       SELECT 1 FROM forum_members fm
                       WHERE fm.forum_id = f.id AND fm.user_id = ?
                   ) AS is_member
            FROM ghost_forums f
            WHERE f.is_private = 0
               OR EXISTS(
                   SELECT 1 FROM forum_members fm
                   WHERE fm.forum_id = f.id AND fm.user_id = ?
               )
            ORDER BY f.updated_at DESC, f.created_at DESC
            ''',
            (user_id, user_id),
        )
        forums = cursor.fetchall()

    return jsonify({
        'success': True,
        'forums': [
            {
                **dict(forum),
                'member_count': forum['live_member_count'],
                'post_count': forum['live_post_count'],
                'is_member': bool(forum['is_member']),
            }
            for forum in forums
        ]
    }), 200


@app.route('/api/forums/create', methods=['POST'])
@csrf_protect
@require_approved_user
def create_forum():
    """Create a new ghost forum."""
    user_id = session['user_id']
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    description = (data.get('description') or '').strip()
    category = (data.get('category') or 'general').strip() or 'general'
    is_private = 1 if data.get('is_private') else 0

    if not name or len(name) < 3:
        return jsonify({'error': 'Forum name must be at least 3 characters'}), 400
    if not description or len(description) < 5:
        return jsonify({'error': 'Forum description must be at least 5 characters'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO ghost_forums (name, description, category, creator_id, is_private, member_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ''',
            (name, description, category, user_id, is_private),
        )
        forum_id = cursor.lastrowid
        cursor.execute(
            'INSERT INTO forum_members (forum_id, user_id, role) VALUES (?, ?, ?)',
            (forum_id, user_id, 'admin'),
        )
        conn.commit()

    return jsonify({'success': True, 'forum_id': forum_id}), 201


@app.route('/api/forums/<int:forum_id>', methods=['GET'])
@require_approved_user
def get_forum_detail(forum_id):
    """Get forum metadata and top-level posts for a specific forum."""
    user_id = session['user_id']

    with admin_get_db() as conn:
        cursor = conn.cursor()
        forum = get_forum_with_access(cursor, forum_id, user_id)
        if not forum:
            return jsonify({'error': 'Forum not found'}), 404
        if forum['is_private'] and not forum['is_member']:
            return jsonify({'error': 'Access denied'}), 403

        if not forum['is_member']:
            ensure_forum_membership(cursor, forum_id, user_id)

        cursor.execute(
            '''
            SELECT fp.*,
                   u.full_name,
                   u.zeus_pin,
                   (
                       SELECT COUNT(*) FROM forum_replies fr
                       WHERE fr.post_id = fp.id
                   ) AS live_reply_count,
                   EXISTS(
                       SELECT 1 FROM forum_votes fv
                       WHERE fv.post_id = fp.id AND fv.user_id = ?
                   ) AS has_voted,
                   (
                       SELECT vote_type FROM forum_votes fv
                       WHERE fv.post_id = fp.id AND fv.user_id = ?
                       LIMIT 1
                   ) AS user_vote
            FROM forum_posts fp
            JOIN users u ON fp.user_id = u.id
            WHERE fp.forum_id = ?
            ORDER BY fp.is_pinned DESC, fp.created_at DESC
            ''',
            (user_id, user_id, forum_id),
        )
        posts = cursor.fetchall()

        conn.commit()

    return jsonify({
        'success': True,
        'forum': {
            **dict(forum),
            'member_count': forum['live_member_count'],
            'post_count': forum['live_post_count'],
            'is_member': bool(forum['is_member']),
        },
        'posts': [
            {
                **dict(post),
                'reply_count': post['live_reply_count'],
                'author_label': 'Anonymous' if post['is_anonymous'] else (post['full_name'] or post['zeus_pin']),
                'has_voted': bool(post['has_voted']),
                'user_vote': post['user_vote'] or 0,
            }
            for post in posts
        ],
    }), 200


@app.route('/api/forums/<int:forum_id>/posts', methods=['POST'])
@csrf_protect
@require_approved_user
def create_forum_post(forum_id):
    """Create a top-level forum post."""
    user_id = session['user_id']
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()
    is_anonymous = 0 if data.get('is_anonymous') is False else 1

    if not title or len(title) < 3:
        return jsonify({'error': 'Post title must be at least 3 characters'}), 400
    if not content or len(content) < 5:
        return jsonify({'error': 'Post content must be at least 5 characters'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        forum = get_forum_with_access(cursor, forum_id, user_id)
        if not forum:
            return jsonify({'error': 'Forum not found'}), 404
        if forum['is_private'] and not forum['is_member']:
            return jsonify({'error': 'Access denied'}), 403

        ensure_forum_membership(cursor, forum_id, user_id)
        cursor.execute(
            '''
            INSERT INTO forum_posts (forum_id, user_id, title, content, is_anonymous)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (forum_id, user_id, title, content, is_anonymous),
        )
        post_id = cursor.lastrowid
        cursor.execute(
            '''
            UPDATE ghost_forums
            SET post_count = (
                    SELECT COUNT(*) FROM forum_posts WHERE forum_id = ?
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            ''',
            (forum_id, forum_id),
        )
        conn.commit()

    return jsonify({'success': True, 'post_id': post_id}), 201


@app.route('/api/forum-posts/<int:post_id>/replies', methods=['GET'])
@require_approved_user
def get_forum_replies(post_id):
    """Get replies for a forum post."""
    user_id = session['user_id']

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT forum_id FROM forum_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        forum = get_forum_with_access(cursor, post['forum_id'], user_id)
        if not forum or (forum['is_private'] and not forum['is_member']):
            return jsonify({'error': 'Access denied'}), 403

        cursor.execute(
            '''
            SELECT fr.*, u.full_name, u.zeus_pin
            FROM forum_replies fr
            JOIN users u ON fr.user_id = u.id
            WHERE fr.post_id = ?
            ORDER BY fr.created_at ASC
            ''',
            (post_id,),
        )
        replies = cursor.fetchall()

    return jsonify({
        'success': True,
        'replies': [
            {
                **dict(reply),
                'author_label': 'Anonymous' if reply['is_anonymous'] else (reply['full_name'] or reply['zeus_pin']),
            }
            for reply in replies
        ],
    }), 200


@app.route('/api/forum-posts/<int:post_id>/replies', methods=['POST'])
@csrf_protect
@require_approved_user
def create_forum_reply(post_id):
    """Create a reply on a forum post."""
    user_id = session['user_id']
    data = request.get_json(silent=True) or {}
    content = (data.get('content') or '').strip()
    is_anonymous = 0 if data.get('is_anonymous') is False else 1

    if not content or len(content) < 2:
        return jsonify({'error': 'Reply must be at least 2 characters'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT forum_id, is_locked FROM forum_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        if post['is_locked']:
            return jsonify({'error': 'Post is locked'}), 403

        forum = get_forum_with_access(cursor, post['forum_id'], user_id)
        if not forum or (forum['is_private'] and not forum['is_member']):
            return jsonify({'error': 'Access denied'}), 403

        ensure_forum_membership(cursor, post['forum_id'], user_id)
        cursor.execute(
            '''
            INSERT INTO forum_replies (post_id, user_id, content, is_anonymous)
            VALUES (?, ?, ?, ?)
            ''',
            (post_id, user_id, content, is_anonymous),
        )
        reply_id = cursor.lastrowid
        cursor.execute(
            '''
            UPDATE forum_posts
            SET reply_count = (
                    SELECT COUNT(*) FROM forum_replies WHERE post_id = ?
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            ''',
            (post_id, post_id),
        )
        conn.commit()

    return jsonify({'success': True, 'reply_id': reply_id}), 201


@app.route('/api/forum-posts/<int:post_id>/vote', methods=['POST'])
@csrf_protect
@require_approved_user
def vote_forum_post(post_id):
    """Upvote or downvote a forum post without double-voting."""
    user_id = session['user_id']
    data = request.get_json(silent=True) or {}
    vote_type = int(data.get('vote_type', 0)) if str(data.get('vote_type', 0)).lstrip('-').isdigit() else 0
    if vote_type not in (-1, 1):
        return jsonify({'error': 'Invalid vote type'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT forum_id FROM forum_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        forum = get_forum_with_access(cursor, post['forum_id'], user_id)
        if not forum or (forum['is_private'] and not forum['is_member']):
            return jsonify({'error': 'Access denied'}), 403

        cursor.execute(
            'SELECT vote_type FROM forum_votes WHERE post_id = ? AND user_id = ?',
            (post_id, user_id),
        )
        existing = cursor.fetchone()

        if existing:
            previous_vote = existing['vote_type']
            if previous_vote == vote_type:
                return jsonify({'success': True, 'unchanged': True}), 200

            cursor.execute(
                'UPDATE forum_votes SET vote_type = ?, created_at = CURRENT_TIMESTAMP WHERE post_id = ? AND user_id = ?',
                (vote_type, post_id, user_id),
            )
            if previous_vote == 1:
                cursor.execute('UPDATE forum_posts SET upvotes = upvotes - 1 WHERE id = ?', (post_id,))
            else:
                cursor.execute('UPDATE forum_posts SET downvotes = downvotes - 1 WHERE id = ?', (post_id,))
        else:
            cursor.execute(
                'INSERT INTO forum_votes (post_id, user_id, vote_type) VALUES (?, ?, ?)',
                (post_id, user_id, vote_type),
            )

        if vote_type == 1:
            cursor.execute('UPDATE forum_posts SET upvotes = upvotes + 1 WHERE id = ?', (post_id,))
        else:
            cursor.execute('UPDATE forum_posts SET downvotes = downvotes + 1 WHERE id = ?', (post_id,))

        cursor.execute('SELECT upvotes, downvotes FROM forum_posts WHERE id = ?', (post_id,))
        counts = cursor.fetchone()
        conn.commit()

    return jsonify({
        'success': True,
        'upvotes': counts['upvotes'],
        'downvotes': counts['downvotes'],
    }), 200


# ============================================
# ULTIMATE GHOST COMMUNITY ENDPOINTS
# ============================================

def get_ghost_ban_status(user_id):
    """Return active ghost-community ban details for a user, if any."""
    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT ghost_banned, ghost_ban_reason, ghost_ban_expires
            FROM users
            WHERE id = ?
            ''',
            (user_id,),
        )
        row = cursor.fetchone()

    if not row or not row['ghost_banned']:
        return None

    expires_at = row['ghost_ban_expires']
    if expires_at:
        try:
            if datetime.fromisoformat(str(expires_at).replace(' ', 'T')) <= datetime.now():
                with admin_get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        '''
                        UPDATE users
                        SET ghost_banned = 0,
                            ghost_ban_reason = NULL,
                            ghost_ban_expires = NULL
                        WHERE id = ?
                        ''',
                        (user_id,),
                    )
                    conn.commit()
                return None
        except Exception:
            pass

    return {
        'reason': row['ghost_ban_reason'] or 'No reason provided',
        'expires_at': row['ghost_ban_expires'],
    }


def ensure_ghost_access(user_id):
    """Return an error response if user is banned from Ghost Community."""
    ban = get_ghost_ban_status(user_id)
    if not ban:
        return None
    return jsonify({
        'error': 'Ghost Community access restricted',
        'reason': ban['reason'],
        'expires_at': ban['expires_at'],
    }), 403


@app.route('/ghost-ultimate')
def ghost_ultimate():
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('ghost-ultimate.html')


@app.route('/creator-wallet')
@require_approved_user
def creator_wallet_page():
    block = ensure_ghost_access(session['user_id'])
    if block:
        return redirect('/chat.html')
    return render_template('creator-wallet.html')


@app.route('/payment/ghost/<int:post_id>')
@require_approved_user
def ghost_payment_page(post_id):
    """Placeholder payment bridge for ghost content unlocks."""
    return jsonify({
        'success': True,
        'post_id': post_id,
        'message': 'Payment initiated. Use /api/ghost/pay for unlock confirmation.'
    })


@app.route('/api/ghost/feed', methods=['GET'])
@require_approved_user
def ghost_feed():
    user_id = session['user_id']
    block = ensure_ghost_access(user_id)
    if block:
        return block

    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    page = max(1, page)
    limit = max(1, min(limit, 20))
    offset = (page - 1) * limit

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT gp.*,
                   CASE WHEN gp.is_paid = 1 AND gp.user_id != ? AND gp.id NOT IN (
                       SELECT post_id FROM ghost_purchases WHERE buyer_id = ?
                   ) THEN 1 ELSE 0 END AS is_locked,
                   CASE WHEN EXISTS(
                       SELECT 1 FROM ghost_purchases
                       WHERE post_id = gp.id AND buyer_id = ?
                   ) THEN 1 ELSE 0 END AS user_purchased,
                   CASE WHEN EXISTS(
                       SELECT 1 FROM ghost_votes
                       WHERE post_id = gp.id AND user_id = ? AND vote_type = 1
                   ) THEN 1 ELSE 0 END AS user_upvoted,
                   CASE WHEN EXISTS(
                       SELECT 1 FROM ghost_votes
                       WHERE post_id = gp.id AND user_id = ? AND vote_type = -1
                   ) THEN 1 ELSE 0 END AS user_downvoted,
                   SUBSTR(u.zeus_pin, 1, 8) || '-XXXX' AS anonymous_id
            FROM ghost_posts gp
            JOIN users u ON gp.user_id = u.id
            WHERE gp.expires_at > datetime('now')
              AND gp.status = 'approved'
            ORDER BY gp.created_at DESC
            LIMIT ? OFFSET ?
            ''',
            (user_id, user_id, user_id, user_id, user_id, limit, offset),
        )
        rows = cursor.fetchall()

        posts = [dict(row) for row in rows]
        comments_by_post = {}

        if posts:
            post_ids = [post['id'] for post in posts]
            placeholders = ','.join('?' * len(post_ids))
            cursor.execute(
                f'''
                SELECT *
                FROM (
                    SELECT gc.*,
                           SUBSTR(u.zeus_pin, 1, 8) || '-XXXX' AS anonymous_id,
                           ROW_NUMBER() OVER (
                               PARTITION BY gc.post_id
                               ORDER BY gc.created_at ASC
                           ) AS comment_rank
                    FROM ghost_comments gc
                    JOIN users u ON gc.user_id = u.id
                    WHERE gc.post_id IN ({placeholders})
                      AND gc.expires_at > datetime('now')
                ) ranked_comments
                WHERE comment_rank <= 5
                ORDER BY post_id ASC, created_at ASC
                ''',
                post_ids,
            )

            for comment_row in cursor.fetchall():
                comment = dict(comment_row)
                comment.pop('comment_rank', None)
                comments_by_post.setdefault(comment['post_id'], []).append(comment)

        for post in posts:
            post['comments'] = comments_by_post.get(post['id'], [])
            if post['is_locked']:
                post['content'] = post.get('preview_text') or 'This post contains paid content.'

    return jsonify({'success': True, 'posts': posts}), 200


@app.route('/api/ghost/create', methods=['POST'])
@csrf_protect
@require_approved_user
def ghost_create_post():
    user_id = session['user_id']
    block = ensure_ghost_access(user_id)
    if block:
        return block

    title = (request.form.get('title') or '').strip()
    content = (request.form.get('content') or '').strip()
    is_paid = str(request.form.get('is_paid', 'false')).lower() == 'true'
    preview_text = (request.form.get('preview_text') or '').strip()
    media = request.files.get('media')

    if not title:
        return jsonify({'error': 'Title required'}), 400

    try:
        price = float(request.form.get('price', 0) or 0)
    except ValueError:
        return jsonify({'error': 'Invalid price'}), 400

    if is_paid and price not in [5, 10, 20, 50, 100]:
        return jsonify({'error': 'Invalid price'}), 400

    media_url = None
    media_type = None
    if media and media.filename:
        os.makedirs('uploads/ghost', exist_ok=True)
        safe_name = ''.join(c for c in media.filename if c.isalnum() or c in ('.', '_', '-')) or 'media.bin'
        filename = f"ghost_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_name}"
        filepath = os.path.join('uploads/ghost', filename)
        media.save(filepath)
        media_url = f'/uploads/ghost/{filename}'
        media_type = 'video' if (media.mimetype or '').startswith('video') else 'image'

    expires_at = ghost_utc_now() + timedelta(hours=24)

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO ghost_posts
                (user_id, title, content, media_url, media_type, is_paid, price, preview_text, expires_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_ai')
            ''',
            (
                user_id,
                title,
                content,
                media_url,
                media_type,
                1 if is_paid else 0,
                price if is_paid else 0,
                preview_text,
                expires_at.isoformat(),
            ),
        )
        post_id = cursor.lastrowid
        cursor.execute(
            '''
            INSERT INTO moderation_queue (post_id, user_id, content_text, media_url, status)
            VALUES (?, ?, ?, ?, 'pending')
            ''',
            (post_id, user_id, f'{title}\n{content}'.strip(), media_url),
        )
        conn.commit()

    return jsonify({'success': True, 'post_id': post_id}), 201


@app.route('/api/ghost/pay', methods=['POST'])
@csrf_protect
@require_approved_user
def ghost_pay_for_post():
    buyer_id = session['user_id']
    block = ensure_ghost_access(buyer_id)
    if block:
        return block

    data = request.get_json(silent=True) or {}
    post_id = data.get('post_id')
    if not post_id:
        return jsonify({'error': 'post_id required'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM ghost_purchases WHERE post_id = ? AND buyer_id = ?', (post_id, buyer_id))
        if cursor.fetchone():
            return jsonify({'error': 'Already purchased'}), 400

        cursor.execute(
            '''
            SELECT user_id, price, is_paid, status, expires_at
            FROM ghost_posts
            WHERE id = ?
            ''',
            (post_id,),
        )
        post = cursor.fetchone()
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        if post['status'] != 'approved' or post['expires_at'] <= ghost_utc_now().isoformat():
            return jsonify({'error': 'Post unavailable'}), 400
        if not post['is_paid']:
            return jsonify({'error': 'Post is free'}), 400
        if post['user_id'] == buyer_id:
            return jsonify({'error': 'You already own this content'}), 400

        creator_id = post['user_id']
        amount_paid = float(post['price'] or 0)
        creator_earnings = round(amount_paid * 0.80, 2)
        zeuschat_commission = round(amount_paid - creator_earnings, 2)

        cursor.execute(
            '''
            INSERT INTO ghost_purchases
                (post_id, buyer_id, amount_paid, creator_earnings, zeuschat_commission)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (post_id, buyer_id, amount_paid, creator_earnings, zeuschat_commission),
        )

        cursor.execute(
            '''
            INSERT INTO creator_wallets (user_id, balance, total_earned, pending_payout, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                balance = balance + excluded.balance,
                total_earned = total_earned + excluded.total_earned,
                pending_payout = pending_payout + excluded.pending_payout,
                updated_at = CURRENT_TIMESTAMP
            ''',
            (creator_id, creator_earnings, creator_earnings, creator_earnings),
        )

        cursor.execute(
            '''
            UPDATE ghost_posts
            SET paid_view_count = paid_view_count + 1,
                total_earnings = total_earnings + ?
            WHERE id = ?
            ''',
            (creator_earnings, post_id),
        )

        week_anchor = ghost_utc_now()
        week_start = (week_anchor - timedelta(days=week_anchor.weekday())).date().isoformat()
        week_end = (datetime.fromisoformat(week_start) + timedelta(days=6)).date().isoformat()
        cursor.execute(
            '''
            INSERT INTO creator_earnings
                (user_id, week_start, week_end, total_revenue, zeuschat_commission, creator_payout)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, week_start, week_end) DO UPDATE SET
                total_revenue = total_revenue + excluded.total_revenue,
                zeuschat_commission = zeuschat_commission + excluded.zeuschat_commission,
                creator_payout = creator_payout + excluded.creator_payout
            ''',
            (creator_id, week_start, week_end, amount_paid, zeuschat_commission, creator_earnings),
        )

        conn.commit()

    return jsonify({'success': True, 'redirect_url': f'/payment/ghost/{post_id}'}), 200


@app.route('/api/ghost/vote', methods=['POST'])
@csrf_protect
@require_approved_user
def ghost_vote():
    user_id = session['user_id']
    block = ensure_ghost_access(user_id)
    if block:
        return block

    data = request.get_json(silent=True) or {}
    post_id = data.get('post_id')
    vote_type = data.get('vote_type')
    if isinstance(vote_type, str):
        normalized_vote = vote_type.strip().lower()
        if normalized_vote in ('up', 'upvote', '1', '+1'):
            vote_type = 1
        elif normalized_vote in ('down', 'downvote', '-1'):
            vote_type = -1
    if vote_type not in (-1, 1):
        return jsonify({'error': 'Invalid vote type'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM ghost_posts WHERE id = ? AND status = \"approved\"', (post_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Post not found'}), 404

        cursor.execute('SELECT id, vote_type FROM ghost_votes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
        existing = cursor.fetchone()

        if existing and existing['vote_type'] == vote_type:
            cursor.execute('DELETE FROM ghost_votes WHERE id = ?', (existing['id'],))
        elif existing:
            cursor.execute('UPDATE ghost_votes SET vote_type = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?', (vote_type, existing['id']))
        else:
            cursor.execute('INSERT INTO ghost_votes (post_id, user_id, vote_type) VALUES (?, ?, ?)', (post_id, user_id, vote_type))

        cursor.execute(
            '''
            UPDATE ghost_posts
            SET upvotes = (SELECT COUNT(*) FROM ghost_votes WHERE post_id = ? AND vote_type = 1),
                downvotes = (SELECT COUNT(*) FROM ghost_votes WHERE post_id = ? AND vote_type = -1)
            WHERE id = ?
            ''',
            (post_id, post_id, post_id),
        )
        cursor.execute('SELECT upvotes, downvotes FROM ghost_posts WHERE id = ?', (post_id,))
        counts = cursor.fetchone()
        conn.commit()

    return jsonify({'success': True, 'upvotes': counts['upvotes'], 'downvotes': counts['downvotes']}), 200


@app.route('/api/ghost/report', methods=['POST'])
@csrf_protect
@require_approved_user
def ghost_report():
    reporter_id = session['user_id']
    block = ensure_ghost_access(reporter_id)
    if block:
        return block

    data = request.get_json(silent=True) or {}
    post_id = data.get('post_id')
    reason = (data.get('reason') or '').strip()
    details = (data.get('details') or '').strip()
    if not post_id or not reason:
        return jsonify({'error': 'post_id and reason are required'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO ghost_reports (post_id, reporter_id, reason, details, status)
            VALUES (?, ?, ?, ?, 'pending')
            ''',
            (post_id, reporter_id, reason, details),
        )
        cursor.execute(
            '''
            UPDATE ghost_posts
            SET report_count = report_count + 1,
                is_flagged = CASE WHEN report_count + 1 >= 3 THEN 1 ELSE is_flagged END
            WHERE id = ?
            ''',
            (post_id,),
        )
        conn.commit()

    return jsonify({'success': True, 'message': 'Report submitted. Admin will review.'}), 201


@app.route('/api/ghost/comment', methods=['POST'])
@csrf_protect
@require_approved_user
def ghost_comment():
    user_id = session['user_id']
    block = ensure_ghost_access(user_id)
    if block:
        return block

    data = request.get_json(silent=True) or {}
    post_id = data.get('post_id')
    content = (data.get('content') or '').strip()
    parent_id = data.get('parent_id')
    if not post_id or not content:
        return jsonify({'error': 'post_id and content are required'}), 400

    expires_at = ghost_utc_now() + timedelta(hours=24)
    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO ghost_comments (post_id, user_id, parent_comment_id, content, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (post_id, user_id, parent_id, content, expires_at.isoformat()),
        )
        cursor.execute('UPDATE ghost_posts SET comment_count = comment_count + 1 WHERE id = ?', (post_id,))
        conn.commit()

    return jsonify({'success': True}), 201


@app.route('/api/ghost/comments/<int:post_id>', methods=['GET'])
@require_approved_user
def ghost_get_comments(post_id):
    user_id = session['user_id']
    block = ensure_ghost_access(user_id)
    if block:
        return block

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT gc.*, SUBSTR(u.zeus_pin, 1, 8) || '-XXXX' AS anonymous_id
            FROM ghost_comments gc
            JOIN users u ON gc.user_id = u.id
            WHERE gc.post_id = ? AND gc.expires_at > datetime('now')
            ORDER BY gc.created_at ASC
            ''',
            (post_id,),
        )
        comments = cursor.fetchall()

    return jsonify({'success': True, 'comments': [dict(c) for c in comments]}), 200


@app.route('/api/ghost/wallet', methods=['GET'])
@require_approved_user
def ghost_wallet_summary():
    user_id = session['user_id']
    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT balance, total_earned, total_withdrawn, pending_payout, last_withdrawal
            FROM creator_wallets
            WHERE user_id = ?
            ''',
            (user_id,),
        )
        wallet = cursor.fetchone()

        cursor.execute(
            '''
            SELECT week_start, week_end, total_revenue, zeuschat_commission, creator_payout, is_paid, paid_at
            FROM creator_earnings
            WHERE user_id = ?
            ORDER BY week_start DESC
            LIMIT 8
            ''',
            (user_id,),
        )
        weekly = cursor.fetchall()

    wallet_data = dict(wallet) if wallet else {
        'balance': 0,
        'total_earned': 0,
        'total_withdrawn': 0,
        'pending_payout': 0,
        'last_withdrawal': None,
    }
    return jsonify({'success': True, 'wallet': wallet_data, 'weekly_earnings': [dict(w) for w in weekly]}), 200


# ============================================
# GHOST MARKET - USER ENDPOINTS
# ============================================

@app.route('/ghost-market')
def ghost_market():
    """Ghost Market main page"""
    return render_template('ghost-market.html')

@app.route('/ghost-market/sell')
def ghost_market_sell():
    """Sell item page"""
    if 'user_id' not in session:
        return redirect('/login.html')
    if get_user_subscription_tier(session['user_id']) == 'free':
        return redirect('/subscription')
    return render_template('ghost-market-sell.html')

@app.route('/ghost-market/apply-seller')
def ghost_market_apply():
    """Apply to become a seller page."""
    if 'user_id' not in session:
        return redirect('/login.html')
    if get_user_subscription_tier(session['user_id']) == 'free':
        return redirect('/subscription')
    return render_template('ghost-market-apply.html')

# ============================================
# LEGAL PAGES
# ============================================

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/kyc-policy')
def kyc_policy():
    return render_template('kyc-policy.html')

@app.route('/ghost-market-policy')
def ghost_market_policy():
    return render_template('ghost-market-policy.html')

@app.route('/refund-policy')
def refund_policy():
    return render_template('refund-policy.html')

@app.route('/cookie-policy')
def cookie_policy():
    return render_template('cookie-policy.html')

@app.route('/acceptable-use')
def acceptable_use():
    return render_template('acceptable-use.html')

@app.route('/api/ghost-market/items', methods=['GET'])
def get_ghost_market_items():
    """Get all approved items plus current user's pending/rejected items."""
    user_id = session.get('user_id')
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip()

    with admin_get_db() as conn:
        cursor = conn.cursor()

        approved_query = '''
            SELECT gmi.*,
                   SUBSTR(u.zeus_pin, 1, 8) || '-XXXX' as seller_pin_half,
                   'approved' as display_status
            FROM ghost_market_items gmi
            JOIN ghost_market_sellers gms ON gmi.seller_id = gms.user_id
            JOIN users u ON gms.user_id = u.id
            WHERE gmi.status = 'approved'
              AND (gmi.expires_at IS NULL OR gmi.expires_at > CURRENT_TIMESTAMP)
        '''
        approved_params = []

        if search:
            approved_query += ' AND (gmi.title LIKE ? OR gmi.description LIKE ?)'
            search_param = '%' + search + '%'
            approved_params.extend([search_param, search_param])

        if category:
            approved_query += ' AND gmi.category = ?'
            approved_params.append(category)

        approved_query += ' ORDER BY gmi.created_at DESC LIMIT 100'
        cursor.execute(approved_query, approved_params)
        approved_items = cursor.fetchall()

        pending_items = []
        if user_id:
            pending_query = '''
                SELECT gmi.*,
                       SUBSTR(u.zeus_pin, 1, 8) || '-XXXX' as seller_pin_half,
                       gmi.status as display_status
                FROM ghost_market_items gmi
                JOIN ghost_market_sellers gms ON gmi.seller_id = gms.user_id
                JOIN users u ON gms.user_id = u.id
                WHERE gmi.seller_id = ?
                  AND gmi.status IN ('pending_approval', 'rejected')
            '''
            pending_params = [user_id]

            if search:
                pending_query += ' AND (gmi.title LIKE ? OR gmi.description LIKE ?)'
                search_param = '%' + search + '%'
                pending_params.extend([search_param, search_param])

            if category:
                pending_query += ' AND gmi.category = ?'
                pending_params.append(category)

            pending_query += ' ORDER BY gmi.created_at DESC'
            cursor.execute(pending_query, pending_params)
            pending_items = cursor.fetchall()

        all_items = list(pending_items) + list(approved_items)

        return jsonify({
            'success': True,
            'items': [
                {
                    'id': item['id'],
                    'title': item['title'],
                    'description': item['description'],
                    'price': item['price'],
                    'images': item['images'],
                    'category': item['category'],
                    'condition': item['condition'],
                    'seller_id': item['seller_id'],
                    'seller_pin_half': item['seller_pin_half'],
                    'status': item['display_status'],
                    'is_owner': bool(user_id and item['seller_id'] == user_id),
                    'rejection_reason': item['rejection_reason'] if item['display_status'] == 'rejected' else None,
                    'created_at': item['created_at']
                }
                for item in all_items
            ]
        })

@app.route('/api/ghost-market/seller-status', methods=['GET'])
@require_approved_user
def ghost_market_seller_status():
    """Check if user is an approved seller"""
    user_id = session['user_id']

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT application_status FROM ghost_market_sellers WHERE user_id = ?',
            (user_id,)
        )
        seller = cursor.fetchone()

    return jsonify({
        'is_seller': seller is not None and seller['application_status'] == 'approved',
        'status': seller['application_status'] if seller else 'not_applied'
    })

@app.route('/api/ghost-market/apply-seller', methods=['POST'])
@csrf_protect
@require_approved_user
def apply_ghost_market_seller():
    """Apply to become a Ghost Market seller"""
    user_id = session['user_id']
    if get_user_subscription_tier(user_id) == 'free':
        return jsonify({'error': 'Only Pro and Teams subscribers can sell on Ghost Market'}), 403

    data = request.get_json() or {}
    store_name = data.get('store_name', '').strip()
    store_description = data.get('store_description', '').strip()

    if not store_name:
        return jsonify({'error': 'Store name is required'}), 400

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO ghost_market_sellers (user_id, store_name, store_description, application_status)
            VALUES (?, ?, ?, 'pending')
        ''', (user_id, store_name, store_description))
        conn.commit()

        socketio.emit('new_seller_application', {
            'user_id': user_id,
            'store_name': store_name
        }, room='admins')

    return jsonify({'success': True, 'message': 'Application submitted for admin review'})

@app.route('/api/ghost-market/submit-item', methods=['POST'])
@csrf_protect
@require_approved_user
def submit_ghost_market_item():
    """Submit item for admin approval"""
    user_id = session['user_id']

    if get_user_subscription_tier(user_id) == 'free':
        return jsonify({'error': 'Only Pro and Teams subscribers can list items'}), 403

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT application_status FROM ghost_market_sellers WHERE user_id = ?',
            (user_id,)
        )
        seller = cursor.fetchone()

    if not seller or seller['application_status'] != 'approved':
        return jsonify({'error': 'You must be an approved seller to list items'}), 403

    title = (request.form.get('title') or '').strip()
    category = (request.form.get('category') or '').strip()
    condition = (request.form.get('condition') or '').strip()
    price_raw = request.form.get('price', '')
    description = (request.form.get('description') or '').strip()
    images = request.files.getlist('images')

    if not title or not price_raw or not description:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        price = float(price_raw)
        if price <= 0:
            raise ValueError
    except ValueError:
        return jsonify({'error': 'Invalid price'}), 400

    from datetime import datetime, timedelta
    os.makedirs('uploads/ghost_market', exist_ok=True)
    image_paths = []
    saver_settings = get_data_saver_preferences(user_id)

    for img in images[:5]:
        safe_name = ''.join(
            c for c in img.filename if c.isalnum() or c in ('.', '_', '-')
        ) or 'upload'
        filename = 'gm_{}_{}_{}'.format(
            user_id,
            datetime.now().strftime('%Y%m%d_%H%M%S'),
            safe_name
        )
        filepath = os.path.join('uploads/ghost_market', filename)

        if saver_settings['data_saver_mode'] and (img.mimetype or '').startswith('image/'):
            compressed_bytes = compress_image(img.read(), quality=saver_settings['image_quality'])
            with open(filepath, 'wb') as f:
                f.write(compressed_bytes)
        else:
            img.save(filepath)

        image_paths.append(filepath)

    with admin_get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ghost_market_items
                (seller_id, title, description, price, category, condition, images, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, title, description, price, category, condition,
            ','.join(image_paths),
            (datetime.now() + timedelta(days=30)).isoformat()
        ))
        conn.commit()

        socketio.emit('new_item_submission', {
            'seller_id': user_id,
            'title': title
        }, room='admins')

    return jsonify({'success': True, 'message': 'Item submitted for admin review'})

@app.route('/api/ghost-market/buy/<int:item_id>', methods=['POST'])
@csrf_protect
@require_approved_user
def ghost_market_buy(item_id):
    """Initiate purchase of an item"""
    buyer_id = session['user_id']

    with admin_get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT gmi.*, gms.user_id as seller_user_id, u.zeus_pin as seller_pin
            FROM ghost_market_items gmi
            JOIN ghost_market_sellers gms ON gmi.seller_id = gms.user_id
            JOIN users u ON gms.user_id = u.id
            WHERE gmi.id = ? AND gmi.status = 'approved'
        ''', (item_id,))
        item = cursor.fetchone()

        if not item:
            return jsonify({'error': 'Item not found or unavailable'}), 404

        if item['seller_user_id'] == buyer_id:
            return jsonify({'error': 'You cannot buy your own item'}), 400

        buyer_pin = session.get('user_zeus_pin', '')
        buyer_pin_half = (buyer_pin[:8] + '-XXXX') if len(buyer_pin) >= 8 else 'ZT-XXXX-XXXX'
        seller_pin_half = (item['seller_pin'][:8] + '-XXXX') if item['seller_pin'] and len(item['seller_pin']) >= 8 else 'ZT-XXXX-XXXX'

        cursor.execute('''
            INSERT INTO ghost_market_orders
                (item_id, buyer_id, seller_id, amount, buyer_pin_half, seller_pin_half, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending_payment')
        ''', (item_id, buyer_id, item['seller_user_id'], item['price'], buyer_pin_half, seller_pin_half))
        order_id = cursor.lastrowid
        conn.commit()

    return jsonify({
        'success': True,
        'redirect_url': '/ghost-market/pay/{}'.format(order_id)
    })

@app.route('/api/ghost-market/confirm-receipt/<int:order_id>', methods=['POST'])
@csrf_protect
@require_approved_user
def confirm_receipt(order_id):
    """Buyer confirms receipt - releases escrow to seller"""
    user_id = session['user_id']

    with admin_get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM ghost_market_orders
            WHERE id = ? AND buyer_id = ? AND status = 'delivered'
        ''', (order_id, user_id))
        order = cursor.fetchone()

        if not order:
            return jsonify({'error': 'Order not found or cannot be completed'}), 404

        cursor.execute('''
            UPDATE ghost_market_orders
            SET status = 'completed', completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (order_id,))

        cursor.execute('''
            UPDATE ghost_market_escrow
            SET status = 'released_to_seller', released_at = CURRENT_TIMESTAMP
            WHERE order_id = ?
        ''', (order_id,))

        cursor.execute('''
            UPDATE ghost_market_sellers
            SET total_sales = total_sales + 1,
                total_earnings = total_earnings + ?
            WHERE user_id = ?
        ''', (order['amount'], order['seller_id']))

        conn.commit()

    return jsonify({'success': True, 'message': 'Thank you! Funds have been released to seller.'})

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
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
