from flask import Flask, request, jsonify, send_from_directory, session, render_template, redirect
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, emit
from flask_compress import Compress
import sqlite3
import os
import secrets
import hashlib
from datetime import datetime
import json
import sys
import flask
from contextlib import contextmanager
from functools import wraps
import time
import gzip
import base64
import threading
from urllib import request as urllib_request
from werkzeug.utils import secure_filename
from admin_middleware import require_approved_user, user_has_unlock, user_has_feature_access, get_user_subscription_tier, log_admin_action, get_db_connection as admin_get_db
from admin_routes import admin_bp
from payment_routes import payment_bp
from pywebpush import webpush, WebPushException

# Startup logging for deployment verification
print("="*60)
print(f"🚀 ZeusChat Server Starting")
print(f"📦 Python Version: {sys.version}")
print(f"📦 Flask Version: {flask.__version__}")
print("="*60)

app = Flask(__name__, static_folder='.', static_url_path='')
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

        cursor.execute('''
            INSERT OR IGNORE INTO admin_users (username, password_hash, email, role, permissions)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            'superadmin',
            '142787a065bc8eaf6bedf5e1221cce84dd759fb1e9503c375927bb0028ecc9c4',
            'admin@zeuschat.co.za',
            'super_admin',
            '{"can_approve_users": true, "can_ban_users": true, "can_approve_payments": true, "can_manage_admins": true, "can_view_logs": true}'
        ))

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

def run_admin_migrations():
    """Auto-create admin tables on app startup (for free tier deployment)"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if admin_users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_users'")
        admin_users_exists = bool(cursor.fetchone())
        if admin_users_exists:
            print("✅ Admin tables already exist - ensuring latest schema...")
        else:
            print("🔄 Running admin migrations...")

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

        # Create default super admin (password: ZeusAdmin2026!)
        import hashlib
        default_password_hash = hashlib.sha256('ZeusAdmin2026!'.encode()).hexdigest()

        cursor.execute('''
        INSERT OR IGNORE INTO admin_users (username, password_hash, email, role, permissions)
        VALUES (?, ?, ?, ?, ?)
        ''', ('superadmin', default_password_hash, 'admin@zeuschat.co.za', 'super_admin',
              '{"can_approve_users": true, "can_ban_users": true, "can_approve_payments": true, "can_manage_admins": true, "can_view_logs": true}'))

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

# Register additive blueprints (no existing route removal)
app.register_blueprint(admin_bp)
app.register_blueprint(payment_bp)
print("✅ Admin and payment routes registered")

# Helper functions
def generate_zeus_pin():
    """Generate unique Zeus PIN in format ZT-XXXX-XXXX"""
    return f"ZT-{secrets.randbelow(9000) + 1000}-{secrets.randbelow(9000) + 1000}"

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

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
        session['user_password'] = password  # Store for PIN-to-view verification
        
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
        session['user_password'] = password

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
        
        password_hash = hash_password(password)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, email, full_name, profile_pic FROM users
                WHERE zeus_pin = ? AND password_hash = ?
            ''', (zeus_pin, password_hash))
            
            user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Invalid PIN or password'}), 401
        
        # Set session
        session['user_id'] = user[0]
        session['zeus_pin'] = zeus_pin
        session['user_email'] = user[1]
        session['user_full_name'] = user[2]
        session['user_password'] = password  # Store for PIN-to-view verification

        with admin_get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT status FROM user_approvals WHERE user_id = ?', (user[0],))
            approval = cursor.fetchone()
            approval_status = approval['status'] if approval else 'pending'
        
        print(f"✅ User logged in: {user[1]}")

        if approval_status != 'approved':
            return jsonify({
                'success': True,
                'message': 'Account pending approval',
                'redirect': '/pending-approval',
                'approved': False,
                'approval_status': approval_status,
                'pending_approval': True,
                'user': {
                    'id': user[0],
                    'email': user[1],
                    'full_name': user[2],
                    'profile_pic': user[3],
                    'zeus_pin': zeus_pin
                }
            }), 200
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': '/dashboard',
            'approved': True,
            'approval_status': approval_status,
            'pending_approval': False,
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

        password_hash = hash_password(password)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id FROM users
                WHERE zeus_pin = ? AND password_hash = ?
            ''', (zeus_pin, password_hash))

            user = cursor.fetchone()

            if not user:
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
            
            # Optional: Mark as "viewed" after recording as missed (prevents duplicate tracking)
        
                cursor.execute('''
                    UPDATE messages 
                    SET viewed_at = datetime('now'),
                        delivered_at = COALESCE(delivered_at, datetime('now')),
                        read_timer_started_at = datetime('now'),
                        status = 'seen'
                    WHERE receiver_id = ? AND viewed_at IS NULL
                ''', (user_id,))
        return jsonify({
            'success': True,
            'missed_count': count,
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


if os.environ.get('RENDER'):
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()

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
@retry_on_locked()
def update_online_status():
    """Update user's online status"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        zeus_pin = data.get('zeus_pin', '').strip()
        is_online = data.get('is_online', False)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if is_online:
                cursor.execute('''
                    UPDATE users SET last_seen = CURRENT_TIMESTAMP
                    WHERE zeus_pin = ?
                ''', (zeus_pin,))
            else:
                # Set last_seen to past time to appear offline
                cursor.execute('''
                    UPDATE users SET last_seen = datetime('now', '-1 hour')
                    WHERE zeus_pin = ?
                ''', (zeus_pin,))
        
        print(f"✅ Online status updated for {zeus_pin}: {'online' if is_online else 'offline'}")
        
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
    """DEBUG: Check Socket.IO connections"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'success': True,
        'current_user_id': session['user_id'],
        'connected_users': dict(connected_users),
        'total_connected': len(connected_users)
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

# ========================================
# CONTACT PROFILE ENDPOINT - PRIVACY AWARE
# ========================================

@app.route('/api/get-contact-profile', methods=['GET'])
@retry_on_locked()
def get_contact_profile():
    """Get contact's profile information for viewing (respects privacy settings)"""
    contact_pin = request.args.get('contact_pin', '').strip()
    viewer_pin = request.args.get('viewer_pin', '').strip()  # PIN of person viewing the profile
    
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
            
            # Check if viewer is in contact's contacts (for myContacts visibility)
            is_contact = False
            if viewer_pin:
                cursor.execute('''
                    SELECT COUNT(*) FROM contacts
                    WHERE (user_id = ? AND contact_user_id IN (SELECT id FROM users WHERE zeus_pin = ?))
                    OR (user_id IN (SELECT id FROM users WHERE zeus_pin = ?) AND contact_user_id = ?)
                ''', (contact_id, viewer_pin, viewer_pin, contact_id))
                
                is_contact = cursor.fetchone()[0] > 0
            
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
@retry_on_locked()
def submit_feedback():
    """Submit user feedback"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        feedback_type = data.get('feedback_type', '').strip()
        message = data.get('message', '').strip()
        
        if not feedback_type or not message:
            return jsonify({'error': 'Feedback type and message required'}), 400
        
        if len(message) < 5:
            return jsonify({'error': 'Message must be at least 5 characters'}), 400
        
        if len(message) > 1000:
            return jsonify({'error': 'Message must be less than 1000 characters'}), 400
        
        # Log feedback (in production, save to database or send to email)
        print(f"📧 Feedback received:")
        print(f"   Type: {feedback_type}")
        print(f"   Message: {message}")
        if 'user_id' in session:
            print(f"   From: User {session.get('user_id')}")
        
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
@retry_on_locked()
def typing_indicator():
    """Update typing status (for future WebSocket implementation)"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
        data = request.get_json()
        user_pin = data.get('user_pin', '').strip()
        contact_pin = data.get('contact_pin', '').strip()
        is_typing = data.get('is_typing', False)
        
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
def process_queue_endpoint():
    """Process queued messages with exponential backoff retries"""
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    try:
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
