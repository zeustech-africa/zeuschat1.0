import os
import random
import time
import sqlite3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def init_db():
    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        zeus_pin TEXT UNIQUE NOT NULL,
        name TEXT,
        about TEXT,
        profile_pic TEXT
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
    conn.commit()
    conn.close()

init_db()

def generate_zeus_pin():
    part1 = random.randint(1000, 9999)
    part2 = random.randint(1000, 9999)
    return f"ZT-{part1}-{part2}"

@app.route('/')
def index():
    return send_from_directory('../', 'otp.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../', path)

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400

    otp = str(random.randint(100000, 999999))
    expires_at = int(time.time()) + 300

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("DELETE FROM otps WHERE email = ?", (email,))
    c.execute("INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
              (email, otp, expires_at))
    conn.commit()
    conn.close()

    # Simulate email (for testing)
    print(f"📧 OTP for {email}: {otp}")
    return jsonify({'message': 'OTP sent successfully'})

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    if not email or not otp:
        return jsonify({'error': 'Email and OTP required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("SELECT otp, expires_at FROM otps WHERE email = ?", (email,))
    result = c.fetchone()
    if not result:
        return jsonify({'error': 'OTP not found'}), 404

    db_otp, expires_at = result
    if time.time() > expires_at:
        c.execute("DELETE FROM otps WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        return jsonify({'error': 'OTP expired'}), 400

    if db_otp != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    zeus_pin = generate_zeus_pin()
    try:
        c.execute("INSERT INTO users (email, zeus_pin) VALUES (?, ?)",
                  (email, zeus_pin))
        conn.commit()
    except sqlite3.IntegrityError:
        c.execute("SELECT zeus_pin FROM users WHERE email = ?", (email,))
        zeus_pin = c.fetchone()[0]
    conn.close()

    return jsonify({'message': 'OTP verified', 'zeus_pin': zeus_pin})

@app.route('/save-profile', methods=['POST'])
def save_profile():
    data = request.json
    zeus_pin = data.get('zeus_pin')
    name = data.get('name')
    about = data.get('about', '')
    profile_pic = data.get('profile_pic', '')
    if not zeus_pin or not name:
        return jsonify({'error': 'Zeus-PIN and name required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("UPDATE users SET name = ?, about = ?, profile_pic = ? WHERE zeus_pin = ?",
              (name, about, profile_pic, zeus_pin))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Profile saved'})

@app.route('/add-contact', methods=['POST'])
def add_contact():
    data = request.json
    user_pin = data.get('user_pin')
    contact_pin = data.get('contact_pin')
    if not user_pin or not contact_pin:
        return jsonify({'error': 'Your Zeus-PIN and contact Zeus-PIN required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE zeus_pin = ?", (contact_pin,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Contact not found — invalid Zeus-PIN'}), 404

    c.execute("SELECT status FROM contacts WHERE (user_pin = ? AND contact_pin = ?) OR (user_pin = ? AND contact_pin = ?)",
              (user_pin, contact_pin, contact_pin, user_pin))
    result = c.fetchone()
    if result:
        status = result[0]
        if status == 'accepted':
            conn.close()
            return jsonify({'message': 'Already connected'})
        elif status == 'pending':
            conn.close()
            return jsonify({'message': 'Request already sent'})

    c.execute("INSERT INTO contacts (user_pin, contact_pin, status, created_at) VALUES (?, ?, 'pending', ?)",
              (user_pin, contact_pin, int(time.time())))
    conn.commit()
    conn.close()

    return jsonify({'message': f'Request sent to {contact_pin}'})

@app.route('/get-requests', methods=['GET'])
def get_requests():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'Zeus-PIN required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("""
        SELECT u.name, c.user_pin 
        FROM contacts c
        JOIN users u ON c.user_pin = u.zeus_pin
        WHERE c.contact_pin = ? AND c.status = 'pending'
    """, (user_pin,))
    requests = [{'name': row[0] or 'User', 'zeus_pin': row[1]} for row in c.fetchall()]
    conn.close()

    return jsonify({'requests': requests})

@app.route('/accept-contact', methods=['POST'])
def accept_contact():
    data = request.json
    user_pin = data.get('user_pin')
    contact_pin = data.get('contact_pin')
    if not user_pin or not contact_pin:
        return jsonify({'error': 'Zeus-PINs required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("""
        UPDATE contacts 
        SET status = 'accepted' 
        WHERE (user_pin = ? AND contact_pin = ?) OR (user_pin = ? AND contact_pin = ?)
    """, (user_pin, contact_pin, contact_pin, user_pin))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Contact accepted'})

@app.route('/get-contacts', methods=['GET'])
def get_contacts():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'Zeus-PIN required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("""
        SELECT u.name, u.zeus_pin, u.profile_pic
        FROM contacts c
        JOIN users u ON 
            (c.user_pin = u.zeus_pin AND c.contact_pin = ?) OR 
            (c.contact_pin = u.zeus_pin AND c.user_pin = ?)
        WHERE c.status = 'accepted'
    """, (user_pin, user_pin))
    contacts = [{'name': row[0] or 'User', 'zeus_pin': row[1], 'profile_pic': row[2]} for row in c.fetchall()]
    conn.close()

    return jsonify({'contacts': contacts})

@app.route('/send-message', methods=['POST'])
def send_message():
    data = request.json
    from_pin = data.get('from_pin')
    to_pin = data.get('to_pin')
    content = data.get('content')
    ttl = data.get('ttl_seconds', 30)
    if not from_pin or not to_pin or not content:
        return jsonify({'error': 'From, to, and content required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("""
        SELECT 1 FROM contacts 
        WHERE ((user_pin = ? AND contact_pin = ?) OR (user_pin = ? AND contact_pin = ?)) 
        AND status = 'accepted'
    """, (from_pin, to_pin, to_pin, from_pin))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Not connected — send request first'}), 403

    c.execute("INSERT INTO messages (from_pin, to_pin, content, ttl_seconds, sent_at) VALUES (?, ?, ?, ?, ?)",
              (from_pin, to_pin, content, ttl, int(time.time())))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Sent'})

@app.route('/get-messages', methods=['GET'])
def get_messages():
    user_pin = request.args.get('user_pin')
    if not user_pin:
        return jsonify({'error': 'Zeus-PIN required'}), 400

    conn = sqlite3.connect('zeuschat.db')
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
    conn.commit()
    conn.close()

    return jsonify({'messages': messages})

@app.route('/mark-viewed', methods=['POST'])
def mark_viewed():
    data = request.json
    msg_id = data.get('id')
    if not msg_id:
        return jsonify({'error': 'Message ID required'}), 400

    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("UPDATE messages SET viewed = 1 WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Marked viewed'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
