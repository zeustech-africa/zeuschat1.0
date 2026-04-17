# ============================================
# ZEUSCHAT CLEAN APP.PY
# Working admin login only
# ============================================

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'zeuschat_secret_key_2024'

# Database helper
def get_db():
    db_path = os.path.join(os.path.dirname(__file__), 'zeuschat_local.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# TEST ROUTES
# ============================================

@app.route('/test', methods=['GET'])
def test():
    return jsonify({'status': 'ok', 'message': 'Server is running!'})

@app.route('/admin/test', methods=['GET', 'POST'])
def admin_test():
    if request.method == 'POST':
        return jsonify({'success': True, 'message': 'POST works!', 'received': request.get_json()})
    return jsonify({'success': True, 'message': 'GET works!'})

# ============================================
# ADMIN LOGIN ROUTES
# ============================================

@app.route('/admin/login')
def admin_login_page():
    return render_template('admin/login.html')

@app.route('/admin/api/login', methods=['POST'])
def admin_api_login():
    try:
        data = request.get_json()
        print(f"Login attempt: {data}")
        
        if not data:
            return jsonify({'error': 'No JSON data'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if username == 'superadmin' and password == 'ZeusAdmin2026Secure!':
            session['admin_id'] = 1
            session['admin_username'] = username
            return jsonify({'success': True, 'redirect': '/admin/dashboard'})
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect('/admin/login')
    return render_template('admin/dashboard.html')

# ============================================
# MAIN ENTRY
# ============================================

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 ZEUSCHAT SERVER STARTING")
    print("=" * 50)
    print("📍 Test: http://localhost:5000/test")
    print("📍 Admin Login: http://localhost:5000/admin/login")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)

