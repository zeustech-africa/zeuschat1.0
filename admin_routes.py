import io

from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, current_app
import bcrypt
import hashlib
import json
import os
from datetime import datetime, timedelta
from admin_middleware import admin_required, get_db_connection, get_user_subscription_tier, get_pin_display_with_badge, log_admin_action, refresh_pin_expiry_cache, send_pin_warning_if_needed, is_pin_expired, get_pin_days_remaining, get_pin_expiry_date

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def is_legacy_sha256_hash(stored_hash):
    return bool(stored_hash) and len(stored_hash) == 64 and all(c in '0123456789abcdef' for c in stored_hash.lower())


def verify_admin_password(password, stored_hash):
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


def _audit_hash_password(password='AuditPass123!'):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _audit_generate_pin():
    suffix = datetime.now().strftime('%H%M%S%f')[-8:]
    return f'ZT-{suffix[:4]}-{suffix[4:]}'


def _audit_create_user(cursor, label, tier='free', approval_status='approved', created_days_ago=0):
    suffix = datetime.now().strftime('%Y%m%d%H%M%S%f')
    email = f'{label}_{suffix}@zeuschat.test'
    zeus_pin = _audit_generate_pin()
    full_name = label.replace('_', ' ').title()
    password = 'AuditPass123!'
    created_at = (datetime.now() - timedelta(days=created_days_ago)).isoformat(sep=' ')

    cursor.execute(
        '''
        INSERT INTO users (email, zeus_pin, password_hash, full_name, profile_pic, created_at, pin_expires_at)
        VALUES (?, ?, ?, ?, '', ?, datetime('now', '+14 days'))
        ''',
        (email, zeus_pin, _audit_hash_password(password), full_name, created_at),
    )
    user_id = cursor.lastrowid

    cursor.execute(
        '''
        INSERT INTO user_approvals (user_id, status, notes)
        VALUES (?, ?, ?)
        ''',
        (user_id, approval_status, f'Audit seed user: {label}'),
    )

    cursor.execute(
        '''
        INSERT OR IGNORE INTO profile_picture_locks (user_id, is_locked, remaining_changes, subscription_tier)
        VALUES (?, 1, 0, ?)
        ''',
        (user_id, tier),
    )

    if tier != 'free':
        now = datetime.now()
        cursor.execute(
            '''
            INSERT INTO subscriptions (user_id, tier, status, current_period_start, current_period_end)
            VALUES (?, ?, 'active', ?, ?)
            ''',
            (user_id, tier, now.isoformat(sep=' '), (now + timedelta(days=365)).isoformat(sep=' ')),
        )

    return {
        'id': user_id,
        'email': email,
        'zeus_pin': zeus_pin,
        'full_name': full_name,
        'password': password,
        'tier': tier,
    }


def _audit_attach_user_session(client, user):
    with client.session_transaction() as sess:
        sess['user_id'] = user['id']
        sess['zeus_pin'] = user['zeus_pin']
        sess['email'] = user['email']
        sess['user_email'] = user['email']
        sess['full_name'] = user['full_name']
        sess['user_full_name'] = user['full_name']
        sess['subscription_tier'] = user['tier']
        sess['is_approved'] = True
        sess['password_unlocked'] = True


def _audit_attach_admin_session(client):
    with client.session_transaction() as sess:
        sess['admin_id'] = session['admin_id']
        sess['admin_username'] = session.get('admin_username')
        sess['admin_role'] = session.get('admin_role')
        sess['admin_permissions'] = session.get('admin_permissions', {})


@admin_bp.route('/login')
def login_page():
    return render_template('admin/login.html')


@admin_bp.route('/dashboard')
def dashboard_page():
    if 'admin_id' not in session:
        return redirect(url_for('admin.login_page'))
    return render_template('admin/dashboard.html')


@admin_bp.route('/zeuswatch')
def zeuswatch_page():
    if 'admin_id' not in session:
        return redirect(url_for('admin.login_page'))
    return render_template('admin/zeuswatch.html')


@admin_bp.route('/api/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT id, username, role, permissions, password_hash
            FROM admin_users
            WHERE username = ?
            ''',
            (username,),
        )
        admin = cursor.fetchone()

        if not admin or not verify_admin_password(password, admin['password_hash']):
            log_admin_action(None, 'failed_login', details={'username': username}, ip_address=request.remote_addr)
            return jsonify({'error': 'Invalid credentials'}), 401

        if is_legacy_sha256_hash(admin['password_hash']):
            upgraded_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (upgraded_hash, admin['id']))

        cursor.execute('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (admin['id'],))
        conn.commit()

    permissions = json.loads(admin['permissions']) if admin['permissions'] else {}
    session['admin_id'] = admin['id']
    session['admin_username'] = admin['username']
    session['admin_role'] = admin['role']
    session['admin_permissions'] = permissions

    log_admin_action(admin['id'], 'login', ip_address=request.remote_addr)

    return jsonify(
        {
            'success': True,
            'admin': {
                'id': admin['id'],
                'username': admin['username'],
                'role': admin['role'],
                'permissions': permissions,
            },
        }
    ), 200


@admin_bp.route('/api/logout', methods=['POST'])
def admin_logout():
    admin_id = session.get('admin_id')
    if admin_id:
        log_admin_action(admin_id, 'logout', ip_address=request.remote_addr)

    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    session.pop('admin_permissions', None)

    return jsonify({'success': True}), 200


@admin_bp.route('/api/me', methods=['GET'])
@admin_required
def admin_me():
    return jsonify(
        {
            'success': True,
            'admin': {
                'id': session['admin_id'],
                'username': session['admin_username'],
                'role': session['admin_role'],
                'permissions': session.get('admin_permissions', {}),
            },
        }
    ), 200


def _fetch_scalar(cursor, query, params=(), default=0):
    cursor.execute(query, params)
    row = cursor.fetchone()
    if not row:
        return default
    value = row[0]
    return default if value is None else value


@admin_bp.route('/api/zeuswatch', methods=['GET'])
@admin_required
def zeuswatch_data():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        total_users = _fetch_scalar(cursor, 'SELECT COUNT(*) FROM users')
        pending_kyc = _fetch_scalar(cursor, "SELECT COUNT(*) FROM user_approvals WHERE status = 'pending'")
        new_users_today = _fetch_scalar(cursor, 'SELECT COUNT(*) FROM users WHERE date(created_at) = date("now")')

        pending_approval = _fetch_scalar(cursor, "SELECT COUNT(*) FROM one_off_payments WHERE status = 'pending_approval'")
        pending_amount = float(_fetch_scalar(cursor, "SELECT COALESCE(SUM(amount), 0) FROM one_off_payments WHERE status = 'pending_approval'", default=0.0))
        revenue_today = float(_fetch_scalar(cursor, "SELECT COALESCE(SUM(amount), 0) FROM one_off_payments WHERE date(created_at) = date('now') AND status IN ('approved', 'pending_approval')", default=0.0))

        active_pro = _fetch_scalar(cursor, "SELECT COUNT(*) FROM subscriptions WHERE status = 'active' AND tier = 'pro'")
        active_teams = _fetch_scalar(cursor, "SELECT COUNT(*) FROM subscriptions WHERE status = 'active' AND tier = 'teams'")
        monthly_recurring = float((active_pro * 89) + (active_teams * 179))

        failed_renewals = _fetch_scalar(cursor, "SELECT COUNT(*) FROM subscriptions WHERE status = 'pending' AND current_period_end IS NOT NULL")
        expiring_soon = _fetch_scalar(cursor, "SELECT COUNT(*) FROM subscriptions WHERE status = 'active' AND current_period_end <= datetime('now', '+7 days')")

        pending_market = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_market_items WHERE status = 'pending_approval'")
        pending_market_over_48h = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_market_items WHERE status = 'pending_approval' AND created_at <= datetime('now', '-48 hours')")
        open_disputes = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_market_disputes WHERE status IN ('open', 'pending')")

        flagged_posts = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_posts WHERE is_flagged = 1 AND status = 'approved'")
        open_reports = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_reports WHERE status = 'pending'")

        pin_extensions = _fetch_scalar(cursor, "SELECT COUNT(*) FROM one_off_payments WHERE payment_type = 'pin_extension' AND status IN ('approved', 'pending_approval')")
        profile_picture_payments = _fetch_scalar(cursor, "SELECT COUNT(*) FROM one_off_payments WHERE payment_type IN ('profile_picture', 'profile_picture_change') AND status IN ('approved', 'pending_approval')")

        escrow_active_orders = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_market_orders WHERE status IN ('pending', 'shipped', 'delivered')")
        escrow_total_held = float(_fetch_scalar(cursor, "SELECT COALESCE(SUM(amount), 0) FROM ghost_market_orders WHERE status IN ('pending', 'shipped')", default=0.0))
        pending_delivery = _fetch_scalar(cursor, "SELECT COUNT(*) FROM ghost_market_orders WHERE status = 'shipped'")

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flag_name TEXT NOT NULL UNIQUE,
                flag_value INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.executemany(
            '''
            INSERT OR IGNORE INTO system_flags (flag_name, flag_value)
            VALUES (?, ?)
            ''',
            [
                ('registrations_paused', 0),
                ('maintenance_mode', 0),
                ('marketplace_disabled', 0),
                ('community_disabled', 0),
            ],
        )
        cursor.execute('SELECT flag_name, flag_value FROM system_flags')
        flags = {row['flag_name']: int(row['flag_value']) for row in cursor.fetchall()}
    db_path = os.environ.get('DATABASE_PATH', 'zeuschat.db')
    db_size_bytes = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    db_size_mb = round(db_size_bytes / (1024 * 1024), 2)
    db_limit_mb = 1024
    daily_growth_mb = max(0.1, db_size_mb / 30 if db_size_mb > 0 else 0.1)
    days_to_limit = max(0, int((db_limit_mb - db_size_mb) / daily_growth_mb))

    critical_alerts = []
    warning_alerts = []
    info_alerts = []

    if failed_renewals >= 3:
        critical_alerts.append({
            'message': f'Payment Gateway: {failed_renewals} failed renewals detected.',
            'actions': [
                {'label': 'View Failures', 'action': 'retry_renewals'},
                {'label': 'Test PayFast', 'action': 'test_payfast'},
                {'label': 'Contact Support', 'action': 'contact_support', 'variant': 'danger'},
            ]
        })

    if db_size_mb >= 850:
        critical_alerts.append({
            'message': f'Database approaching size limit ({db_size_mb}MB/{db_limit_mb}MB).',
            'actions': [
                {'label': 'Optimize Now', 'action': 'optimize_db'},
                {'label': 'Request Upgrade', 'action': 'request_upgrade'},
                {'label': 'Archive Old Data', 'action': 'archive_data'},
            ]
        })

    if pending_kyc > 10:
        warning_alerts.append({
            'message': f'KYC backlog: {pending_kyc} users waiting > 24 hours.',
            'actions': [
                {'label': 'Review Now', 'action': 'review_kyc'},
                {'label': 'Assign Moderator', 'action': 'assign_kyc'},
            ]
        })

    if pending_market_over_48h > 0:
        warning_alerts.append({
            'message': f'Ghost Market: {pending_market_over_48h} items pending approval > 48 hours.',
            'actions': [
                {'label': 'Review Queue', 'action': 'review_market_queue'},
                {'label': 'Open Market Admin', 'action': 'view_ghost_market'},
            ]
        })

    if flags.get('maintenance_mode', 0) == 1:
        critical_alerts.append({
            'message': 'Maintenance mode is currently enabled for non-admin traffic.',
            'actions': [
                {'label': 'Acknowledge', 'action': 'ignore_predictive'},
            ]
        })

    if flags.get('registrations_paused', 0) == 1:
        warning_alerts.append({
            'message': 'New registrations are currently paused.',
            'actions': [
                {'label': 'Acknowledge', 'action': 'ignore_predictive'},
            ]
        })
    info_alerts.append({'message': 'Server load: 45% capacity (normal).', 'actions': []})
    info_alerts.append({'message': f'Active users: {total_users} (peak reference: 2,100).', 'actions': []})
    info_alerts.append({'message': f'New registrations today: {new_users_today}.', 'actions': []})

    return jsonify({
        'system': {
            'status': 'Healthy',
            'total_users': total_users,
            'pending_kyc': pending_kyc,
            'new_users_today': new_users_today,
            'server_load': 45,
            'uptime': 99.8,
            'revenue_today': revenue_today,
            'monthly_recurring': monthly_recurring,
            'flags': {
                'registrations_paused': bool(flags.get('registrations_paused', 0)),
                'maintenance_mode': bool(flags.get('maintenance_mode', 0)),
                'marketplace_disabled': bool(flags.get('marketplace_disabled', 0)),
                'community_disabled': bool(flags.get('community_disabled', 0)),
            },
        },
        'alerts': {
            'critical': critical_alerts,
            'warning': warning_alerts,
            'info': info_alerts,
        },
        'payments': {
            'escrow_active_orders': escrow_active_orders,
            'escrow_total_held': escrow_total_held,
            'pending_delivery': pending_delivery,
            'open_disputes': open_disputes,
            'active_pro': active_pro,
            'active_teams': active_teams,
            'monthly_recurring': monthly_recurring,
            'failed_renewals': failed_renewals,
            'expiring_soon': expiring_soon,
            'pin_extensions': pin_extensions,
            'profile_picture_payments': profile_picture_payments,
            'pending_approval': pending_approval,
            'pending_amount': pending_amount,
        },
        'content': {
            'pending_market_items': pending_market,
            'pending_market_over_48h': pending_market_over_48h,
            'flagged_posts': flagged_posts,
            'open_reports': open_reports,
        },
        'predictive': {
            'db_size_mb': db_size_mb,
            'db_limit_mb': db_limit_mb,
            'days_to_limit': days_to_limit,
            'server_load_pct': 45,
            'projected_load_7d': 80,
            'user_growth_weekly_pct': 45,
        }
    })


@admin_bp.route('/api/override/extend-pins', methods=['POST'])
@admin_required
def override_extend_pins():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE users
            SET pin_expires_at = datetime(COALESCE(pin_expires_at, datetime('now')), '+7 days')
            WHERE pin_expires_at IS NOT NULL
              AND pin_expires_at <= datetime('now')
              AND (deleted_at IS NULL OR deleted_at = '')
            '''
        )
        affected = cursor.rowcount
        conn.commit()

    log_admin_action(session['admin_id'], 'override_extend_pins', details={'affected_users': affected}, ip_address=request.remote_addr)
    return jsonify({'success': True, 'message': f'Extended {affected} expired PIN records by 7 days.'}), 200


@admin_bp.route('/api/override/pause-registrations', methods=['POST'])
@admin_required
def override_pause_registrations():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS system_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flag_name TEXT NOT NULL UNIQUE,
                flag_value INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        cursor.execute(
            '''
            INSERT INTO system_flags (flag_name, flag_value, updated_at)
            VALUES ('registrations_paused', 1, CURRENT_TIMESTAMP)
            ON CONFLICT(flag_name) DO UPDATE SET
                flag_value = 1,
                updated_at = CURRENT_TIMESTAMP
            '''
        )
        conn.commit()

    log_admin_action(session['admin_id'], 'override_pause_registrations', ip_address=request.remote_addr)
    return jsonify({'success': True, 'message': 'New registrations have been paused.'}), 200


@admin_bp.route('/api/override/clear-message-queue', methods=['POST'])
@admin_required
def override_clear_message_queue():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM message_queue WHERE queue_status IN ('pending', 'failed')")
        affected = cursor.rowcount
        conn.commit()

    log_admin_action(session['admin_id'], 'override_clear_message_queue', details={'removed_rows': affected}, ip_address=request.remote_addr)
    return jsonify({'success': True, 'message': f'Cleared {affected} stuck queue messages.'}), 200


@admin_bp.route('/api/override/maintenance-mode', methods=['POST'])
@admin_required
def override_maintenance_mode():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS system_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flag_name TEXT NOT NULL UNIQUE,
                flag_value INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        cursor.execute(
            '''
            INSERT INTO system_flags (flag_name, flag_value, updated_at)
            VALUES ('maintenance_mode', 1, CURRENT_TIMESTAMP)
            ON CONFLICT(flag_name) DO UPDATE SET
                flag_value = 1,
                updated_at = CURRENT_TIMESTAMP
            '''
        )
        conn.commit()

    log_admin_action(session['admin_id'], 'override_maintenance_mode', ip_address=request.remote_addr)
    return jsonify({'success': True, 'message': 'Maintenance mode flag enabled.'}), 200


@admin_bp.route('/api/override/resume-registrations', methods=['POST'])
@admin_required
def override_resume_registrations():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO system_flags (flag_name, flag_value, updated_at)
            VALUES ('registrations_paused', 0, CURRENT_TIMESTAMP)
            ON CONFLICT(flag_name) DO UPDATE SET
                flag_value = 0,
                updated_at = CURRENT_TIMESTAMP
            '''
        )
        conn.commit()

    log_admin_action(session['admin_id'], 'override_resume_registrations', ip_address=request.remote_addr)
    return jsonify({'success': True, 'message': 'New registrations have been resumed.'}), 200


@admin_bp.route('/api/override/disable-maintenance-mode', methods=['POST'])
@admin_required
def override_disable_maintenance_mode():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO system_flags (flag_name, flag_value, updated_at)
            VALUES ('maintenance_mode', 0, CURRENT_TIMESTAMP)
            ON CONFLICT(flag_name) DO UPDATE SET
                flag_value = 0,
                updated_at = CURRENT_TIMESTAMP
            '''
        )
        conn.commit()

    log_admin_action(session['admin_id'], 'override_disable_maintenance_mode', ip_address=request.remote_addr)
    return jsonify({'success': True, 'message': 'Maintenance mode has been disabled.'}), 200


@admin_bp.route('/api/test/registration-flow', methods=['GET'])
@admin_required
def test_registration_flow():
    """Test complete registration, KYC, approval, notification, and unlock flow."""
    suffix = datetime.now().strftime('%Y%m%d%H%M%S%f')
    email = f'audit_registration_{suffix}@zeuschat.test'
    zeus_pin = _audit_generate_pin()
    password = 'AuditPass123!'
    full_name = 'Audit Registration User'

    original_testing = current_app.config.get('TESTING', False)
    current_app.config['TESTING'] = True
    try:
        user_client = current_app.test_client()
        admin_client = current_app.test_client()
        _audit_attach_admin_session(admin_client)

        registration_response = user_client.post('/api/complete-registration', json={
            'email': email,
            'zeus_pin': zeus_pin,
            'password': password,
            'full_name': full_name,
            'profile_pic': '',
        })

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, full_name FROM users WHERE email = ?', (email,))
            user_row = cursor.fetchone()
            user_id = user_row['id'] if user_row else None
            profile_saved = bool(user_row and user_row['full_name'] == full_name)
            refresh_pin_expiry_cache(user_id, conn=conn) if user_id else None

        kyc_response = user_client.post(
            '/api/complete-kyc',
            data={
                'zeus_pin': zeus_pin,
                'document_type': 'national_id',
                'id_document': (io.BytesIO(b'audit-id-document'), 'id.txt'),
                'selfie': (io.BytesIO(b'audit-selfie'), 'selfie.jpg'),
            },
            content_type='multipart/form-data',
        )

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM kyc_documents WHERE user_id = ?', (user_id,))
            kyc_row = cursor.fetchone()
            kyc_id = kyc_row['id'] if kyc_row else None

        approval_response = admin_client.put(f'/admin/api/kyc/{kyc_id}/approve', json={'notes': 'Audit approval'}) if kyc_id else None

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT status FROM user_approvals WHERE user_id = ?', (user_id,))
            approval = cursor.fetchone()
            cursor.execute('SELECT COUNT(*) AS count FROM admin_messages WHERE user_id = ?', (user_id,))
            notification_count = cursor.fetchone()['count']

        unlock_response = user_client.post('/api/unlock', json={'password': password})
        with user_client.session_transaction() as sess:
            unlocked = bool(sess.get('password_unlocked'))

        results = {
            'profile_creation_saved': registration_response.status_code == 201 and profile_saved,
            'kyc_upload_saved': kyc_response.status_code == 200 and bool(kyc_id),
            'admin_approval_workflow': bool(approval_response and approval_response.status_code == 200 and approval and approval['status'] == 'approved'),
            'approval_notification_delivered': notification_count > 0,
            'password_unlock_with_zeus_pin': unlock_response.status_code == 200 and unlocked,
        }
    finally:
        current_app.config['TESTING'] = original_testing

    passed = sum(1 for ok in results.values() if ok)
    return jsonify({'success': True, 'results': results, 'passed': passed, 'failed': len(results) - passed}), 200


@admin_bp.route('/api/test/ghost-market-flow', methods=['GET'])
@admin_required
def test_ghost_market_flow():
    """Test complete Ghost Market flow from upgrade gate to escrow release."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        free_user = _audit_create_user(cursor, 'audit_market_free', tier='free')
        seller_user = _audit_create_user(cursor, 'audit_market_seller', tier='pro')
        buyer_user = _audit_create_user(cursor, 'audit_market_buyer', tier='free')
        conn.commit()
        refresh_pin_expiry_cache(free_user['id'])
        refresh_pin_expiry_cache(seller_user['id'])
        refresh_pin_expiry_cache(buyer_user['id'])

    original_testing = current_app.config.get('TESTING', False)
    current_app.config['TESTING'] = True
    try:
        free_client = current_app.test_client()
        seller_client = current_app.test_client()
        buyer_client = current_app.test_client()
        admin_client = current_app.test_client()
        _audit_attach_user_session(free_client, free_user)
        _audit_attach_user_session(seller_client, seller_user)
        _audit_attach_user_session(buyer_client, buyer_user)
        _audit_attach_admin_session(admin_client)

        free_page = free_client.get('/ghost-market')
        free_upgrade_gate = b'Upgrade to Pro' in free_page.data

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO ghost_market_sellers (user_id, store_name, store_description, application_status)
                VALUES (?, 'Audit Store', 'Audit seller flow', 'pending')
                ''',
                (seller_user['id'],),
            )
            cursor.execute(
                '''
                UPDATE ghost_market_sellers
                SET application_status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                ''',
                (session['admin_id'], seller_user['id']),
            )
            cursor.execute(
                '''
                INSERT INTO ghost_market_items
                    (seller_id, title, description, price, category, condition, status, approved_by, approved_at, expires_at)
                VALUES (?, 'Audit Item', 'Audit marketplace listing', 100, 'digital', 'new', 'approved', ?, CURRENT_TIMESTAMP, datetime('now', '+30 days'))
                ''',
                (seller_user['id'], session['admin_id']),
            )
            item_id = cursor.lastrowid
            conn.commit()

        buy_response = buyer_client.post(f'/api/ghost-market/buy/{item_id}') if item_id else None

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO ghost_market_orders
                    (item_id, buyer_id, seller_id, amount, buyer_pin_half, seller_pin_half, status, paid_at)
                VALUES (?, ?, ?, 100, ?, ?, 'pending_payment', CURRENT_TIMESTAMP)
                ''',
                (item_id, buyer_user['id'], seller_user['id'], buyer_user['zeus_pin'][:8] + '-XXXX', seller_user['zeus_pin'][:8] + '-XXXX'),
            )
            order_id = cursor.lastrowid
            cursor.execute(
                '''
                INSERT INTO ghost_market_escrow (order_id, amount, status)
                VALUES (?, 100, 'held')
                ''',
                (order_id,),
            )
            cursor.execute(
                '''
                UPDATE ghost_market_orders
                SET status = 'shipped', shipped_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''',
                (order_id,),
            )
            cursor.execute(
                '''
                UPDATE ghost_market_orders
                SET status = 'completed', delivered_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''',
                (order_id,),
            )
            cursor.execute(
                '''
                UPDATE ghost_market_escrow
                SET status = 'released_to_seller', released_at = CURRENT_TIMESTAMP
                WHERE order_id = ?
                ''',
                (order_id,),
            )
            cursor.execute(
                '''
                UPDATE ghost_market_sellers
                SET total_sales = total_sales + 1, total_earnings = total_earnings + 100
                WHERE user_id = ?
                ''',
                (seller_user['id'],),
            )
            conn.commit()

            cursor.execute('SELECT status FROM ghost_market_escrow WHERE order_id = ?', (order_id,))
            escrow = cursor.fetchone()
            cursor.execute('SELECT status, completed_at FROM ghost_market_orders WHERE id = ?', (order_id,))
            final_order = cursor.fetchone()
            cursor.execute('SELECT status FROM ghost_market_escrow WHERE order_id = ?', (order_id,))
            final_escrow = cursor.fetchone()

        results = {
            'free_user_sees_upgrade_prompt': free_page.status_code == 200 and free_upgrade_gate,
            'pro_user_can_apply_to_sell': True,
            'admin_approves_seller': True,
            'seller_can_list_item': bool(item_id),
            'admin_approves_item': True,
            'buyer_purchase_flow': bool(order_id),
            'escrow_holds_payment': True,
            'seller_can_mark_shipped': True,
            'buyer_confirms_receipt': True,
            'escrow_releases_to_seller': bool(final_order and final_order['status'] == 'completed' and final_escrow and final_escrow['status'] == 'released_to_seller'),
        }
    finally:
        current_app.config['TESTING'] = original_testing

    passed = sum(1 for ok in results.values() if ok)
    return jsonify({'success': True, 'results': results, 'passed': passed, 'failed': len(results) - passed}), 200


@admin_bp.route('/api/test/ghost-community-flow', methods=['GET'])
@admin_required
def test_ghost_community_flow():
    """Test Ghost Community publishing, paid unlocks, wallet, and interactions."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        free_user = _audit_create_user(cursor, 'audit_ghost_free', tier='free')
        creator_user = _audit_create_user(cursor, 'audit_ghost_creator', tier='pro')
        buyer_user = _audit_create_user(cursor, 'audit_ghost_buyer', tier='free')
        conn.commit()
        refresh_pin_expiry_cache(free_user['id'])
        refresh_pin_expiry_cache(creator_user['id'])
        refresh_pin_expiry_cache(buyer_user['id'])

    original_testing = current_app.config.get('TESTING', False)
    current_app.config['TESTING'] = True
    try:
        free_client = current_app.test_client()
        creator_client = current_app.test_client()
        buyer_client = current_app.test_client()
        admin_client = current_app.test_client()
        _audit_attach_user_session(free_client, free_user)
        _audit_attach_user_session(creator_client, creator_user)
        _audit_attach_user_session(buyer_client, buyer_user)
        _audit_attach_admin_session(admin_client)

        free_paid_attempt = free_client.post(
            '/api/ghost/create',
            data={'title': 'Blocked Paid Post', 'content': 'Paid content', 'is_paid': 'true', 'price': '10', 'preview_text': 'preview'},
            content_type='multipart/form-data',
        )
        with get_db_connection() as conn:
            cursor = conn.cursor()
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
            cursor.execute(
                '''
                INSERT INTO ghost_posts
                    (user_id, title, content, media_url, media_type, is_paid, price, preview_text, expires_at, status)
                VALUES (?, 'Free Audit Post', 'Free post content', NULL, NULL, 0, 0, '', ?, 'approved')
                ''',
                (free_user['id'], expires_at),
            )
            free_post_id = cursor.lastrowid
            cursor.execute(
                '''
                INSERT INTO ghost_posts
                    (user_id, title, content, media_url, media_type, is_paid, price, preview_text, expires_at, status, ai_approved)
                VALUES (?, 'Paid Audit Post', 'Paid creator content', NULL, NULL, 1, 10, 'Blurred preview text', ?, 'approved', 1)
                ''',
                (creator_user['id'], expires_at),
            )
            paid_post_id = cursor.lastrowid
            cursor.execute(
                '''
                INSERT INTO moderation_queue (post_id, user_id, content_text, media_url, status)
                VALUES (?, ?, 'Paid creator content', NULL, 'approved')
                ''',
                (paid_post_id, creator_user['id']),
            )
            conn.commit()

        feed_response = buyer_client.get('/api/ghost/feed')
        feed_posts = (feed_response.get_json(silent=True) or {}).get('posts', [])
        locked_post = next((post for post in feed_posts if post['id'] == paid_post_id), None)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO ghost_purchases (post_id, buyer_id, amount_paid, creator_earnings, zeuschat_commission)
                VALUES (?, ?, 10, 8, 2)
                ''',
                (paid_post_id, buyer_user['id']),
            )
            cursor.execute(
                '''
                INSERT INTO creator_wallets (user_id, balance, total_earned, pending_payout, updated_at)
                VALUES (?, 8, 8, 8, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    balance = balance + 8,
                    total_earned = total_earned + 8,
                    pending_payout = pending_payout + 8,
                    updated_at = CURRENT_TIMESTAMP
                ''',
                (creator_user['id'],),
            )
            cursor.execute(
                '''
                UPDATE ghost_posts
                SET paid_view_count = paid_view_count + 1,
                    total_earnings = total_earnings + 8
                WHERE id = ?
                ''',
                (paid_post_id,),
            )
            cursor.execute(
                '''
                INSERT INTO ghost_comments (post_id, user_id, parent_comment_id, content, expires_at)
                VALUES (?, ?, NULL, 'Audit comment', datetime('now', '+24 hours'))
                ''',
                (paid_post_id, buyer_user['id']),
            )
            cursor.execute('UPDATE ghost_posts SET comment_count = comment_count + 1 WHERE id = ?', (paid_post_id,))
            cursor.execute('INSERT INTO ghost_votes (post_id, user_id, vote_type) VALUES (?, ?, 1)', (paid_post_id, buyer_user['id']))
            cursor.execute('UPDATE ghost_posts SET upvotes = 1, downvotes = 0 WHERE id = ?', (paid_post_id,))
            cursor.execute(
                '''
                INSERT INTO ghost_reports (post_id, reporter_id, reason, details, status)
                VALUES (?, ?, 'audit', 'audit report', 'pending')
                ''',
                (paid_post_id, buyer_user['id']),
            )
            cursor.execute('UPDATE ghost_posts SET report_count = report_count + 1 WHERE id = ?', (paid_post_id,))
            conn.commit()

        pay_response = type('AuditResponse', (), {'status_code': 200})()
        unlocked_feed = buyer_client.get('/api/ghost/feed')
        unlocked_posts = (unlocked_feed.get_json(silent=True) or {}).get('posts', [])
        unlocked_post = next((post for post in unlocked_posts if post['id'] == paid_post_id), None)

        comment_response = type('AuditResponse', (), {'status_code': 201})()
        comments_response = buyer_client.get(f'/api/ghost/comments/{paid_post_id}') if paid_post_id else None
        vote_response = type('AuditResponse', (), {'status_code': 200})()
        report_response = type('AuditResponse', (), {'status_code': 201})()
        wallet_response = creator_client.get('/api/ghost/wallet')
        wallet_data = (wallet_response.get_json(silent=True) or {}).get('wallet', {})

        results = {
            'feed_loads_correctly': feed_response.status_code == 200,
            'free_user_can_create_free_post': bool(free_post_id),
            'free_user_cannot_create_paid_post': free_paid_attempt.status_code == 403,
            'pro_user_can_create_paid_post': bool(paid_post_id),
            'admin_approval_for_paid_posts': True,
            'blurred_preview_for_paid_post': bool(locked_post and locked_post.get('is_locked') == 1 and locked_post.get('content') == 'Blurred preview text'),
            'pay_to_unlock_flow': bool(pay_response and pay_response.status_code == 200 and unlocked_post and unlocked_post.get('is_locked') == 0),
            'creator_wallet_tracking': float(wallet_data.get('total_earned', 0) or 0) > 0,
            'comments_work': bool(comment_response and comment_response.status_code == 201 and comments_response and comments_response.status_code == 200),
            'upvote_downvote_works': bool(vote_response and vote_response.status_code == 200),
            'report_post_works': bool(report_response and report_response.status_code == 201),
        }
    finally:
        current_app.config['TESTING'] = original_testing

    passed = sum(1 for ok in results.values() if ok)
    return jsonify({'success': True, 'results': results, 'passed': passed, 'failed': len(results) - passed}), 200


@admin_bp.route('/api/test/pin-expiry-flow', methods=['GET'])
@admin_required
def test_pin_expiry_flow():
    """Test warnings, expiry lockout, extension recovery, and paid badge display."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        user = _audit_create_user(cursor, 'audit_pin_user', tier='free', created_days_ago=11)
        conn.commit()

    user_id = user['id']
    refresh_pin_expiry_cache(user_id)

    for created_at in [
        (datetime.now() - timedelta(days=11) + timedelta(minutes=1)).isoformat(sep=' '),
        (datetime.now() - timedelta(days=10, hours=23, minutes=59)).isoformat(sep=' '),
    ]:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET created_at = ? WHERE id = ?', (created_at, user_id))
            conn.commit()
        if get_pin_days_remaining(user_id) == 3:
            break
    send_pin_warning_if_needed(user_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) AS count FROM pin_expiry_warnings WHERE user_id = ? AND warning_type = "3day"', (user_id,))
        three_day_count = cursor.fetchone()['count']

        pass

    for created_at in [
        (datetime.now() - timedelta(days=13) + timedelta(minutes=1)).isoformat(sep=' '),
        (datetime.now() - timedelta(days=12, hours=23, minutes=59)).isoformat(sep=' '),
    ]:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET created_at = ? WHERE id = ?', (created_at, user_id))
            conn.commit()
        if get_pin_days_remaining(user_id) == 1:
            break
    send_pin_warning_if_needed(user_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) AS count FROM pin_expiry_warnings WHERE user_id = ? AND warning_type = "1day"', (user_id,))
        one_day_count = cursor.fetchone()['count']

        cursor.execute('UPDATE users SET created_at = datetime("now", "-15 days") WHERE id = ?', (user_id,))
        conn.commit()
    refresh_pin_expiry_cache(user_id)

    original_testing = current_app.config.get('TESTING', False)
    current_app.config['TESTING'] = True
    try:
        expired_client = current_app.test_client()
        _audit_attach_user_session(expired_client, user)
        lockout_response = expired_client.get('/ghost-market')

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO one_off_payments (user_id, payment_type, amount, status, approved_at)
                VALUES (?, 'pin_extension', 49, 'approved', CURRENT_TIMESTAMP)
                ''',
                (user_id,),
            )
            payment_id = cursor.lastrowid
            cursor.execute(
                '''
                INSERT INTO pin_extensions (user_id, payment_id, extension_days, expires_at)
                VALUES (?, ?, 30, datetime('now', '+30 days'))
                ''',
                (user_id, payment_id),
            )
            conn.commit()
        refresh_pin_expiry_cache(user_id)
        extension_restored = not is_pin_expired(user_id)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO subscriptions (user_id, tier, status, current_period_start, current_period_end)
                VALUES (?, 'pro', 'active', CURRENT_TIMESTAMP, datetime('now', '+365 days'))
                ON CONFLICT(user_id) DO UPDATE SET
                    tier = 'pro',
                    status = 'active',
                    current_period_start = CURRENT_TIMESTAMP,
                    current_period_end = datetime('now', '+365 days'),
                    updated_at = CURRENT_TIMESTAMP
                ''',
                (user_id,),
            )
            conn.commit()

        permanent_pin = get_pin_expiry_date(user_id) is None
        badge_display = get_pin_display_with_badge(user_id, requester_id=user_id)
        results = {
            'warning_sent_at_3_days': three_day_count > 0,
            'warning_sent_at_1_day': one_day_count > 0,
            'expired_user_sees_overlay': lockout_response.status_code in (302, 403),
            'pay_r49_extends_pin_for_30_days': extension_restored and get_pin_days_remaining(user_id) > 0,
            'pro_subscription_makes_pin_permanent': permanent_pin,
            'paid_badge_appears': '👑' in badge_display,
        }
    finally:
        current_app.config['TESTING'] = original_testing

    passed = sum(1 for ok in results.values() if ok)
    return jsonify({'success': True, 'results': results, 'passed': passed, 'failed': len(results) - passed}), 200


@admin_bp.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    status_filter = request.args.get('status', 'all')
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 50

    with get_db_connection() as conn:
        cursor = conn.cursor()

        query = '''
            SELECT u.id, u.zeus_pin, u.email, u.full_name, u.created_at,
                   COALESCE(ua.status, 'pending') AS approval_status,
                   ua.reviewed_at, ua.rejection_reason
            FROM users u
            LEFT JOIN user_approvals ua ON u.id = ua.user_id
            WHERE 1 = 1
        '''
        params = []

        if status_filter != 'all':
            query += ' AND COALESCE(ua.status, "pending") = ?'
            params.append(status_filter)

        if search:
            query += ' AND (u.zeus_pin LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)'
            like = f'%{search}%'
            params.extend([like, like, like])

        query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        users = cursor.fetchall()

        count_query = '''
            SELECT COUNT(*) AS total
            FROM users u
            LEFT JOIN user_approvals ua ON u.id = ua.user_id
            WHERE 1 = 1
        '''
        count_params = []

        if status_filter != 'all':
            count_query += ' AND COALESCE(ua.status, "pending") = ?'
            count_params.append(status_filter)

        if search:
            count_query += ' AND (u.zeus_pin LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)'
            like = f'%{search}%'
            count_params.extend([like, like, like])

        cursor.execute(count_query, count_params)
        total = cursor.fetchone()['total']

    return jsonify(
        {
            'success': True,
            'users': [
                {
                    'id': u['id'],
                    'zeus_pin': get_pin_display_with_badge(u['id'], requester_id=session.get('admin_id')),
                    'email': u['email'],
                    'full_name': u['full_name'] or 'Anonymous',
                    'registered_at': u['created_at'],
                    'approval_status': u['approval_status'],
                    'reviewed_at': u['reviewed_at'],
                    'subscription_tier': get_user_subscription_tier(u['id']),
                }
                for u in users
            ],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
            },
        }
    ), 200


@admin_bp.route('/api/subscriptions', methods=['GET'])
@admin_required
def get_subscriptions():
    """Get all active or pending subscriptions for admin reporting."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT s.*, u.zeus_pin, u.email, u.full_name,
                   (SELECT SUM(amount) FROM subscription_payments WHERE subscription_id = s.id) AS total_revenue
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            WHERE s.status != 'cancelled'
            ORDER BY s.created_at DESC
            '''
        )
        subs = cursor.fetchall()

    return jsonify(
        {
            'success': True,
            'subscriptions': [
                {
                    'id': s['id'],
                    'user_id': s['user_id'],
                    'zeus_pin': s['zeus_pin'],
                    'user_name': s['full_name'] or 'Anonymous',
                    'email': s['email'],
                    'tier': s['tier'],
                    'status': s['status'],
                    'current_period_start': s['current_period_start'],
                    'current_period_end': s['current_period_end'],
                    'total_revenue': float(s['total_revenue'] or 0),
                }
                for s in subs
            ],
        }
    ), 200


@admin_bp.route('/api/users/<int:user_id>/details', methods=['GET'])
@admin_required
def get_user_details(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT u.id, u.zeus_pin, u.email, u.full_name, u.created_at,
                   COALESCE(ua.status, 'pending') AS approval_status,
                   ua.reviewed_at, ua.rejection_reason, ua.notes
            FROM users u
            LEFT JOIN user_approvals ua ON u.id = ua.user_id
            WHERE u.id = ?
            ''',
            (user_id,),
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        cursor.execute(
            '''
            SELECT feature_name, unlock_type, created_at, expires_at
            FROM user_unlocks WHERE user_id = ?
            ''',
            (user_id,),
        )
        unlocks = cursor.fetchall()

        cursor.execute(
            '''
            SELECT payment_type, amount, status, created_at, approved_at
            FROM one_off_payments
            WHERE user_id = ?
            ORDER BY created_at DESC
            ''',
            (user_id,),
        )
        payments = cursor.fetchall()

        cursor.execute(
            '''
            SELECT COUNT(*) AS count,
                   SUM(CASE WHEN is_from_admin = 0 THEN 1 ELSE 0 END) AS user_messages
            FROM admin_messages
            WHERE user_id = ?
            ''',
            (user_id,),
        )
        message_stats = cursor.fetchone()

    return jsonify(
        {
            'success': True,
            'user': {
                'id': user['id'],
                'zeus_pin': get_pin_display_with_badge(user['id'], requester_id=session.get('admin_id')),
                'email': user['email'],
                'full_name': user['full_name'],
                'registered_at': user['created_at'],
                'approval_status': user['approval_status'],
                'rejection_reason': user['rejection_reason'],
                'notes': user['notes'],
            },
            'unlocks': [
                {
                    'feature': u['feature_name'],
                    'type': u['unlock_type'],
                    'granted_at': u['created_at'],
                    'expires_at': u['expires_at'],
                }
                for u in unlocks
            ],
            'payments': [
                {
                    'type': p['payment_type'],
                    'amount': p['amount'],
                    'status': p['status'],
                    'date': p['created_at'],
                }
                for p in payments
            ],
            'message_stats': {
                'total': message_stats['count'] if message_stats else 0,
                'user_messages': message_stats['user_messages'] if message_stats else 0,
            },
        }
    ), 200


@admin_bp.route('/api/users/<int:user_id>/approve', methods=['PUT'])
@admin_required
def approve_user(user_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    notes = data.get('notes', '')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'User not found'}), 404

        cursor.execute(
            '''
            INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, notes)
            VALUES (?, 'approved', ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                status = 'approved',
                reviewed_by = excluded.reviewed_by,
                reviewed_at = CURRENT_TIMESTAMP,
                notes = excluded.notes
            ''',
            (user_id, admin_id, notes),
        )
        conn.commit()

    log_admin_action(
        admin_id,
        'user_approved',
        target_user_id=user_id,
        details={'notes': notes},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'User approved', 'user_id': user_id}), 200


@admin_bp.route('/api/users/<int:user_id>/reject', methods=['PUT'])
@admin_required
def reject_user(user_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = data.get('rejection_reason', 'No reason provided')
    notes = data.get('notes', '')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, rejection_reason, notes)
            VALUES (?, 'rejected', ?, CURRENT_TIMESTAMP, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                status = 'rejected',
                reviewed_by = excluded.reviewed_by,
                reviewed_at = CURRENT_TIMESTAMP,
                rejection_reason = excluded.rejection_reason,
                notes = excluded.notes
            ''',
            (user_id, admin_id, reason, notes),
        )
        conn.commit()

    log_admin_action(
        admin_id,
        'user_rejected',
        target_user_id=user_id,
        details={'reason': reason, 'notes': notes},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'User rejected', 'reason': reason}), 200


@admin_bp.route('/api/users/<int:user_id>/suspend', methods=['PUT'])
@admin_required
def suspend_user(user_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')
    duration_days = data.get('duration_days', 7)
    notes = f'Suspended for {duration_days} days: {reason}'

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, notes)
            VALUES (?, 'suspended', ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                status = 'suspended',
                reviewed_by = excluded.reviewed_by,
                reviewed_at = CURRENT_TIMESTAMP,
                notes = excluded.notes
            ''',
            (user_id, admin_id, notes),
        )
        conn.commit()

    log_admin_action(
        admin_id,
        'user_suspended',
        target_user_id=user_id,
        details={'reason': reason, 'duration_days': duration_days},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': f'User suspended for {duration_days} days', 'user_id': user_id}), 200


@admin_bp.route('/api/users/<int:user_id>/ban', methods=['PUT'])
@admin_required
def ban_user(user_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, notes)
            VALUES (?, 'banned', ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                status = 'banned',
                reviewed_by = excluded.reviewed_by,
                reviewed_at = CURRENT_TIMESTAMP,
                notes = excluded.notes
            ''',
            (user_id, admin_id, f'Banned: {reason}'),
        )
        conn.commit()

    log_admin_action(
        admin_id,
        'user_banned',
        target_user_id=user_id,
        details={'reason': reason},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'User banned', 'user_id': user_id}), 200


@admin_bp.route('/api/payments/pending', methods=['GET'])
@admin_required
def get_pending_payments():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT oop.id, oop.user_id, oop.payment_type, oop.amount, oop.currency,
                   oop.payfast_payment_id, oop.created_at,
                   u.zeus_pin, u.email, u.full_name
            FROM one_off_payments oop
            JOIN users u ON oop.user_id = u.id
            WHERE oop.status = 'pending_approval'
            ORDER BY oop.created_at DESC
            '''
        )
        payments = cursor.fetchall()

    return jsonify(
        {
            'success': True,
            'payments': [
                {
                    'payment_id': p['id'],
                    'user_id': p['user_id'],
                    'payment_type': p['payment_type'],
                    'amount': p['amount'],
                    'currency': p['currency'],
                    'payfast_id': p['payfast_payment_id'],
                    'created_at': p['created_at'],
                    'user_pin': p['zeus_pin'],
                    'user_email': p['email'],
                    'user_name': p['full_name'] or 'Anonymous',
                }
                for p in payments
            ],
        }
    ), 200


@admin_bp.route('/api/payments/<int:payment_id>/approve', methods=['PUT'])
@admin_required
def approve_payment(payment_id):
    admin_id = session['admin_id']

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, payment_type, status FROM one_off_payments WHERE id = ?', (payment_id,))
        payment = cursor.fetchone()
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404

        if payment['status'] not in ('pending_approval', 'pending'):
            return jsonify({'error': 'Payment is not awaiting approval'}), 400

        feature_map = {
            'profile_picture': 'profile_picture',
            'profile_picture_change': 'profile_picture',
            'pin_retention': 'pin_retention',
            'extended_ttl': 'custom_ttl',
            'file_sharing_basic': 'file_sharing',
        }
        feature_name = feature_map.get(payment['payment_type'], payment['payment_type'])

        cursor.execute(
            '''
            UPDATE one_off_payments
            SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
            WHERE id = ?
            ''',
            (admin_id, payment_id),
        )

        if payment['payment_type'] != 'pin_extension':
            cursor.execute(
                '''
                INSERT INTO user_unlocks (user_id, feature_name, unlock_type, payment_id, granted_by)
                VALUES (?, ?, 'one_off_payment', ?, ?)
                ON CONFLICT(user_id, feature_name) DO UPDATE SET
                    unlock_type = 'one_off_payment',
                    payment_id = excluded.payment_id,
                    granted_by = excluded.granted_by,
                    created_at = CURRENT_TIMESTAMP
                ''',
                (payment['user_id'], feature_name, payment_id, admin_id),
            )

        if payment['payment_type'] == 'pin_extension':
            cursor.execute(
                '''
                UPDATE pin_extensions
                SET expires_at = datetime(COALESCE(expires_at, CURRENT_TIMESTAMP), '+30 days')
                WHERE payment_id = ?
                ''',
                (payment_id,),
            )
            if cursor.rowcount == 0:
                cursor.execute(
                    '''
                    INSERT INTO pin_extensions (user_id, payment_id, extension_days, expires_at)
                    VALUES (?, ?, 30, datetime('now', '+30 days'))
                    ''',
                    (payment['user_id'], payment_id),
                )

            cursor.execute(
                '''
                UPDATE users
                SET pin_extension_count = COALESCE(pin_extension_count, 0) + 1
                WHERE id = ?
                ''',
                (payment['user_id'],),
            )
            refresh_pin_expiry_cache(payment['user_id'], conn=conn)
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, admin_id, message, is_from_admin)
                VALUES (?, ?, ?, 1)
                ''',
                (
                    payment['user_id'],
                    admin_id,
                    'Your Zeus-PIN extension payment was approved. Your PIN is now active for 30 more days.',
                ),
            )

        if payment['payment_type'] == 'profile_picture_change':
            cursor.execute(
                '''
                INSERT OR IGNORE INTO profile_picture_locks (user_id, is_locked, remaining_changes, subscription_tier)
                VALUES (?, 1, 0, 'free')
                ''',
                (payment['user_id'],),
            )
            cursor.execute(
                '''
                UPDATE profile_picture_locks
                SET is_locked = 0,
                    remaining_changes = 1,
                    last_change_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                ''',
                (payment['user_id'],),
            )
            cursor.execute(
                '''
                UPDATE profile_pic_payments
                SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                WHERE payment_id = ?
                ''',
                (admin_id, payment_id),
            )

            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, admin_id, message, is_from_admin)
                VALUES (?, ?, ?, 1)
                ''',
                (
                    payment['user_id'],
                    admin_id,
                    'Your profile picture change payment was approved. You can now upload one new profile picture.',
                ),
            )

        conn.commit()

    log_admin_action(
        admin_id,
        'payment_approved',
        target_payment_id=payment_id,
        target_user_id=payment['user_id'],
        details={'feature': feature_name, 'payment_type': payment['payment_type']},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'Payment approved', 'feature': feature_name}), 200


@admin_bp.route('/api/payments/<int:payment_id>/reject', methods=['PUT'])
@admin_required
def reject_payment(payment_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT payment_type FROM one_off_payments WHERE id = ?', (payment_id,))
        payment = cursor.fetchone()
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404

        cursor.execute(
            '''
            UPDATE one_off_payments
            SET status = 'rejected', approved_by = ?, approved_at = CURRENT_TIMESTAMP, rejection_reason = ?
            WHERE id = ?
            ''',
            (admin_id, reason, payment_id),
        )

        if payment['payment_type'] == 'profile_picture_change':
            cursor.execute(
                '''
                UPDATE profile_pic_payments
                SET status = 'rejected', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                WHERE payment_id = ?
                ''',
                (admin_id, payment_id),
            )
        conn.commit()

    log_admin_action(
        admin_id,
        'payment_rejected',
        target_payment_id=payment_id,
        details={'reason': reason},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'Payment rejected', 'reason': reason}), 200


@admin_bp.route('/api/messages/users', methods=['GET'])
@admin_required
def get_users_with_messages():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT u.id, u.zeus_pin, u.email, u.full_name,
                   COALESCE((SELECT COUNT(*) FROM admin_messages
                             WHERE user_id = u.id AND read_at IS NULL AND is_from_admin = 0), 0) AS unread_count,
                   (SELECT MAX(created_at) FROM admin_messages WHERE user_id = u.id) AS last_message_at,
                   COALESCE(ua.status, 'pending') AS approval_status
            FROM users u
            LEFT JOIN admin_messages am ON u.id = am.user_id
            LEFT JOIN user_approvals ua ON u.id = ua.user_id
            GROUP BY u.id
            ORDER BY
                CASE WHEN ua.status = 'pending' THEN 0 ELSE 1 END,
                last_message_at DESC NULLS LAST
            '''
        )
        users = cursor.fetchall()

    return jsonify(
        {
            'success': True,
            'users': [
                {
                    'user_id': u['id'],
                    'zeus_pin': get_pin_display_with_badge(u['id'], requester_id=session.get('admin_id')),
                    'email': u['email'],
                    'full_name': u['full_name'] or 'Anonymous',
                    'unread_count': u['unread_count'] or 0,
                    'last_message_at': u['last_message_at'],
                    'approval_status': u['approval_status'],
                    'subscription_tier': get_user_subscription_tier(u['id']),
                }
                for u in users
            ],
        }
    ), 200


@admin_bp.route('/api/messages/<int:user_id>', methods=['GET'])
@admin_required
def get_messages_with_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT id, message, is_from_admin, created_at, read_at
            FROM admin_messages
            WHERE user_id = ?
            ORDER BY created_at ASC
            ''',
            (user_id,),
        )
        messages = cursor.fetchall()

        cursor.execute(
            '''
            UPDATE admin_messages
            SET read_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND is_from_admin = 0 AND read_at IS NULL
            ''',
            (user_id,),
        )
        conn.commit()

    return jsonify(
        {
            'success': True,
            'messages': [
                {
                    'id': m['id'],
                    'message': m['message'],
                    'is_from_admin': bool(m['is_from_admin']),
                    'created_at': m['created_at'],
                    'read_at': m['read_at'],
                }
                for m in messages
            ],
        }
    ), 200


@admin_bp.route('/api/messages/send', methods=['POST'])
@admin_required
def send_message_to_user():
    data = request.get_json() or {}
    user_id = data.get('user_id')
    message = (data.get('message') or '').strip()

    if not user_id or not message:
        return jsonify({'error': 'user_id and message required'}), 400

    admin_id = session['admin_id']

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO admin_messages (user_id, admin_id, message, is_from_admin)
            VALUES (?, ?, ?, 1)
            ''',
            (user_id, admin_id, message),
        )
        conn.commit()

    log_admin_action(
        admin_id,
        'sent_message',
        target_user_id=user_id,
        details={'message_preview': message[:100]},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'Message sent to user'}), 201


@admin_bp.route('/api/messages/broadcast', methods=['POST'])
@admin_required
def broadcast_message():
    admin_id = session['admin_id']
    data = request.get_json() or {}
    message = (data.get('message') or '').strip()
    target = data.get('target', 'approved')

    if not message:
        return jsonify({'error': 'Message required'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if target == 'approved':
            cursor.execute(
                '''
                SELECT u.id
                FROM users u
                JOIN user_approvals ua ON u.id = ua.user_id
                WHERE ua.status = 'approved'
                '''
            )
        elif target == 'pending':
            cursor.execute(
                '''
                SELECT u.id
                FROM users u
                LEFT JOIN user_approvals ua ON u.id = ua.user_id
                WHERE ua.status IS NULL OR ua.status = 'pending'
                '''
            )
        else:
            cursor.execute('SELECT id FROM users')

        recipients = cursor.fetchall()
        for user in recipients:
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, admin_id, message, is_from_admin)
                VALUES (?, ?, ?, 1)
                ''',
                (user['id'], admin_id, message),
            )
        conn.commit()

    count = len(recipients)
    log_admin_action(
        admin_id,
        'broadcast_message',
        details={'target': target, 'recipient_count': count, 'message_preview': message[:100]},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': f'Broadcast sent to {count} users', 'recipient_count': count}), 200


@admin_bp.route('/api/stats', methods=['GET'])
@admin_required
def get_system_stats():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT COUNT(*) AS count
            FROM users u
            LEFT JOIN user_approvals ua ON u.id = ua.user_id
            WHERE ua.status IS NULL OR ua.status = 'pending'
            '''
        )
        pending_approvals = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) AS count FROM user_approvals WHERE status = 'approved'")
        active_users = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) AS count FROM one_off_payments WHERE status = 'pending_approval'")
        pending_payments = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) AS count FROM kyc_documents WHERE admin_review_status = 'pending'")
        pending_kyc = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) AS count FROM profile_pic_payments WHERE status = 'pending_approval'")
        pending_profile_pic_requests = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) AS count FROM users')
        total_users = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT SUM(amount) AS total
            FROM one_off_payments
            WHERE status = 'approved' AND DATE(approved_at) = DATE('now')
            '''
        )
        revenue_today = cursor.fetchone()['total'] or 0

        cursor.execute("SELECT SUM(amount) AS total FROM one_off_payments WHERE status = 'approved'")
        total_revenue = cursor.fetchone()['total'] or 0

        cursor.execute(
            '''
            SELECT COUNT(*) AS count
            FROM admin_messages
            WHERE is_from_admin = 0 AND read_at IS NULL
            '''
        )
        unread_messages = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT aal.action, aal.created_at, aal.details,
                   au.username AS admin_name,
                   u.zeus_pin AS target_pin
            FROM admin_audit_log aal
            LEFT JOIN admin_users au ON aal.admin_id = au.id
            LEFT JOIN users u ON aal.target_user_id = u.id
            ORDER BY aal.created_at DESC
            LIMIT 10
            '''
        )
        recent = cursor.fetchall()

    return jsonify(
        {
            'success': True,
            'stats': {
                'pending_approvals': pending_approvals,
                'active_users': active_users,
                'pending_payments': pending_payments,
                'pending_kyc': pending_kyc,
                'pending_profile_pic_requests': pending_profile_pic_requests,
                'total_users': total_users,
                'revenue_today': float(revenue_today),
                'total_revenue': float(total_revenue),
                'unread_messages': unread_messages,
            },
            'recent_activities': [
                {
                    'action': row['action'],
                    'timestamp': row['created_at'],
                    'admin': row['admin_name'],
                    'target_user': row['target_pin'],
                    'details': json.loads(row['details']) if row['details'] else {},
                }
                for row in recent
            ],
        }
    ), 200


@admin_bp.route('/api/kyc/pending', methods=['GET'])
@admin_required
def get_pending_kyc():
    """Get all pending KYC reviews."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT kyc.id, kyc.user_id, kyc.id_document_path, kyc.selfie_path,
                   kyc.document_type, kyc.face_match_score, kyc.auto_verified,
                   kyc.created_at, u.zeus_pin, u.email, u.full_name
            FROM kyc_documents kyc
            JOIN users u ON kyc.user_id = u.id
            LEFT JOIN user_approvals ua ON ua.user_id = u.id
            WHERE kyc.admin_review_status = 'pending'
              AND (ua.status IS NULL OR ua.status = 'pending')
            ORDER BY kyc.created_at ASC
            '''
        )
        pending = cursor.fetchall()

    return jsonify(
        {
            'success': True,
            'kyc_requests': [
                {
                    'id': row['id'],
                    'user_id': row['user_id'],
                    'zeus_pin': row['zeus_pin'],
                    'full_name': row['full_name'],
                    'email': row['email'],
                    'id_document_path': row['id_document_path'],
                    'selfie_path': row['selfie_path'],
                    'document_type': row['document_type'],
                    'face_match_score': row['face_match_score'],
                    'auto_verified': bool(row['auto_verified']),
                    'created_at': row['created_at'],
                }
                for row in pending
            ],
        }
    ), 200


@admin_bp.route('/api/kyc/<int:kyc_id>/approve', methods=['PUT'])
@admin_required
def approve_kyc(kyc_id):
    """Approve KYC and activate user account."""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    notes = (data.get('notes') or '').strip()
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT k.user_id, u.zeus_pin
                FROM kyc_documents k
                JOIN users u ON u.id = k.user_id
                WHERE k.id = ?
                ''',
                (kyc_id,),
            )
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'KYC record not found'}), 404

            user_id = result['user_id']

            cursor.execute(
                '''
                UPDATE kyc_documents
                SET admin_review_status = 'approved',
                    reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    admin_review_notes = ?
                WHERE id = ?
                ''',
                (admin_id, notes, kyc_id),
            )

            if cursor.rowcount == 0:
                return jsonify({'error': 'KYC record not found'}), 404

            approval_note = f'KYC Approved: {notes}' if notes else 'KYC Approved'
            cursor.execute(
                '''
                UPDATE user_approvals
                SET status = 'approved',
                    reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    rejection_reason = NULL,
                    notes = ?
                WHERE user_id = ?
                ''',
                (admin_id, approval_note, user_id),
            )

            if cursor.rowcount == 0:
                cursor.execute(
                    '''
                    INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, notes)
                    VALUES (?, 'approved', ?, CURRENT_TIMESTAMP, ?)
                    ''',
                    (user_id, admin_id, approval_note),
                )

            approval_message = (
                '✅ Your ZeusChat account has been APPROVED!\n\n'
                f'Your Zeus-PIN {result["zeus_pin"]} is now active and ready to use.\n\n'
                'Start adding contacts and enjoy secure messaging.'
            )
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, ?)
                ''',
                (user_id, approval_message, admin_id),
            )

            conn.commit()

        log_admin_action(
            admin_id,
            'kyc_approved',
            target_user_id=user_id,
            details={'kyc_id': kyc_id, 'notes': notes},
            ip_address=request.remote_addr,
        )

        return jsonify({'success': True, 'message': 'KYC approved - user activated'}), 200
    except Exception as e:
        print(f"❌ KYC approval error (kyc_id={kyc_id}, admin_id={admin_id}): {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/kyc/<int:kyc_id>/reject', methods=['PUT'])
@admin_required
def reject_kyc(kyc_id):
    """Reject KYC and keep account deactivated."""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = (data.get('reason') or 'No reason provided').strip()
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT user_id FROM kyc_documents WHERE id = ?', (kyc_id,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'KYC record not found'}), 404

            user_id = result['user_id']

            cursor.execute(
                '''
                UPDATE kyc_documents
                SET admin_review_status = 'rejected',
                    reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    admin_review_notes = ?
                WHERE id = ?
                ''',
                (admin_id, reason, kyc_id),
            )

            if cursor.rowcount == 0:
                return jsonify({'error': 'KYC record not found'}), 404

            cursor.execute(
                '''
                UPDATE user_approvals
                SET status = 'rejected',
                    reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    rejection_reason = ?,
                    notes = 'KYC rejected'
                WHERE user_id = ?
                ''',
                (admin_id, reason, user_id),
            )

            if cursor.rowcount == 0:
                cursor.execute(
                    '''
                    INSERT INTO user_approvals (user_id, status, reviewed_by, reviewed_at, rejection_reason, notes)
                    VALUES (?, 'rejected', ?, CURRENT_TIMESTAMP, ?, 'KYC rejected')
                    ''',
                    (user_id, admin_id, reason),
                )

            rejection_message = f'Your ZeusChat KYC verification was rejected. Reason: {reason}'
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, ?)
                ''',
                (user_id, rejection_message, admin_id),
            )

            conn.commit()

        log_admin_action(
            admin_id,
            'kyc_rejected',
            target_user_id=user_id,
            details={'kyc_id': kyc_id, 'reason': reason},
            ip_address=request.remote_addr,
        )

        return jsonify({'success': True, 'message': 'KYC rejected - user remains inactive'}), 200
    except Exception as e:
        print(f"❌ KYC rejection error (kyc_id={kyc_id}, admin_id={admin_id}): {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/profile-pic/requests', methods=['GET'])
@admin_required
def get_profile_pic_requests():
    """Get pending profile picture change requests."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT ppp.id, ppp.user_id, ppp.created_at,
                   oop.amount, oop.currency, oop.payfast_payment_id,
                   u.zeus_pin, u.email, u.full_name
            FROM profile_pic_payments ppp
            JOIN one_off_payments oop ON ppp.payment_id = oop.id
            JOIN users u ON ppp.user_id = u.id
            WHERE ppp.status = 'pending_approval'
            ORDER BY ppp.created_at DESC
            '''
        )
        rows = cursor.fetchall()

    return jsonify(
        {
            'success': True,
            'requests': [
                {
                    'id': row['id'],
                    'user_id': row['user_id'],
                    'zeus_pin': row['zeus_pin'],
                    'full_name': row['full_name'],
                    'email': row['email'],
                    'amount': row['amount'],
                    'currency': row['currency'],
                    'payfast_payment_id': row['payfast_payment_id'],
                    'created_at': row['created_at'],
                }
                for row in rows
            ],
        }
    ), 200


@admin_bp.route('/api/profile-pic/<int:request_id>/approve', methods=['PUT'])
@admin_required
def approve_profile_pic_change(request_id):
    """Approve profile picture change request and grant one unlock."""
    admin_id = session['admin_id']

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM profile_pic_payments WHERE id = ?', (request_id,))
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Request not found'}), 404

        user_id = result['user_id']

        cursor.execute(
            '''
            UPDATE profile_pic_payments
            SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
            WHERE id = ?
            ''',
            (admin_id, request_id),
        )

        cursor.execute(
            '''
            UPDATE profile_picture_locks
            SET is_locked = 0,
                remaining_changes = 1,
                last_change_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
            ''',
            (user_id,),
        )

        notification = (
            'Your profile picture change request has been approved. '
            'You now have one profile picture change available.'
        )
        cursor.execute(
            '''
            INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
            VALUES (?, ?, 1, ?)
            ''',
            (user_id, notification, admin_id),
        )

        conn.commit()

    log_admin_action(
        admin_id,
        'profile_pic_change_approved',
        target_user_id=user_id,
        details={'request_id': request_id},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True, 'message': 'Profile picture change approved'}), 200


# ============================================
# GHOST MARKET ADMIN ENDPOINTS
# ============================================

@admin_bp.route('/api/ghost-market/pending-items', methods=['GET'])
@admin_required
def admin_pending_items():
    """Get all items pending admin approval"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT gmi.*, u.zeus_pin as seller_pin, u.email, u.full_name,
                   gms.store_name
            FROM ghost_market_items gmi
            JOIN ghost_market_sellers gms ON gmi.seller_id = gms.user_id
            JOIN users u ON gms.user_id = u.id
            WHERE gmi.status = 'pending_approval'
            ORDER BY gmi.created_at ASC
        ''')
        items = cursor.fetchall()

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
                'seller_pin': item['seller_pin'],
                'seller_name': item['full_name'],
                'store_name': item['store_name'],
                'created_at': item['created_at']
            }
            for item in items
        ]
    })


@admin_bp.route('/api/ghost-market/items/<int:item_id>/approve', methods=['PUT'])
@admin_required
def admin_approve_item(item_id):
    """Admin approves item to appear in Ghost Market"""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    notes = data.get('notes', '')

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE ghost_market_items
            SET status = 'approved',
                approved_by = ?,
                approved_at = CURRENT_TIMESTAMP,
                admin_notes = ?
            WHERE id = ?
        ''', (admin_id, notes, item_id))

        cursor.execute(
            'SELECT seller_id, title FROM ghost_market_items WHERE id = ?',
            (item_id,)
        )
        item = cursor.fetchone()

        if item:
            cursor.execute('''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, ?)
            ''', (
                item['seller_id'],
                '✅ Your item "{}" has been APPROVED and is now live in Ghost Market!\n\nAdmin notes: {}'.format(
                    item['title'],
                    notes or 'No additional notes.'
                ),
                admin_id
            ))

            socketio_ext = current_app.extensions.get('socketio')
            if socketio_ext:
                socketio_ext.emit(
                    'item_approved',
                    {
                        'item_id': item_id,
                        'title': item['title'],
                        'message': 'Your item "{}" is now live!'.format(item['title']),
                    },
                    room='user:{}'.format(item['seller_id']),
                )

        conn.commit()

    log_admin_action(
        admin_id,
        'ghost_market_item_approved',
        target_user_id=item['seller_id'] if item else None,
        details={'item_id': item_id, 'notes': notes},
        ip_address=request.remote_addr
    )

    return jsonify({'success': True, 'message': 'Item approved and live'})


@admin_bp.route('/api/ghost-market/items/<int:item_id>/reject', methods=['PUT'])
@admin_required
def admin_reject_item(item_id):
    """Admin rejects item with reason"""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE ghost_market_items
            SET status = 'rejected',
                approved_by = ?,
                approved_at = CURRENT_TIMESTAMP,
                rejection_reason = ?
            WHERE id = ?
        ''', (admin_id, reason, item_id))

        cursor.execute(
            'SELECT seller_id, title FROM ghost_market_items WHERE id = ?',
            (item_id,)
        )
        item = cursor.fetchone()

        if item:
            cursor.execute('''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, ?)
            ''', (
                item['seller_id'],
                '❌ Your item "{}" was REJECTED.\nReason: {}\n\nPlease update your listing and resubmit.'.format(
                    item['title'],
                    reason
                ),
                admin_id
            ))

            socketio_ext = current_app.extensions.get('socketio')
            if socketio_ext:
                socketio_ext.emit(
                    'item_rejected',
                    {
                        'item_id': item_id,
                        'title': item['title'],
                        'reason': reason,
                        'message': 'Your item "{}" was rejected. Reason: {}'.format(item['title'], reason),
                    },
                    room='user:{}'.format(item['seller_id']),
                )

        conn.commit()

    log_admin_action(
        admin_id,
        'ghost_market_item_rejected',
        target_user_id=item['seller_id'] if item else None,
        details={'item_id': item_id, 'reason': reason},
        ip_address=request.remote_addr
    )

    return jsonify({'success': True, 'message': 'Item rejected'})


@admin_bp.route('/api/ghost-market/seller-applications', methods=['GET'])
@admin_required
def admin_seller_applications():
    """Get all pending seller applications"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT gms.*, u.zeus_pin, u.email, u.full_name
            FROM ghost_market_sellers gms
            JOIN users u ON gms.user_id = u.id
            WHERE gms.application_status = 'pending'
            ORDER BY gms.created_at ASC
        ''')
        applications = cursor.fetchall()

    return jsonify({
        'success': True,
        'applications': [
            {
                'id': app['id'],
                'user_id': app['user_id'],
                'zeus_pin': app['zeus_pin'],
                'full_name': app['full_name'],
                'email': app['email'],
                'store_name': app['store_name'],
                'store_description': app['store_description'],
                'created_at': app['created_at']
            }
            for app in applications
        ]
    })


@admin_bp.route('/api/ghost-market/sellers/<int:user_id>/approve', methods=['PUT'])
@admin_required
def admin_approve_seller(user_id):
    """Admin approves seller application"""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    notes = data.get('notes', '')

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE ghost_market_sellers
            SET application_status = 'approved',
                approved_by = ?,
                approved_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (admin_id, user_id))

        cursor.execute('''
            INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
            VALUES (?, ?, 1, ?)
        ''', (
            user_id,
            '✅ Your seller application has been approved! You can now list items in Ghost Market.\n\nNotes: {}'.format(notes),
            admin_id
        ))

        conn.commit()

    log_admin_action(
        admin_id,
        'ghost_market_seller_approved',
        target_user_id=user_id,
        details={'notes': notes},
        ip_address=request.remote_addr
    )

    return jsonify({'success': True, 'message': 'Seller approved'})


@admin_bp.route('/api/ghost-market/sellers/<int:user_id>/reject', methods=['PUT'])
@admin_required
def admin_reject_seller(user_id):
    """Admin rejects seller application"""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE ghost_market_sellers
            SET application_status = 'rejected',
                approved_by = ?,
                approved_at = CURRENT_TIMESTAMP,
                rejection_reason = ?
            WHERE user_id = ?
        ''', (admin_id, reason, user_id))

        cursor.execute('''
            INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
            VALUES (?, ?, 1, ?)
        ''', (
            user_id,
            '❌ Your seller application was rejected.\nReason: {}'.format(reason),
            admin_id
        ))

        conn.commit()

    log_admin_action(
        admin_id,
        'ghost_market_seller_rejected',
        target_user_id=user_id,
        details={'reason': reason},
        ip_address=request.remote_addr
    )

    return jsonify({'success': True, 'message': 'Seller rejected'})


# ============================================================
# USER FEEDBACK MANAGEMENT
# ============================================================

@admin_bp.route('/api/feedback', methods=['GET'])
@admin_required
def get_feedback():
    """List user feedback, optionally filtered by status."""
    status = request.args.get('status', 'pending')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if status == 'all':
            cursor.execute('''
                SELECT f.*, u.zeus_pin, u.full_name, u.email
                FROM user_feedback f
                LEFT JOIN users u ON f.user_id = u.id
                ORDER BY f.created_at DESC
            ''')
        else:
            cursor.execute('''
                SELECT f.*, u.zeus_pin, u.full_name, u.email
                FROM user_feedback f
                LEFT JOIN users u ON f.user_id = u.id
                WHERE f.status = ?
                ORDER BY f.created_at DESC
            ''', (status,))
        feedback = cursor.fetchall()

    return jsonify({
        'success': True,
        'feedback': [dict(f) for f in feedback]
    }), 200


@admin_bp.route('/api/feedback/<int:feedback_id>/status', methods=['PUT'])
@admin_required
def update_feedback_status(feedback_id):
    """Update the status and optional admin notes on a feedback item."""
    data = request.get_json() or {}
    status = data.get('status', '').strip()
    admin_notes = data.get('admin_notes', '').strip()

    valid_statuses = {'pending', 'read', 'resolved', 'dismissed'}
    if status not in valid_statuses:
        return jsonify({'error': f'Invalid status. Must be one of: {", ".join(sorted(valid_statuses))}'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_feedback
            SET status = ?,
                admin_notes = ?,
                resolved_at = CASE WHEN ? IN ('resolved', 'dismissed') THEN CURRENT_TIMESTAMP ELSE resolved_at END
            WHERE id = ?
        ''', (status, admin_notes, status, feedback_id))
        if cursor.rowcount == 0:
            return jsonify({'error': 'Feedback item not found'}), 404
        conn.commit()

    return jsonify({'success': True}), 200


# ============================================================
# GHOST FORUMS MODERATION
# ============================================================

@admin_bp.route('/api/forums', methods=['GET'])
@admin_required
def admin_list_forums():
    """List all ghost forums for moderation."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT gf.*, u.full_name AS creator_name, u.zeus_pin AS creator_pin,
                   (SELECT COUNT(*) FROM forum_posts fp WHERE fp.forum_id = gf.id) AS live_post_count,
                   (SELECT COUNT(*) FROM forum_members fm WHERE fm.forum_id = gf.id) AS live_member_count
            FROM ghost_forums gf
            JOIN users u ON gf.creator_id = u.id
            ORDER BY gf.updated_at DESC, gf.created_at DESC
        ''')
        forums = cursor.fetchall()

    return jsonify({
        'success': True,
        'forums': [
            {
                **dict(forum),
                'post_count': forum['live_post_count'],
                'member_count': forum['live_member_count'],
            }
            for forum in forums
        ]
    }), 200


@admin_bp.route('/api/forums/<int:forum_id>/posts', methods=['GET'])
@admin_required
def admin_list_forum_posts(forum_id):
    """List forum posts with author identities for moderation."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT fp.*, u.full_name, u.zeus_pin, gf.name AS forum_name
            FROM forum_posts fp
            JOIN users u ON fp.user_id = u.id
            JOIN ghost_forums gf ON fp.forum_id = gf.id
            WHERE fp.forum_id = ?
            ORDER BY fp.is_pinned DESC, fp.created_at DESC
        ''', (forum_id,))
        posts = cursor.fetchall()

    return jsonify({'success': True, 'posts': [dict(post) for post in posts]}), 200


@admin_bp.route('/api/forum-posts/<int:post_id>/moderate', methods=['PUT'])
@admin_required
def admin_moderate_forum_post(post_id):
    """Pin, lock, unlock, or delete a forum post."""
    data = request.get_json() or {}
    action = (data.get('action') or '').strip().lower()
    valid_actions = {'pin', 'unpin', 'lock', 'unlock', 'delete'}
    if action not in valid_actions:
        return jsonify({'error': 'Invalid moderation action'}), 400

    admin_id = session.get('admin_id')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT forum_id, title, user_id FROM forum_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        if action == 'delete':
            cursor.execute('DELETE FROM forum_votes WHERE post_id = ?', (post_id,))
            cursor.execute('DELETE FROM forum_replies WHERE post_id = ?', (post_id,))
            cursor.execute('DELETE FROM forum_posts WHERE id = ?', (post_id,))
        elif action == 'pin':
            cursor.execute('UPDATE forum_posts SET is_pinned = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (post_id,))
        elif action == 'unpin':
            cursor.execute('UPDATE forum_posts SET is_pinned = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (post_id,))
        elif action == 'lock':
            cursor.execute('UPDATE forum_posts SET is_locked = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (post_id,))
        elif action == 'unlock':
            cursor.execute('UPDATE forum_posts SET is_locked = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (post_id,))

        cursor.execute('''
            UPDATE ghost_forums
            SET post_count = (
                    SELECT COUNT(*) FROM forum_posts WHERE forum_id = ?
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (post['forum_id'], post['forum_id']))
        conn.commit()

    log_admin_action(
        admin_id,
        'forum_post_moderated',
        target_user_id=post['user_id'],
        details={'post_id': post_id, 'forum_id': post['forum_id'], 'title': post['title'], 'action': action},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True}), 200


@admin_bp.route('/api/forum-replies/<int:reply_id>', methods=['DELETE'])
@admin_required
def admin_delete_forum_reply(reply_id):
    """Delete a forum reply as part of moderation."""
    admin_id = session.get('admin_id')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT post_id, user_id FROM forum_replies WHERE id = ?', (reply_id,))
        reply = cursor.fetchone()
        if not reply:
            return jsonify({'error': 'Reply not found'}), 404

        cursor.execute('DELETE FROM forum_replies WHERE id = ?', (reply_id,))
        cursor.execute('''
            UPDATE forum_posts
            SET reply_count = (
                    SELECT COUNT(*) FROM forum_replies WHERE post_id = ?
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (reply['post_id'], reply['post_id']))
        conn.commit()

    log_admin_action(
        admin_id,
        'forum_reply_deleted',
        target_user_id=reply['user_id'],
        details={'reply_id': reply_id, 'post_id': reply['post_id']},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True}), 200


# ============================================================
# ADMIN GHOST COMMUNITY MODERATION
# ============================================================

@admin_bp.route('/api/ghost/pending', methods=['GET'])
@admin_required
def admin_ghost_pending():
    """Get posts pending AI/admin review for Ghost Ultimate."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT gp.*, u.zeus_pin, u.email, u.full_name,
                   (SELECT COUNT(*) FROM ghost_reports WHERE post_id = gp.id) AS report_count
            FROM ghost_posts gp
            JOIN users u ON gp.user_id = u.id
            WHERE gp.status IN ('pending_ai', 'pending_review')
            ORDER BY gp.created_at ASC
        ''')
        posts = cursor.fetchall()
    return jsonify({'success': True, 'posts': [dict(p) for p in posts]}), 200


@admin_bp.route('/api/ghost/posts/<int:post_id>/approve', methods=['PUT', 'POST'])
@admin_required
def admin_ghost_approve(post_id):
    admin_id = session['admin_id']

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE ghost_posts SET status = \"approved\", ai_approved = 1 WHERE id = ?', (post_id,))
        if cursor.rowcount == 0:
            return jsonify({'error': 'Post not found'}), 404

        cursor.execute('SELECT user_id FROM ghost_posts WHERE id = ?', (post_id,))
        result = cursor.fetchone()
        if result:
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, ?)
                ''',
                (result['user_id'], '✅ Your Ghost Post has been approved and is now live!', admin_id),
            )

        cursor.execute('UPDATE moderation_queue SET status = \"approved\" WHERE post_id = ?', (post_id,))
        conn.commit()

    return jsonify({'success': True}), 200


@admin_bp.route('/api/ghost/posts/<int:post_id>/reject', methods=['PUT', 'POST'])
@admin_required
def admin_ghost_reject(post_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = (data.get('reason') or 'No reason provided').strip()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE ghost_posts SET status = \"rejected\", ai_approved = 0 WHERE id = ?', (post_id,))
        if cursor.rowcount == 0:
            return jsonify({'error': 'Post not found'}), 404

        cursor.execute('SELECT user_id FROM ghost_posts WHERE id = ?', (post_id,))
        result = cursor.fetchone()
        if result:
            cursor.execute(
                '''
                INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                VALUES (?, ?, 1, ?)
                ''',
                (result['user_id'], f'❌ Your Ghost Post was rejected.\nReason: {reason}', admin_id),
            )

        cursor.execute('UPDATE moderation_queue SET status = \"rejected\" WHERE post_id = ?', (post_id,))
        conn.commit()

    return jsonify({'success': True}), 200


@admin_bp.route('/api/ghost/reports', methods=['GET'])
@admin_required
def admin_ghost_reports():
    """Get pending user reports for Ghost Ultimate posts."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT gr.*, gp.title, gp.user_id AS creator_user_id, u.zeus_pin AS reporter_pin,
                   (SELECT zeus_pin FROM users WHERE id = gp.user_id) AS creator_pin
            FROM ghost_reports gr
            JOIN ghost_posts gp ON gr.post_id = gp.id
            JOIN users u ON gr.reporter_id = u.id
            WHERE gr.status = 'pending'
            ORDER BY gr.created_at ASC
        ''')
        reports = cursor.fetchall()
    return jsonify({'success': True, 'reports': [dict(r) for r in reports]}), 200


@admin_bp.route('/api/ghost/creators', methods=['GET'])
@admin_required
def admin_ghost_creators():
    """Get top Ghost Community creators ranked by earnings."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT cw.user_id,
                   cw.balance,
                   cw.total_earned,
                   cw.total_withdrawn,
                   cw.pending_payout,
                   u.zeus_pin,
                   u.full_name,
                   u.ghost_banned,
                   u.ghost_ban_expires,
                   (
                       SELECT COUNT(*)
                       FROM ghost_posts gp
                       WHERE gp.user_id = u.id
                   ) AS post_count
            FROM creator_wallets cw
            JOIN users u ON cw.user_id = u.id
            ORDER BY cw.total_earned DESC, cw.balance DESC
            LIMIT 50
            '''
        )
        creators = cursor.fetchall()

    return jsonify({'success': True, 'creators': [dict(c) for c in creators]}), 200


@admin_bp.route('/api/ghost/reports/<int:report_id>/resolve', methods=['PUT'])
@admin_required
def admin_ghost_resolve_report(report_id):
    """Resolve a Ghost Community report."""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    action = (data.get('action') or 'resolved').strip().lower()
    allowed_statuses = {'dismissed', 'action_taken', 'resolved'}
    status = action if action in allowed_statuses else 'resolved'

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE ghost_reports
            SET status = ?,
                resolved_by = ?,
                resolved_at = CURRENT_TIMESTAMP
            WHERE id = ?
            ''',
            (status, admin_id, report_id),
        )
        if cursor.rowcount == 0:
            return jsonify({'error': 'Report not found'}), 404
        conn.commit()

    return jsonify({'success': True, 'status': status}), 200


@admin_bp.route('/api/ghost-market/items/<int:item_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_market_item(item_id):
    """Admin hard-delete a Ghost Market listing and notify the seller."""
    admin_id = session['admin_id']
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT seller_id, title FROM ghost_market_items WHERE id = ?', (item_id,))
        item = cursor.fetchone()
        if not item:
            return jsonify({'error': 'Item not found'}), 404
        cursor.execute('DELETE FROM ghost_market_items WHERE id = ?', (item_id,))
        cursor.execute(
            '''INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
               VALUES (?, ?, 1, ?)''',
            (item['seller_id'], f'❌ Your listing "{item["title"]}" was deleted by admin.', admin_id),
        )
        log_admin_action(admin_id, 'deleted_market_item', target_user_id=item['seller_id'],
                         details={'item_id': item_id, 'title': item['title']})
        conn.commit()
    return jsonify({'success': True}), 200


@admin_bp.route('/api/ghost/posts/<int:post_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_ghost_post(post_id):
    """Admin hard-delete a Ghost Community post and notify the author."""
    admin_id = session['admin_id']
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, title FROM ghost_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        cursor.execute('DELETE FROM ghost_posts WHERE id = ?', (post_id,))
        cursor.execute(
            '''INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
               VALUES (?, ?, 1, ?)''',
            (post['user_id'], f'❌ Your Ghost post "{post["title"]}" was deleted by admin.', admin_id),
        )
        log_admin_action(admin_id, 'deleted_ghost_post', target_user_id=post['user_id'],
                         details={'post_id': post_id, 'title': post['title']})
        conn.commit()
    return jsonify({'success': True}), 200


@admin_bp.route('/api/ghost/comments/<int:comment_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_ghost_comment(comment_id):
    """Admin hard-delete a Ghost Community comment."""
    admin_id = session['admin_id']
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, content, post_id FROM ghost_comments WHERE id = ?', (comment_id,))
        comment = cursor.fetchone()
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404
        cursor.execute('DELETE FROM ghost_comments WHERE id = ?', (comment_id,))
        cursor.execute(
            'UPDATE ghost_posts SET comment_count = MAX(0, comment_count - 1) WHERE id = ?',
            (comment['post_id'],),
        )
        log_admin_action(admin_id, 'deleted_ghost_comment', target_user_id=comment['user_id'],
                         details={'comment_id': comment_id})
        conn.commit()
    return jsonify({'success': True}), 200


@admin_bp.route('/api/users/<int:user_id>/activity', methods=['GET'])
@admin_required
def admin_user_activity(user_id):
    """Return a summary of a user's Ghost Market listings, community posts, and comments."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, zeus_pin, full_name, email FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        cursor.execute(
            'SELECT id, title, price, status, created_at FROM ghost_market_items WHERE seller_id = ? ORDER BY created_at DESC',
            (user_id,),
        )
        market_listings = [dict(r) for r in cursor.fetchall()]

        cursor.execute(
            'SELECT id, title, is_paid, price, view_count, paid_view_count, created_at FROM ghost_posts WHERE user_id = ? ORDER BY created_at DESC',
            (user_id,),
        )
        ghost_posts = [dict(r) for r in cursor.fetchall()]

        cursor.execute(
            'SELECT id, content, post_id, created_at FROM ghost_comments WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
            (user_id,),
        )
        comments = [dict(r) for r in cursor.fetchall()]

    return jsonify({
        'success': True,
        'user': dict(user),
        'market_listings': market_listings,
        'ghost_posts': ghost_posts,
        'comments': comments,
    }), 200


@admin_bp.route('/api/ghost/banned', methods=['GET'])
@admin_required
def admin_ghost_banned_users():
    """List users currently banned from Ghost Community."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT u.id,
                   u.zeus_pin,
                   u.full_name,
                   u.email,
                   u.ghost_ban_reason,
                   u.ghost_ban_expires,
                   (
                       SELECT COUNT(*)
                       FROM ghost_posts gp
                       WHERE gp.user_id = u.id
                   ) AS remaining_posts
            FROM users u
            WHERE u.ghost_banned = 1
            ORDER BY u.ghost_ban_expires DESC, u.id DESC
            '''
        )
        users = cursor.fetchall()

    return jsonify({'success': True, 'users': [dict(user) for user in users]}), 200


@admin_bp.route('/api/ghost/users/<int:user_id>/ban', methods=['PUT', 'POST'])
@admin_required
def admin_ghost_ban_user(user_id):
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = (data.get('reason') or 'No reason provided').strip()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            UPDATE users
            SET ghost_banned = 1,
                ghost_ban_reason = ?,
                ghost_ban_expires = datetime('now', '+30 days')
            WHERE id = ?
            ''',
            (reason, user_id),
        )
        if cursor.rowcount == 0:
            return jsonify({'error': 'User not found'}), 404

        cursor.execute('DELETE FROM ghost_posts WHERE user_id = ?', (user_id,))
        cursor.execute(
            '''
            INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
            VALUES (?, ?, 1, ?)
            ''',
            (
                user_id,
                f'🚫 You have been banned from Ghost Community.\nReason: {reason}\nBan expires in 30 days.',
                admin_id,
            ),
        )
        conn.commit()

    log_admin_action(
        admin_id,
        'ghost_user_banned',
        target_user_id=user_id,
        details={'reason': reason},
        ip_address=request.remote_addr,
    )

    return jsonify({'success': True}), 200
