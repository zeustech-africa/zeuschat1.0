from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
import hashlib
import json
from admin_middleware import admin_required, get_db_connection, log_admin_action

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/login')
def login_page():
    return render_template('admin/login.html')


@admin_bp.route('/dashboard')
def dashboard_page():
    if 'admin_id' not in session:
        return redirect(url_for('admin.login_page'))
    return render_template('admin/dashboard.html')


@admin_bp.route('/api/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT id, username, role, permissions
            FROM admin_users
            WHERE username = ? AND password_hash = ?
            ''',
            (username, password_hash),
        )
        admin = cursor.fetchone()

        if not admin:
            log_admin_action(None, 'failed_login', details={'username': username}, ip_address=request.remote_addr)
            return jsonify({'error': 'Invalid credentials'}), 401

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
                    'zeus_pin': u['zeus_pin'],
                    'email': u['email'],
                    'full_name': u['full_name'] or 'Anonymous',
                    'registered_at': u['created_at'],
                    'approval_status': u['approval_status'],
                    'reviewed_at': u['reviewed_at'],
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
                'zeus_pin': user['zeus_pin'],
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

    return jsonify({'success': True, 'message': 'Payment approved, feature unlocked', 'feature': feature_name}), 200


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
                    'zeus_pin': u['zeus_pin'],
                    'email': u['email'],
                    'full_name': u['full_name'] or 'Anonymous',
                    'unread_count': u['unread_count'] or 0,
                    'last_message_at': u['last_message_at'],
                    'approval_status': u['approval_status'],
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
            (user_id, admin_id, f'KYC Approved: {notes}' if notes else 'KYC Approved'),
        )

        approval_message = (
            'Your ZeusChat account has been approved. '
            f'Your PIN {result["zeus_pin"]} is now active and ready to use.'
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


@admin_bp.route('/api/kyc/<int:kyc_id>/reject', methods=['PUT'])
@admin_required
def reject_kyc(kyc_id):
    """Reject KYC and keep account deactivated."""
    admin_id = session['admin_id']
    data = request.get_json() or {}
    reason = (data.get('reason') or 'No reason provided').strip()

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
            (user_id, admin_id, reason, 'KYC rejected'),
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
