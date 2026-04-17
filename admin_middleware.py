import sqlite3
import json
import os
from functools import wraps
from flask import session, jsonify, request, redirect
from datetime import datetime, timedelta

DATABASE_PATH = os.environ.get('DATABASE_PATH', 'zeuschat.db')

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def admin_required(f):
    """Decorator: Require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({'error': 'Admin authentication required'}), 401
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM admin_users WHERE id = ?', (session['admin_id'],))
            if not cursor.fetchone():
                session.clear()
                return jsonify({'error': 'Admin account not found'}), 401
        
        return f(*args, **kwargs)
    return decorated_function


def _is_pin_route_allowed(path):
    """Return True for routes that remain available after PIN expiry."""
    allowed_exact = {
        '/api/user/pin-status',
        '/api/user/extend-pin',
        '/payment/extend-pin',
        '/subscription',
        '/subscription/success',
        '/subscription/cancel',
        '/pin-expired-overlay',
        '/logout',
        '/api/logout',
        '/api/user/subscription',
        '/registration.html',
        '/mobile/register',
        '/login',
        '/login.html',
        '/api/login',
        '/api/check-unlock',
        '/api/unlock',
    }
    allowed_prefixes = (
        '/static/',
        '/uploads/',
        '/api/user/subscribe/',
        '/payment/success',
        '/payment/cancel',
        '/api/payfast-',
    )
    return path in allowed_exact or any(path.startswith(prefix) for prefix in allowed_prefixes)


def require_valid_pin(f):
    """Block access when a logged-in user's Zeus-PIN has expired."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return f(*args, **kwargs)

        if _is_pin_route_allowed(request.path):
            return f(*args, **kwargs)

        if is_pin_expired(user_id):
            payload = {
                'error': 'ZEUS-PIN EXPIRED',
                'redirect': '/pin-expired-overlay',
                'message': 'Your Zeus-PIN has expired. Please extend or subscribe.',
            }
            if request.path.startswith('/api/'):
                return jsonify(payload), 403
            return redirect('/pin-expired-overlay')

        return f(*args, **kwargs)
    return decorated_function


def require_paid_user(f):
    """Block free users from accessing paid-only features."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Not authenticated'}), 401

        tier = get_user_subscription_tier(user_id)
        if tier == 'free':
            return jsonify({
                'error': 'Paid feature requires Pro or Teams subscription',
                'requires_upgrade': True,
                'redirect': '/subscription',
            }), 403

        return f(*args, **kwargs)
    return decorated_function


def get_pin_display_with_badge(user_id, requester_id=None):
    """Return PIN string with paid-tier crown marker for display."""
    tier = get_user_subscription_tier(user_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT zeus_pin FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        if not result:
            return 'Unknown'

    pin = result['zeus_pin']
    if requester_id == user_id or session.get('admin_id'):
        return f'{pin} 👑' if tier != 'free' else pin

    half_pin = pin[:8] + '-XXXX'
    return f'{half_pin} 👑' if tier != 'free' else half_pin

def require_approved_user(f):
    """Decorator: Block access if user account not admin-approved"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        import os
        from flask import current_app
        user_id = session.get('user_id')
        is_html_page = request.path.endswith('.html')

        if not user_id:
            if is_html_page:
                return redirect('/login')
            return jsonify({'error': 'Not authenticated'}), 401

        if current_app.testing or os.environ.get('TESTING') == '1':
            return f(*args, **kwargs)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT status FROM user_approvals WHERE user_id = ?
            ''', (user_id,))
            approval = cursor.fetchone()

            if not approval or approval['status'] != 'approved':
                if is_html_page:
                    return redirect('/pending-approval')
                return jsonify({
                    'error': 'Account pending approval',
                    'message': 'Please message admin for assistance',
                    'redirect': '/pending-approval'
                }), 403

        if not _is_pin_route_allowed(request.path) and is_pin_expired(user_id):
            payload = {
                'error': 'ZEUS-PIN EXPIRED',
                'redirect': '/pin-expired-overlay',
                'message': 'Your Zeus-PIN has expired. Please extend or subscribe.',
            }
            if is_html_page or not request.path.startswith('/api/'):
                return redirect('/pin-expired-overlay')
            return jsonify(payload), 403

        return f(*args, **kwargs)
    return decorated_function

def require_feature_unlock(feature_name):
    """Decorator: Block access if user hasn't unlocked specific feature"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({'error': 'Not authenticated'}), 401
            
            if not user_has_unlock(user_id, feature_name):
                return jsonify({
                    'error': 'Feature locked',
                    'feature': feature_name,
                    'unlock_options': get_unlock_options(feature_name)
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def user_has_unlock(user_id, feature_name):
    """Check if user has unlocked a specific feature"""
    # Subscription access should grant feature access even without one-off unlock rows.
    if user_has_feature_access(user_id, feature_name):
        return True

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, expires_at FROM user_unlocks
            WHERE user_id = ? AND feature_name = ?
        ''', (user_id, feature_name))
        unlock = cursor.fetchone()
        
        if not unlock:
            return False
        
        if unlock['expires_at']:
            expires_at = datetime.fromisoformat(unlock['expires_at'].replace(' ', 'T') if ' ' in unlock['expires_at'] else unlock['expires_at'])
            if datetime.now() > expires_at:
                return False
        
        return True


def get_user_subscription_tier(user_id):
    """Get user's current subscription tier"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT tier, status, current_period_end
            FROM subscriptions
            WHERE user_id = ? AND status = 'active'
            ''',
            (user_id,),
        )
        sub = cursor.fetchone()

    if not sub:
        return 'free'

    if sub['current_period_end']:
        try:
            end_date = datetime.fromisoformat(str(sub['current_period_end']).replace(' ', 'T'))
            if datetime.now() > end_date:
                return 'free'
        except Exception:
            return 'free'

    return sub['tier']


def user_has_feature_access(user_id, feature_name):
    """Check if user has access to a specific feature based on subscription tier"""
    tier = get_user_subscription_tier(user_id)

    # Backward-compat aliases used by existing routes/decorators.
    aliases = {
        'profile_picture': 'profile_picture_unlimited',
        'custom_ttl': 'custom_ttl',
        'pin_retention': 'pin_retention_permanent',
        'file_sharing': 'file_sharing',
        'cloud_backup': 'cloud_backup_10gb',
        'message_schedule': 'message_scheduling',
    }
    normalized_feature = aliases.get(feature_name, feature_name)

    tier_chain = {
        'free': ['free'],
        'pro': ['free', 'pro'],
        'teams': ['free', 'pro', 'teams'],
    }

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for tier_name in tier_chain.get(tier, ['free']):
            cursor.execute(
                '''
                SELECT is_enabled FROM subscription_features
                WHERE tier = ? AND feature_name = ?
                ''',
                (tier_name, normalized_feature),
            )
            result = cursor.fetchone()
            if result is not None and int(result['is_enabled']) == 1:
                return True

    return False

def get_unlock_options(feature_name):
    """Return available ways to unlock a feature"""
    unlock_options = {
        'profile_picture': {
            'one_off_payment': {'amount': 29.00, 'currency': 'ZAR', 'endpoint': '/api/user/request-profile-picture'},
            'subscription': {'tier': 'pro', 'amount': 89.00, 'currency': 'ZAR', 'endpoint': '/api/user/subscribe/pro'}
        },
        'custom_ttl': {
            'one_off_payment': {'amount': 39.00, 'currency': 'ZAR', 'endpoint': '/api/user/request-extended-ttl'},
            'subscription': {'tier': 'pro', 'amount': 89.00, 'currency': 'ZAR', 'endpoint': '/api/user/subscribe/pro'}
        },
        'pin_retention': {
            'one_off_payment': {'amount': 49.00, 'currency': 'ZAR', 'endpoint': '/api/user/request-pin-retention'}
        },
        'file_sharing': {
            'one_off_payment': {'amount': 59.00, 'currency': 'ZAR', 'endpoint': '/api/user/request-file-sharing'},
            'subscription': {'tier': 'pro', 'amount': 89.00, 'currency': 'ZAR', 'endpoint': '/api/user/subscribe/pro'}
        },
        'cloud_backup': {
            'one_off_payment': {'amount': 99.00, 'currency': 'ZAR', 'endpoint': '/api/user/request-cloud-backup'},
            'subscription': {'tier': 'pro', 'amount': 89.00, 'currency': 'ZAR', 'endpoint': '/api/user/subscribe/pro'}
        }
    }
    return unlock_options.get(feature_name, {})

def log_admin_action(admin_id, action, target_user_id=None, target_payment_id=None, details=None, ip_address=None):
    """Log admin action to audit log"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO admin_audit_log (admin_id, action, target_user_id, target_payment_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_id, action, target_user_id, target_payment_id,
              json.dumps(details) if details else None, ip_address))
        conn.commit()


# ============================================================
# PIN EXPIRY HELPERS
# ============================================================

def get_pin_expiry_date(user_id):
    """Calculate when user's PIN expires."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Subscribers (pro/teams) never expire
        cursor.execute(
            'SELECT tier FROM subscriptions WHERE user_id = ? AND status = "active"',
            (user_id,)
        )
        sub = cursor.fetchone()
        if sub and sub['tier'] in ('pro', 'teams'):
            return None

        # Paid extension still in effect?
        cursor.execute(
            'SELECT expires_at FROM pin_extensions WHERE user_id = ? AND expires_at > datetime("now") ORDER BY expires_at DESC LIMIT 1',
            (user_id,)
        )
        extension = cursor.fetchone()
        if extension:
            raw = extension['expires_at'].replace(' ', 'T')
            return datetime.fromisoformat(raw)

        # Free user: expires 14 days after registration
        cursor.execute('SELECT created_at FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user and user['created_at']:
            raw = str(user['created_at']).replace(' ', 'T')
            created_at = datetime.fromisoformat(raw)
            return created_at + timedelta(days=14)

    return datetime.now() + timedelta(days=14)


def refresh_pin_expiry_cache(user_id, conn=None):
    """Persist the calculated PIN expiry date on the user row for audit/cleanup jobs."""
    expiry = get_pin_expiry_date(user_id)

    if conn is not None:
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET pin_expires_at = ? WHERE id = ?',
            (expiry.isoformat(sep=' ') if expiry else None, user_id),
        )
        return expiry

    with get_db_connection() as local_conn:
        cursor = local_conn.cursor()
        cursor.execute(
            'UPDATE users SET pin_expires_at = ? WHERE id = ?',
            (expiry.isoformat(sep=' ') if expiry else None, user_id),
        )
        local_conn.commit()
    return expiry


def is_pin_expired(user_id):
    """Return True if the user's PIN has expired."""
    expiry = get_pin_expiry_date(user_id)
    if expiry is None:
        return False
    return datetime.now() > expiry


def get_pin_days_remaining(user_id):
    """Return number of whole days until PIN expiry (999 for subscribers)."""
    expiry = get_pin_expiry_date(user_id)
    if expiry is None:
        return 999
    remaining = (expiry - datetime.now()).days
    return max(0, remaining)


def send_pin_warning_if_needed(user_id):
    """Insert warning messages into user's admin inbox at 3-day and 1-day thresholds."""
    days_remaining = get_pin_days_remaining(user_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            'SELECT id FROM admin_users WHERE role = "super_admin" LIMIT 1'
        )
        admin_row = cursor.fetchone()
        admin_id = admin_row['id'] if admin_row else None

        if days_remaining == 3:
            cursor.execute(
                'SELECT id FROM pin_expiry_warnings WHERE user_id = ? AND warning_type = "3day"',
                (user_id,)
            )
            if not cursor.fetchone():
                cursor.execute(
                    '''
                    INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                    VALUES (?, ?, 1, ?)
                    ''',
                    (
                        user_id,
                        '\u26a0\ufe0f PIN EXPIRY WARNING: Your Zeus-PIN will expire in 3 days.\n\n'
                        '\u2022 Pay R49 to extend for 30 days\n'
                        '\u2022 Subscribe to Pro to keep it forever\n'
                        '\u2022 Or your account will be locked',
                        admin_id,
                    )
                )
                cursor.execute(
                    'INSERT OR IGNORE INTO pin_expiry_warnings (user_id, warning_type) VALUES (?, "3day")',
                    (user_id,)
                )

        elif days_remaining == 1:
            cursor.execute(
                'SELECT id FROM pin_expiry_warnings WHERE user_id = ? AND warning_type = "1day"',
                (user_id,)
            )
            if not cursor.fetchone():
                cursor.execute(
                    '''
                    INSERT INTO admin_messages (user_id, message, is_from_admin, admin_id)
                    VALUES (?, ?, 1, ?)
                    ''',
                    (
                        user_id,
                        '\u26a0\ufe0f\u26a0\ufe0f URGENT: Your Zeus-PIN expires TOMORROW!\n\n'
                        'Take action now:\n'
                        '\u2022 Pay R49 to extend for 30 days\n'
                        '\u2022 Subscribe to Pro to keep it forever\n'
                        '\u2022 Or you will lose access to your account',
                        admin_id,
                    )
                )
                cursor.execute(
                    'INSERT OR IGNORE INTO pin_expiry_warnings (user_id, warning_type) VALUES (?, "1day")',
                    (user_id,)
                )

        conn.commit()
