import sqlite3
import json
import os
from functools import wraps
from flask import session, jsonify, request, redirect
from datetime import datetime

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

def require_approved_user(f):
    """Decorator: Block access if user account not admin-approved"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        is_html_page = request.path.endswith('.html')

        if not user_id:
            if is_html_page:
                return redirect('/login')
            return jsonify({'error': 'Not authenticated'}), 401

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
