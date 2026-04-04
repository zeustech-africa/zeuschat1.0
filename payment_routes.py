from flask import Blueprint, request, jsonify, session, render_template_string
import hashlib
import urllib.parse
import os
import json
from admin_middleware import get_db_connection, require_approved_user, user_has_unlock

payment_bp = Blueprint('payment', __name__)

PAYFAST_MERCHANT_ID = os.environ.get('PAYFAST_MERCHANT_ID', '10000100')
PAYFAST_MERCHANT_KEY = os.environ.get('PAYFAST_MERCHANT_KEY', '46f0cd694581a')
PAYFAST_PASSPHRASE = os.environ.get('PAYFAST_PASSPHRASE', '')
PAYFAST_TEST_MODE = os.environ.get('PAYFAST_TEST_MODE', 'true').lower() == 'true'

PAYFAST_URL = 'https://sandbox.payfast.co.za/eng/process' if PAYFAST_TEST_MODE else 'https://www.payfast.co.za/eng/process'


def generate_payfast_signature(data):
    """Generate PayFast MD5 signature from request payload."""
    output = []
    for key in sorted(data.keys()):
        if key not in ['signature', 'option', 'Itemid'] and data[key] not in ['', None]:
            output.append(f"{key}={urllib.parse.quote_plus(str(data[key]))}")

    payload = '&'.join(output)
    if PAYFAST_PASSPHRASE:
        payload = payload + '&passphrase=' + urllib.parse.quote_plus(PAYFAST_PASSPHRASE)

    return hashlib.md5(payload.encode()).hexdigest()


def _base_url():
    return os.environ.get('BASE_URL', 'https://zeuschat1-0-ixax.onrender.com').rstrip('/')


def _create_payment_and_redirect(user_id, payment_type, amount, item_name, item_description):
    user_email = session.get('user_email', '')
    user_name = session.get('user_full_name', 'User')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO one_off_payments (user_id, payment_type, amount, status)
            VALUES (?, ?, ?, 'pending')
            ''',
            (user_id, payment_type, amount),
        )
        conn.commit()
        payment_id = cursor.lastrowid

    base_url = _base_url()
    pf_data = {
        'merchant_id': PAYFAST_MERCHANT_ID,
        'merchant_key': PAYFAST_MERCHANT_KEY,
        'return_url': f'{base_url}/payment/success',
        'cancel_url': f'{base_url}/payment/cancel',
        'notify_url': f'{base_url}/api/payfast-itn',
        'name_first': user_name,
        'email_address': user_email,
        'm_payment_id': f'oneoff_{payment_id}_{user_id}',
        'amount': f'{amount:.2f}',
        'item_name': item_name,
        'item_description': item_description,
    }
    pf_data['signature'] = generate_payfast_signature(pf_data)

    form_html = [
        '<!DOCTYPE html>',
        '<html><head><title>Redirecting to PayFast</title>',
        '<meta name="viewport" content="width=device-width, initial-scale=1" />',
        '<style>body{font-family:Arial,sans-serif;text-align:center;padding:40px;} .loader{margin:20px auto;}</style>',
        '</head><body>',
        '<h2>Redirecting to PayFast...</h2>',
        '<p>Please wait while we open the secure checkout.</p>',
        f'<form id="payfast-form" method="POST" action="{PAYFAST_URL}">',
    ]

    for key, value in pf_data.items():
        safe_value = str(value).replace('"', '&quot;')
        form_html.append(f'<input type="hidden" name="{key}" value="{safe_value}" />')

    form_html.extend([
        '</form>',
        '<script>document.getElementById("payfast-form").submit();</script>',
        '</body></html>',
    ])

    return render_template_string(''.join(form_html))


@payment_bp.route('/api/user/request-profile-picture', methods=['POST'])
@require_approved_user
def request_profile_picture():
    user_id = session['user_id']
    if user_has_unlock(user_id, 'profile_picture'):
        return jsonify({'success': True, 'message': 'Feature already unlocked', 'already_unlocked': True}), 200

    return _create_payment_and_redirect(
        user_id,
        'profile_picture',
        29.00,
        'ZeusChat Profile Picture Unlock',
        'One-off payment to unlock custom profile picture upload',
    )


@payment_bp.route('/api/user/request-extended-ttl', methods=['POST'])
@require_approved_user
def request_extended_ttl():
    user_id = session['user_id']
    if user_has_unlock(user_id, 'custom_ttl'):
        return jsonify({'success': True, 'message': 'Feature already unlocked', 'already_unlocked': True}), 200

    return _create_payment_and_redirect(
        user_id,
        'extended_ttl',
        39.00,
        'ZeusChat Extended TTL Timers',
        'Unlock 5s and 30s message timers',
    )


@payment_bp.route('/api/user/request-pin-retention', methods=['POST'])
@require_approved_user
def request_pin_retention():
    user_id = session['user_id']
    if user_has_unlock(user_id, 'pin_retention'):
        return jsonify({'success': True, 'message': 'Feature already unlocked', 'already_unlocked': True}), 200

    return _create_payment_and_redirect(
        user_id,
        'pin_retention',
        49.00,
        'ZeusChat PIN Retention',
        'Keep your Zeus PIN forever',
    )


@payment_bp.route('/api/user/request-profile-picture-change', methods=['POST'])
@require_approved_user
def request_profile_picture_change():
    """Free tier users request a one-off profile picture change payment."""
    user_id = session['user_id']

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT subscription_tier, is_locked, remaining_changes FROM profile_picture_locks WHERE user_id = ?',
            (user_id,),
        )
        lock = cursor.fetchone()

        if not lock:
            cursor.execute(
                '''
                INSERT INTO profile_picture_locks (user_id, is_locked, remaining_changes, subscription_tier)
                VALUES (?, 1, 0, 'free')
                ''',
                (user_id,),
            )
            conn.commit()
            lock = {'subscription_tier': 'free', 'is_locked': 1, 'remaining_changes': 0}

        if lock['subscription_tier'] != 'free':
            return jsonify({'error': 'Subscribers can change profile picture without one-off payment'}), 400

        if lock['is_locked'] == 0 and lock['remaining_changes'] > 0:
            return jsonify(
                {
                    'success': True,
                    'message': 'You already have an approved profile picture change available.',
                    'can_change': True,
                }
            ), 200

        amount = 29.00
        cursor.execute(
            '''
            INSERT INTO one_off_payments (user_id, payment_type, amount, status)
            VALUES (?, 'profile_picture_change', ?, 'pending')
            ''',
            (user_id, amount),
        )
        conn.commit()
        payment_id = cursor.lastrowid

        cursor.execute(
            '''
            INSERT INTO profile_pic_payments (user_id, payment_id, status)
            VALUES (?, ?, 'pending_approval')
            ''',
            (user_id, payment_id),
        )
        conn.commit()

    base_url = _base_url()
    pf_data = {
        'merchant_id': PAYFAST_MERCHANT_ID,
        'merchant_key': PAYFAST_MERCHANT_KEY,
        'return_url': f'{base_url}/payment/success',
        'cancel_url': f'{base_url}/payment/cancel',
        'notify_url': f'{base_url}/api/payfast-itn',
        'name_first': session.get('user_full_name', 'User'),
        'email_address': session.get('user_email', ''),
        'm_payment_id': f'profile_pic_{payment_id}_{user_id}',
        'amount': f'{amount:.2f}',
        'item_name': 'ZeusChat Profile Picture Change',
        'item_description': 'One-off payment to change your profile picture',
    }
    pf_data['signature'] = generate_payfast_signature(pf_data)

    form_html = [
        '<!DOCTYPE html>',
        '<html><head><title>Redirecting to PayFast</title>',
        '<meta name="viewport" content="width=device-width, initial-scale=1" />',
        '<style>body{font-family:Arial,sans-serif;text-align:center;padding:40px;} .loader{margin:20px auto;}</style>',
        '</head><body>',
        '<h2>Redirecting to PayFast...</h2>',
        '<p>Please wait while we open the secure checkout.</p>',
        f'<form id="payfast-form" method="POST" action="{PAYFAST_URL}">',
    ]

    for key, value in pf_data.items():
        safe_value = str(value).replace('"', '&quot;')
        form_html.append(f'<input type="hidden" name="{key}" value="{safe_value}" />')

    form_html.extend([
        '</form>',
        '<script>document.getElementById("payfast-form").submit();</script>',
        '</body></html>',
    ])

    return render_template_string(''.join(form_html))


@payment_bp.route('/api/payfast-itn', methods=['POST'])
def payfast_itn():
    pf_data = request.form.to_dict()

    payload = dict(pf_data)
    payload.pop('signature', None)
    signature = generate_payfast_signature(payload)
    if signature != pf_data.get('signature'):
        return 'Invalid signature', 400

    payment_status = pf_data.get('payment_status')
    payment_ref = pf_data.get('m_payment_id', '')
    parts = payment_ref.split('_')
    if len(parts) < 3:
        return 'Invalid payment reference', 400

    try:
        payment_id = int(parts[-2])
        user_id = int(parts[-1])
    except ValueError:
        return 'Invalid payment reference', 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        if payment_status == 'COMPLETE':
            cursor.execute(
                '''
                UPDATE one_off_payments
                SET status = 'pending_approval',
                    payfast_payment_id = ?,
                    payfast_token = ?
                WHERE id = ?
                ''',
                (pf_data.get('pf_payment_id'), pf_data.get('token'), payment_id),
            )

            cursor.execute(
                '''
                INSERT INTO admin_audit_log (action, target_payment_id, target_user_id, details)
                VALUES (?, ?, ?, ?)
                ''',
                (
                    'payment_received',
                    payment_id,
                    user_id,
                    json.dumps({'amount': pf_data.get('amount'), 'payment_type': 'one_off'}),
                ),
            )
        elif payment_status in ['FAILED', 'CANCELLED']:
            cursor.execute(
                'UPDATE one_off_payments SET status = ? WHERE id = ?',
                (payment_status.lower(), payment_id),
            )

        conn.commit()

    return 'OK', 200


@payment_bp.route('/payment/success', methods=['GET'])
def payment_success():
    return render_template_string(
        '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Successful - ZeusChat</title>
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
                .container { max-width: 560px; margin: 0 auto; border: 1px solid #ddd; border-radius: 10px; padding: 24px; }
                .ok { color: #218838; font-size: 42px; }
                a { display: inline-block; margin-top: 14px; text-decoration: none; background: #1f4ed8; color: #fff; padding: 10px 16px; border-radius: 6px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="ok">Success</div>
                <h1>Payment Received</h1>
                <p>Your payment is complete.</p>
                <p>Your feature will unlock after admin approval.</p>
                <a href="/chat.html">Return to Chat</a>
            </div>
        </body>
        </html>
        '''
    )


@payment_bp.route('/payment/cancel', methods=['GET'])
def payment_cancel():
    return render_template_string(
        '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Cancelled - ZeusChat</title>
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 40px; }
                .container { max-width: 560px; margin: 0 auto; border: 1px solid #ddd; border-radius: 10px; padding: 24px; }
                .no { color: #b91c1c; font-size: 42px; }
                a { display: inline-block; margin-top: 14px; text-decoration: none; background: #1f4ed8; color: #fff; padding: 10px 16px; border-radius: 6px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="no">Cancelled</div>
                <h1>Payment Cancelled</h1>
                <p>No charge was completed.</p>
                <a href="/chat.html">Return to Chat</a>
            </div>
        </body>
        </html>
        '''
    )
