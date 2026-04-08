import json
from datetime import datetime, timedelta, timezone

import app

results = {}
client = app.app.test_client()

with app.get_db_connection() as conn:
    conn.execute(
        "INSERT OR IGNORE INTO users (id, email, zeus_pin, password_hash, full_name) VALUES (1, 'ghost1@example.com', 'GHOST001', 'x', 'Ghost One')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, email, zeus_pin, password_hash, full_name) VALUES (2, 'buyer@example.com', 'BUYER002', 'x', 'Buyer Two')"
    )
    conn.execute("INSERT OR IGNORE INTO user_approvals (user_id, status, reviewed_by, reviewed_at) VALUES (1, 'approved', 1, CURRENT_TIMESTAMP)")
    conn.execute("INSERT OR IGNORE INTO user_approvals (user_id, status, reviewed_by, reviewed_at) VALUES (2, 'approved', 1, CURRENT_TIMESTAMP)")
    conn.execute("INSERT OR IGNORE INTO admin_users (id, username, password_hash, email, role, permissions) VALUES (1, 'admin', 'x', 'admin@example.com', 'super_admin', '{}')")

with client.session_transaction() as sess:
    sess['user_id'] = 1
    sess['user_logged_in'] = True

csrf_user = client.get('/api/csrf-token').get_json().get('csrf_token')

r_feed = client.get('/api/ghost/feed?page=1')
results['feed_status'] = r_feed.status_code

r_create_free = client.post('/api/ghost/create', data={
    'title': 'Free ghost title',
    'content': 'Free ghost content test',
    'price': 0,
    'is_paid': 'false',
    'preview_text': 'free preview',
}, headers={'X-CSRF-Token': csrf_user})
results['create_free_status'] = r_create_free.status_code
free_id = r_create_free.get_json().get('post_id') if r_create_free.is_json else None
results['create_free_post_id'] = free_id

r_create_paid = client.post('/api/ghost/create', data={
    'title': 'Paid ghost title',
    'content': 'Paid ghost content test',
    'price': 20,
    'is_paid': 'true',
    'preview_text': 'paid preview',
}, headers={'X-CSRF-Token': csrf_user})
results['create_paid_status'] = r_create_paid.status_code
paid_id = r_create_paid.get_json().get('post_id') if r_create_paid.is_json else None
results['create_paid_post_id'] = paid_id

admin = app.app.test_client()
with admin.session_transaction() as sess:
    sess['admin_id'] = 1

csrf_admin = admin.get('/api/csrf-token').get_json().get('csrf_token')

if paid_id:
    r_pending_before = admin.get('/admin/api/ghost/pending')
    results['admin_pending_before_status'] = r_pending_before.status_code

    r_approve = admin.post(
        f'/admin/api/ghost/posts/{paid_id}/approve',
        json={'message': 'Looks good', 'csrf_token': csrf_admin},
        headers={'X-CSRF-Token': csrf_admin},
    )
    results['admin_approve_status'] = r_approve.status_code

    r_approve_free = admin.post(
        f'/admin/api/ghost/posts/{free_id}/approve',
        json={'message': 'Looks good', 'csrf_token': csrf_admin},
        headers={'X-CSRF-Token': csrf_admin},
    )
    results['admin_approve_free_status'] = r_approve_free.status_code

r_vote = client.post(
    '/api/ghost/vote',
    json={'post_id': paid_id, 'vote_type': 1, 'csrf_token': csrf_user},
    headers={'X-CSRF-Token': csrf_user},
)
results['vote_status'] = r_vote.status_code

r_comment = client.post(
    '/api/ghost/comment',
    json={'post_id': paid_id, 'content': 'Nice paid post', 'csrf_token': csrf_user},
    headers={'X-CSRF-Token': csrf_user},
)
results['comment_status'] = r_comment.status_code

r_comments = client.get(f'/api/ghost/comments/{paid_id}')
results['comments_status'] = r_comments.status_code
results['comments_count'] = len(r_comments.get_json().get('comments', [])) if r_comments.is_json else -1

r_report = client.post(
    '/api/ghost/report',
    json={'post_id': paid_id, 'reason': 'spam', 'csrf_token': csrf_user},
    headers={'X-CSRF-Token': csrf_user},
)
results['report_status'] = r_report.status_code

with client.session_transaction() as sess:
    sess['user_id'] = 2
    sess['user_logged_in'] = True

csrf_buyer = client.get('/api/csrf-token').get_json().get('csrf_token')

r_pay = client.post('/api/ghost/pay', json={'post_id': paid_id, 'csrf_token': csrf_buyer}, headers={'X-CSRF-Token': csrf_buyer})
results['pay_status'] = r_pay.status_code
results['pay_ok'] = bool(r_pay.is_json and r_pay.get_json().get('success'))

r_wallet = client.get('/api/ghost/wallet')
results['wallet_status'] = r_wallet.status_code

with client.session_transaction() as sess:
    sess['user_id'] = 1
    sess['user_logged_in'] = True

r_creator_wallet = client.get('/api/ghost/wallet')
results['creator_wallet_status'] = r_creator_wallet.status_code
results['creator_wallet_balance'] = (r_creator_wallet.get_json() or {}).get('wallet', {}).get('balance') if r_creator_wallet.is_json else None

r_pending = admin.get('/admin/api/ghost/pending')
results['admin_pending_status'] = r_pending.status_code

r_reports = admin.get('/admin/api/ghost/reports')
results['admin_reports_status'] = r_reports.status_code

with app.get_db_connection() as conn:
    conn.execute(
        "UPDATE ghost_posts SET expires_at = ? WHERE id = ?",
        ((datetime.now(timezone.utc) - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'), free_id)
    )

app.cleanup_expired_ghost_content_once()

with app.get_db_connection() as conn:
    row = conn.execute("SELECT COUNT(*) as c FROM ghost_posts WHERE id = ?", (free_id,)).fetchone()
    results['expired_post_remaining'] = row['c'] if row else -1

with app.get_db_connection() as conn:
    tbls = [
        'ghost_posts', 'ghost_purchases', 'ghost_reports', 'creator_wallets',
        'creator_earnings', 'moderation_queue', 'ghost_comments', 'ghost_votes'
    ]
    existence = {}
    for t in tbls:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()
        existence[t] = bool(row)
    results['tables_exist'] = existence

print(json.dumps(results))
