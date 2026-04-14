#!/usr/bin/env python3
import time
import os
import sys
from statistics import mean

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, get_db_connection


def get_user(email):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, zeus_pin, password_hash FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        return row


def ensure_contact_accepted(a_id, b_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO user_approvals (user_id, status, reviewed_at) VALUES (?, 'approved', CURRENT_TIMESTAMP)", (a_id,))
        c.execute("INSERT OR REPLACE INTO user_approvals (user_id, status, reviewed_at) VALUES (?, 'approved', CURRENT_TIMESTAMP)", (b_id,))
        c.execute("INSERT OR IGNORE INTO contacts (user_id, contact_user_id, status) VALUES (?, ?, 'accepted')", (a_id, b_id))
        c.execute("UPDATE contacts SET status = 'accepted' WHERE user_id = ? AND contact_user_id = ?", (a_id, b_id))
        c.execute("INSERT OR IGNORE INTO contacts (user_id, contact_user_id, status) VALUES (?, ?, 'accepted')", (b_id, a_id))
        c.execute("UPDATE contacts SET status = 'accepted' WHERE user_id = ? AND contact_user_id = ?", (b_id, a_id))
        conn.commit()


def mk_client(uid, pin, tier='free'):
    c = app.test_client()
    with c.session_transaction() as s:
        s['user_id'] = uid
        s['zeus_pin'] = pin
        s['subscription_tier'] = tier
        s['is_approved'] = True
        s['password_unlocked'] = True
        s['csrf_token'] = 'audit_csrf_token'
    return c


def post_json(client, url, payload):
    return client.post(url, json=payload, headers={'X-CSRF-Token': 'audit_csrf_token'})


def main():
    app.config['TESTING'] = True

    a = get_user('audit_a@zeuschat.test')
    b = get_user('audit_b@zeuschat.test')
    p = get_user('audit_pro@zeuschat.test')
    if not a or not b or not p:
        print('FAIL: deterministic audit users missing')
        return 1

    ensure_contact_accepted(a['id'], b['id'])

    client_a = mk_client(a['id'], a['zeus_pin'], 'free')
    client_b = mk_client(b['id'], b['zeus_pin'], 'free')

    # B1 + I1 message speed smoke
    timings = []
    ok = True
    msg_ids = []
    for i in range(10):
        t0 = time.perf_counter()
        r = post_json(client_a, '/api/send-message', {'receiver_pin': b['zeus_pin'], 'content': f'audit burst {i}'})
        dt = (time.perf_counter() - t0)
        timings.append(dt)
        if r.status_code != 200:
            ok = False
            print(f"send[{i}] status={r.status_code} body={r.get_json()}")
        else:
            body = r.get_json() or {}
            if body.get('message_id'):
                msg_ids.append(body['message_id'])

    print(f"B1/I1 send burst status={'PASS' if ok else 'FAIL'} avg={mean(timings):.4f}s max={max(timings):.4f}s")

    # B4 delete everywhere
    if msg_ids:
        delete_id = msg_ids[-1]
        rd = post_json(client_a, '/api/delete-message', {'message_id': delete_id, 'delete_everywhere': True})
        gm = client_b.get(f"/api/get-messages?contact_pin={a['zeus_pin']}")
        payload = gm.get_json() or {}
        messages = payload.get('messages', []) if isinstance(payload, dict) else []
        deleted_placeholder = 'Message deleted' in str(payload) or 'deleted' in str(payload).lower()
        removed_entirely = all(int(m.get('id', -1)) != int(delete_id) for m in messages if isinstance(m, dict))
        ok_delete = rd.status_code == 200 and (deleted_placeholder or removed_entirely)
        print(f"B4 delete-everywhere status={'PASS' if ok_delete else 'FAIL'}")
    else:
        print('B4 delete-everywhere status=FAIL (no message id)')

    # B5 block/unblock
    rb = post_json(client_a, '/api/block-contact', {'zeus_pin': b['zeus_pin']})
    rs = post_json(client_b, '/api/send-message', {'receiver_pin': a['zeus_pin'], 'content': 'should fail while blocked'})
    ru = post_json(client_a, '/api/unblock-contact', {'zeus_pin': b['zeus_pin']})
    if rb.status_code != 200 or rs.status_code != 403 or ru.status_code != 200:
        print('block dbg', rb.status_code, rb.get_json(), rs.status_code, rs.get_json(), ru.status_code, ru.get_json())
    print(f"B5 block status={'PASS' if rb.status_code == 200 and rs.status_code == 403 and ru.status_code == 200 else 'FAIL'}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
