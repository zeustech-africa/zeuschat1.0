#!/usr/bin/env python3
"""M7 Ghost Community mobile audit checks"""
import requests

B = 'http://127.0.0.1:5000'

# Admin approves posts 21 and 22
adm = requests.Session()
ta = adm.get(B + '/api/csrf-token').json()['csrf_token']
adm.post(B + '/admin/api/login', json={'username': 'admin', 'password': 'Admin1234'}, headers={'X-CSRF-Token': ta})
ta = adm.get(B + '/api/csrf-token').json()['csrf_token']
for pid in [21, 22]:
    r = adm.put(B + f'/admin/api/ghost/posts/{pid}/approve', headers={'X-CSRF-Token': ta})
    ta = adm.get(B + '/api/csrf-token').json()['csrf_token']
    print(f'approve_post_{pid}', r.status_code, r.text[:200])

# User B (free) checks feed
sb = requests.Session()
tb = sb.get(B + '/api/csrf-token').json()['csrf_token']
sb.post(B + '/api/login', json={'zeus_pin': 'ZT-9000-0002', 'password': 'AuditB234'}, headers={'X-CSRF-Token': tb})
tb = sb.get(B + '/api/csrf-token').json()['csrf_token']

r2 = sb.get(B + '/api/ghost/feed')
d = r2.json()
posts = d if isinstance(d, list) else d.get('posts', [])
found_free = any(p.get('id') == 21 for p in posts)
found_paid = any(p.get('id') == 22 for p in posts)
print('M7.1_feed_count', len(posts))
print('M7.2_free_post_in_feed', found_free)
print('M7.3_paid_post_in_feed', found_paid)

paid_post = [p for p in posts if p.get('id') == 22]
if paid_post:
    pp = paid_post[0]
    print('M7.3_paid_is_paid', pp.get('is_paid'), 'user_has_access', pp.get('user_has_access'))

# Free user tries to unlock paid post (should require payment)
r3 = sb.post(B + '/api/ghost/pay', json={'post_id': 22}, headers={'X-CSRF-Token': tb})
print('M7.3_free_user_unlock_status', r3.status_code, r3.text[:300])

# Pro user (User A / ZT-9000-0003) unlocks paid post
sp = requests.Session()
tp = sp.get(B + '/api/csrf-token').json()['csrf_token']
sp.post(B + '/api/login', json={'zeus_pin': 'ZT-9000-0003', 'password': 'AuditPro234'}, headers={'X-CSRF-Token': tp})
tp = sp.get(B + '/api/csrf-token').json()['csrf_token']
r4 = sp.post(B + '/api/ghost/pay', json={'post_id': 22}, headers={'X-CSRF-Token': tp})
print('M7.3_owner_pay_attempt', r4.status_code, r4.text[:300])
