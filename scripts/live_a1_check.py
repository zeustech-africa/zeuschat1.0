#!/usr/bin/env python3
import requests
import time

base = 'http://127.0.0.1:5000'
email = f'final_audit_{int(time.time())}@zeuschat.test'
user = requests.Session()

r1 = user.post(base + '/api/start-signup', json={'email': email})
r2 = user.post(base + '/api/verify-otp', json={'email': email, 'otp': '123456'})
zeus_pin = (r2.json() or {}).get('zeus_pin')

files = {
    'id_document': ('id.txt', b'id-bytes'),
    'selfie': ('selfie.jpg', b'selfie-bytes', 'image/jpeg'),
}
data = {
    'full_name': 'Final Audit User',
    'email': email,
    'zeus_pin': zeus_pin,
    'password': 'AuditReg234',
    'document_type': 'national_id',
}
r3 = user.post(
    base + '/api/complete-registration-with-kyc',
    data=data,
    files=files,
    headers={'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'},
)

csrf = user.get(base + '/api/csrf-token')
csrf_token = (csrf.json() or {}).get('csrf_token', '')
r4 = user.post(
    base + '/api/user/admin-messages',
    json={'message': 'Please approve my account for final audit'},
    headers={'X-CSRF-Token': csrf_token},
)

admin = requests.Session()
la = admin.post(base + '/admin/api/login', json={'username': 'admin', 'password': 'Admin1234'})
users = admin.get(base + '/admin/api/messages/users')
found = False
if users.status_code == 200:
    for u in (users.json() or {}).get('users', []):
        if u.get('email') == email and int(u.get('unread_count', 0)) >= 1:
            found = True
            break

print('start', r1.status_code)
print('otp', r2.status_code)
print('complete', r3.status_code, (r3.json() or {}).get('redirect'))
print('msg_admin', r4.status_code)
print('admin_login', la.status_code)
print('admin_inbox_has_user_msg', found)
