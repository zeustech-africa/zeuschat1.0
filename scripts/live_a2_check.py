#!/usr/bin/env python3
import requests
import time

base = 'http://127.0.0.1:5000'
email = f'final_approve_{int(time.time())}@zeuschat.test'
user = requests.Session()

# Create pending user via registration flow
user.post(base + '/api/start-signup', json={'email': email})
r2 = user.post(base + '/api/verify-otp', json={'email': email, 'otp': '123456'})
zeus_pin = (r2.json() or {}).get('zeus_pin')
files = {
    'id_document': ('id.txt', b'id-bytes'),
    'selfie': ('selfie.jpg', b'selfie-bytes', 'image/jpeg'),
}
data = {
    'full_name': 'Approval Audit User',
    'email': email,
    'zeus_pin': zeus_pin,
    'password': 'AuditReg234',
    'document_type': 'national_id',
}
user.post(base + '/api/complete-registration-with-kyc', data=data, files=files)

# Admin login + find pending user
admin = requests.Session()
la = admin.post(base + '/admin/api/login', json={'username': 'admin', 'password': 'Admin1234'})
users = admin.get(base + '/admin/api/users')
user_id = None
if users.status_code == 200:
    payload = users.json()
    rows = payload if isinstance(payload, list) else payload.get('users', [])
    for u in rows:
        if u.get('email') == email:
            user_id = u.get('id') or u.get('user_id')
            break

csrf = admin.get(base + '/api/csrf-token')
csrf_token = (csrf.json() or {}).get('csrf_token', '')
approve_status = None
if user_id:
    ar = admin.put(base + f'/admin/api/users/{user_id}/approve', headers={'X-CSRF-Token': csrf_token})
    approve_status = ar.status_code

# Check user received approval status
status = user.get(base + '/api/user/approval-status')

print('admin_login', la.status_code)
print('target_user_id', user_id)
print('approve_status', approve_status)
print('user_approval_status', status.status_code, (status.json() or {}).get('status'))
