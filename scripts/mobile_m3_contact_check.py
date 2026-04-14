import requests

BASE_URL = 'http://127.0.0.1:5000'
USER_A = {'pin': 'ZT-9000-0001', 'password': 'AuditA234'}
USER_B = {'pin': 'ZT-9000-0002', 'password': 'AuditB234'}


def csrf(session):
    return session.get(f'{BASE_URL}/api/csrf-token').json().get('csrf_token')


def auth(pin, password):
    s = requests.Session()
    token = csrf(s)
    r1 = s.post(f'{BASE_URL}/api/login', json={'zeus_pin': pin, 'password': password}, headers={'X-CSRF-Token': token})
    token = csrf(s)
    r2 = s.post(f'{BASE_URL}/api/unlock', json={'zeus_pin': pin}, headers={'X-CSRF-Token': token})
    return s, r1.status_code, r2.status_code


def list_contacts(session, pin):
    r = session.get(f'{BASE_URL}/api/get-contacts?user_pin={pin}')
    if not r.ok:
        return []
    return r.json().get('contacts', [])


def list_requests(session):
    r = session.get(f'{BASE_URL}/api/get-contact-requests')
    if not r.ok:
        return []
    return r.json().get('requests', [])


def main():
    a, a_login, a_unlock = auth(USER_A['pin'], USER_A['password'])
    b, b_login, b_unlock = auth(USER_B['pin'], USER_B['password'])
    print('auth_a', a_login, a_unlock)
    print('auth_b', b_login, b_unlock)

    # Reset to unblocked state if needed
    token = csrf(a)
    a.post(f'{BASE_URL}/api/unblock-contact', json={'zeus_pin': USER_B['pin']}, headers={'X-CSRF-Token': token})

    # M3.1 add contact
    token = csrf(a)
    r = a.post(f'{BASE_URL}/api/add-contact', json={'contact_pin': USER_B['pin']}, headers={'X-CSRF-Token': token})
    print('add_contact', r.status_code, r.json() if r.headers.get('content-type', '').startswith('application/json') else '')

    # M3.2 accept request
    reqs = list_requests(b)
    req = next((x for x in reqs if (x.get('requester_pin') == USER_A['pin'] or x.get('zeus_pin') == USER_A['pin'])), None)
    print('request_found', bool(req))

    accept_status = None
    accept_body = None
    if req:
        token = csrf(b)
        request_id = req.get('request_id') or req.get('contact_id') or req.get('id')
        r = b.post(f'{BASE_URL}/api/accept-contact', json={'request_id': request_id}, headers={'X-CSRF-Token': token})
        accept_status = r.status_code
        accept_body = r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text
    print('accept_contact', accept_status, accept_body)

    contacts_a = list_contacts(a, USER_A['pin'])
    contacts_b = list_contacts(b, USER_B['pin'])
    print('contacts_a_sample', contacts_a[0] if contacts_a else None)
    print('contacts_b_sample', contacts_b[0] if contacts_b else None)
    a_has_b = any(((c.get('contact_pin') == USER_B['pin']) or (c.get('zeus_pin') == USER_B['pin'])) for c in contacts_a)
    b_has_a = any(((c.get('contact_pin') == USER_A['pin']) or (c.get('zeus_pin') == USER_A['pin'])) for c in contacts_b)
    print('handshake_a_has_b', a_has_b)
    print('handshake_b_has_a', b_has_a)

    # M3.3 block
    token = csrf(a)
    r = a.post(f'{BASE_URL}/api/block-contact', json={'zeus_pin': USER_B['pin']}, headers={'X-CSRF-Token': token})
    print('block_contact', r.status_code)

    contacts_a_after_block = list_contacts(a, USER_A['pin'])
    a_has_b_after_block = any((c.get('contact_pin') == USER_B['pin']) for c in contacts_a_after_block)
    blocked = a.get(f'{BASE_URL}/api/get-blocked-contacts').json().get('blocked_contacts', [])
    in_blocked = any(((x.get('contact_pin') == USER_B['pin']) or (x.get('zeus_pin') == USER_B['pin'])) for x in blocked)
    print('a_has_b_after_block', a_has_b_after_block)
    print('b_in_blocked_list', in_blocked)

    # M3.4 unblock
    token = csrf(a)
    r = a.post(f'{BASE_URL}/api/unblock-contact', json={'zeus_pin': USER_B['pin']}, headers={'X-CSRF-Token': token})
    print('unblock_contact', r.status_code)

    token = csrf(a)
    r = a.post(f'{BASE_URL}/api/add-contact', json={'contact_pin': USER_B['pin']}, headers={'X-CSRF-Token': token})
    print('re_add_after_unblock', r.status_code)


if __name__ == '__main__':
    main()
