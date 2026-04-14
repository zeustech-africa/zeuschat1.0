import io
import requests

BASE_URL = 'http://127.0.0.1:5000'
USER_A = {'pin': 'ZT-9000-0001', 'password': 'AuditA234'}
USER_B = {'pin': 'ZT-9000-0002', 'password': 'AuditB234'}


def csrf(session):
    return session.get(f'{BASE_URL}/api/csrf-token').json().get('csrf_token')


def auth(pin, password):
    s = requests.Session()
    t = csrf(s)
    s.post(f'{BASE_URL}/api/login', json={'zeus_pin': pin, 'password': password}, headers={'X-CSRF-Token': t})
    t = csrf(s)
    s.post(f'{BASE_URL}/api/unlock', json={'zeus_pin': pin}, headers={'X-CSRF-Token': t})
    return s


def ensure_handshake(a, b):
    # Ensure not blocked
    t = csrf(a)
    a.post(f'{BASE_URL}/api/unblock-contact', json={'zeus_pin': USER_B['pin']}, headers={'X-CSRF-Token': t})

    # Send request if needed
    t = csrf(a)
    a.post(f'{BASE_URL}/api/add-contact', json={'contact_pin': USER_B['pin']}, headers={'X-CSRF-Token': t})

    # Accept pending
    reqs = b.get(f'{BASE_URL}/api/get-contact-requests').json().get('requests', [])
    req = next((r for r in reqs if r.get('zeus_pin') == USER_A['pin']), None)
    if req:
        t = csrf(b)
        b.post(f'{BASE_URL}/api/accept-contact', json={'request_id': req.get('request_id')}, headers={'X-CSRF-Token': t})


def send_file(a, receiver_pin, filename, payload, mime):
    t = csrf(a)
    files = {'file': (filename, io.BytesIO(payload), mime)}
    data = {'receiver_pin': receiver_pin}
    return a.post(f'{BASE_URL}/api/send-file', data=data, files=files, headers={'X-CSRF-Token': t})


def receiver_has_file_message(b, contact_pin, must_contain):
    r = b.get(f'{BASE_URL}/api/get-messages?contact_pin={contact_pin}')
    if not r.ok:
        return False, None
    data = r.json()
    messages = data.get('messages', [])
    for m in reversed(messages):
        content = (m.get('content') or '')
        file_url = (m.get('file_url') or '')
        if must_contain in content and file_url.startswith('/uploads/chat_files/'):
            return True, {'content': content, 'file_url': file_url}
    return False, None


def main():
    a = auth(USER_A['pin'], USER_A['password'])
    b = auth(USER_B['pin'], USER_B['password'])
    ensure_handshake(a, b)

    # M4.1 image
    r1 = send_file(a, USER_B['pin'], 'mobile-audit.jpg', b'fake-jpg-data', 'image/jpeg')
    ok1, msg1 = receiver_has_file_message(b, USER_A['pin'], '📷 Photo: mobile-audit.jpg')
    print('send_image_status', r1.status_code)
    print('recv_image_visible', ok1, msg1)

    # M4.2 document
    r2 = send_file(a, USER_B['pin'], 'mobile-audit.pdf', b'%PDF-1.4 fake', 'application/pdf')
    ok2, msg2 = receiver_has_file_message(b, USER_A['pin'], '📎 File: mobile-audit.pdf')
    print('send_doc_status', r2.status_code)
    print('recv_doc_visible', ok2, msg2)

    # M4.3 voice note
    r3 = send_file(a, USER_B['pin'], 'mobile-audit.ogg', b'OggSfake', 'audio/ogg')
    ok3, msg3 = receiver_has_file_message(b, USER_A['pin'], '🎤 Voice note')
    print('send_voice_status', r3.status_code)
    print('recv_voice_visible', ok3, msg3)


if __name__ == '__main__':
    main()
