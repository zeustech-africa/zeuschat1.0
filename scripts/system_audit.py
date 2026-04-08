import json

import app as a


def run_audit():
    client = a.app.test_client()

    routes = [
        '/',
        '/login',
        '/registration.html',
        '/chat.html',
        '/profile.html',
        '/settings.html',
        '/subscription',
        '/ghost-market',
        '/ghost-ultimate',
        '/pending-approval',
        '/admin/login',
        '/admin/dashboard',
    ]

    route_results = {}
    for route in routes:
        response = client.get(route, follow_redirects=False)
        route_results[route] = response.status_code

    with client.session_transaction() as sess:
        sess['admin_id'] = 1
        sess['admin_username'] = 'superadmin'
        sess['admin_role'] = 'super_admin'
        sess['admin_permissions'] = {}

    csrf = client.get('/api/csrf-token').get_json().get('csrf_token')

    api_tests = [
        ('POST', '/api/login', {'zeus_pin': 'NOPE000', 'password': 'wrong'}),
        ('POST', '/api/register', {'email': 'invalid', 'password': 'x', 'confirm_password': 'y'}),
        ('GET', '/api/user/approval-status', None),
        ('GET', '/api/user/subscription', None),
        ('GET', '/api/ghost-market/items', None),
        ('GET', '/api/ghost/feed', None),
        ('GET', '/admin/api/stats', None),
        ('GET', '/admin/api/users', None),
        ('GET', '/admin/api/ghost/pending', None),
        ('GET', '/admin/api/ghost/reports', None),
    ]

    api_results = {}
    for method, path, payload in api_tests:
        if method == 'GET':
            response = client.get(path)
        else:
            response = client.post(
                path,
                json=payload,
                headers={'X-CSRF-Token': csrf},
            )
        api_results[f'{method} {path}'] = response.status_code

    print(json.dumps({'routes': route_results, 'apis': api_results}, indent=2))


if __name__ == '__main__':
    run_audit()
