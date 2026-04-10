"""
test_security.py — CSRF enforcement, SQL injection, XSS, and auth boundary tests.
"""

import json
import pytest


class TestCSRFEnforcement:
    """CSRF checks are skipped in testing mode — these tests verify the
    enforcement logic by temporarily disabling testing mode."""

    def test_csrf_protected_route_blocked_without_token(self, app, client):
        """With testing mode OFF, a mutating request without a CSRF token is rejected."""
        app.config["TESTING"] = False
        try:
            # Inject a user session so auth passes but CSRF fails
            with client.session_transaction() as sess:
                sess["user_id"] = 1
                sess["zeus_pin"] = "TSTPIN0001"
                sess["subscription_tier"] = "free"
            r = client.post(
                "/api/send-message",
                data=json.dumps({"receiver_id": 2, "content": "hi"}),
                content_type="application/json",
                headers={},  # No X-CSRF-Token header
            )
            assert r.status_code == 403
        finally:
            app.config["TESTING"] = True

    def test_csrf_exempt_endpoint_accessible_without_token(self, app, client):
        """Login is CSRF-exempt and must return its normal response."""
        app.config["TESTING"] = False
        try:
            r = client.post(
                "/api/login",
                data=json.dumps({"zeus_pin": "FAKE0000", "password": "wrong"}),
                content_type="application/json",
            )
            # 401 means the endpoint was reached (not 403 CSRF)
            assert r.status_code == 401
        finally:
            app.config["TESTING"] = True

    def test_csrf_protection_admin_api(self, app, admin_client):
        """Admin API mutation without CSRF token must return 403."""
        app.config["TESTING"] = False
        try:
            r = admin_client.post(
                "/admin/api/override/pause-registrations",
                data=json.dumps({}),
                content_type="application/json",
                headers={},
            )
            assert r.status_code == 403
        finally:
            app.config["TESTING"] = True

    def test_csrf_token_mismatch(self, app, client):
        """A tampered CSRF token must be rejected."""
        app.config["TESTING"] = False
        try:
            with client.session_transaction() as sess:
                sess["user_id"] = 1
                sess["zeus_pin"] = "TSTPIN0001"
                sess["subscription_tier"] = "free"
                sess["csrf_token"] = "correct_token"
            r = client.post(
                "/api/send-message",
                data=json.dumps({"receiver_id": 2, "content": "hi"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "tampered_token"},
            )
            assert r.status_code == 403
        finally:
            app.config["TESTING"] = True


class TestSQLInjection:
    def test_sql_injection_in_login_pin(self, client):
        """SQL injection payloads in zeus_pin should not cause 500."""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT * FROM users--",
        ]
        for payload in payloads:
            r = client.post(
                "/api/login",
                data=json.dumps({"zeus_pin": payload, "password": "test"}),
                content_type="application/json",
            )
            assert r.status_code in (400, 401), f"Payload caused unexpected status: {r.status_code}"
            assert r.status_code != 500

    def test_sql_injection_in_login_password(self, client):
        payloads = ["' OR 1=1--", "admin'--", "x'; INSERT INTO users"]
        for payload in payloads:
            r = client.post(
                "/api/login",
                data=json.dumps({"zeus_pin": "TSTPIN0001", "password": payload}),
                content_type="application/json",
            )
            assert r.status_code != 500

    def test_sql_injection_in_start_signup(self, client):
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": "'; DROP TABLE users;--@test.com"}),
            content_type="application/json",
        )
        assert r.status_code != 500


class TestXSSProtection:
    def test_xss_payload_in_message_does_not_500(self, auth_client):
        """XSS payloads in message content must be handled without 500."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
        ]
        for payload in xss_payloads:
            r = auth_client.post(
                "/api/send-message",
                data=json.dumps({"receiver_id": 99999, "content": payload}),
                content_type="application/json",
            )
            assert r.status_code != 500

    def test_xss_in_profile_update_does_not_500(self, auth_client):
        r = auth_client.post(
            "/api/user/update-profile",
            data=json.dumps({"full_name": "<script>alert('xss')</script>"}),
            content_type="application/json",
        )
        assert r.status_code != 500


class TestUnauthenticatedAccess:
    """Protected routes must return 401 or 403, never 200, for unauthenticated callers."""

    protected_routes = [
        ("GET", "/api/user/pin-status"),
        ("GET", "/api/get-contacts"),
        ("GET", "/api/get-contact-requests"),
        ("GET", "/api/user/profile"),
        ("GET", "/api/ghost-market/seller-status"),
    ]

    @pytest.mark.parametrize("method,path", protected_routes)
    def test_protected_route_blocks_unauthenticated(self, client, method, path):
        r = client.open(path, method=method)
        assert r.status_code in (401, 403), (
            f"{method} {path} returned {r.status_code} for unauthenticated request"
        )

    def test_admin_api_blocks_unauthenticated(self, client):
        r = client.get("/admin/api/users")
        assert r.status_code == 401

    def test_admin_zeuswatch_api_blocks_unauthenticated(self, client):
        r = client.get("/admin/api/zeuswatch")
        assert r.status_code == 401
