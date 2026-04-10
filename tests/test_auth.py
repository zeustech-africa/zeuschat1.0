"""
test_auth.py — Login, logout, CSRF token, and session tests.
"""

import json
import pytest
from tests.conftest import TEST_PIN, TEST_EMAIL, TEST_PASSWORD


class TestCSRF:
    def test_csrf_token_returns_200(self, client):
        r = client.get("/api/csrf-token")
        assert r.status_code == 200
        data = r.get_json()
        assert "csrf_token" in data
        assert len(data["csrf_token"]) > 10

    def test_csrf_token_is_string(self, client):
        data = client.get("/api/csrf-token").get_json()
        assert isinstance(data["csrf_token"], str)


class TestLogin:
    def test_login_missing_body(self, client):
        r = client.post(
            "/api/login",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_login_missing_pin(self, client):
        r = client.post(
            "/api/login",
            data=json.dumps({"password": TEST_PASSWORD}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_login_missing_password(self, client):
        r = client.post(
            "/api/login",
            data=json.dumps({"zeus_pin": TEST_PIN}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_login_wrong_password(self, client):
        r = client.post(
            "/api/login",
            data=json.dumps({"zeus_pin": TEST_PIN, "password": "WrongPassword!"}),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_login_nonexistent_pin(self, client):
        r = client.post(
            "/api/login",
            data=json.dumps({"zeus_pin": "XXXX000000", "password": TEST_PASSWORD}),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_login_success(self, client):
        r = client.post(
            "/api/login",
            data=json.dumps({"zeus_pin": TEST_PIN, "password": TEST_PASSWORD}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("success") is True

    def test_login_sets_session(self, client):
        with client.session_transaction() as pre_sess:
            pre_sess.clear()

        client.post(
            "/api/login",
            data=json.dumps({"zeus_pin": TEST_PIN, "password": TEST_PASSWORD}),
            content_type="application/json",
        )

        with client.session_transaction() as sess:
            assert "user_id" in sess
            assert sess.get("zeus_pin") == TEST_PIN


class TestLogout:
    def test_logout_clears_session(self, auth_client):
        with auth_client.session_transaction() as sess:
            assert "user_id" in sess

        r = auth_client.post("/api/logout")
        assert r.status_code == 200

        with auth_client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_logout_unauthenticated_returns_200(self, client):
        """Logout is idempotent — always returns 200 even if not logged in."""
        r = client.post("/api/logout")
        assert r.status_code == 200
