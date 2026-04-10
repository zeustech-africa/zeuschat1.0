"""
test_admin.py — Admin auth, dashboard, user management, and ZeusWatch API.
"""

import json
import pytest
from tests.conftest import TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD, get_test_user_id


class TestAdminLoginPage:
    def test_admin_login_page_loads(self, client):
        r = client.get("/admin/login")
        assert r.status_code == 200

    def test_admin_dashboard_requires_auth(self, client):
        r = client.get("/admin/dashboard")
        # Redirects to login or returns 401/403
        assert r.status_code in (302, 401, 403)

    def test_admin_zeuswatch_requires_auth(self, client):
        r = client.get("/admin/zeuswatch")
        assert r.status_code in (302, 401, 403)


class TestAdminAPILogin:
    def test_admin_login_no_body(self, client):
        r = client.post("/admin/api/login", content_type="application/json")
        assert r.status_code == 400

    def test_admin_login_wrong_password(self, client):
        r = client.post(
            "/admin/api/login",
            data=json.dumps({"username": TEST_ADMIN_USERNAME, "password": "WrongPass!"}),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_admin_login_nonexistent_user(self, client):
        r = client.post(
            "/admin/api/login",
            data=json.dumps({"username": "ghost_admin", "password": "anything"}),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_admin_login_success(self, client):
        r = client.post(
            "/admin/api/login",
            data=json.dumps({"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("success") is True
        assert "admin" in data

    def test_admin_login_sets_session(self, client):
        client.post(
            "/admin/api/login",
            data=json.dumps({"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}),
            content_type="application/json",
        )
        with client.session_transaction() as sess:
            assert "admin_id" in sess
            assert sess.get("admin_username") == TEST_ADMIN_USERNAME


class TestAdminLogout:
    def test_admin_logout(self, admin_client):
        r = admin_client.post("/admin/api/logout")
        assert r.status_code == 200
        with admin_client.session_transaction() as sess:
            assert "admin_id" not in sess


class TestAdminDashboard:
    def test_admin_dashboard_loads_with_auth(self, admin_client):
        r = admin_client.get("/admin/dashboard")
        assert r.status_code == 200

    def test_zeuswatch_page_loads_with_auth(self, admin_client):
        r = admin_client.get("/admin/zeuswatch")
        assert r.status_code == 200

    def test_zeuswatch_api_returns_data(self, admin_client):
        r = admin_client.get("/admin/api/zeuswatch")
        assert r.status_code == 200
        data = r.get_json()
        assert "system" in data
        assert "alerts" in data


class TestAdminUserManagement:
    def test_get_users_requires_admin(self, client):
        r = client.get("/admin/api/users")
        assert r.status_code == 401

    def test_get_users_with_admin(self, admin_client):
        r = admin_client.get("/admin/api/users")
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, (list, dict))

    def test_get_user_details_requires_admin(self, client):
        user_id = get_test_user_id()
        r = client.get(f"/admin/api/users/{user_id}/details")
        assert r.status_code == 401

    def test_get_user_details_with_admin(self, admin_client):
        user_id = get_test_user_id()
        r = admin_client.get(f"/admin/api/users/{user_id}/details")
        assert r.status_code in (200, 404)
        assert r.status_code != 500

    def test_approve_user_requires_admin(self, client):
        user_id = get_test_user_id()
        r = client.put(f"/admin/api/users/{user_id}/approve")
        assert r.status_code == 401

    def test_approve_nonexistent_user(self, admin_client):
        r = admin_client.put("/admin/api/users/99999999/approve")
        assert r.status_code in (400, 404, 415)
        assert r.status_code != 500

    def test_me_endpoint_returns_admin_info(self, admin_client):
        r = admin_client.get("/admin/api/me")
        assert r.status_code == 200
        data = r.get_json()
        assert "username" in data or "admin" in data


class TestAdminKYC:
    def test_get_pending_kyc_requires_admin(self, client):
        r = client.get("/admin/api/kyc/pending")
        assert r.status_code == 401

    def test_get_pending_kyc_with_admin(self, admin_client):
        r = admin_client.get("/admin/api/kyc/pending")
        assert r.status_code == 200
        assert r.status_code != 500


class TestAdminGhostMarket:
    def test_pending_items_requires_admin(self, client):
        r = client.get("/admin/api/ghost-market/pending-items")
        assert r.status_code == 401

    def test_pending_items_with_admin(self, admin_client):
        r = admin_client.get("/admin/api/ghost-market/pending-items")
        assert r.status_code == 200
        assert r.status_code != 500

    def test_seller_applications_requires_admin(self, client):
        r = client.get("/admin/api/ghost-market/seller-applications")
        assert r.status_code == 401
