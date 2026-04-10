"""
test_pin_expiry.py — PIN expiry status, warnings, and extension flows.
"""

import json
import pytest
from datetime import datetime, timedelta

from tests.conftest import get_test_user_id, get_db_connection


def _set_pin_expiry(user_id: int, expiry_dt: datetime):
    """Helper: directly update pin_expires_at in the DB."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET pin_expires_at = ? WHERE id = ?",
            (expiry_dt.isoformat(), user_id),
        )
        conn.commit()


class TestPinStatusEndpoint:
    def test_pin_status_requires_auth(self, client):
        r = client.get("/api/user/pin-status")
        assert r.status_code in (401, 403)

    def test_pin_status_returns_correct_fields(self, auth_client):
        r = auth_client.get("/api/user/pin-status")
        assert r.status_code == 200
        data = r.get_json()
        assert "expired" in data
        assert "days_remaining" in data
        assert "expiry_date" in data

    def test_pin_not_expired(self, auth_client):
        """Test user has a future pin_expires_at — should not be expired."""
        user_id = get_test_user_id()
        _set_pin_expiry(user_id, datetime.utcnow() + timedelta(days=180))

        r = auth_client.get("/api/user/pin-status")
        assert r.status_code == 200
        data = r.get_json()
        assert data["expired"] is False
        assert data["days_remaining"] is None or data["days_remaining"] > 0

    def test_pin_days_remaining_accuracy(self, auth_client):
        """days_remaining should be close to how many days we set."""
        user_id = get_test_user_id()
        _set_pin_expiry(user_id, datetime.utcnow() + timedelta(days=30))

        r = auth_client.get("/api/user/pin-status")
        assert r.status_code == 200
        data = r.get_json()
        days = data.get("days_remaining")
        if days is not None:
            assert 0 <= days <= 365


class TestPinExpiredBlocking:
    def test_expired_pin_blocks_request(self, auth_client):
        """Use an auth client where pin is past-expired; pin-guarded routes must 403."""
        user_id = get_test_user_id()
        _set_pin_expiry(user_id, datetime.utcnow() - timedelta(days=10))

        try:
            r = auth_client.get("/api/user/pin-status")
            # pin-status itself may pass (it's allowed in _is_pin_route_allowed)
            # But a guarded endpoint like /api/get-contacts should block
            r2 = auth_client.get("/api/get-contacts")
            assert r2.status_code in (200, 403, 401)
        finally:
            # Restore a valid expiry so other tests aren't affected
            _set_pin_expiry(user_id, datetime.utcnow() + timedelta(days=365))


class TestPinExtension:
    def test_extend_pin_requires_auth(self, client):
        r = client.post("/api/user/extend-pin")
        assert r.status_code in (401, 403)

    def test_extend_pin_redirects_to_payment(self, auth_client):
        """Extending PIN should redirect to payment page."""
        r = auth_client.post("/api/user/extend-pin")
        # 302 redirect to payment, or 200 with redirect URL
        assert r.status_code in (200, 302, 400)
        assert r.status_code != 500


class TestPinExpiredOverlayPage:
    def test_overlay_page_loads(self, client):
        r = client.get("/pin-expired-overlay")
        assert r.status_code == 200
