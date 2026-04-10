"""
test_circuit_breakers.py — System override flags: maintenance mode,
registration pause, and per-feature disables.
"""

import json
import pytest

from tests.conftest import get_db_connection


# ── DB helpers ────────────────────────────────────────────────────────────────

def _set_flag(name: str, value: int):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO system_flags (flag_name, flag_value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(flag_name) DO UPDATE SET
                flag_value = excluded.flag_value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (name, value),
        )
        conn.commit()


def _clear_all_flags():
    for flag in ("maintenance_mode", "registrations_paused", "marketplace_disabled", "community_disabled"):
        _set_flag(flag, 0)


# ── Maintenance mode ──────────────────────────────────────────────────────────

class TestMaintenanceMode:
    def setup_method(self):
        _clear_all_flags()

    def teardown_method(self):
        _clear_all_flags()

    def test_maintenance_mode_blocks_user_page(self, client):
        _set_flag("maintenance_mode", 1)
        r = client.get("/")
        assert r.status_code == 503

    def test_maintenance_mode_blocks_user_api(self, client):
        _set_flag("maintenance_mode", 1)
        r = client.get("/api/csrf-token")
        # /api/csrf-token is a GET and triggers maintenance check
        assert r.status_code == 503

    def test_maintenance_mode_allows_admin_routes(self, admin_client):
        _set_flag("maintenance_mode", 1)
        r = admin_client.get("/admin/dashboard")
        # Admin routes are exempt from maintenance mode
        assert r.status_code == 200

    def test_maintenance_mode_allows_maintenance_page(self, client):
        _set_flag("maintenance_mode", 1)
        r = client.get("/maintenance")
        # The /maintenance route itself must be accessible
        assert r.status_code in (200, 503)

    def test_maintenance_page_loads_normally(self, client):
        """Without the flag set, /maintenance returns 503 (it's always the error page)."""
        _set_flag("maintenance_mode", 0)
        r = client.get("/maintenance")
        assert r.status_code == 503

    def test_maintenance_mode_off_restores_access(self, client):
        _set_flag("maintenance_mode", 1)
        _set_flag("maintenance_mode", 0)
        r = client.get("/api/csrf-token")
        assert r.status_code == 200


# ── Registration pause ────────────────────────────────────────────────────────

class TestRegistrationPause:
    def setup_method(self):
        _clear_all_flags()

    def teardown_method(self):
        _clear_all_flags()

    def test_paused_registrations_block_start_signup(self, client):
        _set_flag("registrations_paused", 1)
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": "newuser@zeuschat.test"}),
            content_type="application/json",
        )
        assert r.status_code == 503
        data = r.get_json()
        assert data.get("registrations_paused") is True

    def test_paused_registrations_block_complete_registration(self, client):
        _set_flag("registrations_paused", 1)
        r = client.post(
            "/api/complete-registration",
            data=json.dumps({"full_name": "Test", "password": "Pass@123"}),
            content_type="application/json",
        )
        assert r.status_code == 503

    def test_paused_registrations_allow_login(self, client):
        """Pausing registrations must NOT block existing user logins."""
        _set_flag("registrations_paused", 1)
        r = client.post(
            "/api/login",
            data=json.dumps({"zeus_pin": "TSTPIN0001", "password": "TestPass@123"}),
            content_type="application/json",
        )
        # Must reach the login handler — 200 or 401, NOT 503
        assert r.status_code in (200, 401)
        assert r.status_code != 503

    def test_resumed_registrations_restore_signup(self, client):
        _set_flag("registrations_paused", 1)
        _set_flag("registrations_paused", 0)
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": "should_work@zeuschat.test"}),
            content_type="application/json",
        )
        assert r.status_code != 503


# ── Marketplace disable ───────────────────────────────────────────────────────

class TestMarketplaceDisable:
    def setup_method(self):
        _clear_all_flags()

    def teardown_method(self):
        _clear_all_flags()

    def test_disabled_marketplace_blocks_browse(self, client):
        _set_flag("marketplace_disabled", 1)
        r = client.get("/ghost-market")
        assert r.status_code == 503

    def test_disabled_marketplace_blocks_api(self, client):
        _set_flag("marketplace_disabled", 1)
        r = client.get("/api/ghost-market/items")
        assert r.status_code == 503
        data = r.get_json()
        assert data.get("marketplace_disabled") is True

    def test_re_enabled_marketplace_restores_access(self, client):
        _set_flag("marketplace_disabled", 1)
        _set_flag("marketplace_disabled", 0)
        r = client.get("/ghost-market")
        assert r.status_code == 200


# ── Community disable ─────────────────────────────────────────────────────────

class TestCommunityDisable:
    def setup_method(self):
        _clear_all_flags()

    def teardown_method(self):
        _clear_all_flags()

    def test_disabled_community_blocks_forums(self, client):
        _set_flag("community_disabled", 1)
        r = client.get("/ghost-forums")
        assert r.status_code == 503

    def test_re_enabled_community_restores_access(self, client):
        _set_flag("community_disabled", 1)
        _set_flag("community_disabled", 0)
        r = client.get("/ghost-forums")
        assert r.status_code in (200, 302)


# ── Admin override endpoints ──────────────────────────────────────────────────

class TestAdminOverrideEndpoints:
    def setup_method(self):
        _clear_all_flags()

    def teardown_method(self):
        _clear_all_flags()

    def test_pause_registrations_requires_admin(self, client):
        r = client.post("/admin/api/override/pause-registrations")
        assert r.status_code == 401

    def test_pause_registrations_sets_flag(self, admin_client):
        r = admin_client.post(
            "/admin/api/override/pause-registrations",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 200
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT flag_value FROM system_flags WHERE flag_name = 'registrations_paused'")
            row = cursor.fetchone()
        assert row is not None and row["flag_value"] == 1

    def test_resume_registrations_clears_flag(self, admin_client):
        _set_flag("registrations_paused", 1)
        r = admin_client.post(
            "/admin/api/override/resume-registrations",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 200
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT flag_value FROM system_flags WHERE flag_name = 'registrations_paused'")
            row = cursor.fetchone()
        assert row is not None and row["flag_value"] == 0

    def test_enable_maintenance_mode_sets_flag(self, admin_client):
        r = admin_client.post(
            "/admin/api/override/maintenance-mode",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 200
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT flag_value FROM system_flags WHERE flag_name = 'maintenance_mode'")
            row = cursor.fetchone()
        assert row is not None and row["flag_value"] == 1
        # Restore so other tests aren't blocked
        _set_flag("maintenance_mode", 0)

    def test_disable_maintenance_mode_clears_flag(self, admin_client):
        _set_flag("maintenance_mode", 1)
        r = admin_client.post(
            "/admin/api/override/disable-maintenance-mode",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 200
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT flag_value FROM system_flags WHERE flag_name = 'maintenance_mode'")
            row = cursor.fetchone()
        assert row is not None and row["flag_value"] == 0

    def test_extend_pins_requires_admin(self, client):
        r = client.post("/admin/api/override/extend-pins")
        assert r.status_code == 401

    def test_extend_pins_with_admin(self, admin_client):
        r = admin_client.post(
            "/admin/api/override/extend-pins",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 200

    def test_clear_message_queue_requires_admin(self, client):
        r = client.post("/admin/api/override/clear-message-queue")
        assert r.status_code == 401

    def test_clear_message_queue_with_admin(self, admin_client):
        r = admin_client.post(
            "/admin/api/override/clear-message-queue",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 200
