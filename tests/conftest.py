"""
ZeusChat Test Suite - Shared fixtures and configuration.
"""

import os
import sys
import json
import tempfile
from datetime import datetime, timedelta

import bcrypt
import pytest

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Isolated test DB — MUST be set before importing app ─────────────────────
_db_fd, _db_path = tempfile.mkstemp(suffix="_zeuschat_test.db")
os.environ["DATABASE_PATH"] = _db_path

# ── Import app AFTER env var is set ─────────────────────────────────────────
from app import app as flask_app, get_db_connection  # noqa: E402

# ── Test credentials ─────────────────────────────────────────────────────────
TEST_PIN = "TSTPIN0001"
TEST_EMAIL = "testuser@zeuschat.test"
TEST_PASSWORD = "TestPass@123"
TEST_NAME = "Test User"

TEST_ADMIN_USERNAME = "test_admin"
TEST_ADMIN_PASSWORD = "AdminPass@123"
TEST_ADMIN_EMAIL = "admin@zeuschat.test"

# ── Seed helpers ─────────────────────────────────────────────────────────────

def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def seed_test_data() -> int:
    """Insert a verified test user + admin and return the user's id."""
    future_expiry = (datetime.utcnow() + timedelta(days=365)).isoformat()
    admin_perms = json.dumps({
        "can_approve_users": True,
        "can_ban_users": True,
        "can_approve_payments": True,
        "can_manage_admins": True,
        "can_view_logs": True,
    })
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # --- test user ---
        cursor.execute(
            """
            INSERT OR IGNORE INTO users
                (email, zeus_pin, password_hash, full_name, pin_expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (TEST_EMAIL, TEST_PIN, _hash(TEST_PASSWORD), TEST_NAME, future_expiry),
        )
        cursor.execute("SELECT id FROM users WHERE email = ?", (TEST_EMAIL,))
        row = cursor.fetchone()
        user_id = row["id"]

        # --- approve the test user ---
        cursor.execute(
            "INSERT OR IGNORE INTO user_approvals (user_id, status) VALUES (?, 'approved')",
            (user_id,),
        )

        # --- test admin ---
        cursor.execute(
            """
            INSERT OR IGNORE INTO admin_users
                (username, password_hash, email, role, permissions)
            VALUES (?, ?, ?, 'super_admin', ?)
            """,
            (TEST_ADMIN_USERNAME, _hash(TEST_ADMIN_PASSWORD), TEST_ADMIN_EMAIL, admin_perms),
        )
        conn.commit()
    return user_id


def get_test_user_id() -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (TEST_EMAIL,))
        row = cursor.fetchone()
        return row["id"] if row else 1


def get_test_admin_id() -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM admin_users WHERE username = ?", (TEST_ADMIN_USERNAME,))
        row = cursor.fetchone()
        return row["id"] if row else 1


# ── Session-scoped DB seed ────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def seed_db():
    """Seed test users once for the entire test session."""
    flask_app.config["TESTING"] = True
    seed_test_data()
    yield
    # Teardown: close and remove temp DB
    try:
        os.close(_db_fd)
    except OSError:
        pass
    try:
        os.unlink(_db_path)
    except OSError:
        pass


# ── Per-test fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def app():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def auth_client(app):
    """Test client pre-authenticated as the free-tier test user."""
    c = app.test_client()
    uid = get_test_user_id()
    with c.session_transaction() as sess:
        sess["user_id"] = uid
        sess["zeus_pin"] = TEST_PIN
        sess["email"] = TEST_EMAIL
        sess["user_email"] = TEST_EMAIL
        sess["full_name"] = TEST_NAME
        sess["user_full_name"] = TEST_NAME
        sess["subscription_tier"] = "free"
        sess["is_approved"] = True
        sess["password_unlocked"] = True
    return c


@pytest.fixture
def pro_auth_client(app):
    """Test client pre-authenticated as a Pro-tier test user."""
    c = app.test_client()
    uid = get_test_user_id()
    with c.session_transaction() as sess:
        sess["user_id"] = uid
        sess["zeus_pin"] = TEST_PIN
        sess["email"] = TEST_EMAIL
        sess["user_email"] = TEST_EMAIL
        sess["full_name"] = TEST_NAME
        sess["user_full_name"] = TEST_NAME
        sess["subscription_tier"] = "pro"
        sess["is_approved"] = True
        sess["password_unlocked"] = True
    return c


@pytest.fixture
def admin_client(app):
    """Test client pre-authenticated as the test admin."""
    c = app.test_client()
    aid = get_test_admin_id()
    with c.session_transaction() as sess:
        sess["admin_id"] = aid
        sess["admin_username"] = TEST_ADMIN_USERNAME
        sess["admin_role"] = "super_admin"
        sess["admin_permissions"] = {
            "can_approve_users": True,
            "can_ban_users": True,
            "can_approve_payments": True,
            "can_manage_admins": True,
            "can_view_logs": True,
        }
    return c
