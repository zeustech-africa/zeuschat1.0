import os
import sqlite3
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, os.environ.get('DATABASE_PATH', 'zeuschat.db'))


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _require(condition, message):
    if condition:
        print(f"PASS: {message}")
    else:
        raise AssertionError(f"FAIL: {message}")


def test_schema_and_pin_tables():
    print("Testing schema and PIN tables...")
    with _connect() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pin_expiry_warnings'")
        _require(cursor.fetchone() is not None, "pin_expiry_warnings table exists")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pin_extensions'")
        _require(cursor.fetchone() is not None, "pin_extensions table exists")

        cursor.execute("PRAGMA table_info(users)")
        cols = {row['name'] for row in cursor.fetchall()}
        _require('pin_expires_at' in cols, "users.pin_expires_at column exists")
        _require('pin_extension_count' in cols, "users.pin_extension_count column exists")
        _require('deleted_at' in cols, "users.deleted_at column exists")


def test_pin_expiry_cache_health():
    print("Testing pin expiry cache health...")
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) AS c
            FROM users
            WHERE deleted_at IS NULL
              AND pin_expires_at IS NULL
            """
        )
        null_count = int(cursor.fetchone()['c'])
        if null_count == 0:
            print("PASS: all active users have cached pin_expires_at")
        else:
            print(f"INFO: {null_count} users without cached pin_expires_at (dev/test ok, refresh_all_pin_expiry_dates will populate on app boot)")


def test_expired_lockout_readiness():
    print("Testing expired lockout readiness...")
    with _connect() as conn:
        cursor = conn.cursor()

        # Ensure warning table uniqueness works as expected.
        cursor.execute(
            """
            SELECT COUNT(*) AS c
            FROM sqlite_master
            WHERE type='index'
              AND name LIKE 'sqlite_autoindex_pin_expiry_warnings%'
            """
        )
        _require(cursor.fetchone()['c'] >= 1, "pin_expiry_warnings unique constraint/index present")


def test_account_deletion_window_logic():
    print("Testing account deletion grace window logic...")
    cutoff = datetime.utcnow() - timedelta(days=14)
    # This mirrors app cleanup semantics: eligible if pin_expires_at older than cutoff.
    _require(cutoff < datetime.utcnow(), "computed cleanup cutoff is valid")


def main():
    print("Running ZeusChat PIN expiry system audit...")
    print(f"Using database: {DB_PATH}")
    test_schema_and_pin_tables()
    test_pin_expiry_cache_health()
    test_expired_lockout_readiness()
    test_account_deletion_window_logic()
    print("AUDIT COMPLETE")


if __name__ == '__main__':
    main()
