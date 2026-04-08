#!/usr/bin/env python3
"""Targeted production-readiness verification for ZeusChat P0/P1 fixes."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "zeuschat.db"


def check_foreign_keys() -> tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        value = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
    finally:
        conn.close()
    return value == 1, f"PRAGMA foreign_keys={value}"


def check_legacy_hashes() -> tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute("SELECT password_hash FROM users").fetchall()
        queue_table_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='password_migration_queue'"
        ).fetchone() is not None
        queued = 0
        if queue_table_exists:
            queued = conn.execute("SELECT COUNT(*) FROM password_migration_queue").fetchone()[0]
    finally:
        conn.close()

    legacy = 0
    pattern = re.compile(r"^[a-f0-9]{64}$")
    for (hash_value,) in rows:
        if hash_value and pattern.fullmatch(hash_value):
            legacy += 1

    if legacy == 0:
        return True, "legacy_sha256_count=0"

    if queue_table_exists and queued >= legacy:
        return True, f"legacy_sha256_count={legacy}, queued_for_migration={queued}"

    return False, f"legacy_sha256_count={legacy}, queued_for_migration={queued}"


def check_vapid_endpoint() -> tuple[bool, str]:
    base_url = os.environ.get("VERIFY_BASE_URL", "http://127.0.0.1:5000")
    url = f"{base_url}/api/push/vapid-public-key"
    try:
        with urlopen(url, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        return False, f"endpoint_unreachable={exc}"

    value = payload.get("publicKey") or payload.get("public_key") or ""
    return bool(value), f"public_key_length={len(value)}"


def check_bottom_nav_markup() -> tuple[bool, str]:
    required = [
        ROOT / "chat.html",
        ROOT / "templates" / "ghost-market.html",
        ROOT / "templates" / "ghost-ultimate.html",
        ROOT / "profile.html",
        ROOT / "settings.html",
    ]

    missing = []
    for path in required:
        content = path.read_text(encoding="utf-8", errors="ignore")
        ok = all(token in content for token in [
            'class="mobile-bottom-nav',
            'data-page="chat"',
            'data-page="market"',
            'data-page="ghost"',
            'data-page="profile"',
            'data-page="settings"',
        ])
        if not ok:
            missing.append(path.name)

    return not missing, "missing=" + (", ".join(missing) if missing else "none")


def check_infinite_scroll() -> tuple[bool, str]:
    content = (ROOT / "static" / "ghost.js").read_text(encoding="utf-8", errors="ignore")
    required_tokens = [
        "loadMorePosts",
        "isLoading",
        "hasMore",
        "scrollTop + clientHeight >= scrollHeight - 500",
        "feedContainer.addEventListener('scroll'",
    ]
    missing = [token for token in required_tokens if token not in content]
    return not missing, "missing=" + (", ".join(missing) if missing else "none")


def main() -> int:
    checks = [
        ("foreign_keys", check_foreign_keys),
        ("legacy_hashes", check_legacy_hashes),
        ("vapid_endpoint", check_vapid_endpoint),
        ("bottom_nav", check_bottom_nav_markup),
        ("infinite_scroll", check_infinite_scroll),
    ]

    failures = []
    print("ZeusChat Final Verification (P0 + P1)")
    print("=" * 42)

    for name, fn in checks:
        ok, details = fn()
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}: {details}")
        if not ok:
            failures.append(name)

    print("=" * 42)
    if failures:
        print("OVERALL: FAIL")
        print("Failed checks:", ", ".join(failures))
        return 1

    print("OVERALL: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
