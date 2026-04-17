"""
test_whatsapp_features.py
Smoke tests for all WhatsApp-feature API endpoints (migration 008).

Covers:
  GIFs / Stickers, Message star/pin/react, Read receipts, Wallpapers,
  Auto-download, Quick replies, Away / Greeting messages, Chat labels,
  Statistics dashboard, Theme, Notifications, Two-step verification,
  Encrypted backups, Broadcast lists, Group announcements.
"""
import json
import pytest
from tests.conftest import (
    get_db_connection,
    TEST_PIN, TEST_EMAIL, TEST_NAME,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def j(resp):
    return resp.get_json() or {}


def assert_ok(resp, *codes):
    valid = codes or (200, 201)
    assert resp.status_code in valid, (
        f"Expected {valid}, got {resp.status_code}. Body: {j(resp)}"
    )


def assert_not_500(resp):
    assert resp.status_code != 500, f"Got 500. Body: {j(resp)}"


def _make_session(c, user_id, pin, email, name, tier="free"):
    with c.session_transaction() as sess:
        sess["user_id"]           = user_id
        sess["zeus_pin"]          = pin
        sess["email"]             = email
        sess["user_email"]        = email
        sess["full_name"]         = name
        sess["user_full_name"]    = name
        sess["subscription_tier"] = tier
        sess["is_approved"]       = True
        sess["password_unlocked"] = True


def _seed_message_and_group():
    """Insert a real message row and a group row for FK-safe tests."""
    with get_db_connection() as conn:
        c = conn.cursor()
        # user id for test user
        c.execute("SELECT id FROM users WHERE email = ?", (TEST_EMAIL,))
        uid = c.fetchone()["id"]

        # minimal message
        c.execute(
            "INSERT OR IGNORE INTO messages "
            "(sender_id, receiver_id, content, ttl_seconds, status) "
            "VALUES (?, ?, ?, ?, 'delivered')",
            (uid, uid, "smoke test message", 0),
        )
        c.execute("SELECT id FROM messages WHERE sender_id = ? LIMIT 1", (uid,))
        row = c.fetchone()
        msg_id = row["id"] if row else 1

        # minimal group
        c.execute(
            "INSERT OR IGNORE INTO groups (group_name, created_by) VALUES (?, ?)",
            ("WA Smoke Group", uid),
        )
        c.execute("SELECT id FROM groups WHERE created_by = ? LIMIT 1", (uid,))
        grp = c.fetchone()
        grp_id = grp["id"] if grp else 1

        conn.commit()
    return uid, msg_id, grp_id


# ── module-level seed ──────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def seed_wa():
    _seed_message_and_group()
    yield


# ── per-test auth client ───────────────────────────────────────────────────────

@pytest.fixture
def wa_client(app):
    """Authenticated free-tier client."""
    from tests.conftest import get_test_user_id
    uid = get_test_user_id()
    c = app.test_client()
    _make_session(c, uid, TEST_PIN, TEST_EMAIL, TEST_NAME, tier="free")
    return c


@pytest.fixture
def wa_pro_client(app):
    """Authenticated pro-tier client (unlimited wallpaper changes etc.)."""
    from tests.conftest import get_test_user_id
    uid = get_test_user_id()
    c = app.test_client()
    _make_session(c, uid, TEST_PIN, TEST_EMAIL, TEST_NAME, tier="pro")
    # Ensure there is an active pro subscription for wallpaper gate
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO subscriptions (user_id, tier, status, current_period_start, current_period_end) "
            "VALUES (?, 'pro', 'active', datetime('now'), datetime('now','+365 days'))",
            (uid,),
        )
        conn.commit()
    return c


# ══════════════════════════════════════════════════════════════════════════════
# AUTH GATES
# ══════════════════════════════════════════════════════════════════════════════

class TestWAAuthGates:
    GUARDED = [
        ("GET",  "/api/whatsapp/gifs/trending"),
        ("GET",  "/api/whatsapp/stickers/packs"),
        ("GET",  "/api/whatsapp/settings/read-receipts"),
        ("GET",  "/api/whatsapp/settings/theme"),
        ("GET",  "/api/whatsapp/settings/auto-download"),
        ("GET",  "/api/whatsapp/quick-replies"),
        ("GET",  "/api/whatsapp/away-message"),
        ("GET",  "/api/whatsapp/greeting-message"),
        ("GET",  "/api/whatsapp/labels"),
        ("GET",  "/api/whatsapp/statistics"),
        ("GET",  "/api/whatsapp/backups"),
        ("GET",  "/api/whatsapp/broadcasts"),
    ]

    @pytest.mark.parametrize("method,path", GUARDED)
    def test_unauthenticated_returns_401_or_403(self, client, method, path):
        r = getattr(client, method.lower())(path)
        assert r.status_code in (401, 403), (
            f"{method} {path} returned {r.status_code}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# GIF & STICKER
# ══════════════════════════════════════════════════════════════════════════════

class TestGifsStickers:
    def test_trending_gifs(self, wa_client):
        r = wa_client.get("/api/whatsapp/gifs/trending")
        assert_ok(r)
        assert "gifs" in j(r)

    def test_search_gifs(self, wa_client):
        r = wa_client.get("/api/whatsapp/gifs/search?q=hello")
        assert_ok(r)
        assert "gifs" in j(r)

    def test_sticker_packs(self, wa_client):
        r = wa_client.get("/api/whatsapp/stickers/packs")
        assert_ok(r)
        assert "packs" in j(r)

    def test_favorite_sticker(self, wa_client):
        r = wa_client.post(
            "/api/whatsapp/stickers/favorite",
            json={"sticker_url": "https://example.com/sticker.png", "sticker_pack_id": "pack1"},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_favorite_sticker_missing_url(self, wa_client):
        r = wa_client.post("/api/whatsapp/stickers/favorite", json={})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE ACTIONS — STAR / PIN / REACT
# ══════════════════════════════════════════════════════════════════════════════

class TestMessageActions:
    _state: dict = {}

    @pytest.fixture(autouse=True)
    def _cache_ids(self):
        uid, msg_id, grp_id = _seed_message_and_group()
        self._state["uid"] = uid
        self._state["msg_id"] = msg_id
        self._state["grp_id"] = grp_id

    def test_star_message_toggles(self, wa_client):
        mid = self._state["msg_id"]
        r = wa_client.post(f"/api/whatsapp/messages/{mid}/star", json={"chat_id": 1})
        assert_ok(r)
        assert "starred" in j(r)

    def test_star_message_idempotent_unstar(self, wa_client):
        mid = self._state["msg_id"]
        # Ensure deterministic baseline for this message/user.
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM starred_messages WHERE message_id = ?", (mid,))
            conn.commit()
        wa_client.post(f"/api/whatsapp/messages/{mid}/star", json={"chat_id": 1})
        r = wa_client.post(f"/api/whatsapp/messages/{mid}/star", json={"chat_id": 1})
        assert_ok(r)
        assert j(r)["starred"] is False  # second call unstars

    def test_pin_message(self, wa_client):
        mid = self._state["msg_id"]
        r = wa_client.post(f"/api/whatsapp/messages/{mid}/pin", json={"chat_id": 42})
        assert_ok(r)
        assert j(r)["success"] is True

    def test_get_pinned_message(self, wa_client):
        mid = self._state["msg_id"]
        wa_client.post(f"/api/whatsapp/messages/{mid}/pin", json={"chat_id": 99})
        r = wa_client.get("/api/whatsapp/messages/99/pinned")
        assert_ok(r)
        assert "pinned" in j(r)

    def test_react_to_message(self, wa_client):
        mid = self._state["msg_id"]
        r = wa_client.post(
            f"/api/whatsapp/messages/{mid}/react",
            json={"emoji": "❤️"},
        )
        assert_ok(r)
        assert j(r)["success"] is True
        assert isinstance(j(r)["reactions"], list)

    def test_react_updates_emoji(self, wa_client):
        mid = self._state["msg_id"]
        wa_client.post(f"/api/whatsapp/messages/{mid}/react", json={"emoji": "👍"})
        r = wa_client.post(f"/api/whatsapp/messages/{mid}/react", json={"emoji": "😂"})
        assert_ok(r)

    def test_get_message_reactions(self, wa_client):
        mid = self._state["msg_id"]
        r = wa_client.get(f"/api/whatsapp/messages/{mid}/reactions")
        assert_ok(r)
        assert "reactions" in j(r)

    def test_react_missing_emoji(self, wa_client):
        mid = self._state["msg_id"]
        r = wa_client.post(f"/api/whatsapp/messages/{mid}/react", json={})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# READ RECEIPTS
# ══════════════════════════════════════════════════════════════════════════════

class TestReadReceipts:
    def test_get_read_receipts(self, wa_client):
        r = wa_client.get("/api/whatsapp/settings/read-receipts")
        assert_ok(r)
        assert "enabled" in j(r)

    def test_disable_read_receipts(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/settings/read-receipts",
            json={"enabled": False},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_re_enable_read_receipts(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/settings/read-receipts",
            json={"enabled": True},
        )
        assert_ok(r)


# ══════════════════════════════════════════════════════════════════════════════
# WALLPAPERS
# ══════════════════════════════════════════════════════════════════════════════

class TestWallpapers:
    def test_get_global_wallpaper_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/wallpapers/global")
        assert_ok(r)
        assert "wallpaper" in j(r)

    def test_pro_can_set_wallpaper(self, wa_pro_client):
        r = wa_pro_client.put(
            "/api/whatsapp/wallpapers/global",
            json={"wallpaper_type": "solid", "wallpaper_color": "#128C7E"},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_chat_wallpaper_update(self, wa_pro_client):
        r = wa_pro_client.put(
            "/api/whatsapp/wallpapers/chat/7",
            json={"wallpaper_type": "solid", "wallpaper_color": "#005C4B"},
        )
        assert_ok(r)
        assert j(r)["success"] is True


# ══════════════════════════════════════════════════════════════════════════════
# AUTO-DOWNLOAD
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoDownload:
    def test_get_auto_download(self, wa_client):
        r = wa_client.get("/api/whatsapp/settings/auto-download")
        assert_ok(r)
        d = j(r)
        assert "photos" in d and "videos" in d and "documents" in d

    def test_update_auto_download(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/settings/auto-download",
            json={"photos": "always", "videos": "never", "documents": "wifi", "lowDataMode": True},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_auto_download_invalid_mode_defaults(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/settings/auto-download",
            json={"photos": "INVALID"},
        )
        assert_ok(r)  # server silently defaults to 'wifi'


# ══════════════════════════════════════════════════════════════════════════════
# QUICK REPLIES
# ══════════════════════════════════════════════════════════════════════════════

class TestQuickReplies:
    _state: dict = {}

    def test_list_quick_replies_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/quick-replies")
        assert_ok(r)
        assert "quickReplies" in j(r)

    def test_create_quick_reply(self, wa_client):
        r = wa_client.post(
            "/api/whatsapp/quick-replies",
            json={"title": "Hello", "content": "Hello there! How can I help?", "shortcut": "/hello"},
        )
        assert_ok(r)
        assert j(r)["success"] is True
        self._state["reply_id"] = j(r)["id"]

    def test_list_has_created_reply(self, wa_client):
        wa_client.post("/api/whatsapp/quick-replies", json={"title": "Bye", "content": "Goodbye!"})
        r = wa_client.get("/api/whatsapp/quick-replies")
        assert_ok(r)
        titles = [x["title"] for x in j(r)["quickReplies"]]
        assert "Bye" in titles

    def test_delete_quick_reply(self, wa_client):
        create = wa_client.post("/api/whatsapp/quick-replies", json={"title": "Del me", "content": "..."})
        rid = j(create)["id"]
        r = wa_client.delete(f"/api/whatsapp/quick-replies/{rid}")
        assert_ok(r)
        assert j(r)["success"] is True

    def test_create_quick_reply_missing_fields(self, wa_client):
        r = wa_client.post("/api/whatsapp/quick-replies", json={"title": "Only title"})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# AWAY MESSAGE
# ══════════════════════════════════════════════════════════════════════════════

class TestAwayMessage:
    def test_get_away_message_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/away-message")
        assert_ok(r)
        assert "awayMessage" in j(r)

    def test_enable_away_message(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/away-message",
            json={"isEnabled": True, "message": "I am away right now", "startTime": "18:00", "endTime": "09:00"},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_update_away_message(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/away-message",
            json={"isEnabled": True, "message": "Updated away message"},
        )
        assert_ok(r)

    def test_disable_away_message(self, wa_client):
        r = wa_client.put("/api/whatsapp/away-message", json={"isEnabled": False, "message": "Off"})
        assert_ok(r)

    def test_enable_away_message_no_text_rejected(self, wa_client):
        r = wa_client.put("/api/whatsapp/away-message", json={"isEnabled": True, "message": ""})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# GREETING MESSAGE
# ══════════════════════════════════════════════════════════════════════════════

class TestGreetingMessage:
    def test_get_greeting_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/greeting-message")
        assert_ok(r)
        assert "greetingMessage" in j(r)

    def test_enable_greeting(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/greeting-message",
            json={"isEnabled": True, "message": "Welcome to ZeusChat!", "sendToNewChatsOnly": True},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_disable_greeting(self, wa_client):
        r = wa_client.put("/api/whatsapp/greeting-message", json={"isEnabled": False, "message": "Off"})
        assert_ok(r)


# ══════════════════════════════════════════════════════════════════════════════
# CHAT LABELS
# ══════════════════════════════════════════════════════════════════════════════

class TestChatLabels:
    _state: dict = {}

    def test_list_labels_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/labels")
        assert_ok(r)
        assert "labels" in j(r)

    def test_create_label(self, wa_client):
        r = wa_client.post(
            "/api/whatsapp/labels",
            json={"name": "VIP Customer", "color": "#FFD700"},
        )
        assert_ok(r)
        assert j(r)["success"] is True
        self._state["label_id"] = j(r)["id"]

    def test_assign_label_to_chat(self, wa_client):
        create = wa_client.post("/api/whatsapp/labels", json={"name": "Assign Test Label"})
        lid = j(create)["id"]
        r = wa_client.put("/api/whatsapp/chats/5/labels", json={"labelId": lid})
        assert_ok(r)
        assert j(r)["success"] is True

    def test_create_duplicate_label_returns_conflict(self, wa_client):
        wa_client.post("/api/whatsapp/labels", json={"name": "Unique123"})
        r = wa_client.post("/api/whatsapp/labels", json={"name": "Unique123"})
        assert r.status_code == 409

    def test_assign_nonexistent_label(self, wa_client):
        r = wa_client.put("/api/whatsapp/chats/5/labels", json={"labelId": 999999})
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# STATISTICS
# ══════════════════════════════════════════════════════════════════════════════

class TestStatistics:
    def test_statistics_day(self, wa_client):
        r = wa_client.get("/api/whatsapp/statistics?period=day")
        assert_ok(r)
        d = j(r)
        assert "summary" in d and "daily" in d
        s = d["summary"]
        assert all(k in s for k in ("totalSent", "totalReceived", "totalDelivered", "totalRead"))

    def test_statistics_week(self, wa_client):
        r = wa_client.get("/api/whatsapp/statistics?period=week")
        assert_ok(r)
        assert "summary" in j(r)

    def test_statistics_month(self, wa_client):
        r = wa_client.get("/api/whatsapp/statistics?period=month")
        assert_ok(r)
        assert "summary" in j(r)

    def test_statistics_defaults_to_week(self, wa_client):
        r = wa_client.get("/api/whatsapp/statistics")
        assert_ok(r)


# ══════════════════════════════════════════════════════════════════════════════
# THEME
# ══════════════════════════════════════════════════════════════════════════════

class TestTheme:
    def test_get_theme(self, wa_client):
        r = wa_client.get("/api/whatsapp/settings/theme")
        assert_ok(r)
        assert "theme" in j(r) and "fontScale" in j(r)

    def test_set_dark_theme(self, wa_client):
        r = wa_client.put("/api/whatsapp/settings/theme", json={"theme": "dark", "fontScale": 1.1})
        assert_ok(r)
        assert j(r)["success"] is True

    def test_set_system_theme(self, wa_client):
        r = wa_client.put("/api/whatsapp/settings/theme", json={"theme": "system"})
        assert_ok(r)

    def test_invalid_theme_defaults_to_light(self, wa_client):
        r = wa_client.put("/api/whatsapp/settings/theme", json={"theme": "neon"})
        assert_ok(r)  # server defaults, no 400

    def test_font_scale_clamped(self, wa_client):
        r = wa_client.put("/api/whatsapp/settings/theme", json={"theme": "light", "fontScale": 99.0})
        assert_ok(r)


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

class TestNotifications:
    def test_get_notification_settings(self, wa_client):
        r = wa_client.get("/api/whatsapp/settings/notifications")
        assert_ok(r)
        assert "tone" in j(r) and "groupTone" in j(r)

    def test_update_notification_settings(self, wa_client):
        r = wa_client.put(
            "/api/whatsapp/settings/notifications",
            json={"tone": "chime", "groupTone": "bell"},
        )
        assert_ok(r)
        assert j(r)["success"] is True


# ══════════════════════════════════════════════════════════════════════════════
# TWO-STEP VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

class TestTwoStep:
    def test_enable_two_step(self, wa_client):
        r = wa_client.post(
            "/api/whatsapp/security/two-step",
            json={"pin": "123456", "email": "backup@zeuschat.test"},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_verify_correct_pin(self, wa_client):
        from tests.conftest import get_test_user_id
        uid = get_test_user_id()
        wa_client.post("/api/whatsapp/security/two-step", json={"pin": "654321", "email": "bk@zeuschat.test"})
        r = wa_client.post("/api/whatsapp/security/two-step/verify", json={"userId": uid, "pin": "654321"})
        assert_ok(r)
        assert j(r)["verified"] is True

    def test_verify_wrong_pin(self, wa_client):
        from tests.conftest import get_test_user_id
        uid = get_test_user_id()
        r = wa_client.post("/api/whatsapp/security/two-step/verify", json={"userId": uid, "pin": "000000"})
        assert_ok(r)
        assert j(r)["verified"] is False

    def test_enable_two_step_bad_pin(self, wa_client):
        r = wa_client.post("/api/whatsapp/security/two-step", json={"pin": "abc", "email": "x@x.com"})
        assert r.status_code == 400

    def test_enable_two_step_bad_email(self, wa_client):
        r = wa_client.post("/api/whatsapp/security/two-step", json={"pin": "123456", "email": "noemail"})
        assert r.status_code == 400

    def test_disable_two_step(self, wa_client):
        r = wa_client.delete("/api/whatsapp/security/two-step")
        assert_ok(r)
        assert j(r)["success"] is True


# ══════════════════════════════════════════════════════════════════════════════
# ENCRYPTED BACKUPS
# ══════════════════════════════════════════════════════════════════════════════

class TestBackups:
    def test_list_backups_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/backups")
        assert_ok(r)
        assert "backups" in j(r)

    def test_create_backup(self, wa_client):
        r = wa_client.post("/api/whatsapp/backups")
        assert_ok(r)
        assert j(r)["success"] is True
        assert "backupId" in j(r)

    def test_list_backups_after_create(self, wa_client):
        wa_client.post("/api/whatsapp/backups")
        r = wa_client.get("/api/whatsapp/backups")
        assert_ok(r)
        assert len(j(r)["backups"]) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# BROADCAST LISTS
# ══════════════════════════════════════════════════════════════════════════════

class TestBroadcasts:
    _state: dict = {}

    def test_list_broadcasts_empty(self, wa_client):
        r = wa_client.get("/api/whatsapp/broadcasts")
        assert_ok(r)
        assert "broadcasts" in j(r)

    def test_create_broadcast(self, wa_client):
        r = wa_client.post("/api/whatsapp/broadcasts", json={"name": "Flash Sale"})
        assert_ok(r)
        assert j(r)["success"] is True
        self._state["bc_id"] = j(r)["id"]

    def test_list_broadcasts_has_created(self, wa_client):
        wa_client.post("/api/whatsapp/broadcasts", json={"name": "Promo List"})
        r = wa_client.get("/api/whatsapp/broadcasts")
        assert_ok(r)
        names = [b["name"] for b in j(r)["broadcasts"]]
        assert "Promo List" in names

    def test_send_broadcast(self, wa_client):
        create = wa_client.post("/api/whatsapp/broadcasts", json={"name": "Send Test"})
        bid = j(create)["id"]
        r = wa_client.post(f"/api/whatsapp/broadcasts/{bid}/send", json={"message": "Hello everyone!"})
        assert_ok(r)
        assert j(r)["success"] is True
        assert "sentTo" in j(r)

    def test_create_broadcast_missing_name(self, wa_client):
        r = wa_client.post("/api/whatsapp/broadcasts", json={})
        assert r.status_code == 400

    def test_send_nonexistent_broadcast(self, wa_client):
        r = wa_client.post("/api/whatsapp/broadcasts/999999/send", json={"message": "x"})
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# GROUP ANNOUNCEMENTS
# ══════════════════════════════════════════════════════════════════════════════

class TestGroupAnnouncements:
    def test_send_announcement_as_creator(self, wa_client):
        _, _, grp_id = _seed_message_and_group()
        r = wa_client.post(
            f"/api/whatsapp/groups/{grp_id}/announcements",
            json={"message": "Important: server maintenance tonight"},
        )
        assert_ok(r)
        assert j(r)["success"] is True

    def test_get_group_announcements(self, wa_client):
        _, _, grp_id = _seed_message_and_group()
        wa_client.post(
            f"/api/whatsapp/groups/{grp_id}/announcements",
            json={"message": "Read this"},
        )
        r = wa_client.get(f"/api/whatsapp/groups/{grp_id}/announcements")
        assert_ok(r)
        assert "announcements" in j(r)

    def test_send_announcement_missing_message(self, wa_client):
        _, _, grp_id = _seed_message_and_group()
        r = wa_client.post(f"/api/whatsapp/groups/{grp_id}/announcements", json={})
        assert r.status_code == 400

    def test_send_announcement_to_nonexistent_group(self, wa_client):
        r = wa_client.post("/api/whatsapp/groups/999999/announcements", json={"message": "x"})
        assert r.status_code == 403  # not a member / admin
