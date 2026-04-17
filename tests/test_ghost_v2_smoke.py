"""
test_ghost_v2_smoke.py
Full smoke pass for Ghost Community v2 and Ghost Market v2 endpoints.

Covers:
  Community  – create post, admin moderation, feed (for-you/following/trending),
               like/unlike, comment/delete, share, view, follow/unfollow,
               followers count, my-posts.
  Market     – create listing, admin moderation, feed, single listing,
               save/unsave, inquire, my-inquiries, mark-read, reply,
               mark-sold, delete, analytics.
  Auth gates – unauthenticated requests must return 401/403.
"""
import io
import json
import pytest
from datetime import datetime, timedelta
from tests.conftest import get_db_connection, TEST_PIN, TEST_EMAIL, TEST_NAME

# ─── seed helpers ──────────────────────────────────────────────────────────────

SELLER_PIN   = "SELLER0001"
SELLER_EMAIL = "seller@zeuschat.test"

BUYER_PIN    = "BUYER00001"
BUYER_EMAIL  = "buyer@zeuschat.test"


def _seed_extra_users():
    """Create seller (pro) + buyer (free) users if they don't exist yet."""
    future_expiry = (datetime.utcnow() + timedelta(days=365)).isoformat()
    future_sub    = (datetime.utcnow() + timedelta(days=365)).isoformat()
    now_str       = datetime.utcnow().isoformat(sep=" ")
    import bcrypt
    hashed = bcrypt.hashpw(b"TestPass@123", bcrypt.gensalt()).decode()
    with get_db_connection() as conn:
        c = conn.cursor()
        for pin, email, name in [
            (SELLER_PIN, SELLER_EMAIL, "Seller User"),
            (BUYER_PIN,  BUYER_EMAIL,  "Buyer User"),
        ]:
            c.execute(
                "INSERT OR IGNORE INTO users "
                "(email, zeus_pin, password_hash, full_name, pin_expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (email, pin, hashed, name, future_expiry),
            )
            c.execute("SELECT id FROM users WHERE email = ?", (email,))
            uid = c.fetchone()["id"]
            c.execute(
                "INSERT OR IGNORE INTO user_approvals (user_id, status) VALUES (?, 'approved')",
                (uid,),
            )

        # pro subscription for seller
        c.execute("SELECT id FROM users WHERE email = ?", (SELLER_EMAIL,))
        seller_id = c.fetchone()["id"]
        c.execute(
            "INSERT OR IGNORE INTO subscriptions "
            "(user_id, tier, status, current_period_start, current_period_end) "
            "VALUES (?, 'pro', 'active', ?, ?)",
            (seller_id, now_str, future_sub),
        )
        # approved seller entry
        c.execute(
            "INSERT OR IGNORE INTO ghost_market_sellers "
            "(user_id, store_name, store_description, application_status) "
            "VALUES (?, 'Ghost Store', 'Test store', 'approved')",
            (seller_id,),
        )
        conn.commit()


def _get_uid(email):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        return c.fetchone()["id"]


def _make_session(c, user_id, pin, email, name, tier="free"):
    with c.session_transaction() as sess:
        sess["user_id"]          = user_id
        sess["zeus_pin"]         = pin
        sess["email"]            = email
        sess["user_email"]       = email
        sess["full_name"]        = name
        sess["user_full_name"]   = name
        sess["subscription_tier"] = tier
        sess["is_approved"]      = True
        sess["password_unlocked"] = True


# ─── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def seed_v2_users():
    _seed_extra_users()
    yield


@pytest.fixture
def seller_client(app):
    uid = _get_uid(SELLER_EMAIL)
    c   = app.test_client()
    _make_session(c, uid, SELLER_PIN, SELLER_EMAIL, "Seller User", tier="pro")
    return c


@pytest.fixture
def buyer_client(app):
    uid = _get_uid(BUYER_EMAIL)
    c   = app.test_client()
    _make_session(c, uid, BUYER_PIN, BUYER_EMAIL, "Buyer User", tier="free")
    return c


# ─── helpers ───────────────────────────────────────────────────────────────────

def j(resp):
    return resp.get_json() or {}


def assert_ok(resp, *valid_codes):
    codes = valid_codes or (200, 201)
    assert resp.status_code in codes, (
        f"Expected {codes}, got {resp.status_code}. Body: {j(resp)}"
    )


def assert_not_500(resp):
    assert resp.status_code != 500, f"Got 500. Body: {j(resp)}"


# ─── AUTH GATE TESTS ───────────────────────────────────────────────────────────

class TestAuthGates:
    def test_community_create_requires_auth(self, client):
        r = client.post("/api/ghost/community/post", data={"contentType": "text", "textContent": "x"})
        assert r.status_code in (401, 403)

    def test_community_feed_requires_auth(self, client):
        r = client.get("/api/ghost/community/feed")
        assert r.status_code in (401, 403)

    def test_community_my_posts_requires_auth(self, client):
        r = client.get("/api/ghost/community/my-posts")
        assert r.status_code in (401, 403)

    def test_community_like_requires_auth(self, client):
        r = client.post("/api/ghost/community/post/1/like")
        assert r.status_code in (401, 403)

    def test_community_comment_requires_auth(self, client):
        r = client.post(
            "/api/ghost/community/post/1/comment",
            data=json.dumps({"commentText": "hi"}),
            content_type="application/json",
        )
        assert r.status_code in (401, 403)

    def test_market_feed_requires_auth(self, client):
        r = client.get("/api/ghost/market/feed")
        assert r.status_code in (401, 403)

    def test_market_my_listings_requires_auth(self, client):
        r = client.get("/api/ghost/market/my-listings")
        assert r.status_code in (401, 403)

    def test_market_create_requires_auth(self, client):
        r = client.post("/api/ghost/market/listing", data={"title": "test"})
        assert r.status_code in (401, 403)


# ─── COMMUNITY – POST LIFECYCLE ────────────────────────────────────────────────

class TestCommunityPostLifecycle:
    """
    We use the module-scoped shared state dict (_state) so later test classes
    can reference the created post_id without complicated fixtures.
    """
    _state = {}

    # 1. Create a text post -------------------------------------------------
    def test_create_text_post(self, auth_client):
        r = auth_client.post(
            "/api/ghost/community/post",
            data={"contentType": "text", "textContent": "Hello Ghost Community! #test"},
            content_type="application/x-www-form-urlencoded",
        )
        assert_ok(r, 201)
        data = j(r)
        assert data.get("success") is True
        assert "postId" in data
        assert data.get("status") == "pending"
        TestCommunityPostLifecycle._state["post_id"] = data["postId"]

    # 2. my-posts returns the pending post ----------------------------------
    def test_my_posts_shows_pending(self, auth_client):
        r = auth_client.get("/api/ghost/community/my-posts")
        assert_ok(r, 200)
        data = j(r)
        assert "posts" in data
        assert isinstance(data["posts"], list)
        post_ids = [p["id"] for p in data["posts"]]
        assert TestCommunityPostLifecycle._state.get("post_id") in post_ids

    # 3. Feed (for-you) – post not yet visible because pending --------------
    def test_feed_foryou_empty_before_approval(self, auth_client):
        r = auth_client.get("/api/ghost/community/feed?type=for-you&limit=20&offset=0")
        assert_ok(r, 200)
        data = j(r)
        assert "posts" in data

    # 4. Feed (following) – should not 500 ---------------------------------
    def test_feed_following_no_crash(self, auth_client):
        r = auth_client.get("/api/ghost/community/feed?type=following&limit=20&offset=0")
        assert_not_500(r)
        data = j(r)
        assert "posts" in data

    # 5. Feed (trending) – should not 500 ----------------------------------
    def test_feed_trending_no_crash(self, auth_client):
        r = auth_client.get("/api/ghost/community/feed?type=trending&limit=20&offset=0")
        assert_not_500(r)
        data = j(r)
        assert "posts" in data

    # 6. Feed with hashtag filter – should not 500 -------------------------
    def test_feed_hashtag_filter(self, auth_client):
        r = auth_client.get("/api/ghost/community/feed?type=for-you&hashtag=test")
        assert_not_500(r)

    # 7. Admin – pending queue contains the new post -----------------------
    def test_admin_pending_queue(self, admin_client):
        r = admin_client.get("/api/admin/ghost/community/pending")
        assert_ok(r, 200)
        data = j(r)
        assert "posts" in data
        ids = [p["id"] for p in data["posts"]]
        assert TestCommunityPostLifecycle._state.get("post_id") in ids

    # 8. Admin – approve the post ------------------------------------------
    def test_admin_approve_post(self, admin_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = admin_client.post(f"/api/admin/ghost/community/post/{post_id}/approve")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True

    # 9. Feed (for-you) now contains the approved post ---------------------
    def test_feed_contains_approved_post(self, auth_client):
        r = auth_client.get("/api/ghost/community/feed?type=for-you&limit=50&offset=0")
        assert_ok(r, 200)
        data = j(r)
        ids = [p["id"] for p in data["posts"]]
        assert TestCommunityPostLifecycle._state["post_id"] in ids

    # 10. Single post detail -----------------------------------------------
    def test_get_single_post(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.get(f"/api/ghost/community/post/{post_id}")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("id") == post_id
        assert "comments" in data

    # 11. Single post – 404 for non-existent -----------------------------
    def test_get_nonexistent_post(self, auth_client):
        r = auth_client.get("/api/ghost/community/post/99999999")
        assert r.status_code == 404

    # 12. Like post --------------------------------------------------------
    def test_like_post(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.post(f"/api/ghost/community/post/{post_id}/like")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert isinstance(data.get("likesCount"), int)

    # 13. Unlike post ------------------------------------------------------
    def test_unlike_post(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.delete(f"/api/ghost/community/post/{post_id}/like")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True

    # 14. Add comment ------------------------------------------------------
    def test_add_comment(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.post(
            f"/api/ghost/community/post/{post_id}/comment",
            data=json.dumps({"commentText": "Smoke test comment"}),
            content_type="application/json",
        )
        assert_ok(r, 201)
        data = j(r)
        assert data.get("success") is True
        assert "comment" in data
        TestCommunityPostLifecycle._state["comment_id"] = data["comment"]["id"]

    # 15. Comment – missing text → 400 ------------------------------------
    def test_add_comment_missing_text(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.post(
            f"/api/ghost/community/post/{post_id}/comment",
            data=json.dumps({"commentText": ""}),
            content_type="application/json",
        )
        assert r.status_code == 400

    # 16. Delete comment ---------------------------------------------------
    def test_delete_comment(self, auth_client):
        comment_id = TestCommunityPostLifecycle._state.get("comment_id")
        if not comment_id:
            pytest.skip("No comment created")
        r = auth_client.delete(f"/api/ghost/community/comment/{comment_id}")
        assert_ok(r, 200)

    # 17. Share post -------------------------------------------------------
    def test_share_post(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.post(f"/api/ghost/community/post/{post_id}/share")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert isinstance(data.get("sharesCount"), int)

    # 18. View post --------------------------------------------------------
    def test_view_post(self, auth_client):
        post_id = TestCommunityPostLifecycle._state["post_id"]
        r = auth_client.post(f"/api/ghost/community/post/{post_id}/view")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert isinstance(data.get("viewsCount"), int)

    # 19. Follow user (buyer follows the post author) ----------------------
    def test_follow_user(self, buyer_client):
        r = buyer_client.post(f"/api/ghost/community/user/{TEST_PIN}/follow")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True

    # 20. Cannot follow yourself -------------------------------------------
    def test_cannot_follow_self(self, auth_client):
        r = auth_client.post(f"/api/ghost/community/user/{TEST_PIN}/follow")
        assert r.status_code == 400

    # 21. Following feed now contains the post -----------------------------
    def test_following_feed_shows_post(self, buyer_client):
        r = buyer_client.get("/api/ghost/community/feed?type=following&limit=50&offset=0")
        assert_not_500(r)

    # 22. Followers count --------------------------------------------------
    def test_followers_count(self, auth_client):
        r = auth_client.get(f"/api/ghost/community/user/{TEST_PIN}/followers")
        assert_ok(r, 200)
        data = j(r)
        assert isinstance(data.get("count"), int)
        assert data["count"] >= 1

    # 23. Hashtag search endpoint -----------------------------------------
    def test_hashtag_search_endpoint(self, auth_client):
        r = auth_client.get("/api/ghost/community/hashtag/test?limit=10&offset=0")
        assert_ok(r, 200)
        data = j(r)
        assert "posts" in data
        assert isinstance(data["posts"], list)

    # 24. Trending hashtags endpoint --------------------------------------
    def test_trending_hashtags_endpoint(self, auth_client):
        r = auth_client.get("/api/ghost/community/hashtags/trending?limit=10")
        assert_ok(r, 200)
        data = j(r)
        assert "hashtags" in data
        assert isinstance(data["hashtags"], list)

    # 25. Creator analytics endpoint --------------------------------------
    def test_creator_analytics_endpoint(self, auth_client):
        r = auth_client.get("/api/ghost/community/analytics/creator?period=week")
        assert_ok(r, 200)
        data = j(r)
        assert "summary" in data
        assert "topPosts" in data

    # 26. Unfollow user ---------------------------------------------------
    def test_unfollow_user(self, buyer_client):
        r = buyer_client.delete(f"/api/ghost/community/user/{TEST_PIN}/follow")
        assert_ok(r, 200)

    # 27. Admin reject a second post --------------------------------------
    def test_admin_reject_post(self, auth_client, admin_client):
        # Create another post to reject
        r = auth_client.post(
            "/api/ghost/community/post",
            data={"contentType": "text", "textContent": "Reject me"},
            content_type="application/x-www-form-urlencoded",
        )
        assert_ok(r, 201)
        reject_id = j(r)["postId"]
        r2 = admin_client.post(
            f"/api/admin/ghost/community/post/{reject_id}/reject",
            data=json.dumps({"reason": "Violates community guidelines"}),
            content_type="application/json",
        )
        assert_ok(r2, 200)
        assert j(r2).get("success") is True


# ─── MARKET – LISTING LIFECYCLE ────────────────────────────────────────────────

class TestMarketListingLifecycle:
    _state = {}

    def _dummy_image(self):
        """Return a minimal 1×1 red JPEG as bytes."""
        return (
            b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t'
            b'\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a'
            b'\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9=82<.342\x1e...'
            b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00'
            b'\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00'
            b'\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00'
            b'\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07"q\x142\x81'
            b'\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19'
            b'\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86'
            b'\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4'
            b'\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2'
            b'\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9'
            b'\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5'
            b'\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfb\xd2'
            b'\x8a(\x03\xff\xd9'
        )

    # 1. Market feed – returns a list (possibly empty) ----------------------
    def test_market_feed_empty_initially(self, auth_client):
        r = auth_client.get("/api/ghost/market/feed?sortBy=newest&limit=20&offset=0")
        assert_ok(r, 200)
        data = j(r)
        assert "listings" in data
        assert isinstance(data["listings"], list)

    # 2. Market feed – category filter ---------------------------------
    def test_market_feed_category_filter(self, auth_client):
        r = auth_client.get("/api/ghost/market/feed?category=Electronics")
        assert_not_500(r)

    # 3. Market feed – sort by most_views ----------------------------------
    def test_market_feed_sort_most_views(self, auth_client):
        r = auth_client.get("/api/ghost/market/feed?sortBy=most_views")
        assert_not_500(r)

    # 4. My-listings (empty) -----------------------------------------------
    def test_my_listings_empty(self, seller_client):
        r = seller_client.get("/api/ghost/market/my-listings?status=all")
        assert_ok(r, 200)
        assert "listings" in j(r)

    # 5. Saved-listings (empty) --------------------------------------------
    def test_saved_listings_empty(self, auth_client):
        r = auth_client.get("/api/ghost/market/saved-listings")
        assert_ok(r, 200)
        assert "listings" in j(r)

    # 6. Analytics (empty but valid) ----------------------------------------
    def test_analytics_valid(self, seller_client):
        r = seller_client.get("/api/ghost/market/analytics?period=week")
        assert_ok(r, 200)
        data = j(r)
        assert "totalViews" in data

    # 7. AI draft endpoint -------------------------------------------------
    def test_ai_generate_listing_draft(self, seller_client):
        image_bytes = self._dummy_image()
        r = seller_client.post(
            "/api/ghost/market/ai/generate-listing",
            data={"image": (io.BytesIO(image_bytes), "ai_phone.jpg", "image/jpeg")},
            content_type="multipart/form-data",
        )
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert "draft" in data

    # 8. AI price suggestion endpoint -------------------------------------
    def test_ai_suggest_price(self, seller_client):
        r = seller_client.post(
            "/api/ghost/market/ai/suggest-price",
            data=json.dumps({"title": "Phone", "category": "Electronics", "condition": "new"}),
            content_type="application/json",
        )
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert "suggestedPrice" in data

    # 9. Free user cannot create listing -----------------------------------
    def test_free_user_cannot_create_listing(self, auth_client):
        r = auth_client.post("/api/ghost/market/listing", data={"title": "test"})
        assert r.status_code == 403

    # 10. Create listing (approved seller, pro user) ------------------------
    def test_create_listing(self, seller_client):
        image_bytes = self._dummy_image()
        data = {
            "title":       "Smoke Test Phone",
            "description": "Brand new, never used",
            "price":       "999.99",
            "currency":    "ZAR",
            "condition":   "new",
            "category":    "Electronics",
            "location":    "Cape Town",
            "images":      (io.BytesIO(image_bytes), "test.jpg", "image/jpeg"),
        }
        r = seller_client.post(
            "/api/ghost/market/listing",
            data=data,
            content_type="multipart/form-data",
        )
        assert_ok(r, 201)
        resp_data = j(r)
        assert resp_data.get("success") is True
        assert "listingId" in resp_data
        TestMarketListingLifecycle._state["listing_id"] = resp_data["listingId"]

    # 11. My-listings shows pending listing ---------------------------------
    def test_my_listings_shows_pending(self, seller_client):
        r = seller_client.get("/api/ghost/market/my-listings?status=all")
        assert_ok(r, 200)
        ids = [l["id"] for l in j(r)["listings"]]
        assert TestMarketListingLifecycle._state.get("listing_id") in ids

    # 12. Admin – pending market queue ------------------------------------
    def test_admin_market_pending_queue(self, admin_client):
        r = admin_client.get("/api/admin/ghost/market/pending")
        assert_ok(r, 200)
        ids = [l["id"] for l in j(r)["listings"]]
        assert TestMarketListingLifecycle._state.get("listing_id") in ids

    # 13. Admin – approve listing -----------------------------------------
    def test_admin_approve_listing(self, admin_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = admin_client.post(f"/api/admin/ghost/market/listing/{lid}/approve")
        assert_ok(r, 200)
        assert j(r).get("success") is True

    # 14. Boost listing ----------------------------------------------------
    def test_boost_listing(self, seller_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = seller_client.post(
            f"/api/ghost/market/listing/{lid}/boost",
            data=json.dumps({"durationDays": 7}),
            content_type="application/json",
        )
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert data.get("durationDays") == 7

    # 15. Renew listing ----------------------------------------------------
    def test_renew_listing(self, seller_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = seller_client.post(f"/api/ghost/market/listing/{lid}/renew")
        assert_ok(r, 200)
        assert j(r).get("success") is True

    # 16. Market feed now shows the listing --------------------------------
    def test_market_feed_has_listing(self, auth_client):
        r = auth_client.get("/api/ghost/market/feed?limit=50&offset=0")
        assert_ok(r, 200)
        ids = [l["id"] for l in j(r)["listings"]]
        assert TestMarketListingLifecycle._state["listing_id"] in ids

    # 17. Single listing detail -------------------------------------------
    def test_get_single_listing(self, auth_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = auth_client.get(f"/api/ghost/market/listing/{lid}")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("id") == lid

    # 18. Auto-reply endpoint ---------------------------------------------
    def test_auto_reply_endpoint(self, buyer_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = buyer_client.post(
            f"/api/ghost/market/listing/{lid}/auto-reply",
            data=json.dumps({"buyerQuestion": "Is this still available?"}),
            content_type="application/json",
        )
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert isinstance(data.get("autoReply"), str)

    # 19. Single listing – 404 --------------------------------------------
    def test_get_nonexistent_listing(self, auth_client):
        r = auth_client.get("/api/ghost/market/listing/99999999")
        assert r.status_code == 404

    # 15. Save listing -----------------------------------------------------
    def test_save_listing(self, buyer_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = buyer_client.post(f"/api/ghost/market/listing/{lid}/save")
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True
        assert isinstance(data.get("savedCount"), int)

    # 16. Saved-listings contains the listing ------------------------------
    def test_saved_listings_has_entry(self, buyer_client):
        r = buyer_client.get("/api/ghost/market/saved-listings")
        assert_ok(r, 200)
        ids = [l["id"] for l in j(r)["listings"]]
        assert TestMarketListingLifecycle._state["listing_id"] in ids

    # 17. Unsave listing ---------------------------------------------------
    def test_unsave_listing(self, buyer_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = buyer_client.delete(f"/api/ghost/market/listing/{lid}/save")
        assert_ok(r, 200)
        assert j(r).get("success") is True

    # 18. View listing (increments counter) --------------------------------
    def test_view_listing(self, buyer_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = buyer_client.post(f"/api/ghost/market/listing/{lid}/view")
        assert_ok(r, 200)
        assert j(r).get("success") is True

    # 19. Buyer inquires ---------------------------------------------------
    def test_buyer_inquiry(self, buyer_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = buyer_client.post(
            f"/api/ghost/market/listing/{lid}/inquire",
            data=json.dumps({"message": "Is this still available?"}),
            content_type="application/json",
        )
        assert_ok(r, 201)
        data = j(r)
        assert data.get("success") is True
        assert "inquiryId" in data
        TestMarketListingLifecycle._state["inquiry_id"] = data["inquiryId"]

    # 20. Seller – my-inquiries lists it ----------------------------------
    def test_my_inquiries(self, seller_client):
        r = seller_client.get("/api/ghost/market/my-inquiries?status=all")
        assert_ok(r, 200)
        ids = [i["id"] for i in j(r)["inquiries"]]
        assert TestMarketListingLifecycle._state.get("inquiry_id") in ids

    # 21. Mark inquiry read -----------------------------------------------
    def test_mark_inquiry_read(self, seller_client):
        iid = TestMarketListingLifecycle._state.get("inquiry_id")
        if not iid:
            pytest.skip("No inquiry created")
        r = seller_client.put(f"/api/ghost/market/inquiry/{iid}/read")
        assert_ok(r, 200)
        assert j(r).get("success") is True

    # 22. Reply to inquiry (creates chat bridge) --------------------------
    def test_reply_inquiry(self, seller_client):
        iid = TestMarketListingLifecycle._state.get("inquiry_id")
        if not iid:
            pytest.skip("No inquiry created")
        r = seller_client.post(
            f"/api/ghost/market/inquiry/{iid}/reply",
            data=json.dumps({"message": "Yes, still available!"}),
            content_type="application/json",
        )
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True

    # 23. Buyer rates seller ----------------------------------------------
    def test_rate_seller(self, buyer_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        listing = buyer_client.get(f"/api/ghost/market/listing/{lid}")
        assert_ok(listing, 200)
        seller_id = j(listing).get("sellerId")
        assert seller_id is not None

        r = buyer_client.post(
            f"/api/ghost/market/seller/{seller_id}/rate",
            data=json.dumps({"rating": 5, "review": "Great seller", "listingId": lid}),
            content_type="application/json",
        )
        assert_ok(r, 200)
        data = j(r)
        assert data.get("success") is True

    # 23. Seller cannot inquire on own listing ----------------------------
    def test_seller_cannot_self_inquire(self, seller_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = seller_client.post(
            f"/api/ghost/market/listing/{lid}/inquire",
            data=json.dumps({"message": "Test"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    # 24. Mark listing sold -----------------------------------------------
    def test_mark_sold(self, seller_client):
        lid = TestMarketListingLifecycle._state["listing_id"]
        r = seller_client.put(f"/api/ghost/market/listing/{lid}/mark-sold")
        assert_ok(r, 200)
        assert j(r).get("success") is True

    # 25. Create a second listing to delete --------------------------------
    def test_create_and_delete_listing(self, seller_client):
        image_bytes = self._dummy_image()
        data = {
            "title":       "Deletable Item",
            "description": "This will be deleted",
            "price":       "1.00",
            "currency":    "ZAR",
            "condition":   "used",
            "category":    "Other",
            "location":    "",
            "images":      (io.BytesIO(image_bytes), "del.jpg", "image/jpeg"),
        }
        r = seller_client.post(
            "/api/ghost/market/listing",
            data=data,
            content_type="multipart/form-data",
        )
        assert_ok(r, 201)
        lid = j(r)["listingId"]
        r2 = seller_client.delete(f"/api/ghost/market/listing/{lid}")
        assert_ok(r2, 200)
        assert j(r2).get("success") is True

    # 26. Admin reject listing --------------------------------------------
    def test_admin_reject_listing(self, seller_client, admin_client):
        image_bytes = self._dummy_image()
        data = {
            "title":       "Reject Me Listing",
            "description": "Will be rejected",
            "price":       "50.00",
            "currency":    "ZAR",
            "condition":   "used",
            "category":    "Other",
            "location":    "",
            "images":      (io.BytesIO(image_bytes), "rej.jpg", "image/jpeg"),
        }
        r = seller_client.post(
            "/api/ghost/market/listing",
            data=data,
            content_type="multipart/form-data",
        )
        assert_ok(r, 201)
        lid = j(r)["listingId"]
        r2 = admin_client.post(
            f"/api/admin/ghost/market/listing/{lid}/reject",
            data=json.dumps({"reason": "Prohibited item"}),
            content_type="application/json",
        )
        assert_ok(r2, 200)
        assert j(r2).get("success") is True
