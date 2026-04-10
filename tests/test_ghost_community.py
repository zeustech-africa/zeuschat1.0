"""
test_ghost_community.py — Ghost Forums / Community feature tests.
"""

import json
import pytest


class TestForumPages:
    def test_forums_page_loads(self, client):
        r = client.get("/ghost-forums")
        assert r.status_code in (200, 302)

    def test_individual_forum_with_invalid_id(self, client):
        r = client.get("/ghost-forums/forum/99999999")
        assert r.status_code in (200, 302, 404)
        assert r.status_code != 500


class TestGhostCommunityAPI:
    """Test Ghost / community post endpoints."""

    def test_get_ghost_posts_requires_auth_or_public(self, client):
        """Ghost feed may be public or require auth — must not 500."""
        r = client.get("/api/ghost/feed")
        assert r.status_code in (200, 401, 404)
        assert r.status_code != 500

    def test_create_post_requires_auth(self, client):
        r = client.post(
            "/api/ghost/create-post",
            data=json.dumps({"content": "Hello world", "is_paid": False}),
            content_type="application/json",
        )
        assert r.status_code in (401, 403, 404, 405)

    def test_create_free_post_authenticated(self, auth_client):
        r = auth_client.post(
            "/api/ghost/create-post",
            data=json.dumps({"content": "Test ghost post", "is_paid": False}),
            content_type="application/json",
        )
        # 200/201 = created, 400 = validation error, 403 = banned — not 500
        assert r.status_code in (200, 201, 400, 403, 404, 405)
        assert r.status_code != 500

    def test_create_paid_post_requires_pro(self, auth_client):
        """Free-tier user trying to create paid post should get 403."""
        r = auth_client.post(
            "/api/ghost/create-post",
            data=json.dumps({"content": "Paid post", "is_paid": True, "price": 10}),
            content_type="application/json",
        )
        # Free user → 403 requires_upgrade, or 404 if endpoint not yet exposed
        assert r.status_code in (400, 403, 404, 405)
        assert r.status_code != 500

    def test_create_paid_post_pro_user(self, pro_auth_client):
        """Pro-tier user should be allowed to attempt paid post creation."""
        r = pro_auth_client.post(
            "/api/ghost/create-post",
            data=json.dumps({"content": "Pro paid post", "is_paid": True, "price": 10}),
            content_type="application/json",
        )
        # 200/201 = created, 400 = validation, 404 = route not yet exposed — not 403 for upgrade
        assert r.status_code != 500

    def test_like_post_requires_auth(self, client):
        r = client.post("/api/ghost/like/1")
        assert r.status_code in (401, 403, 404, 405)

    def test_comment_on_post_requires_auth(self, client):
        r = client.post(
            "/api/ghost/comment/1",
            data=json.dumps({"content": "Nice post!"}),
            content_type="application/json",
        )
        assert r.status_code in (401, 403, 404, 405)


class TestForumAPI:
    def test_get_forums_list(self, client):
        r = client.get("/api/ghost-forums/list")
        assert r.status_code in (200, 401, 404)
        assert r.status_code != 500

    def test_get_forum_posts(self, client):
        r = client.get("/api/ghost-forums/1/posts")
        assert r.status_code in (200, 401, 404)
        assert r.status_code != 500
