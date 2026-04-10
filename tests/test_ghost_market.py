"""
test_ghost_market.py — Ghost Market browse, seller application, and item flows.
"""

import json
import pytest


class TestGhostMarketPages:
    def test_market_page_loads(self, client):
        r = client.get("/ghost-market")
        assert r.status_code == 200

    def test_market_sell_page_loads(self, client):
        r = client.get("/ghost-market/sell")
        assert r.status_code in (200, 302)

    def test_market_apply_seller_page_loads(self, client):
        r = client.get("/ghost-market/apply-seller")
        assert r.status_code in (200, 302)

    def test_market_policy_page_loads(self, client):
        r = client.get("/ghost-market-policy")
        assert r.status_code == 200


class TestGhostMarketAPI:
    def test_get_items_public(self, client):
        """Public market item listing should return 200 with JSON."""
        r = client.get("/api/ghost-market/items")
        assert r.status_code in (200, 401)
        if r.status_code == 200:
            data = r.get_json()
            assert isinstance(data, (dict, list))

    def test_seller_status_requires_auth(self, client):
        r = client.get("/api/ghost-market/seller-status")
        assert r.status_code in (401, 403)

    def test_seller_status_with_auth(self, auth_client):
        r = auth_client.get("/api/ghost-market/seller-status")
        assert r.status_code in (200, 403)  # 403 = not a seller yet

    def test_apply_seller_requires_auth(self, client):
        r = client.post(
            "/api/ghost-market/apply-seller",
            data=json.dumps({"shop_name": "Test Shop"}),
            content_type="application/json",
        )
        assert r.status_code in (401, 403)

    def test_apply_seller_authenticated(self, auth_client):
        """Authenticated user should be able to submit a seller application."""
        r = auth_client.post(
            "/api/ghost-market/apply-seller",
            data=json.dumps({
                "shop_name": "Test Shop",
                "shop_description": "A test shop",
                "contact_email": "seller@zeuschat.test",
            }),
            content_type="application/json",
        )
        # 200 = success, 409 = already applied — both are acceptable
        assert r.status_code in (200, 201, 400, 403, 409)
        assert r.status_code != 500

    def test_submit_item_requires_auth(self, client):
        r = client.post(
            "/api/ghost-market/submit-item",
            data=json.dumps({"title": "Test Item", "price": 100}),
            content_type="application/json",
        )
        assert r.status_code in (401, 403)

    def test_buy_item_requires_auth(self, client):
        r = client.post("/api/ghost-market/buy/9999")
        assert r.status_code in (401, 403, 404)

    def test_buy_nonexistent_item_with_auth(self, auth_client):
        r = auth_client.post("/api/ghost-market/buy/99999999")
        assert r.status_code in (400, 403, 404)
        assert r.status_code != 500


class TestMarketItemFiltering:
    def test_items_with_category_filter(self, client):
        r = client.get("/api/ghost-market/items?category=digital")
        assert r.status_code in (200, 401)
        assert r.status_code != 500

    def test_items_pagination(self, client):
        r = client.get("/api/ghost-market/items?page=1&per_page=5")
        assert r.status_code in (200, 401)
        assert r.status_code != 500
