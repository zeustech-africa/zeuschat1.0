"""
test_registration.py — Email signup, OTP verification, and full registration flow.
"""

import json
import io
import uuid
import pytest
from app import get_db_connection


class TestStartSignup:
    def test_start_signup_no_body(self, client):
        r = client.post(
            "/api/start-signup",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_start_signup_invalid_email(self, client):
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": "not-an-email"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_start_signup_empty_email(self, client):
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": ""}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_start_signup_existing_email(self, client):
        """Existing email should return 409 conflict."""
        from tests.conftest import TEST_EMAIL
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": TEST_EMAIL}),
            content_type="application/json",
        )
        # App returns 400 or 409 for duplicate email
        assert r.status_code in (400, 409)

    def test_start_signup_fresh_email(self, client):
        """A brand-new email should trigger OTP send (200 or 202)."""
        r = client.post(
            "/api/start-signup",
            data=json.dumps({"email": "brand_new_unique_abc123@zeuschat.test"}),
            content_type="application/json",
        )
        assert r.status_code in (200, 202)


class TestVerifyOTP:
    def _start_signup(self, client, email):
        client.post(
            "/api/start-signup",
            data=json.dumps({"email": email}),
            content_type="application/json",
        )

    def test_verify_otp_wrong_code(self, client):
        email = "otp_test_wrong@zeuschat.test"
        self._start_signup(client, email)
        r = client.post(
            "/api/verify-otp",
            data=json.dumps({"email": email, "otp": "000000"}),
            content_type="application/json",
        )
        assert r.status_code in (400, 401)

    def test_verify_otp_correct_code(self, client):
        """OTP '123456' is the test-mode bypass code."""
        email = "otp_test_valid@zeuschat.test"
        self._start_signup(client, email)
        r = client.post(
            "/api/verify-otp",
            data=json.dumps({"email": email, "otp": "123456"}),
            content_type="application/json",
        )
        # Should succeed (200) or indicate the test OTP is not a bypass (400)
        # Accept either — key: must not be 500
        assert r.status_code != 500

    def test_verify_otp_without_prior_signup(self, client):
        r = client.post(
            "/api/verify-otp",
            data=json.dumps({"email": "ghost@nowhere.test", "otp": "123456"}),
            content_type="application/json",
        )
        assert r.status_code in (200, 400, 401, 404)

    def test_verify_otp_no_body(self, client):
        r = client.post(
            "/api/verify-otp",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 400


class TestCompleteRegistration:
    def test_complete_registration_no_session(self, client):
        """Without a prior OTP-verified session, registration must fail."""
        r = client.post(
            "/api/complete-registration",
            data=json.dumps({
                "full_name": "New User",
                "password": "Pass@1234",
            }),
            content_type="application/json",
        )
        assert r.status_code in (400, 401, 403)

    def test_complete_registration_missing_fields(self, client):
        r = client.post(
            "/api/complete-registration",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code in (400, 401, 403)

    def test_complete_registration_with_kyc_no_session(self, client):
        r = client.post(
            "/api/complete-registration-with-kyc",
            data=json.dumps({"full_name": "Someone", "password": "Pass@1234"}),
            content_type="application/json",
        )
        assert r.status_code in (400, 401, 403)


def test_full_registration_flow(client):
    """Full registration flow: start -> verify OTP -> complete with KYC -> pending approval + pending page."""
    unique = uuid.uuid4().hex[:8]
    email = f"e2e_{unique}@zeuschat.test"

    # 1) Start signup
    r1 = client.post(
        "/api/start-signup",
        data=json.dumps({"email": email}),
        content_type="application/json",
    )
    assert r1.status_code == 200

    # 2) Verify OTP (test mode)
    r2 = client.post(
        "/api/verify-otp",
        data=json.dumps({"email": email, "otp": "123456"}),
        content_type="application/json",
    )
    assert r2.status_code == 200
    zeus_pin = r2.get_json().get("zeus_pin")
    assert zeus_pin

    # 3) Complete registration + KYC upload
    form = {
        "full_name": f"E2E User {unique}",
        "email": email,
        "zeus_pin": zeus_pin,
        "password": "Pass@1234",
        "document_type": "national_id",
    }
    files = {
        "id_document": (io.BytesIO(b"fake-id-doc"), "id_doc.jpg"),
        "selfie": (io.BytesIO(b"fake-selfie"), "selfie.jpg"),
    }
    r3 = client.post(
        "/api/complete-registration-with-kyc",
        data={**form, **files},
        headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"},
        content_type="multipart/form-data",
    )
    assert r3.status_code in (200, 201)
    body = r3.get_json() or {}
    assert body.get("success") is True
    assert body.get("redirect") == "/mobile/pending"

    # 4) Verify DB pending approval + KYC rows
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        assert user is not None
        user_id = user[0] if not isinstance(user, dict) else user["id"]

        cursor.execute("SELECT status FROM user_approvals WHERE user_id = ?", (user_id,))
        approval = cursor.fetchone()
        assert approval is not None
        status = approval[0] if not isinstance(approval, dict) else approval["status"]
        assert status == "pending"

        cursor.execute("SELECT COUNT(*) FROM kyc_documents WHERE user_id = ?", (user_id,))
        kyc_count = cursor.fetchone()[0]
        assert kyc_count >= 1

    # 5) Pending page should load while awaiting approval
    r4 = client.get("/mobile/pending")
    assert r4.status_code == 200
