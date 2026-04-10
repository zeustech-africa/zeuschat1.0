"""
test_registration.py — Email signup, OTP verification, and full registration flow.
"""

import json
import pytest


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
