import io
import uuid
import requests

BASE_URL = "http://127.0.0.1:5000"


def get_csrf(session):
    return session.get(f"{BASE_URL}/api/csrf-token").json().get("csrf_token")


def main():
    user = requests.Session()
    email = f"mobile_m2_{uuid.uuid4().hex[:8]}@zeuschat.test"

    r = user.post(f"{BASE_URL}/api/start-signup", json={"email": email})
    print("start_signup", r.status_code)

    r = user.post(f"{BASE_URL}/api/verify-otp", json={"email": email, "otp": "123456"})
    print("verify_otp", r.status_code)
    payload = r.json() if r.ok else {}
    zeus_pin = payload.get("zeus_pin")
    print("zeus_pin", zeus_pin)

    form = {
        "full_name": "Mobile M2 Audit",
        "email": email,
        "zeus_pin": zeus_pin,
        "password": "AuditPending234",
        "document_type": "national_id",
    }
    files = {
        "id_document": ("id_doc.jpg", io.BytesIO(b"fake-id"), "image/jpeg"),
        "selfie": ("selfie.jpg", io.BytesIO(b"fake-selfie"), "image/jpeg"),
    }
    r = user.post(
        f"{BASE_URL}/api/complete-registration-with-kyc",
        data=form,
        files=files,
        headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"},
    )
    body = r.json() if "application/json" in r.headers.get("content-type", "") else {}
    print("complete_registration", r.status_code, body.get("redirect"))

    csrf = get_csrf(user)
    r = user.post(
        f"{BASE_URL}/api/user/admin-messages",
        json={"message": "Please approve my account"},
        headers={"X-CSRF-Token": csrf},
    )
    print("send_text_to_admin", r.status_code)

    csrf = get_csrf(user)
    attachment = {
        "file": ("audit-proof.pdf", io.BytesIO(b"%PDF-1.4\n%fake-data"), "application/pdf"),
    }
    r = user.post(
        f"{BASE_URL}/api/user/admin-messages",
        files=attachment,
        headers={"X-CSRF-Token": csrf},
    )
    print("send_attachment_to_admin", r.status_code)

    admin = requests.Session()
    csrf = get_csrf(admin)
    r = admin.post(
        f"{BASE_URL}/admin/api/login",
        json={"username": "admin", "password": "Admin1234"},
        headers={"X-CSRF-Token": csrf},
    )
    print("admin_login", r.status_code)

    r = admin.get(f"{BASE_URL}/admin/api/messages/users")
    users = r.json().get("users", []) if r.ok else []
    user_row = next((u for u in users if u.get("zeus_pin") == zeus_pin), None)
    target_user_id = user_row.get("user_id") if user_row else None
    print("target_user_id", target_user_id)

    has_text = False
    has_attachment = False
    attachment_url = None

    if target_user_id:
        r = admin.get(f"{BASE_URL}/admin/api/messages/{target_user_id}")
        messages = r.json().get("messages", []) if r.ok else []
        for m in messages:
            msg = m.get("message") or ""
            if "Please approve my account" in msg:
                has_text = True
            if "/uploads/admin_messages/" in msg and "audit-proof.pdf" in msg:
                has_attachment = True
                start = msg.find('/uploads/admin_messages/')
                end = msg.find('"', start)
                attachment_url = msg[start:end] if start != -1 and end != -1 else None

    print("admin_has_text", has_text)
    print("admin_has_attachment", has_attachment)

    if attachment_url:
        download = admin.get(f"{BASE_URL}{attachment_url}")
        print("admin_attachment_download", download.status_code, len(download.content) > 0)
    else:
        print("admin_attachment_download", None, False)

    if target_user_id:
        r = admin.put(f"{BASE_URL}/admin/api/users/{target_user_id}/approve", json={})
        print("admin_approve", r.status_code)

    r = user.get(f"{BASE_URL}/api/user/approval-status")
    status_payload = r.json() if r.ok else {}
    print("user_approval_status", r.status_code, status_payload.get("status"))


if __name__ == "__main__":
    main()
