# ZeusChat Admin Control Room — Deployment Checklist

> **Deployment target:** Render.com — `https://zeuschat1-0-ixax.onrender.com`  
> **Stack:** Flask + Flask-SocketIO + SQLite (WAL) + PayFast  
> **Admin modules added in this release:** `admin_middleware.py`, `admin_routes.py`, `payment_routes.py`, `templates/admin/`

---

## 1. Pre-Deployment Checklist

### 1.1 Code Verification

Run these checks locally before pushing to Render:

```bash
# Validate Python syntax for all new/modified backend files
python3 -m py_compile app.py && echo "app.py OK"
python3 -m py_compile admin_middleware.py && echo "admin_middleware.py OK"
python3 -m py_compile admin_routes.py && echo "admin_routes.py OK"
python3 -m py_compile payment_routes.py && echo "payment_routes.py OK"
```

```bash
# Confirm all required admin templates exist
ls templates/admin/login.html templates/admin/dashboard.html && echo "Admin templates OK"

# Confirm pending-approval template exists (user-facing)
ls templates/pending-approval.html 2>/dev/null || echo "⚠️  WARNING: templates/pending-approval.html missing"
```

```bash
# Check that no leftover sandbox PayFast credentials are hardcoded
grep -n "10000100\|46f0cd694581a" payment_routes.py && echo "⚠️  Sandbox defaults still present — override via env vars before going live"
```

### 1.2 Git Status

```bash
# Review all changed files before committing
git status
git diff --stat

# Commit the Admin Control Room release
git add app.py admin_middleware.py admin_routes.py payment_routes.py \
        templates/admin/login.html templates/admin/dashboard.html \
        login.html
git commit -m "feat: Admin Control Room — approval flow, PayFast payments, admin dashboard"
git push origin main
```

---

## 2. Environment Variables to Set on Render

Go to **Render Dashboard → Your Service → Environment** and add/verify the following variables:

### 2.1 Required — Core App

| Variable | Value | Notes |
|---|---|---|
| `DATABASE_PATH` | `/opt/render/project/src/zeuschat.db` | Absolute path inside Render container |
| `SECRET_KEY` | *(generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`)* | Must be stable across deploys — store the value |

### 2.2 Required — PayFast (Production)

| Variable | Value | Notes |
|---|---|---|
| `PAYFAST_MERCHANT_ID` | *(your live merchant ID from PayFast dashboard)* | Sandbox default: `10000100` |
| `PAYFAST_MERCHANT_KEY` | *(your live merchant key)* | Sandbox default: `46f0cd694581a` |
| `PAYFAST_PASSPHRASE` | *(your PayFast passphrase, if set)* | Leave blank if not configured in PayFast |
| `PAYFAST_TEST_MODE` | `false` | Set `true` to keep sandbox mode active |
| `BASE_URL` | `https://zeuschat1-0-ixax.onrender.com` | Used for PayFast return/cancel/notify URLs |

### 2.3 Optional — Email OTP (when ready)

| Variable | Value |
|---|---|
| `MAIL_SERVER` | `smtp.gmail.com` |
| `MAIL_PORT` | `587` |
| `MAIL_USERNAME` | *(sender email address)* |
| `MAIL_PASSWORD` | *(app-specific password)* |

> **Note:** If these are not set, the app will fall back to logging OTPs to the server console (test mode behaviour).

---

## 3. Render Deployment Steps

### 3.1 Via Git Push (recommended)

```bash
# Push triggers automatic redeploy if auto-deploy is enabled on Render
git push origin main
```

Then monitor from the **Render Dashboard → Logs** tab.

### 3.2 Manual Deploy

1. Go to `https://dashboard.render.com`
2. Select the **zeuschat1.0** web service
3. Click **Manual Deploy → Deploy latest commit**
4. Watch the build log for these success markers:

```
✅ Admin tables already exist          ← (first deploy: "Running admin migrations...")
✅ Admin and payment routes registered
✅ Admin Control Room: /admin/login
```

### 3.3 Expected Startup Log (healthy deploy)

```
🔑 Loaded existing secret key from .secret_key
✅ Database initialized with WAL mode enabled
✅ Admin migrations completed successfully!    ← first deploy only
✅ Admin and payment routes registered
 * Running on http://0.0.0.0:10000
```

---

## 4. Post-Deployment Verification Tests

Run these from a browser or terminal after the deploy is live.

### 4.1 Health Check

```bash
curl -s https://zeuschat1-0-ixax.onrender.com/api/health | python3 -m json.tool
# Expected: {"status": "healthy", ...}
```

### 4.2 Admin Login Page

- [ ] Open `https://zeuschat1-0-ixax.onrender.com/admin/login`
- [ ] Page loads with gradient dark theme (no 404 / no blank screen)
- [ ] Enter credentials: `superadmin` / `ZeusAdmin2026!`
- [ ] Should redirect to `/admin/dashboard`
- [ ] Dashboard shows 5 tabs: Dashboard, Users, Approvals, Payments, Messages

> **Security note:** Change the default admin password immediately after first login.

### 4.3 User Approval Flow

- [ ] Register a new test account via `https://zeuschat1-0-ixax.onrender.com`
- [ ] Complete OTP verification
- [ ] Try to log in — should redirect to `/pending-approval` (not chat)
- [ ] In admin dashboard → **Approvals** tab → approve the test user
- [ ] Log in as test user again — should now reach `/dashboard` (chat)

### 4.4 Approval Status API

```bash
# Replace <session_cookie> with a valid logged-in session from browser devtools
curl -s -b "session=<session_cookie>" \
  https://zeuschat1-0-ixax.onrender.com/api/user/approval-status \
  | python3 -m json.tool
# Expected: {"status": "pending" | "approved" | "rejected"}
```

### 4.5 Admin API Smoke Tests

```bash
BASE="https://zeuschat1-0-ixax.onrender.com"

# Login and capture cookie
curl -s -c /tmp/admin_cookie.txt \
  -X POST "$BASE/admin/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin","password":"ZeusAdmin2026!"}' \
  | python3 -m json.tool

# Stats endpoint
curl -s -b /tmp/admin_cookie.txt "$BASE/admin/api/stats" | python3 -m json.tool

# Pending approvals list
curl -s -b /tmp/admin_cookie.txt "$BASE/admin/api/approvals/pending" | python3 -m json.tool

# Pending payments list
curl -s -b /tmp/admin_cookie.txt "$BASE/admin/api/payments/pending" | python3 -m json.tool
```

### 4.6 PayFast Payment Flow (Sandbox)

- [ ] Ensure `PAYFAST_TEST_MODE=true` in env vars for testing
- [ ] Log in as an approved user
- [ ] Initiate a payment via the app
- [ ] PayFast sandbox page should load (`sandbox.payfast.co.za`)
- [ ] Complete test payment using [PayFast sandbox test cards](https://developers.payfast.co.za/docs#testing)
- [ ] Return URL `/payment/success` should render success page
- [ ] Admin dashboard → Payments tab should show the completed payment

---

## 5. Troubleshooting Guide

### 5.1 `ModuleNotFoundError: No module named 'admin_middleware'`

**Cause:** The three new Python files are not in the same directory as `app.py`, or git did not include them.

```bash
# Verify files are committed and on the remote
git log --oneline -5
git show HEAD --stat | grep -E "admin_middleware|admin_routes|payment_routes"
```

If missing, add and push them:

```bash
git add admin_middleware.py admin_routes.py payment_routes.py
git commit -m "fix: include admin backend modules"
git push
```

---

### 5.2 Admin Login Returns 401 "Invalid credentials"

**Cause 1:** The default admin was created with the old hash from `init_db()` (password `admin123` or similar) rather than `ZeusAdmin2026!`.

**Fix:** Reset the admin password directly in the database. SSH into the Render shell (**Dashboard → Shell** tab):

```python
python3 - <<'EOF'
import sqlite3, hashlib, os
db = os.environ.get('DATABASE_PATH', 'zeuschat.db')
new_pw = 'ZeusAdmin2026!'
h = hashlib.sha256(new_pw.encode()).hexdigest()
conn = sqlite3.connect(db)
conn.execute("UPDATE admin_users SET password_hash=? WHERE username='superadmin'", (h,))
conn.commit()
conn.close()
print("Password reset OK. Hash:", h)
EOF
```

**Cause 2:** `SECRET_KEY` env var changed between deploys, invalidating all existing sessions.  
**Fix:** Set `SECRET_KEY` to the same stable value in Render env vars on every redeploy.

---

### 5.3 `/pending-approval` Returns Jinja2 TemplateNotFound

**Cause:** `templates/pending-approval.html` does not exist.

**Fix:** Create the template. Minimal working version:

```html
<!DOCTYPE html>
<html>
<head><title>Pending Approval — ZeusChat</title></head>
<body style="font-family:sans-serif;text-align:center;padding:60px;background:#0f3460;color:#fff;">
  <h1>⏳ Account Pending Approval</h1>
  <p>Your registration is under review by the ZeusChat admin team.</p>
  <p>You will be notified once your account is approved.</p>
  <br>
  <a href="/login.html" style="color:#e94560;">← Back to Login</a>
</body>
</html>
```

```bash
# Save to correct path
git add templates/pending-approval.html
git commit -m "feat: add pending-approval template"
git push
```

---

### 5.4 PayFast ITN Webhook Fails (payment not marked complete)

**Cause 1:** `BASE_URL` env var is wrong — PayFast cannot reach the notify URL.  
**Fix:** Set `BASE_URL=https://zeuschat1-0-ixax.onrender.com` (no trailing slash).

**Cause 2:** Render free tier puts the service to sleep. PayFast ITN POST hits a sleeping instance.  
**Fix:** Upgrade to Render Starter plan ($7/mo) to prevent spin-down, or configure [UptimeRobot](https://uptimerobot.com) to ping `/api/health` every 5 minutes.

**Cause 3:** Signature mismatch — `PAYFAST_PASSPHRASE` mismatch between app and PayFast dashboard.  
**Fix:** In payfast.co.za merchant dashboard, check **Settings → Passphrase** matches `PAYFAST_PASSPHRASE` env var exactly (case-sensitive). If no passphrase is set in the dashboard, leave `PAYFAST_PASSPHRASE` blank.

---

### 5.5 Admin Dashboard Shows "Unauthorized" After Login

**Cause:** Session cookie not being sent because the browser blocks it (SameSite/Secure mismatch).

**Fix:** Ensure the Flask session cookie settings in `app.py` include:

```python
app.config['SESSION_COOKIE_SECURE'] = True    # HTTPS only
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

Verify by checking browser DevTools → Application → Cookies for the `session` cookie.

---

### 5.6 Existing Users Cannot Log In After Deployment

**Cause:** The admin migration auto-approves users who existed before admin tables were created. If migration ran before the database was accessible (e.g., `DATABASE_PATH` not set), the backfill may have failed.

**Fix:** Run manual backfill via Render Shell:

```python
python3 - <<'EOF'
import sqlite3, os
db = os.environ.get('DATABASE_PATH', 'zeuschat.db')
conn = sqlite3.connect(db)
conn.execute("""
  INSERT OR IGNORE INTO user_approvals (user_id, status, reviewed_at)
  SELECT id, 'approved', CURRENT_TIMESTAMP FROM users
""")
conn.commit()
rows = conn.execute("SELECT COUNT(*) FROM user_approvals WHERE status='approved'").fetchone()[0]
conn.close()
print(f"Approved users in DB: {rows}")
EOF
```

---

## 6. Default Admin Credentials

| Field | Value |
|---|---|
| URL | `https://zeuschat1-0-ixax.onrender.com/admin/login` |
| Username | `superadmin` |
| Default Password | `ZeusAdmin2026!` |

> ⚠️ **Change this password immediately after first login via the Render Shell** using the script in section 5.2.

---

## 7. Summary of New Routes Added

| Route | Method | Purpose |
|---|---|---|
| `/admin/login` | GET | Admin login page |
| `/admin/dashboard` | GET | Admin Control Room SPA |
| `/admin/api/login` | POST | Admin authenticate |
| `/admin/api/logout` | POST | Admin logout |
| `/admin/api/me` | GET | Current admin info |
| `/admin/api/stats` | GET | Dashboard stats |
| `/admin/api/users` | GET | All users list |
| `/admin/api/approvals/pending` | GET | Pending user approvals |
| `/admin/api/approvals/<id>/approve` | POST | Approve user |
| `/admin/api/approvals/<id>/reject` | POST | Reject user |
| `/admin/api/ban/<id>` | POST | Ban user |
| `/admin/api/payments/pending` | GET | Pending payments |
| `/admin/api/payments/<id>/approve` | POST | Approve payment |
| `/admin/api/payments/<id>/reject` | POST | Reject payment |
| `/admin/api/messages/users` | GET | Users with messages |
| `/admin/api/messages/send` | POST | Send admin message |
| `/admin/api/logs` | GET | Audit log |
| `/api/payment/request-unlock` | POST | User initiates payment |
| `/api/payfast-itn` | POST | PayFast webhook |
| `/payment/success` | GET | Payment success page |
| `/payment/cancel` | GET | Payment cancel page |
| `/pending-approval` | GET | User waiting room |
| `/api/user/approval-status` | GET | User polls own status |
| `/api/user/admin-messages` | GET/POST | User ↔ admin messaging |
