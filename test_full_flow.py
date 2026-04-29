#!/usr/bin/env python3
"""Test the complete mobile registration flow end-to-end"""
import requests
import json
import time
import sys

BASE = "http://127.0.0.1:8888"
session = requests.Session()

def test(step, func):
    try:
        result = func()
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}: {step}")
        return result
    except Exception as e:
        print(f"  ❌ FAIL: {step} - {e}")
        return False

def main():
    results = []
    
    print("\n=== MOBILE TEMPLATE ROUTES ===")
    for route in ["/mobile/email", "/mobile/otp", "/mobile/profile-create", 
                   "/mobile/kyc", "/mobile/pending", "/mobile/login",
                   "/mobile/chat", "/mobile/community", "/mobile/market",
                   "/mobile/settings", "/mobile/profile", "/mobile/add-contact"]:
        r = session.get(f"{BASE}{route}")
        results.append(("GET " + route, r.status_code == 200))
        status = "✅" if r.status_code == 200 else "❌"
        print(f"  {status} {route} -> {r.status_code}")
    
    print("\n=== API ENDPOINTS ===")
    
    # Test CSRF token
    r = session.get(f"{BASE}/api/csrf-token")
    results.append(("GET /api/csrf-token", r.status_code == 200))
    print(f"  {'✅' if r.status_code == 200 else '❌'} /api/csrf-token -> {r.status_code}")
    csrf_data = r.json()
    print(f"    csrf_token: {csrf_data.get('csrf_token', 'N/A')[:20]}...")
    
    # Test start signup
    test_email = f"test_{int(time.time())}@example.com"
    print(f"\n  Using email: {test_email}")
    r = session.post(f"{BASE}/api/start-signup", json={"email": test_email})
    results.append(("POST /api/start-signup", r.status_code == 200 and r.json().get("success")))
    print(f"  {'✅' if r.status_code == 200 and r.json().get('success') else '❌'} /api/start-signup -> {r.status_code}")
    print(f"    Response: {r.json()}")
    
    # The OTP is printed to server stdout. We need to query the DB to get it.
    import sqlite3
    conn = sqlite3.connect('zeuschat.db')
    c = conn.cursor()
    c.execute("SELECT otp FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1", (test_email,))
    row = c.fetchone()
    # Also check if user already exists
    c.execute("SELECT zeus_pin FROM users WHERE email = ?", (test_email,))
    existing_user = c.fetchone()
    conn.close()
    
    if existing_user:
        print(f"    ⚠️  User already exists in DB with PIN: {existing_user[0]}")
    
    if row:
        actual_otp = row[0]
        print(f"    Found OTP in DB: {actual_otp}")
    else:
        print(f"    ⚠️  No OTP found in DB for {test_email}")
        actual_otp = "000000"
    
    # Test verify OTP
    print(f"    Sending verify-otp with email={test_email}, otp={actual_otp}")
    r = session.post(f"{BASE}/api/verify-otp", json={"email": test_email, "otp": actual_otp})
    results.append(("POST /api/verify-otp", r.status_code == 200 and r.json().get("success")))
    print(f"  {'✅' if r.status_code == 200 and r.json().get('success') else '❌'} /api/verify-otp -> {r.status_code}")
    resp = r.json()
    print(f"    Response: {resp}")
    
    if resp.get("success"):
        zeus_pin = resp.get("zeus_pin")
        print(f"    Zeus PIN: {zeus_pin}")
    else:
        print(f"    ⚠️  Cannot continue - OTP verification failed")
        # Try to get existing zeus_pin from DB
        conn = sqlite3.connect('zeuschat.db')
        c = conn.cursor()
        c.execute("SELECT zeus_pin FROM users WHERE email = ?", (test_email,))
        row = c.fetchone()
        conn.close()
        if row:
            zeus_pin = row[0]
            print(f"    Found existing Zeus PIN in DB: {zeus_pin}")
        else:
            print("    ❌ Cannot proceed - no zeus_pin available")
            return
    
    # Test complete registration
    r = session.post(f"{BASE}/api/complete-registration", json={
        "zeus_pin": zeus_pin,
        "email": test_email,
        "full_name": "Test User",
        "password": "test123456",
        "profile_pic": ""
    })
    results.append(("POST /api/complete-registration", r.status_code == 200 and r.json().get("success")))
    print(f"  {'✅' if r.status_code == 200 and r.json().get('success') else '❌'} /api/complete-registration -> {r.status_code}")
    print(f"    Response: {r.json()}")
    
    # Test login
    r = session.post(f"{BASE}/api/login", json={
        "zeus_pin": zeus_pin,
        "password": "test123456"
    })
    results.append(("POST /api/login", r.status_code == 200 and r.json().get("success")))
    print(f"  {'✅' if r.status_code == 200 and r.json().get('success') else '❌'} /api/login -> {r.status_code}")
    resp = r.json()
    print(f"    Response: {json.dumps(resp, indent=4)}")
    
    if resp.get("success"):
        # Test approval status
        r = session.get(f"{BASE}/api/user/approval-status")
        results.append(("GET /api/user/approval-status", r.status_code == 200))
        print(f"  {'✅' if r.status_code == 200 else '❌'} /api/user/approval-status -> {r.status_code}")
        print(f"    Response: {r.json()}")
        
        # Test admin messages GET
        r = session.get(f"{BASE}/api/user/admin-messages")
        results.append(("GET /api/user/admin-messages", r.status_code == 200))
        print(f"  {'✅' if r.status_code == 200 else '❌'} /api/user/admin-messages -> {r.status_code}")
        print(f"    Response: {r.json()}")
        
        # Test admin messages POST
        r = session.post(f"{BASE}/api/user/admin-messages", json={"message": "Hello admin!"})
        results.append(("POST /api/user/admin-messages", r.status_code == 200 and r.json().get("success")))
        print(f"  {'✅' if r.status_code == 200 and r.json().get('success') else '❌'} /api/user/admin-messages -> {r.status_code}")
        print(f"    Response: {r.json()}")
        
        # Test logout
        r = session.post(f"{BASE}/api/logout")
        results.append(("POST /api/logout", r.status_code == 200 and r.json().get("success")))
        print(f"  {'✅' if r.status_code == 200 and r.json().get('success') else '❌'} /api/logout -> {r.status_code}")
        print(f"    Response: {r.json()}")
    
    # Summary
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    for name, ok in results:
        print(f"  {'✅' if ok else '❌'} {name}")
    print(f"\n  {passed}/{total} tests passed ({passed*100//total}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Mobile registration flow is working end-to-end!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")

if __name__ == "__main__":
    main()
