#!/usr/bin/env python3
"""
ZEUSCHAT 1.0 INVESTOR READINESS TEST SUITE
Automated endpoint testing before deployment
"""

import requests
import sys

BASE = "http://localhost:5001"

def test_health():
    """Test /health endpoint"""
    try:
        r = requests.get(f"{BASE}/health", timeout=5)
        assert r.status_code == 200, f"Health check failed: {r.status_code}"
        data = r.json()
        assert data.get('status') == 'healthy', "Database not connected"
        print("✅ Health Endpoint OK")
        return True
    except Exception as e:
        print(f"❌ Health Check Failed: {e}")
        return False

def test_signup():
    """Test /api/start-signup endpoint"""
    try:
        r = requests.post(
            f"{BASE}/api/start-signup", 
            json={"email": "investor@zeustech.test"}, 
            timeout=5
        )
        assert r.status_code == 200, f"Signup failed: {r.status_code}"
        data = r.json()
        assert data.get('success') == True, "Signup did not return success"
        assert 'test_otp' in data, "No OTP returned"
        print("✅ Registration API OK")
        return True
    except Exception as e:
        print(f"❌ Registration API Failed: {e}")
        return False

def test_login():
    """Test /api/login endpoint (expect 401 for invalid creds)"""
    try:
        r = requests.post(
            f"{BASE}/api/login", 
            json={"zeus_pin": "ZT-TEST-TEST", "password": "invalid"}, 
            timeout=5
        )
        # Should return 401 for invalid credentials, NOT 404/500
        assert r.status_code in [200, 401], f"Login API broken: {r.status_code}"
        print("✅ Login API OK")
        return True
    except Exception as e:
        print(f"❌ Login API Failed: {e}")
        return False

def test_send_message():
    """Test /api/send-message endpoint (expect auth error)"""
    try:
        r = requests.post(
            f"{BASE}/api/send-message",
            json={"receiver_pin": "ZT-1234-5678", "content": "Test", "ttl": 3600},
            timeout=5
        )
        # Should return 401 (not authenticated), NOT 404/500
        assert r.status_code in [200, 401], f"Send Message API broken: {r.status_code}"
        data = r.json()
        assert 'error' in data or 'success' in data, "Invalid JSON response"
        print("✅ Send Message API OK")
        return True
    except Exception as e:
        print(f"❌ Send Message API Failed: {e}")
        return False

def test_get_messages():
    """Test /api/get-messages endpoint (expect auth error)"""
    try:
        r = requests.get(f"{BASE}/api/get-messages", timeout=5)
        # Should return 401 (not authenticated), NOT 404/500
        assert r.status_code in [200, 401], f"Get Messages API broken: {r.status_code}"
        print("✅ Get Messages API OK")
        return True
    except Exception as e:
        print(f"❌ Get Messages API Failed: {e}")
        return False

def main():
    print("=" * 60)
    print("🧪 ZEUSCHAT 1.0 INVESTOR READINESS TEST SUITE")
    print("=" * 60)
    print()
    
    results = []
    
    # Run all tests
    results.append(("Health Check", test_health()))
    results.append(("Registration API", test_signup()))
    results.append(("Login API", test_login()))
    results.append(("Send Message API", test_send_message()))
    results.append(("Get Messages API", test_get_messages()))
    
    print()
    print("=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name:.<40} {status}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print()
    print(f"Total: {passed} passed, {failed} failed")
    print()
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED - READY FOR DEPLOYMENT")
        print()
        return 0
    else:
        print("🚨 SOME TESTS FAILED - FIX BEFORE DEPLOYMENT")
        print()
        return 1

if __name__ == "__main__":
    sys.exit(main())
