#!/usr/bin/env python3
"""
ZEUSCHAT 1.0 LIVE DEPLOYMENT VERIFICATION
Test suite for https://zeuschat1-0.onrender.com
"""

import requests
import json
import sys
from datetime import datetime

BASE = "https://zeuschat1-0.onrender.com"

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def test_health():
    """Test /health endpoint"""
    print("\n🧪 TEST 1: Health Check")
    try:
        r = requests.get(f"{BASE}/health", timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(f"   ✅ Status: {r.status_code}")
            print(f"   ✅ Response: {json.dumps(data, indent=6)}")
            assert data.get('status') == 'healthy', "Database not connected"
            return True, data
        else:
            print(f"   ❌ Status: {r.status_code}")
            print(f"   ❌ Response: {r.text[:200]}")
            return False, None
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False, None

def test_signup():
    """Test /api/start-signup endpoint"""
    print("\n🧪 TEST 2: Registration API")
    try:
        r = requests.post(
            f"{BASE}/api/start-signup", 
            json={"email": "investor@zeustech.test"}, 
            timeout=10
        )
        print(f"   Status: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            if data.get('success'):
                print(f"   ✅ Registration successful")
                print(f"   ✅ Test OTP: {data.get('test_otp')}")
                return True, data
            else:
                print(f"   ❌ Error: {data.get('error')}")
                return False, data
        else:
            print(f"   ❌ HTTP {r.status_code}")
            print(f"   Response: {r.text[:300]}")
            return False, None
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False, None

def test_login():
    """Test /api/login endpoint"""
    print("\n🧪 TEST 3: Login API")
    try:
        r = requests.post(
            f"{BASE}/api/login",
            json={"zeus_pin": "ZT-TEST-TEST", "password": "testpass123"},
            timeout=10
        )
        print(f"   Status: {r.status_code}")
        
        # Expect 401 for invalid creds, NOT 404/500
        if r.status_code in [200, 401]:
            print(f"   ✅ Login endpoint responding correctly")
            return True, r.json()
        else:
            print(f"   ❌ Unexpected status: {r.status_code}")
            print(f"   Response: {r.text[:200]}")
            return False, None
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False, None

def test_welcome_page():
    """Test / (welcome page)"""
    print("\n🧪 TEST 4: Welcome Page")
    try:
        r = requests.get(f"{BASE}/", timeout=10)
        print(f"   Status: {r.status_code}")
        
        if r.status_code == 200:
            if 'ZeusChat' in r.text or 'zeuschat' in r.text.lower():
                print(f"   ✅ Welcome page loading")
                print(f"   ✅ Content length: {len(r.text)} bytes")
                return True, len(r.text)
            else:
                print(f"   ⚠️  Page loaded but 'ZeusChat' not found in content")
                return False, None
        else:
            print(f"   ❌ HTTP {r.status_code}")
            return False, None
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False, None

def test_video_file():
    """Test video file accessibility"""
    print("\n🧪 TEST 5: Background Video")
    try:
        r = requests.head(f"{BASE}/zeustech-register.mp4", timeout=10)
        print(f"   Status: {r.status_code}")
        
        # 200 = OK, 206 = Partial Content (video streaming)
        if r.status_code in [200, 206]:
            print(f"   ✅ Video accessible")
            if 'content-length' in r.headers:
                size_mb = int(r.headers['content-length']) / (1024*1024)
                print(f"   ✅ Size: {size_mb:.2f} MB")
            return True, r.status_code
        elif r.status_code == 404:
            print(f"   ⚠️  Video not found (404) - may need to be uploaded")
            return False, None
        else:
            print(f"   ❌ Unexpected status: {r.status_code}")
            return False, None
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False, None

def test_messaging_api():
    """Test messaging endpoints"""
    print("\n🧪 TEST 6: Messaging APIs")
    try:
        # Test send-message (expect auth error)
        r1 = requests.post(
            f"{BASE}/api/send-message",
            json={"receiver_pin": "ZT-1234-5678", "content": "Test", "ttl": 3600},
            timeout=10
        )
        print(f"   send-message status: {r1.status_code}")
        
        # Test get-messages (expect auth error)
        r2 = requests.get(f"{BASE}/api/get-messages", timeout=10)
        print(f"   get-messages status: {r2.status_code}")
        
        # Both should return 401 (not authenticated), NOT 404/500
        if r1.status_code in [200, 401] and r2.status_code in [200, 401]:
            print(f"   ✅ Messaging endpoints responding correctly")
            return True, {'send': r1.status_code, 'get': r2.status_code}
        else:
            print(f"   ❌ Unexpected status codes")
            return False, None
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False, None

def generate_report(results):
    """Generate investor readiness report"""
    print_header("🏁 ZEUSCHAT INVESTOR READINESS CONFIRMATION")
    
    print(f"\nDate: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}")
    print(f"URL: {BASE}")
    print(f"Python Version: Check Render logs for confirmation")
    
    print("\n" + "="*60)
    print("📊 TEST RESULTS SUMMARY")
    print("="*60)
    
    passed = sum(1 for r in results if r[0])
    failed = len(results) - passed
    
    for name, success, _ in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{name:.<45} {status}")
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    print("\n" + "="*60)
    print("✅ INFRASTRUCTURE CHECKLIST")
    print("="*60)
    print("[ ] Docker build successful (check Render logs)")
    print("[ ] Python 3.13.4 confirmed in logs")
    print("[ ] Gunicorn workers running")
    print("[✅] Database initialized" if results[0][0] else "[❌] Database connection failed")
    
    print("\n" + "="*60)
    print("✅ API ENDPOINTS")
    print("="*60)
    for name, success, _ in results[:3]:
        status = "[✅]" if success else "[❌]"
        print(f"{status} {name}")
    
    print("\n" + "="*60)
    print("✅ USER EXPERIENCE")
    print("="*60)
    print("[✅] Registration flow endpoint working" if results[1][0] else "[❌] Registration endpoint broken")
    print("[✅] Login endpoint working" if results[2][0] else "[❌] Login endpoint broken")
    print("[✅] Messaging endpoints working" if results[5][0] else "[❌] Messaging endpoints broken")
    print("[✅] Welcome page loads" if results[3][0] else "[❌] Welcome page broken")
    print("[✅] Videos accessible" if results[4][0] else "[⚠️ ] Videos not found")
    
    print("\n" + "="*60)
    
    if failed == 0:
        print("✅✅✅ INVESTOR DEMO READY: YES ✅✅✅")
        print("\nAll automated tests passed.")
        print("Proceed with manual browser testing:")
        print("  1. Open URL in browser")
        print("  2. Test registration flow")
        print("  3. Test login")
        print("  4. Test messaging")
        print("  5. Verify video playback")
    else:
        print("🚨🚨🚨 INVESTOR DEMO READY: NO 🚨🚨🚨")
        print(f"\n{failed} tests failed. Fix issues before investor demo.")
        print("\nAction Items:")
        for name, success, _ in results:
            if not success:
                print(f"  - Fix: {name}")
    
    print("="*60 + "\n")
    
    return failed == 0

def main():
    print_header("🧪 ZEUSCHAT 1.0 LIVE DEPLOYMENT TEST SUITE")
    print(f"\nTarget: {BASE}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = []
    
    # Run all tests
    results.append(("Health Check", *test_health()))
    results.append(("Registration API", *test_signup()))
    results.append(("Login API", *test_login()))
    results.append(("Welcome Page", *test_welcome_page()))
    results.append(("Video Files", *test_video_file()))
    results.append(("Messaging APIs", *test_messaging_api()))
    
    # Generate final report
    all_passed = generate_report(results)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
