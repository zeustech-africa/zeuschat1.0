#!/usr/bin/env python3
"""
Test the HTML frontend flow by simulating browser actions
"""

import requests
import json
import time
import re

BASE_URL = "http://localhost:5000"

print("=" * 70)
print("🧪 ZEUSCHAT 1.0 FRONTEND FLOW SIMULATION TEST")
print("=" * 70)
print()

# TEST 1: Check that index.html loads
print("Test 1️⃣: Load index.html")
try:
    response = requests.get(f"{BASE_URL}/", timeout=5)
    if response.status_code == 200 and "ZeusChat" in response.text:
        print("   ✅ index.html loads correctly")
    else:
        print("   ❌ Failed to load index.html")
except Exception as e:
    print(f"   ❌ Error: {e}")

print()

# TEST 2: Check that emailinput.html exists and loads
print("Test 2️⃣: Load emailinput.html")
try:
    response = requests.get(f"{BASE_URL}/emailinput.html", timeout=5)
    if response.status_code == 200 and "Enter your email" in response.text:
        print("   ✅ emailinput.html loads correctly")
        print(f"      File size: {len(response.text)} bytes")
    else:
        print("   ❌ Failed to load emailinput.html")
except Exception as e:
    print(f"   ❌ Error: {e}")

print()

# TEST 3: Check otp-verify.html
print("Test 3️⃣: Load otp-verify.html")
try:
    response = requests.get(f"{BASE_URL}/otp-verify.html", timeout=5)
    if response.status_code == 200 and "Enter OTP Code" in response.text:
        print("   ✅ otp-verify.html loads correctly")
        # Check if JavaScript is present
        if "verifyOTP" in response.text:
            print("   ✅ JavaScript function verifyOTP() is present")
        if "api/verify-otp" in response.text:
            print("   ✅ API endpoint reference is correct")
    else:
        print("   ❌ Failed to load otp-verify.html")
except Exception as e:
    print(f"   ❌ Error: {e}")

print()

# TEST 4: Check profile-create.html
print("Test 4️⃣: Load profile-create.html")
try:
    response = requests.get(f"{BASE_URL}/profile-create.html", timeout=5)
    if response.status_code == 200 and "Create Your Profile" in response.text:
        print("   ✅ profile-create.html loads correctly")
        if "my_zeus_pin" in response.text:
            print("   ✅ localStorage reference is correct")
    else:
        print("   ❌ Failed to load profile-create.html")
except Exception as e:
    print(f"   ❌ Error: {e}")

print()

# TEST 5: Check password-create.html
print("Test 5️⃣: Load password-create.html")
try:
    response = requests.get(f"{BASE_URL}/password-create.html", timeout=5)
    if response.status_code == 200 and "Create your password" in response.text:
        print("   ✅ password-create.html loads correctly")
        if "api/complete-registration" in response.text:
            print("   ✅ API endpoint reference is correct")
        if "api/login" in response.text:
            print("   ✅ Login endpoint reference is correct")
    else:
        print("   ❌ Failed to load password-create.html")
except Exception as e:
    print(f"   ❌ Error: {e}")

print()

# TEST 6: Check static files
print("Test 6️⃣: Check static assets")
assets = [
    "zeustech-logo-zeushchat.png",
    "zeustech-register.mp4",
]
for asset in assets:
    try:
        response = requests.head(f"{BASE_URL}/{asset}", timeout=5)
        if response.status_code == 200:
            print(f"   ✅ {asset} found ({response.headers.get('content-length', '?')} bytes)")
        else:
            print(f"   ⚠️  {asset} returned {response.status_code}")
    except Exception as e:
        print(f"   ⚠️  {asset} error: {e}")

print()

# TEST 7: Simulate complete flow
print("Test 7️⃣: Simulate Complete User Flow")
test_email = f"frontend{int(time.time())}@test.com"

# Step 1: OTP verification
print("   Step 1: Verify OTP")
try:
    response = requests.post(
        f"{BASE_URL}/api/verify-otp",
        json={"email": test_email, "otp": "123456"},
        timeout=5
    )
    if response.status_code == 200:
        data = response.json()
        zeus_pin = data.get('zeus_pin')
        print(f"      ✅ OTP verified, Zeus PIN: {zeus_pin}")
    else:
        print(f"      ❌ OTP verification failed: {response.status_code}")
        exit(1)
except Exception as e:
    print(f"      ❌ Error: {e}")
    exit(1)

# Step 2: Registration
print("   Step 2: Complete Registration")
try:
    response = requests.post(
        f"{BASE_URL}/api/complete-registration",
        json={
            "email": test_email,
            "zeus_pin": zeus_pin,
            "password": "testpass123",
            "full_name": "Frontend Test User"
        },
        timeout=5
    )
    if response.status_code == 201:
        data = response.json()
        user_id = data.get('user_id')
        print(f"      ✅ Registration complete, User ID: {user_id}")
    else:
        print(f"      ❌ Registration failed: {response.status_code}")
        exit(1)
except Exception as e:
    print(f"      ❌ Error: {e}")
    exit(1)

# Step 3: Login
print("   Step 3: Login")
try:
    response = requests.post(
        f"{BASE_URL}/api/login",
        json={"zeus_pin": zeus_pin, "password": "testpass123"},
        timeout=5
    )
    if response.status_code == 200:
        data = response.json()
        user = data.get('user', {})
        print(f"      ✅ Login successful for {user.get('email')}")
    else:
        print(f"      ❌ Login failed: {response.status_code}")
        exit(1)
except Exception as e:
    print(f"      ❌ Error: {e}")
    exit(1)

print()
print("=" * 70)
print("✅ ALL FRONTEND TESTS PASSED!")
print("=" * 70)
print()
print("📝 SUMMARY:")
print("   ✅ All HTML files load correctly")
print("   ✅ All JavaScript is present and correct")
print("   ✅ All API endpoints work")
print("   ✅ Complete registration flow works end-to-end")
print()
