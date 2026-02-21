#!/usr/bin/env python3
"""
ZeusChat 1.0 Registration Flow Test
Tests all endpoints from email to login
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"
TEST_EMAIL = f"testflow{int(time.time())}@example.com"
TEST_PASSWORD = "password123"
TEST_NAME = "Test User Flow"

print("=" * 60)
print("🧪 ZEUSCHAT 1.0 REGISTRATION FLOW TEST")
print("=" * 60)
print()

# STEP 1: Verify OTP
print("📧 STEP 1: OTP Verification")
print(f"   Testing: POST /api/verify-otp")
try:
    response = requests.post(
        f"{BASE_URL}/api/verify-otp",
        json={"email": TEST_EMAIL, "otp": "123456"},
        timeout=5
    )
    print(f"   Status: {response.status_code}")
    data = response.json()
    print(f"   Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 200 and 'zeus_pin' in data:
        zeus_pin = data['zeus_pin']
        print(f"   ✅ SUCCESS: Zeus PIN generated: {zeus_pin}")
    else:
        print(f"   ❌ FAILED: {data.get('error', 'Unknown error')}")
        exit(1)
except Exception as e:
    print(f"   ❌ ERROR: {e}")
    exit(1)

print()

# STEP 2: Complete Registration
print("👤 STEP 2: Complete Registration")
print(f"   Testing: POST /api/complete-registration")
try:
    response = requests.post(
        f"{BASE_URL}/api/complete-registration",
        json={
            "email": TEST_EMAIL,
            "zeus_pin": zeus_pin,
            "password": TEST_PASSWORD,
            "full_name": TEST_NAME
        },
        timeout=5
    )
    print(f"   Status: {response.status_code}")
    data = response.json()
    print(f"   Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 201 and data.get('success'):
        user_id = data.get('user_id')
        print(f"   ✅ SUCCESS: User created with ID: {user_id}")
    else:
        print(f"   ❌ FAILED: {data.get('error', 'Unknown error')}")
        exit(1)
except Exception as e:
    print(f"   ❌ ERROR: {e}")
    exit(1)

print()

# STEP 3: Login
print("🔐 STEP 3: Login")
print(f"   Testing: POST /api/login")
try:
    response = requests.post(
        f"{BASE_URL}/api/login",
        json={
            "zeus_pin": zeus_pin,
            "password": TEST_PASSWORD
        },
        timeout=5
    )
    print(f"   Status: {response.status_code}")
    data = response.json()
    print(f"   Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 200 and data.get('success'):
        user = data.get('user', {})
        print(f"   ✅ SUCCESS: Login successful for {user.get('email')}")
        print(f"   User ID: {user.get('id')}")
        print(f"   Name: {user.get('full_name')}")
        print(f"   Zeus PIN: {user.get('zeus_pin')}")
    else:
        print(f"   ❌ FAILED: {data.get('error', 'Unknown error')}")
        exit(1)
except Exception as e:
    print(f"   ❌ ERROR: {e}")
    exit(1)

print()
print("=" * 60)
print("✅ ALL TESTS PASSED!")
print("=" * 60)
print()
print("Summary:")
print(f"  Email: {TEST_EMAIL}")
print(f"  Zeus PIN: {zeus_pin}")
print(f"  Password: {TEST_PASSWORD}")
print(f"  Full Name: {TEST_NAME}")
print()
