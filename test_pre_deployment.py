#!/usr/bin/env python3
"""
PRE-DEPLOYMENT VERIFICATION TEST
Tests EVERYTHING before deploying to Render
"""

import requests
import time
import json
import sys
from datetime import datetime

BASE_URL = "http://localhost:5000"

def log(message, status="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    symbols = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "TEST": "🧪"}
    print(f"[{timestamp}] {symbols.get(status, 'ℹ️')} {message}")

def test_backend_health():
    """Test 1: Backend is running"""
    log("Testing backend health...", "TEST")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code == 200:
            log("Backend is responding correctly", "SUCCESS")
            return True
        else:
            log(f"Backend returned status {response.status_code}", "ERROR")
            return False
    except Exception as e:
        log(f"Backend connection failed: {str(e)}", "ERROR")
        return False

def test_email_submission():
    """Test 2: Email submission endpoint"""
    log("Testing email submission...", "TEST")
    try:
        email = f"test_{int(time.time())}@zeuschat.com"
        response = requests.post(
            f"{BASE_URL}/api/start-signup",
            json={"email": email},
            timeout=5
        )
        data = response.json()
        
        if response.status_code == 200 and data.get("success"):
            log(f"Email submission successful for {email}", "SUCCESS")
            return email
        else:
            log(f"Email submission failed: {data}", "ERROR")
            return None
    except Exception as e:
        log(f"Email submission error: {str(e)}", "ERROR")
        return None

def test_otp_verification(email):
    """Test 3: OTP verification (THE CRITICAL TEST)"""
    log("Testing OTP verification...", "TEST")
    try:
        response = requests.post(
            f"{BASE_URL}/api/verify-otp",
            json={"email": email, "otp": "123456"},
            timeout=5
        )
        data = response.json()
        
        if response.status_code == 200 and data.get("success"):
            zeus_pin = data.get("zeus_pin")
            if zeus_pin and zeus_pin.startswith("ZT-"):
                log(f"OTP verification successful! Zeus PIN: {zeus_pin}", "SUCCESS")
                return zeus_pin
            else:
                log(f"OTP verified but no Zeus PIN: {data}", "ERROR")
                return None
        else:
            log(f"OTP verification failed: {data}", "ERROR")
            return None
    except Exception as e:
        log(f"OTP verification error: {str(e)}", "ERROR")
        return None

def test_complete_registration(email, zeus_pin):
    """Test 4: Complete registration"""
    log("Testing complete registration...", "TEST")
    try:
        response = requests.post(
            f"{BASE_URL}/api/complete-registration",
            json={
                "email": email,
                "zeus_pin": zeus_pin,
                "full_name": "Test User",
                "username": f"testuser_{int(time.time())}",
                "password": "Test123!"
            },
            timeout=5
        )
        data = response.json()
        
        if response.status_code in [200, 201] and data.get("success"):
            log(f"Registration completed successfully! User ID: {data.get('user_id')}", "SUCCESS")
            return data.get('user_id')
        else:
            log(f"Registration failed: {data} (status: {response.status_code})", "ERROR")
            return None
    except Exception as e:
        log(f"Registration error: {str(e)}", "ERROR")
        return None

def test_login(zeus_pin):
    """Test 5: Login functionality"""
    log("Testing login...", "TEST")
    try:
        response = requests.post(
            f"{BASE_URL}/api/login",
            json={"zeus_pin": zeus_pin, "password": "Test123!"},
            timeout=5
        )
        data = response.json()
        
        if response.status_code == 200 and data.get("success"):
            user = data.get("user", {})
            log(f"Login successful! Username: {user.get('username')}, Zeus PIN: {user.get('zeus_pin')}", "SUCCESS")
            return user
        else:
            log(f"Login failed: {data}", "ERROR")
            return None
    except Exception as e:
        log(f"Login error: {str(e)}", "ERROR")
        return None

def test_4k_videos():
    """Test 6: All 4K videos are accessible"""
    log("Testing 4K video accessibility...", "TEST")
    videos = [
        "zeuschat-chatpage.mp4",
        "zeuschat-profile.mp4",
        "zeustech-register.mp4",
        "zeustech-background.mp4"
    ]
    
    all_ok = True
    for video in videos:
        try:
            response = requests.head(f"{BASE_URL}/videos/{video}", timeout=5)
            if response.status_code == 200:
                size_mb = int(response.headers.get('Content-Length', 0)) / (1024 * 1024)
                log(f"✓ {video} accessible ({size_mb:.1f}MB)", "SUCCESS")
            else:
                log(f"✗ {video} returned status {response.status_code}", "ERROR")
                all_ok = False
        except Exception as e:
            log(f"✗ {video} error: {str(e)}", "ERROR")
            all_ok = False
    
    return all_ok

def test_html_pages():
    """Test 7: All HTML pages load"""
    log("Testing HTML pages...", "TEST")
    pages = [
        "index.html",
        "emailinput.html",
        "otp-verify.html",
        "profile-create.html",
        "password-create.html",
        "chat.html",
        "settings.html"
    ]
    
    all_ok = True
    for page in pages:
        try:
            response = requests.get(f"{BASE_URL}/{page}", timeout=5)
            if response.status_code == 200 and len(response.text) > 100:
                log(f"✓ {page} loads correctly ({len(response.text)} bytes)", "SUCCESS")
            else:
                log(f"✗ {page} status {response.status_code}", "ERROR")
                all_ok = False
        except Exception as e:
            log(f"✗ {page} error: {str(e)}", "ERROR")
            all_ok = False
    
    return all_ok

def main():
    print("\n" + "="*60)
    print("🚀 ZEUSCHAT 1.0 - PRE-DEPLOYMENT VERIFICATION")
    print("="*60 + "\n")
    
    tests_passed = 0
    tests_total = 7
    
    # Test 1: Backend Health
    if test_backend_health():
        tests_passed += 1
    else:
        log("CRITICAL: Backend not running! Cannot proceed.", "ERROR")
        sys.exit(1)
    
    print()
    
    # Test 2: Email Submission
    email = test_email_submission()
    if email:
        tests_passed += 1
    else:
        log("CRITICAL: Email submission failed!", "ERROR")
        sys.exit(1)
    
    print()
    
    # Test 3: OTP Verification (MOST CRITICAL)
    zeus_pin = test_otp_verification(email)
    if zeus_pin:
        tests_passed += 1
    else:
        log("CRITICAL: OTP verification failed! This is the error user experienced!", "ERROR")
        sys.exit(1)
    
    print()
    
    # Test 4: Complete Registration
    user_id = test_complete_registration(email, zeus_pin)
    if user_id:
        tests_passed += 1
    else:
        log("CRITICAL: Registration completion failed!", "ERROR")
        sys.exit(1)
    
    print()
    
    # Test 5: Login
    user = test_login(zeus_pin)
    if user:
        tests_passed += 1
    else:
        log("CRITICAL: Login failed!", "ERROR")
        sys.exit(1)
    
    print()
    
    # Test 6: 4K Videos
    if test_4k_videos():
        tests_passed += 1
    else:
        log("WARNING: Some videos not accessible", "ERROR")
    
    print()
    
    # Test 7: HTML Pages
    if test_html_pages():
        tests_passed += 1
    else:
        log("WARNING: Some HTML pages not loading", "ERROR")
    
    print("\n" + "="*60)
    print(f"FINAL RESULT: {tests_passed}/{tests_total} TESTS PASSED")
    print("="*60 + "\n")
    
    if tests_passed == tests_total:
        log("🎉 ALL TESTS PASSED! SYSTEM IS READY FOR DEPLOYMENT!", "SUCCESS")
        print("\n✅ NO OTP ERRORS")
        print("✅ NO SIGNUP ERRORS")
        print("✅ ALL VIDEOS WORKING")
        print("✅ ALL PAGES LOADING")
        print("\n🚀 SAFE TO DEPLOY TO RENDER!\n")
        return 0
    else:
        log(f"⚠️  ONLY {tests_passed}/{tests_total} TESTS PASSED - DO NOT DEPLOY YET!", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())
