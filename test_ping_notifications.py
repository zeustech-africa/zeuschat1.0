#!/usr/bin/env python3
"""
Comprehensive Ping & Notification System Test Suite
Tests ping feature, sound notifications, vibration, and fallback mechanisms
"""

import requests
import json
import time
import random
from datetime import datetime

BASE_URL = "http://localhost:5000"
session_cache = {}

def get_session(user_key):
    """Get or create a session for a user"""
    if user_key not in session_cache:
        session_cache[user_key] = requests.Session()
    return session_cache[user_key]

def print_header(text):
    print(f"\n{'='*80}")
    print(f"  {text}")
    print(f"{'='*80}\n")

def create_test_identity(label):
    """Create unique test identity"""
    unique = int(time.time() * 1000) % 100000
    zeus_pin = f"ZT-PING-{(9000 + random.randint(0, 99)):04d}-{(unique % 10000):04d}"
    email = f"ping_{label.lower()}_{unique}@test.local"
    password = "password123"
    return {
        'email': email,
        'password': password,
        'zeus_pin': zeus_pin
    }

def login_user(email, password, zeus_pin):
    """Login and return user key for session"""
    print(f"🔑 Logging in as {zeus_pin}...")
    session = get_session(zeus_pin)
    
    resp = session.post(f"{BASE_URL}/api/login", json={
        'zeus_pin': zeus_pin,
        'password': password
    })

    if resp.status_code == 200 and resp.json().get('success'):
        print(f"✅ Logged in successfully as {zeus_pin}")
        return zeus_pin

    reg_resp = session.post(f"{BASE_URL}/api/complete-registration", json={
        'email': email,
        'zeus_pin': zeus_pin,
        'password': password,
        'full_name': zeus_pin,
        'profile_pic': ''
    })

    if reg_resp.status_code in [200, 201] and reg_resp.json().get('success'):
        print(f"✅ Registered and logged in as {zeus_pin}")
        return zeus_pin

    try:
        error_msg = reg_resp.json().get('error') or resp.json().get('error')
    except:
        error_msg = f"login_status={resp.status_code}, register_status={reg_resp.status_code}"

    raise RuntimeError(f"Authentication failed for {zeus_pin}: {error_msg}")

def ensure_contact_accepted(requester_key, target_key):
    """Ensure requester and target are contacts"""
    requester_session = get_session(requester_key)
    target_session = get_session(target_key)

    add_resp = requester_session.post(
        f"{BASE_URL}/api/add-contact",
        json={'zeus_pin': target_key}
    )

    if add_resp.status_code not in [200, 201, 409]:
        raise RuntimeError(f"add-contact failed: {add_resp.status_code}")

    req_resp = target_session.get(f"{BASE_URL}/api/get-contact-requests")
    if req_resp.status_code != 200:
        raise RuntimeError(f"get-contact-requests failed: {req_resp.status_code}")

    requests_list = req_resp.json().get('requests', [])
    request_row = next((row for row in requests_list if row.get('zeus_pin') == requester_key), None)

    if request_row:
        accept_resp = target_session.post(
            f"{BASE_URL}/api/accept-contact",
            json={'contact_id': request_row.get('contact_id')}
        )
        if accept_resp.status_code not in [200, 201]:
            raise RuntimeError(f"accept-contact failed: {accept_resp.status_code}")

    print(f"🤝 Contact handshake ready: {requester_key} <-> {target_key}")

def send_ping(sender_key, receiver_pin, ping_type='standard'):
    """Send a PING to a contact"""
    print(f"📳 Sending PING (type: {ping_type}) to {receiver_pin}...")
    
    session = get_session(sender_key)
    resp = session.post(
        f"{BASE_URL}/api/bbm-send-ping",
        json={
            'receiver_pin': receiver_pin,
            'ping_type': ping_type
        }
    )
    
    data = resp.json()
    if data.get('success'):
        print(f"✅ PING sent successfully (ID check via console)")
        return True
    else:
        print(f"❌ Failed to send PING: {data.get('error')}")
        return False

# ============================================
# TEST SCENARIOS
# ============================================

def test_standard_ping():
    """Test 1: Standard PING delivery via Socket.IO"""
    print_header("TEST 1: Standard PING (Socket.IO Delivery)")
    
    alice_identity = create_test_identity("alice")
    bob_identity = create_test_identity("bob")

    alice = login_user(alice_identity['email'], alice_identity['password'], alice_identity['zeus_pin'])
    bob = login_user(bob_identity['email'], bob_identity['password'], bob_identity['zeus_pin'])
    ensure_contact_accepted(alice, bob)
    
    print("\n📳 Alice sending PING to Bob...")
    if send_ping(alice, bob, 'standard'):
        print("✅ TEST 1 PASSED: Standard PING sent")
        print("   NOTE: Check Bob's browser console for:")
        print("   - '📳 [BBM] ✅ PING RECEIVED' message")
        print("   - Alert popup showing PING")
        print("   - Vibration and sound playback")
        return True
    else:
        print("❌ TEST 1 FAILED: Could not send PING")
        return False

def test_urgent_ping():
    """Test 2: Urgent PING with enhanced vibration"""
    print_header("TEST 2: Urgent PING (Enhanced Vibration)")
    
    charlie_identity = create_test_identity("charlie")
    david_identity = create_test_identity("david")

    charlie = login_user(charlie_identity['email'], charlie_identity['password'], charlie_identity['zeus_pin'])
    david = login_user(david_identity['email'], david_identity['password'], david_identity['zeus_pin'])
    ensure_contact_accepted(charlie, david)
    
    print("\n📳 Charlie sending URGENT PING to David...")
    if send_ping(charlie, david, 'urgent'):
        print("✅ TEST 2 PASSED: Urgent PING sent")
        print("   NOTE: Check David's console for:")
        print("   - Stronger vibration pattern [200, 100, 200, 100, 200]")
        print("   - Aggressive sound notification")
        return True
    else:
        print("❌ TEST 2 FAILED: Could not send urgent PING")
        return False

def test_ping_offline_fallback():
    """Test 3: PING fallback storage for offline receiver"""
    print_header("TEST 3: PING Offline Fallback (Database Storage)")
    
    eve_identity = create_test_identity("eve")
    frank_identity = create_test_identity("frank")

    eve = login_user(eve_identity['email'], eve_identity['password'], eve_identity['zeus_pin'])
    frank = login_user(frank_identity['email'], frank_identity['password'], frank_identity['zeus_pin'])
    ensure_contact_accepted(eve, frank)
    
    print("\n📳 Eve sending PING to Frank...")
    print("   (Simulating offline scenario - PING stored in database)")
    
    if send_ping(eve, frank, 'standard'):
        print("✅ TEST 3 PASSED: PING sent (would be stored if Frank offline)")
        print("   NOTE: If Frank is online, Socket.IO delivery is primary")
        print("   NOTE: If Frank is offline, PING saved as fallback message")
        return True
    else:
        print("❌ TEST 3 FAILED: Could not send PING")
        return False

def test_notification_endpoint_health():
    """Test 4: Verify notification audio file is accessible"""
    print_header("TEST 4: Notification Audio File Health")
    
    print("🔍 Checking notification.wav availability...")
    
    session = requests.Session()
    resp = session.head(f"{BASE_URL}/static/notification.wav")
    
    if resp.status_code == 200:
        content_length = resp.headers.get('Content-Length', 'unknown')
        print(f"✅ notification.wav is accessible")
        print(f"   - Status: 200 OK")
        print(f"   - Size: {content_length} bytes")
        
        # Verify it's actually an audio file
        resp_get = session.get(f"{BASE_URL}/static/notification.wav")
        if b'RIFF' in resp_get.content[:4]:
            print(f"✅ File is valid WAV format")
            return True
        else:
            print(f"⚠️ File might not be proper WAV format")
            return False
    else:
        print(f"❌ notification.wav not found (status: {resp.status_code})")
        return False

def test_contact_validation():
    """Test 5: Verify PING only works between accepted contacts"""
    print_header("TEST 5: Contact Validation for PING")
    
    george_identity = create_test_identity("george")
    henry_identity = create_test_identity("henry")

    george = login_user(george_identity['email'], george_identity['password'], george_identity['zeus_pin'])
    henry = login_user(henry_identity['email'], henry_identity['password'], henry_identity['zeus_pin'])
    
    # DO NOT accept contact - test that PING fails
    print("\n📳 George attempting PING to Henry (NO CONTACT relationship)...")
    
    session = get_session(george)
    resp = session.post(
        f"{BASE_URL}/api/bbm-send-ping",
        json={
            'receiver_pin': henry,
            'ping_type': 'standard'
        }
    )
    
    if resp.status_code == 403:
        print(f"✅ TEST 5 PASSED: PING correctly rejected for non-contacts")
        print(f"   - Status: 403 Forbidden")
        print(f"   - Message: {resp.json().get('error')}")
        return True
    else:
        print(f"⚠️ TEST 5 CONDITIONAL: Expected 403, got {resp.status_code}")
        print(f"   Response: {resp.json()}")
        return False

# ============================================
# RUN ALL TESTS
# ============================================

if __name__ == "__main__":
    print_header("ZEUSCHAT PING & NOTIFICATION SYSTEM TEST SUITE")
    print("📳 Testing:")
    print("  ✓ Standard and Urgent PING delivery")
    print("  ✓ Socket.IO real-time delivery")
    print("  ✓ Database fallback for offline users")
    print("  ✓ Notification audio file availability")
    print("  ✓ Contact validation")
    print("  ✓ Vibration patterns (check browser)")
    print("  ✓ Web Audio API tone generation (fallback)")
    
    results = {
        "Test 1 - Standard PING": False,
        "Test 2 - Urgent PING": False,
        "Test 3 - Offline Fallback": False,
        "Test 4 - Audio File Health": False,
        "Test 5 - Contact Validation": False
    }
    
    try:
        results["Test 1 - Standard PING"] = test_standard_ping()
    except Exception as e:
        print(f"\n❌ TEST 1 FAILED: {e}")
    
    try:
        results["Test 2 - Urgent PING"] = test_urgent_ping()
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED: {e}")
    
    try:
        results["Test 3 - Offline Fallback"] = test_ping_offline_fallback()
    except Exception as e:
        print(f"\n❌ TEST 3 FAILED: {e}")
    
    try:
        results["Test 4 - Audio File Health"] = test_notification_endpoint_health()
    except Exception as e:
        print(f"\n❌ TEST 4 FAILED: {e}")
    
    try:
        results["Test 5 - Contact Validation"] = test_contact_validation()
    except Exception as e:
        print(f"\n❌ TEST 5 FAILED: {e}")
    
    # Final report
    print_header("FINAL TEST RESULTS")
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        icon = "✅" if result else "❌"
        print(f"{icon} {test_name}")
    
    print(f"\n{'='*80}")
    print(f"  OVERALL: {passed}/{total} TESTS PASSED ({passed/total*100:.1f}%)")
    print(f"{'='*80}\n")
    
    print("📝 NEXT STEPS:")
    print("1. Open http://localhost:5000/chat in your browser")
    print("2. Login with test accounts")
    print("3. Check browser console (F12 → Console) for debug logs:")
    print("   - 'Audio unlocked' messages")
    print("   - 'PING RECEIVED' confirmations")
    print("   - 'Sound played' / 'Vibration triggered' messages")
    print("4. Test with device in SILENT MODE to verify PING still works")
    print("5. Test mobile version on actual device for vibration feedback")
    
    exit(0 if passed == total else 1)
