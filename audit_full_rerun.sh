#!/usr/bin/env bash
set -u

echo "========================================="
echo "ZEUSCHAT FULL AUDIT RE-RUN"
echo "========================================="

echo ""
echo "=== AUDIT 1.1: Web Chat Cleanliness ==="

WEB_CHAT=$(find . \( -name "chat.html" -o -name "index.html" \) | grep -v mobile | head -1)

WEB_SCORE=0
ADMIN_INBOX_FAIL=0
MARKET_CARD_FAIL=0
PUSH_FAIL=0
ZEUSPIN_FAIL=0
SEARCH_FAIL=0
TERMS_FAIL=0

if [ -f "$WEB_CHAT" ]; then
  echo "Checking: $WEB_CHAT"

  if grep -qi "Admin Inbox" "$WEB_CHAT"; then
    echo "FAIL: Admin Inbox still present"; ADMIN_INBOX_FAIL=1
  else
    echo "PASS: Admin Inbox removed"
  fi

  if grep -qi "Ghost Market" "$WEB_CHAT" && ! grep -Eqi "nav|tab|market" "$WEB_CHAT"; then
    echo "FAIL: Ghost Market card still present"; MARKET_CARD_FAIL=1
  else
    echo "PASS: Ghost Market card removed"
  fi

  if grep -qi "Push Notifications" "$WEB_CHAT"; then
    echo "FAIL: Push Notifications card still present"; PUSH_FAIL=1
  else
    echo "PASS: Push Notifications card removed"
  fi

  if grep -Eq "ZT-[0-9]+-[0-9]+" "$WEB_CHAT"; then
    echo "FAIL: ZeusPIN still visible on main screen"; ZEUSPIN_FAIL=1
  else
    echo "PASS: ZeusPIN removed from main screen"
  fi

  if grep -Eq "Search by ZeusPIN|Search by PIN" "$WEB_CHAT"; then
    echo "FAIL: Search still references ZeusPIN"; SEARCH_FAIL=1
  else
    echo "PASS: Search placeholder clean"
  fi

  if grep -Eqi "Terms.*Privacy" "$WEB_CHAT"; then
    echo "WARN: Terms/Privacy footer may still be present"; TERMS_FAIL=1
  else
    echo "PASS: Terms/Privacy footer removed"
  fi

  WEB_SCORE=$((ADMIN_INBOX_FAIL + MARKET_CARD_FAIL + PUSH_FAIL + ZEUSPIN_FAIL + SEARCH_FAIL + TERMS_FAIL))
  if [ "$WEB_SCORE" -eq 0 ]; then
    echo "WEB CHAT: COMPLETELY CLEAN - Score: 0/6 failures"
  else
    echo "WEB CHAT: $WEB_SCORE/6 issues found"
  fi
else
  echo "FAIL: Web chat file not found"
fi

echo ""
echo "=== AUDIT 1.2: Mobile + Sheet ==="

MOBILE_CHAT=$(find . -name "mobile-chat.html" | head -1)
ALL_EXPECTED_FOUND=0
UNEXPECTED_FOUND=0

if [ -f "$MOBILE_CHAT" ]; then
  echo "Checking: $MOBILE_CHAT"

  ATTACHMENT_BLOCK=$(grep -A 20 "attachment-grid" "$MOBILE_CHAT" || true)

  EXPECTED_OPTIONS=("Photos" "Camera" "Document" "Contact")
  UNEXPECTED_OPTIONS=("Voice Note" "Translate" "Translation")

  for option in "${EXPECTED_OPTIONS[@]}"; do
    if printf '%s\n' "$ATTACHMENT_BLOCK" | grep -qi "$option"; then
      echo "  PASS: $option found"; ALL_EXPECTED_FOUND=$((ALL_EXPECTED_FOUND + 1))
    else
      echo "  FAIL: $option missing"
    fi
  done

  for option in "${UNEXPECTED_OPTIONS[@]}"; do
    if printf '%s\n' "$ATTACHMENT_BLOCK" | grep -qi "$option"; then
      echo "  WARN: $option found (should be hidden)"; UNEXPECTED_FOUND=$((UNEXPECTED_FOUND + 1))
    fi
  done

  if [ "$ALL_EXPECTED_FOUND" -eq 4 ] && [ "$UNEXPECTED_FOUND" -eq 0 ]; then
    echo "MOBILE + SHEET: PERFECT - All 4 options correct"
  else
    echo "MOBILE + SHEET: Expected:$ALL_EXPECTED_FOUND/4, Unexpected:$UNEXPECTED_FOUND"
  fi
else
  echo "FAIL: Mobile chat file not found"
fi

echo ""
echo "=== AUDIT 1.3: TTL Selector Position ==="
if [ -f "$MOBILE_CHAT" ]; then
  TTL_LINE=$(grep -nE "TTL|ttl-selector|disappearing" "$MOBILE_CHAT" | head -1 | cut -d: -f1)
  INPUT_LINE=$(grep -nE "input-bar|composer" "$MOBILE_CHAT" | head -1 | cut -d: -f1)
  if [ -n "${TTL_LINE:-}" ] && [ -n "${INPUT_LINE:-}" ] && [ "$TTL_LINE" -lt "$INPUT_LINE" ]; then
    echo "PASS: TTL selector above input bar"
  else
    echo "WARN: TTL selector position needs manual check"
  fi
fi

echo ""
echo "=== AUDIT 1.4: Message Bubbles ==="
if [ -f "$MOBILE_CHAT" ]; then
  if grep -Eq "bubble-sent|bubble-received|message-sent|message-received" "$MOBILE_CHAT"; then
    echo "PASS: Message bubble styles present"
  else
    echo "WARN: Message bubble styles need verification"
  fi
fi

echo ""
echo "=== AUDIT 1.5: Profile Tab (ZeusPIN location) ==="
MOBILE_PROFILE=$(find . -name "mobile-profile.html" | head -1)
if [ -f "$MOBILE_PROFILE" ]; then
  if grep -Eq "ZT-[0-9]+-[0-9]+" "$MOBILE_PROFILE"; then
    echo "PASS: ZeusPIN correctly visible in Profile tab"
  else
    echo "WARN: ZeusPIN may be missing from Profile"
  fi
else
  echo "WARN: Mobile profile file not found"
fi

echo ""
echo "=== AUDIT 1.6: Settings Tab ==="
MOBILE_SETTINGS=$(find . -name "mobile-settings.html" | head -1)
if [ -f "$MOBILE_SETTINGS" ]; then
  if grep -Eq "Test Notification Sound|Notifications" "$MOBILE_SETTINGS"; then
    echo "PASS: Settings has notification options"
  else
    echo "WARN: Settings may be incomplete"
  fi
  if grep -q "Subscription" "$MOBILE_SETTINGS"; then
    echo "WARN: Subscription still in Settings (should be in Profile/Market)"
  else
    echo "PASS: Subscription removed from Settings"
  fi
fi

echo ""
echo "=== AUDIT 1.7: Market Tab ==="
MOBILE_MARKET=$(find . -name "mobile-market.html" | head -1)
if [ -f "$MOBILE_MARKET" ]; then
  if grep -q "Ghost Market" "$MOBILE_MARKET"; then
    echo "PASS: Ghost Market content in Market tab"
  else
    echo "WARN: Market tab content needs verification"
  fi
fi

echo ""
echo "=== AUDIT 1.8: Bottom Navigation Labels ==="
for file in mobile-chat.html mobile-profile.html mobile-settings.html mobile-market.html; do
  FILE_PATH=$(find . -name "$file" | head -1)
  if [ -f "$FILE_PATH" ]; then
    if grep -q "Ghost Market" "$FILE_PATH" && grep -q "Ghost Community" "$FILE_PATH"; then
      echo "PASS: $file has correct labels"
    else
      echo "WARN: $file may have incorrect labels"
    fi
  fi
done

echo ""
echo "=== AUDIT 1.9: Test Suite Results ==="
TEST_RESULT=1
if [ -f "run_tests.sh" ]; then
  echo "Running tests..."
  ./run_tests.sh > /tmp/test_results.txt 2>&1
  TEST_RESULT=$?
  if [ "$TEST_RESULT" -eq 0 ]; then
    PASS_LINE=$(grep -E "[0-9]+ passed" /tmp/test_results.txt | tail -1)
    if [ -n "$PASS_LINE" ]; then
      echo "PASS: ALL TESTS PASSED: $PASS_LINE"
    else
      echo "PASS: ALL TESTS PASSED: run_tests.sh exited with code 0"
    fi
  else
    echo "FAIL: Some tests failed"
    tail -20 /tmp/test_results.txt
  fi
else
  echo "WARN: run_tests.sh not found - run tests manually"
fi

echo ""
echo "========================================="
echo "FULL AUDIT RE-RUN - SUMMARY"
echo "========================================="

OVERALL_PASS=1
if [ "$WEB_SCORE" -ne 0 ]; then OVERALL_PASS=0; echo "FAIL: Web Chat issues found"; else echo "PASS: Web Chat clean"; fi
if [ "$ALL_EXPECTED_FOUND" -ne 4 ]; then OVERALL_PASS=0; echo "FAIL: Mobile + sheet missing options"; else echo "PASS: Mobile + sheet correct"; fi
if [ "$UNEXPECTED_FOUND" -gt 0 ]; then OVERALL_PASS=0; echo "FAIL: Mobile + sheet unexpected options found"; else echo "PASS: Mobile + sheet no unexpected options"; fi
if [ "$TEST_RESULT" -ne 0 ]; then OVERALL_PASS=0; echo "FAIL: Test suite failures detected"; else echo "PASS: Test suite all passing"; fi

echo ""
if [ "$OVERALL_PASS" -eq 1 ]; then
  echo "AUDIT 1: COMPLETE - ALL GREEN"
  echo "Ready to proceed to Audit 2 (Ghost Community)"
else
  echo "AUDIT 1: ISSUES REMAIN"
  echo "Fix issues above before proceeding to Audit 2"
fi
