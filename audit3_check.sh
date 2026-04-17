#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "========================================="
echo "AUDIT 3: GHOST MARKET + MOBILE BACKGROUNDS"
echo "========================================="

echo ""
echo "=== PART A: GHOST MARKET (Facebook Marketplace Mirror) ==="

check() {
  local label="$1"
  local pattern="$2"
  local mode="${3:-PASS}"
  echo ""
  echo "--- ${label} ---"
  if grep -Eqi "$pattern" app.py 2>/dev/null; then
    echo "✅ PASS: ${label}"
  else
    if [[ "$mode" == "WARN" ]]; then
      echo "⚠️ WARNING: ${label} (pattern not found)"
    else
      echo "❌ FAIL: ${label} (pattern not found)"
    fi
  fi
}

check "A1 Marketplace feed endpoint exists" "ghost/market/feed|market.*feed|marketplace"
check "A2 Listing creation endpoint exists" "ghost/market/listing|create.*listing|new.*listing"
check "A3 AI auto-listing endpoint exists" "ghost/market/ai/generate-listing|ai.*listing|auto.*listing" WARN
check "A4 AI price suggestion exists" "ghost/market/ai/suggest-price|price.*suggest|suggest.*price" WARN
check "A5 Save listing exists" "listing/.*/save|save.*listing|bookmark"
check "A6 Inquire to seller exists" "listing/.*/inquire|inquire|message.*seller"
check "A7 AI auto-reply exists" "listing/.*/auto-reply|auto[_-]?reply" WARN
check "A8 Mark as sold exists" "mark-sold|mark.*sold"
check "A9 Seller ratings exist" "seller/.*/rate|rating.*seller|seller.*rating" WARN
check "A10 Seller analytics exists" "ghost/market/analytics|seller.*analytics|analytics.*seller" WARN
check "A11 Boost listing exists" "listing/.*/boost|boost.*listing" WARN
check "A12 Categories/filters exist" "category|filter"

echo ""
echo "=== PART B: MOBILE CHAT 4K BACKGROUND ==="
MOBILE_CHAT="templates/mobile-chat.html"
if [[ -f "$MOBILE_CHAT" ]]; then
  echo "Found mobile chat at: $MOBILE_CHAT"
  if grep -Eq "chat-background-video|chat-bg-4k\.mp4" "$MOBILE_CHAT"; then
    echo "✅ PASS: Mobile background video wired"
  else
    echo "❌ FAIL: Mobile background video wiring missing"
  fi
else
  echo "❌ FAIL: templates/mobile-chat.html not found"
fi

echo ""
echo "=== PART C: CROSS-PLATFORM SYNC CHECK ==="
WEB_CHAT="chat.html"
if [[ -f "$WEB_CHAT" ]]; then
  if grep -Eqi "video-bg|background.*video|source src=" "$WEB_CHAT"; then
    WEB_VIDEO_SRC=$(grep -Eo '(source src=")([^"]+)' "$WEB_CHAT" | head -1 | sed -E 's/source src="//')
    echo "✅ PASS: Web chat has background video"
    echo "Web video source: ${WEB_VIDEO_SRC:-unknown}"
  else
    echo "⚠️ WARNING: Web chat background video not detected"
  fi
else
  echo "⚠️ WARNING: web chat file not found"
fi

mkdir -p static/videos
if [[ -f static/videos/README.md ]]; then
  echo "✅ PASS: static/videos/README.md exists"
else
  echo "⚠️ WARNING: static/videos/README.md missing"
fi

echo ""
echo "=== PART D: MOBILE OPTIMIZATION CHECK ==="
if grep -Eqi "saveData|prefers-reduced-motion|initMobileBackgroundVideo" "$MOBILE_CHAT"; then
  echo "✅ PASS: Mobile optimization logic present"
else
  echo "⚠️ WARNING: Mobile optimization logic not found"
fi

echo ""
echo "=== PART E: GHOST MARKET SMOKE TESTS ==="
if [[ -f tests/test_ghost_market.py ]]; then
  echo "Running tests/test_ghost_market.py ..."
  /opt/local/bin/python3.14 -m pytest -q tests/test_ghost_market.py --tb=short
  echo "✅ PASS: Ghost Market smoke tests passed"
else
  echo "⚠️ WARNING: tests/test_ghost_market.py not found; skipped"
fi

echo ""
echo "========================================="
echo "AUDIT 3 SUMMARY"
echo "========================================="
echo "Manual checklist (Y/N):"
echo "- Marketplace feed loads"
echo "- Can create listing with photos"
echo "- AI auto-listing works"
echo "- AI price suggestion works"
echo "- Can save/bookmark listings"
echo "- Can inquire to seller"
echo "- AI auto-reply works"
echo "- Can mark as sold"
echo "- Seller ratings work"
echo "- Seller analytics show data"
echo "- Can boost listing"
echo "- Categories/filters work"
echo "- Web chat has background video"
echo "- Mobile chat has same background source intent"
echo "- Video plays smoothly on mobile"
echo "- Video does not impact performance"
echo "- Background does not interfere with chat UI"
