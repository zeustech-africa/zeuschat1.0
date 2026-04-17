#!/usr/bin/env bash
set -u

PASS=0
FAIL=0

check_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$file"
  else
    grep -Eq "$pattern" "$file"
  fi

  if [[ $? -eq 0 ]]; then
    echo "[PASS] $label"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] $label"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== VERIFY WHATSAPP FEATURES UI (MOBILE + WEB) ==="

check_contains "mobile-settings.html" "id=\"theme-select\"" "Mobile settings has theme selector"
check_contains "templates/mobile-settings.html" "id=\"theme-select\"" "Template mobile settings has theme selector"
check_contains "settings.html" "id=\"theme-select\"" "Web settings has theme selector"

check_contains "mobile-settings.html" "id=\"wallpaper-upload\"" "Mobile settings has wallpaper upload"
check_contains "templates/mobile-settings.html" "id=\"wallpaper-upload\"" "Template mobile settings has wallpaper upload"
check_contains "settings.html" "id=\"wallpaper-upload\"" "Web settings has wallpaper upload"

check_contains "mobile-settings.html" "function setTheme\(" "Mobile settings has setTheme()"
check_contains "templates/mobile-settings.html" "function setTheme\(" "Template mobile settings has setTheme()"
check_contains "settings.html" "function setTheme\(" "Web settings has setTheme()"

check_contains "mobile-chat.html" "function openGifPicker\(" "Root mobile chat has GIF picker"
check_contains "templates/mobile-chat.html" "function openGifPicker\(" "Template mobile chat has GIF picker"

check_contains "mobile-chat.html" "function openStickerPicker\(" "Root mobile chat has sticker picker"
check_contains "templates/mobile-chat.html" "function openStickerPicker\(" "Template mobile chat has sticker picker"

check_contains "mobile-chat.html" "function showQuickReplies\(" "Root mobile chat has quick replies"
check_contains "templates/mobile-chat.html" "function showQuickReplies\(" "Template mobile chat has quick replies"

check_contains "templates/mobile-chat.html" "id=\"quick-replies-panel\"" "Template mobile chat quick replies panel exists"
check_contains "chat.html" "zeuschat_wallpaper_color" "Web chat applies wallpaper preferences"

TOTAL=$((PASS + FAIL))
echo "=== RESULT: PASS=$PASS FAIL=$FAIL TOTAL=$TOTAL ==="

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
