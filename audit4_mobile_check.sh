#!/bin/bash

echo "========================================="
echo "MOBILE APP AUDIT 4 - WHATSAPP FEATURES"
echo "========================================="

# Define search locations
MOBILE_FILES="mobile-chat.html mobile-chat.html templates/mobile-chat.html"
SETTINGS_FILES="mobile-settings.html mobile-settings.html templates/mobile-settings.html"

echo ""
echo "=== PRIORITY 1 FEATURES (Mobile) ==="
echo ""

# A1: GIF Support
echo "--- A1: GIF Support ---"
FOUND=0
for file in $MOBILE_FILES; do
    if [ -f "$file" ] && grep -qi "gif\|giphy\|tenor" "$file" 2>/dev/null; then
        echo "✅ PASS: GIF support found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "⚠️ WARNING: GIF support not found in mobile files"
fi

# A2: Sticker Support
echo ""
echo "--- A2: Sticker Support ---"
FOUND=0
for file in $MOBILE_FILES; do
    if [ -f "$file" ] && grep -qi "sticker" "$file" 2>/dev/null; then
        echo "✅ PASS: Sticker support found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "⚠️ WARNING: Sticker support not found in mobile files"
fi

# A3: Long-press Message Menu
echo ""
echo "--- A3: Long-press Message Menu ---"
FOUND=0
for file in $MOBILE_FILES; do
    if [ -f "$file" ] && grep -qi "contextmenu\|longpress\|message-menu" "$file" 2>/dev/null; then
        echo "✅ PASS: Long-press menu found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "❌ FAIL: Long-press menu not found in mobile files"
fi

# Check menu items
echo "  Checking menu items..."
for item in "Forward" "Star" "Reply" "React" "Copy" "Delete"; do
    FOUND=0
    for file in $MOBILE_FILES; do
        if [ -f "$file" ] && grep -qi "$item" "$file" 2>/dev/null; then
            echo "    ✅ $item found"
            FOUND=1
            break
        fi
    done
    if [ $FOUND -eq 0 ]; then
        echo "    ❌ $item missing"
    fi
done

# A4: Read Receipts Toggle
echo ""
echo "--- A4: Read Receipts Toggle ---"
FOUND=0
for file in $SETTINGS_FILES; do
    if [ -f "$file" ] && grep -qi "read.*receipt" "$file" 2>/dev/null; then
        echo "✅ PASS: Read receipts toggle found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "⚠️ WARNING: Read receipts toggle not found in mobile settings"
fi

# A5: Light/Dark Mode
echo ""
echo "--- A5: Light/Dark Mode ---"
FOUND=0
for file in $SETTINGS_FILES; do
    if [ -f "$file" ] && grep -qi "dark-mode\|dark_mode\|theme" "$file" 2>/dev/null; then
        echo "✅ PASS: Theme support found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "⚠️ WARNING: Theme support not found in mobile settings"
fi

# A6: Chat Wallpapers
echo ""
echo "--- A6: Chat Wallpapers ---"
FOUND=0
for file in $SETTINGS_FILES $MOBILE_FILES; do
    if [ -f "$file" ] && grep -qi "wallpaper" "$file" 2>/dev/null; then
        echo "✅ PASS: Wallpaper support found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "❌ FAIL: Wallpaper support not found in mobile files"
fi

# A7: Auto-Download Rules
echo ""
echo "--- A7: Auto-Download Rules ---"
FOUND=0
for file in $SETTINGS_FILES; do
    if [ -f "$file" ] && grep -qi "auto.*download\|download.*rule" "$file" 2>/dev/null; then
        echo "✅ PASS: Auto-download rules found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "⚠️ WARNING: Auto-download rules not found in mobile settings"
fi

# A8: Quick Replies
echo ""
echo "--- A8: Quick Replies ---"
FOUND=0
for file in $MOBILE_FILES; do
    if [ -f "$file" ] && grep -qi "quick-reply\|quick_reply\|/.*reply" "$file" 2>/dev/null; then
        echo "✅ PASS: Quick replies found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "❌ FAIL: Quick replies not found in mobile files"
fi

# A9: Away Messages
echo ""
echo "--- A9: Away Messages ---"
FOUND=0
for file in $SETTINGS_FILES; do
    if [ -f "$file" ] && grep -qi "away.*message" "$file" 2>/dev/null; then
        echo "✅ PASS: Away messages found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "⚠️ WARNING: Away messages not found in mobile settings"
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo "========================================="
echo "MOBILE AUDIT 4 SUMMARY"
echo "========================================="
echo ""
echo "Files checked:"
echo "  - mobile-chat.html"
echo "  - templates/mobile-chat.html (if exists)"
echo "  - mobile-settings.html"
echo "  - templates/mobile-settings.html (if exists)"
echo ""
echo "To complete mobile audit, manually verify:"
echo "  ☐ GIF picker opens and sends GIFs"
echo "  ☐ Sticker picker opens and sends stickers"
echo "  ☐ Long-press shows all 6 menu items"
echo "  ☐ Read receipts toggle works"
echo "  ☐ Dark mode switches correctly"
echo "  ☐ Wallpaper picker opens and changes background"
echo "  ☐ Auto-download rules save"
echo "  ☐ Quick replies work (type /)"
echo "  ☐ Away messages auto-reply"
echo ""
echo "========================================="
