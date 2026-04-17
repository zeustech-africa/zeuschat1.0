#!/usr/bin/env bash
set +e

echo "========================================="
echo "FULL MOBILE APP AUDIT"
echo "Verifying ALL implemented features"
echo "========================================="

MOBILE_CHAT="mobile-chat.html"
MOBILE_SETTINGS="mobile-settings.html"
MOBILE_PROFILE="mobile-profile.html"
MOBILE_MARKET="mobile-market.html"
MOBILE_COMMUNITY="mobile-community.html"
MOBILE_GHOST="mobile-ghost.html"
TEMPLATE_DIRS="templates/ templates/mobile/"

echo ""
echo "=== PHASE 1: CLEAN STRUCTURE ==="
echo ""

echo "--- 1.1 ⊕ Folder (Bottom Sheet) ---"
FOUND=0
for file in $MOBILE_CHAT; do
    if [ -f "$file" ] && grep -q "attach-option\|attach-options\|bottom-sheet" "$file" 2>/dev/null; then
        echo "✅ PASS: ⊕ folder found in $file"
        FOUND=1
        break
    fi
done
if [ $FOUND -eq 0 ]; then
    echo "❌ FAIL: ⊕ folder not found"
fi

echo ""
echo "--- 1.2 ⊕ Sheet Options ---"
OPTIONS=("Photos" "Camera" "Document" "Contact")
for option in "${OPTIONS[@]}"; do
    FOUND=0
    for file in $MOBILE_CHAT; do
        if [ -f "$file" ] && grep -qi "$option" "$file" 2>/dev/null; then
            echo "✅ $option found"
            FOUND=1
            break
        fi
    done
    if [ $FOUND -eq 0 ]; then
        echo "❌ $option missing"
    fi
done

echo ""
echo "--- 1.3 Input Bar Elements ---"
for element in "⊕" "😊" "🎙️"; do
    if [ -f "$MOBILE_CHAT" ] && grep -q "$element" "$MOBILE_CHAT" 2>/dev/null; then
        echo "✅ $element found"
    else
        echo "❌ $element missing"
    fi
done

echo ""
echo "--- 1.4 TTL Selector ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "TTL\|ttl-selector\|disappearing" "$MOBILE_CHAT" 2>/dev/null; then
    echo "✅ PASS: TTL selector found"
else
    echo "❌ FAIL: TTL selector missing"
fi

echo ""
echo "--- 1.5 Message Bubbles ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "bubble-sent\|bubble-received\|message-sent" "$MOBILE_CHAT" 2>/dev/null; then
    echo "✅ PASS: Message bubbles styled"
else
    echo "⚠️ WARNING: Message bubble styles need verification"
fi

echo ""
echo "--- 1.6 Read Receipts ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "✓\|read-receipt" "$MOBILE_CHAT" 2>/dev/null; then
    echo "✅ PASS: Read receipts present"
else
    echo "⚠️ WARNING: Read receipts need verification"
fi

echo ""
echo "--- 1.7 No ZeusPIN in Chat ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "ZT-[0-9]*-[0-9]*" "$MOBILE_CHAT" 2>/dev/null; then
    echo "⚠️ WARNING: ZeusPIN may be visible in chat"
else
    echo "✅ PASS: No ZeusPIN in chat"
fi

echo ""
echo "--- 1.8 Bottom Navigation ---"
TABS=("Chats" "Market" "Ghost" "Profile" "Settings")
for tab in "${TABS[@]}"; do
    if [ -f "$MOBILE_CHAT" ] && grep -q "$tab" "$MOBILE_CHAT" 2>/dev/null; then
        echo "✅ $tab tab found"
    else
        echo "❌ $tab tab missing"
    fi
done

echo ""
echo "=== PHASE 2: GHOST COMMUNITY ==="
echo ""

echo "--- 2.1 Feed Types ---"
for feed in "foryou\|for-you" "following" "trending"; do
    if [ -f "$MOBILE_COMMUNITY" ] && grep -qi "$feed" "$MOBILE_COMMUNITY" 2>/dev/null; then
        echo "✅ $feed feed found"
    else
        echo "⚠️ $feed feed may be missing"
    fi
done

echo ""
echo "--- 2.2 Post Creation ---"
if [ -f "$MOBILE_COMMUNITY" ] && grep -q "create.*post\|composer" "$MOBILE_COMMUNITY" 2>/dev/null; then
    echo "✅ PASS: Post composer found"
else
    echo "⚠️ WARNING: Post composer may be missing"
fi

echo ""
echo "--- 2.3 Hashtags ---"
if [ -f "$MOBILE_COMMUNITY" ] && grep -q "hashtag\|#" "$MOBILE_COMMUNITY" 2>/dev/null; then
    echo "✅ PASS: Hashtag support found"
else
    echo "⚠️ WARNING: Hashtag support may be missing"
fi

echo ""
echo "--- 2.4 Engagement Buttons ---"
for btn in "like" "comment" "share"; do
    if [ -f "$MOBILE_COMMUNITY" ] && grep -qi "$btn" "$MOBILE_COMMUNITY" 2>/dev/null; then
        echo "✅ $btn button found"
    else
        echo "⚠️ $btn button may be missing"
    fi
done

echo ""
echo "=== PHASE 3: GHOST MARKET ==="
echo ""

echo "--- 3.1 Marketplace Feed ---"
if [ -f "$MOBILE_MARKET" ] && grep -q "market.*feed\|listing" "$MOBILE_MARKET" 2>/dev/null; then
    echo "✅ PASS: Marketplace feed found"
else
    echo "⚠️ WARNING: Marketplace feed may be missing"
fi

echo ""
echo "--- 3.2 Listing Creation ---"
if [ -f "$MOBILE_MARKET" ] && grep -q "create.*listing\|sell" "$MOBILE_MARKET" 2>/dev/null; then
    echo "✅ PASS: Listing creation found"
else
    echo "⚠️ WARNING: Listing creation may be missing"
fi

echo ""
echo "--- 3.3 Save/Inquire ---"
for action in "save" "inquire\|message"; do
    if [ -f "$MOBILE_MARKET" ] && grep -qi "$action" "$MOBILE_MARKET" 2>/dev/null; then
        echo "✅ $action found"
    else
        echo "⚠️ $action may be missing"
    fi
done

echo ""
echo "=== PHASE 4: WHATSAPP FEATURES ==="
echo ""

echo "--- 4.1 GIF Support ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "gif\|giphy" "$MOBILE_CHAT" 2>/dev/null; then
    echo "✅ PASS: GIF support found"
else
    echo "❌ FAIL: GIF support missing"
fi

echo ""
echo "--- 4.2 Sticker Support ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "sticker" "$MOBILE_CHAT" 2>/dev/null; then
    echo "✅ PASS: Sticker support found"
else
    echo "❌ FAIL: Sticker support missing"
fi

echo ""
echo "--- 4.3 Long-press Menu ---"
MENU_ITEMS=("Forward" "Star" "Reply" "React" "Copy" "Delete")
for item in "${MENU_ITEMS[@]}"; do
    if [ -f "$MOBILE_CHAT" ] && grep -q "$item" "$MOBILE_CHAT" 2>/dev/null; then
        echo "✅ $item found"
    else
        echo "❌ $item missing"
    fi
done

echo ""
echo "--- 4.4 Read Receipts Toggle ---"
if [ -f "$MOBILE_SETTINGS" ] && grep -q "read.*receipt" "$MOBILE_SETTINGS" 2>/dev/null; then
    echo "✅ PASS: Read receipts toggle found"
else
    echo "❌ FAIL: Read receipts toggle missing"
fi

echo ""
echo "--- 4.5 Dark Mode ---"
if [ -f "$MOBILE_SETTINGS" ] && grep -q "dark\|theme" "$MOBILE_SETTINGS" 2>/dev/null; then
    echo "✅ PASS: Dark mode support found"
else
    echo "⚠️ WARNING: Dark mode may be missing"
fi

echo ""
echo "--- 4.6 Chat Wallpapers ---"
if [ -f "$MOBILE_SETTINGS" ] && grep -q "wallpaper" "$MOBILE_SETTINGS" 2>/dev/null; then
    echo "✅ PASS: Wallpaper support found"
else
    echo "❌ FAIL: Wallpaper support missing"
fi

echo ""
echo "--- 4.7 Auto-Download Rules ---"
if [ -f "$MOBILE_SETTINGS" ] && grep -q "auto.*download" "$MOBILE_SETTINGS" 2>/dev/null; then
    echo "✅ PASS: Auto-download found"
else
    echo "⚠️ WARNING: Auto-download may be missing"
fi

echo ""
echo "--- 4.8 Quick Replies ---"
if [ -f "$MOBILE_CHAT" ] && grep -q "quick.*reply" "$MOBILE_CHAT" 2>/dev/null; then
    echo "✅ PASS: Quick replies found"
else
    echo "⚠️ WARNING: Quick replies may be missing"
fi

echo ""
echo "--- 4.9 Away Messages ---"
if [ -f "$MOBILE_SETTINGS" ] && grep -q "away.*message" "$MOBILE_SETTINGS" 2>/dev/null; then
    echo "✅ PASS: Away messages found"
else
    echo "⚠️ WARNING: Away messages may be missing"
fi

echo ""
echo "=== PHASE 5: VIDEO OPTIMIZATION ==="
echo ""

echo "--- 5.1 Connection Detection ---"
if [ -f "static/js/connection-detector.js" ]; then
    echo "✅ PASS: Connection detector exists"
else
    echo "❌ FAIL: Connection detector missing"
fi

echo ""
echo "--- 5.2 Data Warning ---"
if [ -f "static/js/data-warning.js" ]; then
    echo "✅ PASS: Data warning exists"
else
    echo "❌ FAIL: Data warning missing"
fi

echo ""
echo "--- 5.3 User Preference ---"
if [ -f "static/js/video-preference.js" ]; then
    echo "✅ PASS: Video preference exists"
else
    echo "❌ FAIL: Video preference missing"
fi

echo ""
echo "--- 5.4 Scripts in Mobile Chat ---"
if [ -f "$MOBILE_CHAT" ]; then
    for script in connection-detector data-warning video-preference; do
        if grep -q "$script.js" "$MOBILE_CHAT" 2>/dev/null; then
            echo "✅ $script.js included"
        else
            echo "❌ $script.js missing from mobile chat"
        fi
    done
fi
