#!/bin/bash

echo "========================================="
echo "FULL MOBILE AUDIT V2 (Updated Patterns)"
echo "========================================="

PASS=0
FAIL=0
WARN=0

check() {
    local name=$1
    local pattern=$2
    local file=$3

    if [ -f "$file" ] && grep -Eqi "$pattern" "$file" 2>/dev/null; then
        echo "✅ PASS: $name"
        ((PASS++))
        return 0
    else
        echo "⚠️ WARNING: $name (pattern not matched)"
        ((WARN++))
        return 1
    fi
}

echo ""
echo "=== PHASE 1: CLEAN STRUCTURE ==="
check "⊕ Folder" "attachment-sheet|attach-options" "mobile-chat.html"
check "Photos in ⊕ sheet" "Photos" "mobile-chat.html"
check "Camera in ⊕ sheet" "Camera" "mobile-chat.html"
check "⊕ button" "attach-button|⊕" "mobile-chat.html"
check "🎙️ button" "voice-button|🎙️" "mobile-chat.html"
check "TTL Selector" "TTL|disappearing" "mobile-chat.html"
check "Message Bubbles" "bubble-sent|message-sent" "mobile-chat.html"
check "Bottom Navigation" "Chats|Market|Ghost|Profile|Settings" "mobile-chat.html"

echo ""
echo "=== PHASE 2: GHOST COMMUNITY ==="
check "For You Feed" "foryou|for-you" "mobile-community.html"
check "Following Feed" "following" "mobile-community.html"
check "Trending Feed" "trending" "mobile-community.html"
check "Like Button" "like-button|onclick.*like" "mobile-community.html"
check "Comment Button" "comment-button|onclick.*comment" "mobile-community.html"
check "Share Button" "share-button|onclick.*share" "mobile-community.html"

echo ""
echo "=== PHASE 3: GHOST MARKET ==="
check "Save Button" "save-button|onclick.*save" "mobile-market.html"
check "Inquire Button" "inquire|message.*seller" "mobile-market.html"

echo ""
echo "=== PHASE 4: WHATSAPP FEATURES ==="
check "GIF Support" "gif|giphy" "mobile-chat.html"
check "Sticker Support" "sticker" "mobile-chat.html"
check "Long-press Copy" "Copy" "mobile-chat.html"
check "Quick Replies" "quick-reply|quick_reply" "mobile-chat.html"

echo ""
echo "========================================="
echo "RESULTS: PASS=$PASS, FAIL=$FAIL, WARN=$WARN"
echo "========================================="
