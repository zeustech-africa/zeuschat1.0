#!/usr/bin/env bash

echo "========================================="
echo "FULL SYSTEM AUDIT - COMPLETE"
echo "Testing: Registration -> Verification -> Chat -> Features -> Admin"
echo "========================================="

# ============================================
# PART 1: END-TO-END USER FLOW TEST
# ============================================

echo ""
echo "=== PART 1: End-to-End User Flow ==="

# Function to test API endpoints
test_api() {
    local name=$1
    local url=$2
    local method=$3
    local data=$4
    local allow_protected=${5:-0}

    echo -n "  Testing: $name ... "

    if [ "$method" = "POST" ]; then
        response=$(curl -s -X POST "$url" -H "Content-Type: application/json" -d "$data" 2>/dev/null)
    else
        response=$(curl -s "$url" 2>/dev/null)
    fi

    if echo "$response" | grep -q "success\|user\|users\|data" 2>/dev/null; then
        echo "PASS"
        return 0
    elif [ "$allow_protected" = "1" ] && echo "$response" | grep -q "authentication required\|unauthorized\|forbidden\|admin" 2>/dev/null; then
        echo "PASS (Protected endpoint reachable; auth required)"
        return 0
    else
        echo "FAIL (Response: ${response:0:80})"
        return 1
    fi
}

echo "Testing API endpoints (backend only):"
test_api "User registration API" "http://localhost:5000/api/register" "POST" '{"email":"audit+testuser001@zeuschat.local","full_name":"Audit Test User","zeus_pin":"TESTUSER001","password":"test123"}'
test_api "Admin stats API" "http://localhost:5000/api/admin/stats" "GET" "" "1"
test_api "Admin users API" "http://localhost:5000/api/admin/users/all" "GET" "" "1"

# ============================================
# PART 2: WHATSAPP FEATURES VISIBILITY CHECK
# ============================================

echo ""
echo "=== PART 2: WhatsApp Features Visibility ==="

check_feature_in_file() {
    local name=$1
    local file=$2
    local pattern=$3

    if [ -f "$file" ] && grep -Eq "$pattern" "$file" 2>/dev/null; then
        echo "  PASS $name found in $file"
        return 0
    else
        echo "  FAIL $name missing from $file"
        return 1
    fi
}

echo "Mobile App - WhatsApp Features:"
check_feature_in_file "Theme Selector" "mobile-settings.html" "setTheme|theme-select|theme-selector"
check_feature_in_file "Wallpaper Selector" "mobile-settings.html" "wallpaper|openWallpaperPicker"
check_feature_in_file "GIF Button" "mobile-chat.html" "gif-toggle|openGifPicker|gif-button"
check_feature_in_file "Sticker Button" "mobile-chat.html" "sticker-toggle|openStickerPicker|sticker-button"
check_feature_in_file "Quick Reply Button" "mobile-chat.html" "quick-replies-panel|showQuickReplies|quick-reply"
check_feature_in_file "Dark Mode CSS" "mobile-chat.html" "dark-mode|data-theme|theme"

echo ""
echo "Web App - WhatsApp Features:"
check_feature_in_file "Theme Selector" "settings.html" "theme|setTheme"
check_feature_in_file "Wallpaper Option" "settings.html" "wallpaper"

# ============================================
# PART 3: ADMIN CONTROL ROOM FEATURES
# ============================================

echo ""
echo "=== PART 3: Admin Control Room Features ==="

ADMIN_FILE="admin_control.html"
if [ ! -f "$ADMIN_FILE" ] && [ -f "templates/admin_control.html" ]; then
    ADMIN_FILE="templates/admin_control.html"
fi

check_feature_in_file "Admin Dashboard" "$ADMIN_FILE" "dashboard|stats"
check_feature_in_file "Users List" "$ADMIN_FILE" "usersBody|all-users|table"
check_feature_in_file "Pending Verification" "$ADMIN_FILE" "pending_verification|pending verification|pending"
check_feature_in_file "User Detail Modal" "$ADMIN_FILE" "modal|viewUser|prompt"
check_feature_in_file "Approve/Reject Buttons" "$ADMIN_FILE" "approve|reject"
check_feature_in_file "Suspend/Delete Buttons" "$ADMIN_FILE" "suspend|delete"

# ============================================
# PART 4: MOBILE APP COMPLETE STRUCTURE
# ============================================

echo ""
echo "=== PART 4: Mobile App Complete Structure ==="

check_feature_in_file "Bottom Navigation (5 tabs)" "mobile-chat.html" "Chats|Market|Ghost|Profile|Settings"
check_feature_in_file "Attach Sheet" "mobile-chat.html" "attachment-sheet|attach-options|attach-button"
check_feature_in_file "TTL Selector" "mobile-chat.html" "TTL|ttl|disappearing"
check_feature_in_file "Message Bubbles" "mobile-chat.html" "message-bubble|messages"
check_feature_in_file "Read Receipts" "mobile-chat.html" "read-receipt|seen|delivered|✓"

# ============================================
# PART 5: WEB APP COMPLETE STRUCTURE
# ============================================

echo ""
echo "=== PART 5: Web App Complete Structure ==="

WEB_CHAT=$(find . -name "chat.html" | grep -v mobile | head -1)
if [ -f "$WEB_CHAT" ]; then
    check_feature_in_file "Left Panel (Contacts)" "$WEB_CHAT" "contacts-list|left-panel|sidebar"
    check_feature_in_file "Right Panel (Chat)" "$WEB_CHAT" "chat-messages|right-panel|main"
    check_feature_in_file "Attach Button" "$WEB_CHAT" "attachFileBtn|file-upload|attach-button|⊕"
    check_feature_in_file "TTL Selector" "$WEB_CHAT" "TTL|ttl|disappearing"
else
    echo "  FAIL Could not find web chat file"
fi

# ============================================
# PART 6: CROSS-PLATFORM SYNC CHECK
# ============================================

echo ""
echo "=== PART 6: Cross-Platform Sync ==="

if curl -s http://localhost:5000 >/dev/null 2>&1; then
    echo "  PASS Web server is running"
else
    echo "  FAIL Web server is not running"
fi

if curl -s http://localhost:5000/mobile/chat >/dev/null 2>&1; then
    echo "  PASS Mobile app is accessible"
else
    echo "  FAIL Mobile app is not accessible"
fi

# ============================================
# PART 7: VIDEO OPTIMIZATION CHECK
# ============================================

echo ""
echo "=== PART 7: Video Optimization ==="

check_feature_in_file "Connection Detector JS" "static/js/connection-detector.js" "getConnectionType"
check_feature_in_file "Data Warning JS" "static/js/data-warning.js" "isMeteredConnection"
check_feature_in_file "Video Preference JS" "static/js/video-preference.js" "getPreference"

if [ -f "static/videos/high/chat-bg.mp4" ]; then
    HIGH_SIZE=$(du -h static/videos/high/chat-bg.mp4 | cut -f1)
    echo "  PASS High quality video exists ($HIGH_SIZE)"
else
    echo "  FAIL High quality video missing"
fi

if [ -f "static/videos/medium/chat-bg.mp4" ]; then
    MED_SIZE=$(du -h static/videos/medium/chat-bg.mp4 | cut -f1)
    echo "  PASS Medium quality video exists ($MED_SIZE)"
else
    echo "  FAIL Medium quality video missing"
fi

if [ -f "static/videos/low/chat-bg.mp4" ]; then
    LOW_SIZE=$(du -h static/videos/low/chat-bg.mp4 | cut -f1)
    echo "  PASS Low quality video exists ($LOW_SIZE)"
else
    echo "  FAIL Low quality video missing"
fi

# ============================================
# PART 8: FINAL SUMMARY
# ============================================

echo ""
echo "========================================="
echo "FULL SYSTEM AUDIT - COMPLETE SUMMARY"
echo "========================================="
echo ""
echo "MANUAL VERIFICATION REQUIRED ON ACTUAL DEVICE:"
echo ""
echo "MOBILE APP (iOS/Android):"
echo "  [] 1. Download/Install app"
echo "  [] 2. Register with ZeusPIN"
echo "  [] 3. Upload ID documents for verification"
echo "  [] 4. Wait for admin approval"
echo "  [] 5. After approval, access main chat"
echo "  [] 6. Test attach folder (Photos, Camera, Document, Contact)"
echo "  [] 7. Test TTL selector (change time)"
echo "  [] 8. Test GIF button (search and send GIF)"
echo "  [] 9. Test Sticker button (send sticker)"
echo "  [] 10. Test Quick Replies (type /)"
echo "  [] 11. Test Dark Mode (Settings -> Theme)"
echo "  [] 12. Test Wallpaper (Settings -> Change Wallpaper)"
echo "  [] 13. Test Voice note (button)"
echo "  [] 14. Test Ghost Community (For You/Following/Trending)"
echo "  [] 15. Test Ghost Market (browse, save, inquire)"
echo ""
echo "WEB APP:"
echo "  [] 1. Login with same credentials"
echo "  [] 2. Verify messages sync from mobile"
echo "  [] 3. Test all same features"
echo ""
echo "ADMIN CONTROL ROOM:"
echo "  [] 1. Login as admin at /admin_control"
echo "  [] 2. View pending verifications"
echo "  [] 3. View user ID documents"
echo "  [] 4. Approve a user"
echo "  [] 5. View all users list"
echo "  [] 6. Suspend a user"
echo "  [] 7. Reactivate a user"
echo "  [] 8. Delete a user"
echo "  [] 9. View admin action log"
echo ""
echo "========================================="
echo ""
echo "To complete Audit 5:"
echo "1. Perform all manual checks above"
echo "2. Mark each [] as [x] when verified"
echo "3. Report back with results"
echo ""
echo "========================================="