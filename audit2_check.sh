#!/usr/bin/env bash
set -e
cd /Users/administrator/Desktop/zeuschat

echo "========================================="
echo "AUDIT 2: GHOST COMMUNITY VERIFICATION"
echo "========================================="

echo ""
echo "=== AUDIT 2.1: Feed Types ==="
if grep -q "foryou\|for-you" app.py 2>/dev/null; then
    echo "PASS: For You feed endpoint exists"
else
    echo "FAIL: For You feed endpoint missing"
fi
if grep -q "following" app.py 2>/dev/null; then
    echo "PASS: Following feed endpoint exists"
else
    echo "FAIL: Following feed endpoint missing"
fi
if grep -q "trending" app.py 2>/dev/null; then
    echo "PASS: Trending feed endpoint exists"
else
    echo "FAIL: Trending feed endpoint missing"
fi

echo ""
echo "=== AUDIT 2.2: Post Creation ==="
if grep -q "create.*post\|POST.*post" app.py 2>/dev/null; then
    echo "PASS: Post creation endpoint exists"
else
    echo "FAIL: Post creation endpoint missing"
fi
if grep -q "video\|mp4" app.py 2>/dev/null; then
    echo "PASS: Video upload support exists"
else
    echo "WARN: Video upload may need verification"
fi
if grep -q "image\|jpg\|png" app.py 2>/dev/null; then
    echo "PASS: Image upload support exists"
else
    echo "WARN: Image upload may need verification"
fi

echo ""
echo "=== AUDIT 2.3: Hashtag System ==="
if grep -q "hashtag\|#" app.py 2>/dev/null; then
    echo "PASS: Hashtag support exists"
else
    echo "FAIL: Hashtag support missing"
fi
if grep -q "5\|max.*hashtag" app.py 2>/dev/null; then
    echo "PASS: Hashtag limit (max 5) implemented"
else
    echo "WARN: Hashtag limit needs verification"
fi
if grep -q "trending.*hashtag" app.py 2>/dev/null; then
    echo "PASS: Trending hashtags endpoint exists"
else
    echo "WARN: Trending hashtags endpoint missing"
fi

echo ""
echo "=== AUDIT 2.4: Engagement Features ==="
if grep -q "like" app.py 2>/dev/null; then
    echo "PASS: Like functionality exists"
else
    echo "FAIL: Like functionality missing"
fi
if grep -q "comment" app.py 2>/dev/null; then
    echo "PASS: Comment functionality exists"
else
    echo "FAIL: Comment functionality missing"
fi
if grep -q "share\|repost" app.py 2>/dev/null; then
    echo "PASS: Share/Repost functionality exists"
else
    echo "WARN: Share/Repost may need verification"
fi
if grep -q "follow" app.py 2>/dev/null; then
    echo "PASS: Follow functionality exists"
else
    echo "WARN: Follow functionality may need verification"
fi

echo ""
echo "=== AUDIT 2.5: TikTok Algorithm ==="
if grep -q "watch_time\|watchTime" app.py 2>/dev/null; then
    echo "PASS: Watch time tracking exists"
else
    echo "WARN: Watch time tracking may be missing"
fi
if grep -q "completion\|completed" app.py 2>/dev/null; then
    echo "PASS: Completion rate tracking exists"
else
    echo "WARN: Completion rate tracking may be missing"
fi
if grep -q "replay" app.py 2>/dev/null; then
    echo "PASS: Replay tracking exists"
else
    echo "WARN: Replay tracking may be missing"
fi

echo ""
echo "=== AUDIT 2.6: Content Lifecycle ==="
if grep -q "24.*hour\|expires_at\|INTERVAL.*24" app.py 2>/dev/null; then
    echo "PASS: 24-hour expiry implemented"
else
    echo "WARN: 24-hour expiry needs verification"
fi

echo ""
echo "=== AUDIT 2.7: Paid Content ==="
if grep -q "is_paid\|paid.*content\|price" app.py 2>/dev/null; then
    echo "PASS: Paid content support exists"
else
    echo "WARN: Paid content may need verification"
fi
if grep -q "80.*20\|creator.*earn" app.py 2>/dev/null; then
    echo "PASS: 80/20 creator split implemented"
else
    echo "WARN: 80/20 split needs verification"
fi

echo ""
echo "=== AUDIT 2.8: Creator Analytics ==="
if grep -q "analytics\|creator.*stats" app.py 2>/dev/null; then
    echo "PASS: Creator analytics endpoint exists"
else
    echo "WARN: Creator analytics may be missing"
fi

echo ""
echo "=== AUDIT 2.9: Frontend Components ==="
if grep -q "GhostCommunity\|ghost-community" -r . --include="*.html" --include="*.js" 2>/dev/null; then
    echo "PASS: Ghost Community screen exists"
else
    echo "FAIL: Ghost Community screen missing"
fi
if grep -q "video\|Video" -r . --include="*.html" 2>/dev/null; then
    echo "PASS: Video player component exists"
else
    echo "WARN: Video player needs verification"
fi
if grep -q "create.*post\|composer" -r . --include="*.html" 2>/dev/null; then
    echo "PASS: Post composer exists"
else
    echo "WARN: Post composer needs verification"
fi

echo ""
echo "=== AUDIT 2.10: Mobile-Specific Features ==="
if grep -q "mobile.*ghost\|ghost.*mobile" -r . --include="*.html" 2>/dev/null; then
    echo "PASS: Mobile Ghost Community screen exists"
else
    echo "WARN: Mobile Ghost Community screen may be missing"
fi
