#!/bin/bash

echo "========================================="
echo "AUDIT 4: WHATSAPP FEATURES (Web + Mobile)"
echo "========================================="

# Run web audit
echo ""
echo "=== WEB APP AUDIT ==="
if [ -f "audit4_web_check.sh" ]; then
    ./audit4_web_check.sh
else
    echo "⚠️ audit4_web_check.sh not found"
fi

# Run mobile audit
echo ""
echo "=== MOBILE APP AUDIT ==="
if [ -f "audit4_mobile_check.sh" ]; then
    ./audit4_mobile_check.sh
else
    echo "⚠️ audit4_mobile_check.sh not found"
fi

echo ""
echo "========================================="
echo "AUDIT 4 COMPLETE"
echo "========================================="
