#!/usr/bin/env bash
set -u

BASE_URL="${BASE_URL:-http://localhost:5000}"
PASS=0
FAIL=0

ok() {
  echo "✅ $1"
  PASS=$((PASS + 1))
}

bad() {
  echo "❌ $1"
  FAIL=$((FAIL + 1))
}

check_http_code() {
  local name="$1"
  local url="$2"
  local expected_regex="$3"
  local code
  code=$(curl -sS -o /tmp/zt_audit5_resp.txt -w "%{http_code}" "$url" || echo "000")
  if echo "$code" | grep -Eq "$expected_regex"; then
    ok "$name (HTTP $code)"
  else
    bad "$name (HTTP $code)"
  fi
}

check_method_http_code() {
  local name="$1"
  local method="$2"
  local url="$3"
  local expected_regex="$4"
  local code
  code=$(curl -sS -o /tmp/zt_audit5_resp.txt -w "%{http_code}" -X "$method" "$url" || echo "000")
  if echo "$code" | grep -Eq "$expected_regex"; then
    ok "$name (HTTP $code)"
  else
    bad "$name (HTTP $code)"
  fi
}

echo "========================================="
echo "AUDIT 5: FULL SYSTEM INTEGRATION TEST"
echo "========================================="

echo
echo "=== Mobile + Web flow availability ==="
check_http_code "Mobile welcome route" "$BASE_URL/mobile" "200|30[12]"
check_http_code "Mobile KYC route" "$BASE_URL/mobile/kyc" "200|30[12]"
check_http_code "Mobile pending route" "$BASE_URL/mobile/pending" "200|30[12]"
check_http_code "Web KYC upload route" "$BASE_URL/kyc-upload" "200|30[12]"
check_http_code "Web pending approval route" "$BASE_URL/pending-approval" "200|30[12]"

echo
echo "=== Admin Control Room availability ==="
check_http_code "Admin control room page" "$BASE_URL/admin_control" "200|30[12]"
check_http_code "Admin dashboard page" "$BASE_URL/admin/dashboard" "200|30[12]"

echo
echo "=== Admin APIs protected and present ==="
check_http_code "Admin stats API" "$BASE_URL/api/admin/stats" "200|401|403"
check_http_code "Admin users API" "$BASE_URL/api/admin/users/all" "200|401|403"
check_http_code "Admin pending verification API" "$BASE_URL/api/admin/users/pending-verification" "200|401|403"

echo
echo "=== User identification APIs present ==="
check_method_http_code "Identification submit API (method check)" "POST" "$BASE_URL/api/user/identification/submit" "200|400|401|403"
check_method_http_code "Identification upload API (method check)" "POST" "$BASE_URL/api/user/identification/upload-document" "200|400|401|403"

echo
echo "========================================="
echo "RESULTS: PASS=$PASS FAIL=$FAIL"
echo "========================================="

if [[ "$FAIL" -eq 0 ]]; then
  echo "✅ AUDIT 5 baseline checks passed"
  exit 0
fi

echo "❌ AUDIT 5 checks found failures"
exit 1
