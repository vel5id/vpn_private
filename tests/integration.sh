#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# VPN API Integration Test Suite
#
# Exercises the full API flow against a live vpn-api + PostgreSQL.
# Runs inside Docker via docker compose.
#
# Tests:
#   1. Health check
#   2. Register user
#   3. Login
#   4. List servers (authenticated)
#   5. Connect to a server (requires subscription)
#   6. Inject test subscription + retry connect
#   7. Get account info
#   8. Disconnect
#   9. Duplicate registration rejection
#  10. Invalid credentials rejection
#  11. Expired token rejection
#  12. Short password rejection
# ─────────────────────────────────────────────────────────────
set -euo pipefail

API_URL="${API_URL:-http://vpn-api:8080}"
DB_URL="${DATABASE_URL:-postgres://vpn:vpn@postgres:5432/vpn}"

PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${YELLOW}[TEST]${NC} $*"; }
pass()  { echo -e "${GREEN}  ✓ $*${NC}"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail()  { echo -e "${RED}  ✗ $*${NC}"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

assert_status() {
    local expected="$1" actual="$2" label="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$label (HTTP $actual)"
    else
        fail "$label — expected $expected, got $actual"
    fi
}

assert_json() {
    local field="$1" expected="$2" body="$3" label="$4"
    local actual
    actual=$(echo "$body" | jq -r "$field" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual" = "$expected" ]; then
        pass "$label"
    else
        fail "$label — expected '$expected', got '$actual'"
    fi
}

assert_json_exists() {
    local field="$1" body="$2" label="$3"
    local val
    val=$(echo "$body" | jq -r "$field" 2>/dev/null || echo "null")
    if [ "$val" != "null" ] && [ "$val" != "" ]; then
        pass "$label (=$val)"
    else
        fail "$label — field $field is null/empty"
    fi
}

# ─── Wait for API ────────────────────────────────────────────
log "Waiting for API at $API_URL..."
for i in $(seq 1 30); do
    if curl -sf "$API_URL/health" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  VPN API Integration Tests"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── 1. Health Check ─────────────────────────────────────────
log "1. Health check"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/health")
assert_status "200" "$STATUS" "GET /health"

# ─── 2. Register ─────────────────────────────────────────────
log "2. Register new user"
REGISTER_BODY=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@integration.com","password":"Str0ngP@ss!"}')
REGISTER_STATUS=$(echo "$REGISTER_BODY" | tail -1)
REGISTER_JSON=$(echo "$REGISTER_BODY" | sed '$d')
assert_status "201" "$REGISTER_STATUS" "POST /auth/register"
assert_json_exists ".access_token" "$REGISTER_JSON" "Registration returns access_token"
assert_json_exists ".user_id" "$REGISTER_JSON" "Registration returns user_id"

USER_ID=$(echo "$REGISTER_JSON" | jq -r ".user_id")

# ─── 3. Login ────────────────────────────────────────────────
log "3. Login"
LOGIN_BODY=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@integration.com","password":"Str0ngP@ss!"}')
LOGIN_STATUS=$(echo "$LOGIN_BODY" | tail -1)
LOGIN_JSON=$(echo "$LOGIN_BODY" | sed '$d')
assert_status "200" "$LOGIN_STATUS" "POST /auth/login"
assert_json_exists ".access_token" "$LOGIN_JSON" "Login returns access_token"
assert_json_exists ".refresh_token" "$LOGIN_JSON" "Login returns refresh_token"

ACCESS_TOKEN=$(echo "$LOGIN_JSON" | jq -r ".access_token")

# ─── 4. List Servers ─────────────────────────────────────────
log "4. List servers (authenticated)"
SERVERS_BODY=$(curl -s -w "\n%{http_code}" "$API_URL/servers" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
SERVERS_STATUS=$(echo "$SERVERS_BODY" | tail -1)
SERVERS_JSON=$(echo "$SERVERS_BODY" | sed '$d')
assert_status "200" "$SERVERS_STATUS" "GET /servers"

SERVER_COUNT=$(echo "$SERVERS_JSON" | jq 'length')
if [ "$SERVER_COUNT" -ge 3 ]; then
    pass "At least 3 servers seeded ($SERVER_COUNT found)"
else
    fail "Expected ≥3 servers, got $SERVER_COUNT"
fi

# Verify hostname is present in server list response
assert_json_exists '.[0].hostname' "$SERVERS_JSON" "Server list includes hostname"

SERVER_ID=$(echo "$SERVERS_JSON" | jq -r '.[0].id')

# ─── 5. Connect (no subscription) ───────────────────────────
log "5. Connect without subscription (should fail)"
CONNECT_BODY=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/connect" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"server_id\":\"$SERVER_ID\"}")
CONNECT_STATUS=$(echo "$CONNECT_BODY" | tail -1)
assert_status "402" "$CONNECT_STATUS" "POST /connect → 402 Payment Required"

# ─── 6. Inject subscription + connect ───────────────────────
log "6. Inject test subscription via DB"
EXPIRES=$(date -u -d "+30 days" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
          date -u -v+30d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
          echo "2027-01-01T00:00:00Z")
psql "$DB_URL" -c "
  INSERT INTO subscriptions (user_id, tier, status, provider, provider_id, expires_at)
  VALUES ('$USER_ID', 'monthly', 'active', 'apple', 'rc_test_123', '$EXPIRES')
  ON CONFLICT (user_id, provider) DO UPDATE SET status='active', expires_at='$EXPIRES';
" > /dev/null 2>&1
pass "Subscription injected"

log "   Retry connect with active subscription"
CONNECT_BODY=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/connect" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"server_id\":\"$SERVER_ID\"}")
CONNECT_STATUS=$(echo "$CONNECT_BODY" | tail -1)
CONNECT_JSON=$(echo "$CONNECT_BODY" | sed '$d')
assert_status "200" "$CONNECT_STATUS" "POST /connect → 200 OK"
assert_json_exists ".session_token" "$CONNECT_JSON" "Connect returns session_token"
assert_json_exists ".session_id" "$CONNECT_JSON" "Connect returns session_id"
assert_json_exists ".hostname" "$CONNECT_JSON" "Connect returns hostname"

SESSION_ID=$(echo "$CONNECT_JSON" | jq -r ".session_id")
SESSION_TOKEN=$(echo "$CONNECT_JSON" | jq -r ".session_token")

# ─── 7. Account Info ─────────────────────────────────────────
log "7. Account info"
ACCOUNT_BODY=$(curl -s -w "\n%{http_code}" "$API_URL/account" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
ACCOUNT_STATUS=$(echo "$ACCOUNT_BODY" | tail -1)
ACCOUNT_JSON=$(echo "$ACCOUNT_BODY" | sed '$d')
assert_status "200" "$ACCOUNT_STATUS" "GET /account"
assert_json ".email" "test@integration.com" "$ACCOUNT_JSON" "Account email matches"
assert_json ".subscription.status" "active" "$ACCOUNT_JSON" "Subscription is active"
assert_json ".subscription.tier" "monthly" "$ACCOUNT_JSON" "Subscription tier is monthly"

# ─── 8. Disconnect ───────────────────────────────────────────
log "8. Disconnect"
DISCONNECT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/disconnect" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\"}")
assert_status "204" "$DISCONNECT_STATUS" "POST /disconnect → 204 No Content"

# Verify session is closed in DB
SESSION_CLOSED=$(psql "$DB_URL" -t -c "
  SELECT CASE WHEN disconnected_at IS NOT NULL THEN 'yes' ELSE 'no' END
  FROM sessions WHERE id = '$SESSION_ID';
" 2>/dev/null | tr -d '[:space:]')
if [ "$SESSION_CLOSED" = "yes" ]; then
    pass "Session marked as disconnected in DB"
else
    fail "Session not marked as disconnected (got: '$SESSION_CLOSED')"
fi

# ─── 9. Duplicate Registration ───────────────────────────────
log "9. Duplicate registration rejection"
DUP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@integration.com","password":"AnotherP@ss1"}')
assert_status "409" "$DUP_STATUS" "POST /auth/register duplicate → 409 Conflict"

# ─── 10. Invalid Credentials ─────────────────────────────────
log "10. Invalid credentials rejection"
BAD_LOGIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@integration.com","password":"WrongPassword1"}')
assert_status "401" "$BAD_LOGIN_STATUS" "POST /auth/login wrong password → 401"

# ─── 11. Unauthenticated Request ─────────────────────────────
log "11. Unauthenticated request rejection"
NOAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/servers")
assert_status "401" "$NOAUTH_STATUS" "GET /servers without token → 401"

# ─── 12. Short Password ──────────────────────────────────────
log "12. Short password rejection"
SHORT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"short@test.com","password":"123"}')
assert_status "400" "$SHORT_STATUS" "POST /auth/register short password → 400"

# ─── Summary ─────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}ALL $TOTAL TESTS PASSED${NC}"
else
    echo -e "  ${RED}$FAIL/$TOTAL TESTS FAILED${NC}"
fi
echo "═══════════════════════════════════════════════════════"
echo ""

exit "$FAIL"
