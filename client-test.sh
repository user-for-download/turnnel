#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[TEST]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ─── НАСТРОЙКИ ────────────────────────────────────────
VPS="${VPS_IP:-<<<<<<<VPS_IP>>>>>>>}"
LISTEN="127.0.0.1:51821"
LISTEN_PORT=51821
PEER_PORT="${PEER_PORT:-9999}"
BINARY="${BINARY:-./target/release/turnnel}"

CALL_URL="${1:-}"
AUTH_TOKEN="${2:-}"

if [[ -z "$CALL_URL" ]]; then
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 <vk-call-url> [auth-token]"
    echo ""
    echo "  auth-token is OPTIONAL — the anonymous flow does not need it."
    echo "  If provided, it will be used as fallback if anonymous flow fails."
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  # Anonymous flow (recommended, no token needed):"
    echo "  $0 'https://vk.com/call/join/xxxxx'"
    echo ""
    echo "  # With fallback auth token:"
    echo "  $0 'https://vk.com/call/join/xxxxx' '\$3w6jWNuUI...'"
    echo ""
    echo "  # Different VPS:"
    echo "  VPS_IP=1.2.3.4 $0 'https://vk.com/call/join/xxxxx'"
    exit 1
fi

echo -e "${BOLD}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   turnnel e2e test via VK TURN                  ║${NC}"
echo -e "${BOLD}╚═════════════════════════════════════════════════╝${NC}"
echo -e "  VPS peer:    ${CYAN}${VPS}:${PEER_PORT}${NC}"
echo -e "  TURN:        ${CYAN}VK (anonymous 4-step flow)${NC}"
echo -e "  Local proxy: ${CYAN}${LISTEN}${NC}"

if [[ -n "$AUTH_TOKEN" ]]; then
    echo -e "  Auth token:  ${CYAN}provided (fallback)${NC}"
else
    echo -e "  Auth token:  ${CYAN}not needed (anonymous flow)${NC}"
fi
echo ""

[[ -x "$BINARY" ]] || { fail "Binary not found: $BINARY (run: cargo build --release)"; exit 1; }

# ── cleanup ───────────────────────────────────────────
CLIENT_PID=""
cleanup() {
    echo ""
    info "Cleaning up..."
    if [[ -n "$CLIENT_PID" ]]; then
        kill "$CLIENT_PID" 2>/dev/null
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ── запуск turnnel client ────────────────────────────
rm -f /tmp/turnnel-client.log
info "Starting turnnel client (VK provider, anonymous flow)..."

CLIENT_ARGS=(
    client
    --provider vk
    --call-url "$CALL_URL"
    --peer "${VPS}:${PEER_PORT}"
    --listen "$LISTEN"
)

if [[ -n "$AUTH_TOKEN" ]]; then
    CLIENT_ARGS+=(--auth-token "$AUTH_TOKEN")
fi

RUST_LOG=debug "$BINARY" "${CLIENT_ARGS[@]}" \
    >>/tmp/turnnel-client.log 2>&1 &
CLIENT_PID=$!

echo -n "  Connecting"
ESTABLISHED=false
for _ in $(seq 1 60); do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo ""
        fail "Client exited prematurely:"
        echo -e "${YELLOW}--- last 20 lines of log ---${NC}"
        tail -20 /tmp/turnnel-client.log 2>/dev/null
        echo -e "${YELLOW}--- end log ---${NC}"
        exit 1
    fi
    if grep -qE "proxy ready|session active|TURN tunnel established" /tmp/turnnel-client.log 2>/dev/null; then
        ESTABLISHED=true
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

if ! $ESTABLISHED; then
    fail "Tunnel not established within 60s"
    echo -e "${YELLOW}--- last 20 lines of log ---${NC}"
    tail -20 /tmp/turnnel-client.log 2>/dev/null
    echo -e "${YELLOW}--- end log ---${NC}"
    exit 1
fi
ok "TURN tunnel established via VK!"

# Show which flow succeeded
if grep -q "step 4/4" /tmp/turnnel-client.log 2>/dev/null; then
    echo -e "  ${GREEN}▸${NC} Used: anonymous 4-step flow (no auth needed)"
elif grep -q "auth_token" /tmp/turnnel-client.log 2>/dev/null; then
    echo -e "  ${YELLOW}▸${NC} Used: auth_token fallback flow"
else
    echo -e "  ${CYAN}▸${NC} Used: page scraping fallback"
fi

RELAY=$(grep -oP 'relay[= ]+\K[0-9.:]+' /tmp/turnnel-client.log 2>/dev/null | head -1 || true)
[[ -n "$RELAY" ]] && echo -e "  ${CYAN}▸${NC} Relay: $RELAY"

TURN_SERVER=$(grep -oP 'server[= ]+\K[0-9.:]+' /tmp/turnnel-client.log 2>/dev/null | head -1 || true)
[[ -n "$TURN_SERVER" ]] && echo -e "  ${CYAN}▸${NC} TURN server: $TURN_SERVER"
echo ""
sleep 1

# ── тесты ────────────────────────────────────────────
info "Sending test packets..."
echo -e "  ${CYAN}Path: ${LISTEN} → VK TURN → ${VPS}:${PEER_PORT} → echo → back${NC}\n"

PASS=0; TOTAL=0

# 5 echo-пакетов
for i in $(seq 1 5); do
    TOTAL=$((TOTAL + 1))
    PAYLOAD="turnnel-vk-test-${i}-$(date +%s%N)"

    RESP=$(python3 << PYEOF
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"${PAYLOAD}", ("127.0.0.1", ${LISTEN_PORT}))
try:
    d, _ = s.recvfrom(65535)
    sys.stdout.write(d.decode())
except socket.timeout:
    sys.stdout.write("TIMEOUT")
except Exception as e:
    sys.stdout.write(f"ERROR:{e}")
PYEOF
    ) || true

    if [[ "$RESP" == "$PAYLOAD" ]]; then
        ok "Packet $i/5: ${#PAYLOAD} bytes ✓"
        PASS=$((PASS + 1))
    elif [[ "$RESP" == "TIMEOUT" ]]; then
        fail "Packet $i/5: timeout (5s)"
    else
        fail "Packet $i/5: mismatch (got: ${RESP:0:50})"
    fi
    sleep 0.3
done

# Large packet (1400 bytes)
echo ""
TOTAL=$((TOTAL + 1))
info "Large packet test (1400 bytes)..."
LARGE=$(python3 << 'PYEOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(8)
p = b"W" * 1400
s.sendto(p, ("127.0.0.1", 51821))
try:
    d, _ = s.recvfrom(65535)
    sys.stdout.write("OK" if d == p else f"MISMATCH:{len(d)}")
except socket.timeout:
    sys.stdout.write("TIMEOUT")
except Exception as e:
    sys.stdout.write(f"ERROR:{e}")
PYEOF
) || true

if [[ "$LARGE" == "OK" ]]; then
    ok "1400 bytes echoed ✓"
    PASS=$((PASS + 1))
else
    fail "Large packet: $LARGE"
fi

# Burst test
echo ""
TOTAL=$((TOTAL + 1))
info "Burst test (10 packets)..."
BURST=$(python3 << 'PYEOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
for i in range(10):
    s.sendto(f"burst-{i}".encode(), ("127.0.0.1", 51821))
r = 0
for _ in range(10):
    try:
        s.recvfrom(65535)
        r += 1
    except Exception:
        break
sys.stdout.write(str(r))
PYEOF
) || true

if [[ -n "$BURST" && "$BURST" -ge 8 ]] 2>/dev/null; then
    ok "Burst: ${BURST}/10 received ✓"
    PASS=$((PASS + 1))
else
    fail "Burst: ${BURST:-0}/10 received"
fi

# ── итог ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════${NC}"
if [[ $PASS -eq $TOTAL ]]; then
    echo -e "${GREEN}${BOLD}  ALL $PASS/$TOTAL PASSED — VK TURN TUNNEL WORKS! 🎉${NC}"
else
    echo -e "${YELLOW}${BOLD}  $PASS/$TOTAL PASSED${NC}"
fi
echo -e "${BOLD}════════════════════════════════════════════${NC}"

echo ""
info "Log digest:"
grep -E "step [0-9]|flow|TURN|error|failed|credentials" /tmp/turnnel-client.log 2>/dev/null | head -15 || true
echo ""
info "Full log: /tmp/turnnel-client.log"

[[ $PASS -eq $TOTAL ]] && exit 0 || exit 1