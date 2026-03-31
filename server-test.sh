#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[PEER]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ─── НАСТРОЙКИ ────────────────────────────────────────
PEER_LISTEN="${PEER_LISTEN:-0.0.0.0:9999}"
PEER_PORT="${PEER_PORT:-9999}"
FORWARD="${FORWARD:-127.0.0.1:51820}"
ECHO_PORT="${ECHO_PORT:-51820}"
BINARY="${BINARY:-./target/release/turnnel}"

echo -e "${BOLD}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   turnnel PEER + ECHO server (VPS side)         ║${NC}"
echo -e "${BOLD}╚═════════════════════════════════════════════════╝${NC}"
echo -e "  Peer listen: ${CYAN}${PEER_LISTEN}${NC}"
echo -e "  Forward to:  ${CYAN}${FORWARD}${NC}"
echo -e "  Echo server: ${CYAN}127.0.0.1:${ECHO_PORT}${NC}"
echo ""

# ── проверки ──────────────────────────────────────────
if [[ ! -x "$BINARY" ]]; then
    info "Binary not found at $BINARY, trying to build..."
    if [[ -f Cargo.toml ]]; then
        cargo build --release
    else
        fail "No binary and no Cargo.toml — cannot continue"
        exit 1
    fi
fi

# ── cleanup ───────────────────────────────────────────
ECHO_PID=""
PEER_PID=""
cleanup() {
    echo ""
    info "Shutting down..."
    [[ -n "$PEER_PID" ]] && kill "$PEER_PID" 2>/dev/null && wait "$PEER_PID" 2>/dev/null || true
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null && wait "$ECHO_PID" 2>/dev/null || true
    info "Done."
}
trap cleanup EXIT INT TERM

# ── echo сервер (UDP) ────────────────────────────────
info "Starting UDP echo server on 127.0.0.1:${ECHO_PORT}..."

python3 -u << 'PYEOF' &
import socket, os, signal, sys

port = int(os.environ.get("ECHO_PORT", "51820"))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))

def handler(sig, frame):
    s.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

count = 0
print(f"Echo server listening on 127.0.0.1:{port}", flush=True)
while True:
    try:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)
        count += 1
        if count % 100 == 1:
            print(f"  echo #{count}: {len(data)} bytes from {addr}", flush=True)
    except Exception as e:
        print(f"Echo error: {e}", flush=True)
        break
PYEOF
ECHO_PID=$!
sleep 0.5

if ! kill -0 "$ECHO_PID" 2>/dev/null; then
    fail "Echo server failed to start (port ${ECHO_PORT} busy?)"
    exit 1
fi
ok "Echo server running (PID $ECHO_PID)"

# ── проверка echo сервера ────────────────────────────
info "Testing echo server locally..."
ECHO_TEST=$(python3 << PYEOF
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"selftest", ("127.0.0.1", ${ECHO_PORT}))
try:
    d, _ = s.recvfrom(65535)
    sys.stdout.write("OK" if d == b"selftest" else "MISMATCH")
except socket.timeout:
    sys.stdout.write("TIMEOUT")
except Exception as e:
    sys.stdout.write(f"ERROR:{e}")
PYEOF
) || true

if [[ "$ECHO_TEST" == "OK" ]]; then
    ok "Echo self-test passed ✓"
else
    fail "Echo self-test failed: $ECHO_TEST"
    exit 1
fi

# ── turnnel peer ─────────────────────────────────────
rm -f /tmp/turnnel-peer.log
info "Starting turnnel peer..."

RUST_LOG=info "$BINARY" peer \
    --listen "$PEER_LISTEN" \
    --forward "$FORWARD" \
    >>/tmp/turnnel-peer.log 2>&1 &
PEER_PID=$!
sleep 1

if ! kill -0 "$PEER_PID" 2>/dev/null; then
    fail "Peer failed to start:"
    tail -10 /tmp/turnnel-peer.log 2>/dev/null
    exit 1
fi
ok "Peer relay running (PID $PEER_PID)"

# ── проверка порта ───────────────────────────────────
if command -v ss &>/dev/null; then
    if ss -ulnp | grep -q ":${PEER_PORT}"; then
        ok "Port ${PEER_PORT}/udp is listening"
    else
        fail "Port ${PEER_PORT}/udp not found in ss output"
        ss -ulnp | grep turnnel || true
    fi
fi

# ── проверка firewall ────────────────────────────────
if command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "${PEER_PORT}"; then
        ok "UFW: port ${PEER_PORT} allowed"
    else
        echo -e "  ${YELLOW}⚠${NC}  UFW may be blocking port ${PEER_PORT}. Run:"
        echo -e "     ${CYAN}sudo ufw allow ${PEER_PORT}/udp${NC}"
    fi
elif command -v iptables &>/dev/null; then
    if iptables -L -n 2>/dev/null | grep -q "${PEER_PORT}"; then
        ok "iptables: port ${PEER_PORT} rule found"
    else
        echo -e "  ${YELLOW}⚠${NC}  No iptables rule for port ${PEER_PORT} (may be OK if policy is ACCEPT)"
    fi
fi

# ── показать внешний IP ──────────────────────────────
EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || \
              curl -s --connect-timeout 5 icanhazip.com 2>/dev/null || \
              echo "unknown")
echo ""
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  PEER READY${NC}"
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo ""
echo -e "  External IP:  ${CYAN}${EXTERNAL_IP}${NC}"
echo -e "  Peer port:    ${CYAN}${PEER_PORT}/udp${NC}"
echo ""
echo -e "  ${BOLD}On the client machine, run:${NC}"
echo ""
echo -e "  ${CYAN}./client-test.sh 'https://vk.com/call/join/YOUR_LINK'${NC}"
echo ""
echo -e "  Or with custom VPS IP:"
echo -e "  ${CYAN}VPS_IP=${EXTERNAL_IP} ./client-test.sh 'https://vk.com/call/join/YOUR_LINK'${NC}"
echo ""
echo -e "  Logs: ${CYAN}/tmp/turnnel-peer.log${NC}"
echo ""
info "Waiting for connections... (Ctrl+C to stop)"

# ── мониторинг ───────────────────────────────────────
LAST_LINES=0
while true; do
    sleep 5

    if ! kill -0 "$ECHO_PID" 2>/dev/null; then
        fail "Echo server died, restarting..."
        python3 -u -c "
import socket, os, signal, sys
port = int(os.environ.get('ECHO_PORT', '51820'))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)
" &
        ECHO_PID=$!
        ok "Echo server restarted (PID $ECHO_PID)"
    fi

    if ! kill -0 "$PEER_PID" 2>/dev/null; then
        fail "Peer relay died, restarting..."
        RUST_LOG=info "$BINARY" peer \
            --listen "$PEER_LISTEN" \
            --forward "$FORWARD" \
            >>/tmp/turnnel-peer.log 2>&1 &
        PEER_PID=$!
        sleep 1
        if kill -0 "$PEER_PID" 2>/dev/null; then
            ok "Peer relay restarted (PID $PEER_PID)"
        else
            fail "Peer relay failed to restart"
        fi
    fi

    # Show new log lines
    CURRENT_LINES=$(wc -l < /tmp/turnnel-peer.log 2>/dev/null || echo 0)
    if [[ "$CURRENT_LINES" -gt "$LAST_LINES" ]]; then
        tail -n +$((LAST_LINES + 1)) /tmp/turnnel-peer.log | head -20
        LAST_LINES=$CURRENT_LINES
    fi
done