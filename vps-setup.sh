#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}[VPS]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK]${NC} $*"; }

BINARY="./turnnel"
PEER_PORT=9999
ECHO_PORT=15820

if [[ ! -x "$BINARY" ]]; then
    info "Building..."
    cargo build --release
fi
ok "Binary ready"

ECHO_PID=""
cleanup() {
    echo ""
    info "Cleaning up..."
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null
    info "Done"
}
trap cleanup EXIT INT TERM

info "Starting echo server on :${ECHO_PORT}..."
python3 -u -c "
import socket, signal, sys
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${ECHO_PORT}))
print(f'echo: listening on 127.0.0.1:${ECHO_PORT}', flush=True)
while True:
    data, addr = s.recvfrom(65535)
    print(f'echo: {len(data)}B from {addr}', flush=True)
    s.sendto(data, addr)
" &
ECHO_PID=$!
sleep 1
ok "Echo server running (PID $ECHO_PID)"

echo -e "${BOLD}────────────────────────────────────────${NC}"
echo -e "  peer:  ${GREEN}0.0.0.0:${PEER_PORT}${NC} → echo :${ECHO_PORT}"
echo -e "  ${CYAN}Waiting for TURN-relayed packets...${NC}"
echo -e "${BOLD}────────────────────────────────────────${NC}"

RUST_LOG=info exec "$BINARY" peer \
    --listen "0.0.0.0:${PEER_PORT}" \
    --forward "127.0.0.1:${ECHO_PORT}"
