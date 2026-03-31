#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

CALL_URL="${1:-}"
VPS_IP="${2:-${VPS_IP:-}}"
BINARY="${BINARY:-./target/release/turnnel}"
LISTEN="${LISTEN:-127.0.0.1:51821}"
PEER_PORT="${PEER_PORT:-9999}"

if [[ -z "$CALL_URL" || -z "$VPS_IP" ]]; then
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 <vk-call-url> <vps-ip>"
    echo ""
    echo -e "${BOLD}Example:${NC}"
    echo "  $0 'https://vk.com/call/join/xxxxx' 185.239.130.173"
    echo ""
    echo "First time? Run login once:"
    echo "  python3 get_vk_token.py --login 'https://vk.com/call/join/xxxxx'"
    exit 1
fi

# ── проверки ──────────────────────────────────────────
[[ -x "$BINARY" ]] || fail "Binary not found: $BINARY (run: cargo build --release)"
command -v python3 >/dev/null || fail "python3 not found"
python3 -c "from playwright.sync_api import sync_playwright" 2>/dev/null \
    || fail "playwright not installed (run: pip install playwright && playwright install chromium)"

# ── получаем токен ────────────────────────────────────
info "Getting fresh auth_token via Playwright..."
TOKEN=$(python3 get_vk_token.py "$CALL_URL" 2>&1 >/dev/null | tee /dev/stderr; \
        python3 get_vk_token.py "$CALL_URL" 2>/dev/null) || true

# Костыль выше не работает красиво. Проще:
TOKEN=""
TOKEN=$(python3 get_vk_token.py "$CALL_URL" 2>/tmp/turnnel-token.log) || true
cat /tmp/turnnel-token.log >&2

if [[ -z "$TOKEN" || ! "$TOKEN" == \$* ]]; then
    fail "Could not get auth_token. Check /tmp/turnnel-token.log\n  Maybe run: python3 get_vk_token.py --login '$CALL_URL'"
fi

ok "Token: ${TOKEN:0:20}..."

# ── запускаем turnnel ─────────────────────────────────
info "Starting turnnel client → ${VPS_IP}:${PEER_PORT}"

exec env RUST_LOG=info "$BINARY" client \
    --provider vk \
    --call-url "$CALL_URL" \
    --auth-token "$TOKEN" \
    --peer "${VPS_IP}:${PEER_PORT}" \
    --listen "$LISTEN"