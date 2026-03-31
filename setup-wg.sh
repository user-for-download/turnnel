#!/usr/bin/env bash
set -e

# Проверяем, установлен ли WireGuard
if ! command -v wg &> /dev/null; then
    echo "Установите WireGuard: sudo apt install wireguard-tools"
    exit 1
fi

echo "Генерация ключей WireGuard..."
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# Лимит скорости для TURN-релея (VK ~2 Mbps)
RATE_LIMIT="1.8mbit"

# Конфиг для VPS (Сервер)
cat > wg-server.conf <<CONFIG
[Interface]
PrivateKey = $SERVER_PRIV
Address = 10.222.0.1/24
ListenPort = 51820
# Ограничиваем исходящий трафик, чтобы не превышать лимит TURN-релея
PostUp = tc qdisc add dev %i root tbf rate $RATE_LIMIT burst 32kbit latency 50ms
PostDown = tc qdisc del dev %i root 2>/dev/null || true

[Peer]
# Local Client
PublicKey = $CLIENT_PUB
AllowedIPs = 10.222.0.2/32
CONFIG

# Конфиг для Клиента (Локально)
cat > wg-client.conf <<CONFIG
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.222.0.2/24
# Уменьшенный MTU, так как трафик заворачивается в STUN ChannelData
MTU = 1360
# Ограничиваем исходящий трафик, чтобы не превышать лимит TURN-релея
PostUp = tc qdisc add dev %i root tbf rate $RATE_LIMIT burst 32kbit latency 50ms
PostDown = tc qdisc del dev %i root 2>/dev/null || true

[Peer]
# VPS Server
PublicKey = $SERVER_PUB
AllowedIPs = 10.222.0.0/24
# Подключаемся к локальному turnnel client!
Endpoint = 127.0.0.1:51821
PersistentKeepalive = 25
CONFIG

echo -e "\n✅ Конфиги созданы: wg-server.conf и wg-client.conf"
echo -e "📊 Rate limit: $RATE_LIMIT на обоих концах (под лимит VK TURN)"