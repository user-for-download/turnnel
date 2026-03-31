# Turnnel

TURN-based tunnel for routing UDP traffic (e.g. WireGuard) through public TURN/STUN relays.

Uses TURN servers from video-calling services (VK Calls, Yandex Telemost) or any standard TURN server as transport — no VPS required.

## How It Works

```text
┌──────────┐     ┌────────────┐     ┌─────────────┐     ┌──────────┐     ┌──────────┐
│ WireGuard│◄───►│  turnnel   │◄───►│ TURN Server │◄───►│ turnnel  │◄───►│ WireGuard│
│  Client  │ UDP │  client    │TURN │ (any public)│TURN │  peer    │ UDP │  Server  │
└──────────┘     └────────────┘     └─────────────┘     └──────────┘     └──────────┘
   :51821           Allocate +                             :9999           :51820
                    ChannelBind
server:                    
[VPS] Starting echo server on :15820...
echo: listening on 127.0.0.1:15820
[ OK] Echo server running (PID 3979492)
────────────────────────────────────────
peer:  0.0.0.0:9999 → echo :15820
Waiting for TURN-relayed packets...
────────────────────────────────────────
2026-03-31T08:07:14.268566Z  INFO turnnel: starting peer relay listen=0.0.0.0:9999 forward=127.0.0.1:15820
2026-03-31T08:07:14.268815Z  INFO turnnel_peer::relay: external socket ready listen=0.0.0.0:9999
2026-03-31T08:07:14.268910Z  INFO turnnel_peer::relay: WireGuard socket ready local=127.0.0.1:60998 forward=127.0.0.1:15820
echo: 37B from ('127.0.0.1', 60998)
echo: 37B from ('127.0.0.1', 60998)
echo: 37B from ('127.0.0.1', 60998)
echo: 37B from ('127.0.0.1', 60998)

client:
2026-03-31T08:06:52.239476Z  INFO turnnel_session::session: TURN session active relay=155.212.207.13:60798 peer=185.139.230.73:9999 channel=0x4000 protocol=Udp
2026-03-31T08:06:52.239492Z  INFO turnnel_client::proxy: TURN tunnel established relay=155.212.207.13:60798 peer=185.139.230.73:9999
2026-03-31T08:06:52.239533Z  INFO turnnel_client::proxy: WireGuard proxy ready listen=127.0.0.1:51821

[ OK ] TURN tunnel established via VK!

[TEST] Sending test packets...
Path: 127.0.0.1:51821 → VK TURN → 185.139.230.73:9999 → echo → back

[ OK ] Packet 1/5: 37 bytes ✓
[ OK ] Packet 2/5: 37 bytes ✓
[ OK ] Packet 3/5: 37 bytes ✓
[ OK ] Packet 4/5: 37 bytes ✓
[ OK ] Packet 5/5: 37 bytes ✓

[TEST] Burst test (10 packets)...
[ OK ] Burst: 10/10 received ✓

════════════════════════════════════════════
ALL 6/6 PASSED — VK TURN TUNNEL WORKS! 🎉
════════════════════════════════════════════

[TEST] Cleaning up...
```

1. **Client** allocates a relay on the TURN server, binds a channel to the peer
2. **Peer** listens for relayed packets and forwards them to the local WireGuard
3. All WireGuard traffic flows through the TURN relay using ChannelData framing

## Features

- **Full STUN/TURN implementation** — Allocate, CreatePermission, ChannelBind, Refresh
- **Transport**: UDP, TCP, TLS (with SNI)
- **Credential providers**: manual, VK Calls, Yandex Telemost (auto-extract from call pages)
- **ChannelData framing** — minimal overhead (4-byte header)
- **Auto-refresh** — allocation, permission, and channel bindings refreshed automatically
- **Pure Rust** — no C dependencies, no OpenSSL (uses rustls)

## Build

```bash
cargo build --release
```

Binary: `target/release/turnnel`

## Usage

### Peer Side (where WireGuard server runs)

```bash
turnnel peer --listen 0.0.0.0:9999 --forward 127.0.0.1:51820
```

### Client Side — Manual TURN Credentials

```bash
turnnel client \
  --provider manual \
  --turn-server 1.2.3.4:3478 \
  --turn-user myuser \
  --turn-pass mypass \
  --peer <PEER_PUBLIC_IP>:9999 \
  --listen 127.0.0.1:51821
```

Then point WireGuard client endpoint to `127.0.0.1:51821`.

### Client Side — VK Calls

```bash
turnnel client \
  --provider vk \
  --call-url "https://vk.com/call/join/..." \
  --cookie "remixsid=..." \
  --peer <PEER_PUBLIC_IP>:9999 \
  --listen 127.0.0.1:51821
```

### Client Side — Yandex Telemost

```bash
turnnel client \
  --provider yandex \
  --call-url "https://telemost.yandex.ru/j/..." \
  --peer <PEER_PUBLIC_IP>:9999 \
  --listen 127.0.0.1:51821
```

### TCP / TLS Transport

```bash
# TCP
turnnel client --tcp --provider manual --turn-server 1.2.3.4:3478 ...

# TLS
turnnel client --tls-sni turn.example.com --provider manual --turn-server 1.2.3.4:5349 ...
```

## Project Structure

```text
turnnel/
├── src/main.rs                    # CLI entrypoint
├── crates/
│   ├── turnnel-stun/              # STUN/TURN protocol codec
│   │   ├── message.rs             #   message encode/decode
│   │   ├── attribute.rs           #   XOR-MAPPED-ADDRESS, LIFETIME, etc.
│   │   ├── channel_data.rs        #   ChannelData framing
│   │   ├── integrity.rs           #   HMAC-SHA1, fingerprint, long-term key
│   │   └── types.rs               #   Method/Class enums
│   ├── turnnel-session/           # TURN session state machine
│   │   ├── session.rs             #   Allocate → Permission → ChannelBind
│   │   ├── transport.rs           #   UDP / TCP / TLS transport layer
│   │   └── codec.rs               #   TCP/TLS stream framing
│   ├── turnnel-client/            # WireGuard ↔ TURN proxy
│   │   └── proxy.rs               #   local UDP ↔ ChannelData relay
│   ├── turnnel-peer/              # Peer-side relay
│   │   └── relay.rs               #   TURN relay ↔ WireGuard server
│   └── turnnel-providers/         # TURN credential extraction
│       ├── manual.rs              #   CLI-provided credentials
│       ├── vk.rs                  #   VK Calls page scraper
│       ├── yandex.rs              #   Yandex Telemost scraper
│       └── sdp.rs                 #   iceServers JSON parser
```

## Testing

```bash
# All unit tests
cargo test

# With logs
RUST_LOG=debug cargo test -- --nocapture
```

## Status

**Beta** — core tunnel works, not production-hardened yet.

## License

MIT
