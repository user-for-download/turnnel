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
