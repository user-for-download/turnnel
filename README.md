# Turnnel

TURN-based tunnel for routing UDP traffic (e.g. WireGuard) through public TURN/STUN relays.

Uses TURN servers from video-calling services (VK Calls, Yandex Telemost) or any standard TURN server as transport.

## How It Works

```text
┌──────────┐     ┌────────────┐     ┌─────────────┐     ┌──────────┐     ┌──────────┐
│ WireGuard│◄───►│  turnnel   │◄───►│ TURN Server │◄───►│ turnnel  │◄───►│ WireGuard│
│  Client  │ UDP │  client    │TURN │ (any public)│TURN │  peer    │ UDP │  Server  │
└──────────┘     └────────────┘     └─────────────┘     └──────────┘     └──────────┘
   :51821           Allocate +                             :9999           :51820
                    ChannelBind
```

## VK TURN: ~2 Mbps! need wg shape speed! 
```text
PostUp = tc qdisc add dev %i root tbf rate 1.8mbit burst 32kbit latency 50ms
PostDown = tc qdisc del dev %i root 2>/dev/null || true
```
```bash
❯ iperf3 -c 10.222.0.1
Connecting to host 10.222.0.1, port 5201
[  5] local 10.222.0.2 port 25878 connected to 10.222.0.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   896 KBytes  7.33 Mbits/sec    0   40.9 KBytes
[  5]   1.00-2.00   sec   384 KBytes  3.15 Mbits/sec    0   38.3 KBytes
[  5]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec    0   38.3 KBytes
[  5]   3.00-4.00   sec   384 KBytes  3.15 Mbits/sec    0   38.3 KBytes
[  5]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec    0   38.3 KBytes
[  5]   5.00-6.00   sec   384 KBytes  3.15 Mbits/sec    0   40.9 KBytes
[  5]   6.00-7.00   sec   384 KBytes  3.14 Mbits/sec    0   40.9 KBytes
[  5]   7.00-8.00   sec  0.00 Bytes  0.00 bits/sec    0   38.3 KBytes
[  5]   8.00-9.00   sec   384 KBytes  3.15 Mbits/sec    0   40.9 KBytes
[  5]   9.00-10.00  sec  0.00 Bytes  0.00 bits/sec    0   40.9 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  2.75 MBytes  2.31 Mbits/sec    0             sender
[  5]   0.00-10.54  sec  2.12 MBytes  1.69 Mbits/sec                  receiver

iperf Done.
```
```bash
❯ iperf3 -s
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------
Accepted connection from 10.222.0.2, port 25864
[  5] local 10.222.0.1 port 5201 connected to 10.222.0.2 port 25878
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-1.92   sec   384 KBytes  1.64 Mbits/sec
[  5]   1.92-3.13   sec   256 KBytes  1.73 Mbits/sec
[  5]   3.13-4.94   sec   384 KBytes  1.73 Mbits/sec
[  5]   4.94-6.16   sec   256 KBytes  1.72 Mbits/sec
[  5]   6.16-7.97   sec   384 KBytes  1.73 Mbits/sec
[  5]   7.97-9.18   sec   256 KBytes  1.73 Mbits/sec
[  5]   9.18-10.54  sec   256 KBytes  1.55 Mbits/sec
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-10.54  sec  2.12 MBytes  1.69 Mbits/sec                  receiver
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------
```


1. **Client** allocates a relay on the TURN server, binds a channel to the peer
2. **Peer** listens for relayed packets and forwards them to the local WireGuard
3. All WireGuard traffic flows through the TURN relay using ChannelData framing

## Features

- **Full STUN/TURN implementation** — Allocate, CreatePermission, ChannelBind, Refresh
- **Transport**: UDP, TCP, TLS (with SNI)
- **Credential providers**: manual, VK Calls (anonymous, no login), Yandex Telemost
- **ChannelData framing** — minimal overhead (4-byte header)
- **Auto-refresh** — allocation, permission, and channel bindings refreshed automatically
- **Pure Rust** — no C dependencies, no OpenSSL (uses rustls)

## Build

```bash
cargo build --release
```

Binary: `target/release/turnnel`

## Quick Start — VK Calls (Anonymous, No Login Required)

### 1. Create a VK call link

Open [vk.com](https://vk.com), start a call, copy the invite link:
`https://vk.com/call/join/XXXXX`

### 2. Start peer on your VPS

```bash
# On VPS (public IP, e.g. 203.0.113.50)
turnnel peer --listen 0.0.0.0:9999 --forward 127.0.0.1:51820
```

### 3. Start client locally

```bash
# On local machine — no cookies, no tokens, no login!
turnnel client \
  --provider vk \
  --call-url "https://vk.com/call/join/XXXXX" \
  --peer 203.0.113.50:9999 \
  --listen 127.0.0.1:51821
```

### 4. Point WireGuard to the tunnel

Set WireGuard client endpoint to `127.0.0.1:51821`.

### VK Anonymous Flow

The VK provider uses a fully anonymous 4-step flow — no browser cookies,
no auth tokens, no VK account required:

```text
Step 1: POST login.vk.ru          → VK anonymous access_token
Step 2: POST api.vk.ru            → call-specific anonymToken
Step 3: POST calls.okcdn.ru       → OK platform session_key
Step 4: POST calls.okcdn.ru       → TURN server credentials
```

Credentials are obtained in ~1 second:

```
step 1/4 ✓  VK anon access_token     67ms
step 2/4 ✓  call anonymToken         728ms
step 3/4 ✓  OK session_key            38ms
step 4/4 ✓  TURN credentials         216ms
```

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

### Client Side — VK Calls (Anonymous)

```bash
# No cookies or tokens needed!
turnnel client \
  --provider vk \
  --call-url "https://vk.com/call/join/XXXXX" \
  --peer <PEER_PUBLIC_IP>:9999 \
  --listen 127.0.0.1:51821
```

If the anonymous flow fails (e.g. VK changes their API), you can provide
a fallback auth token obtained from the browser:

```bash
turnnel client \
  --provider vk \
  --call-url "https://vk.com/call/join/XXXXX" \
  --auth-token '$3w6jWNuUI...' \
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

## End-to-End Testing

### On VPS

```bash
chmod +x server-test.sh
./server-test.sh
```

```text
╔═════════════════════════════════════════════════╗
║   turnnel PEER + ECHO server (VPS side)         ║
╚═════════════════════════════════════════════════╝
  Peer listen: 0.0.0.0:9999
  Forward to:  127.0.0.1:51820
  Echo server: 127.0.0.1:51820

[ OK ] Echo server running
[ OK ] Peer relay running
[ OK ] Port 9999/udp is listening

════════════════════════════════════════════
  PEER READY
════════════════════════════════════════════

  On the client machine, run:
  ./client-test.sh 'https://vk.com/call/join/YOUR_LINK'
```

### On Client

```bash
chmod +x client-test.sh
./client-test.sh 'https://vk.com/call/join/YOUR_LINK'
```

```text
╔═════════════════════════════════════════════════╗
║   turnnel e2e test via VK TURN                  ║
╚═════════════════════════════════════════════════╝
  VPS peer:    203.0.113.50:9999
  TURN:        VK (anonymous 4-step flow)
  Auth token:  not needed (anonymous flow)

[ OK ] TURN tunnel established via VK!
  ▸ Used: anonymous 4-step flow (no auth needed)

[ OK ] Packet 1/5: 37 bytes ✓
[ OK ] Packet 2/5: 37 bytes ✓
[ OK ] Packet 3/5: 37 bytes ✓
[ OK ] Packet 4/5: 37 bytes ✓
[ OK ] Packet 5/5: 37 bytes ✓
[ OK ] 1400 bytes echoed ✓
[ OK ] Burst: 10/10 received ✓

════════════════════════════════════════════
  ALL 7/7 PASSED — VK TURN TUNNEL WORKS! 🎉
════════════════════════════════════════════
```

Environment variables for test scripts:

| Variable | Default | Description |
|---|---|---|
| `VPS_IP` | `185.239.130.173` | Peer VPS address |
| `PEER_PORT` | `9999` | Peer UDP port |
| `PEER_LISTEN` | `0.0.0.0:9999` | Peer listen address |
| `FORWARD` | `127.0.0.1:51820` | WireGuard forward address |
| `ECHO_PORT` | `51820` | Echo server port |
| `BINARY` | `./target/release/turnnel` | Path to binary |

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
│       ├── vk.rs                  #   VK Calls (anonymous 4-step flow)
│       ├── yandex.rs              #   Yandex Telemost
│       └── sdp.rs                 #   iceServers JSON parser
├── server-test.sh                 # VPS-side: peer + echo server
├── client-test.sh                 # Client-side: e2e test suite
└── README.md
```

## Testing

```bash
# Unit tests
cargo test --workspace

# With logs
RUST_LOG=debug cargo test --workspace -- --nocapture

# End-to-end (requires VPS + VK call link)
./server-test.sh                                          # on VPS
./client-test.sh 'https://vk.com/call/join/YOUR_LINK'    # on client
```

## How VK Provider Works

VK Calls use the OK (Odnoklassniki) media infrastructure for WebRTC.
The anonymous flow exploits the guest-join feature — same as joining
a VK call without a VK account from a browser.

```text
VK Calls app (ID ____________)          OK media backend
┌──────────────────────┐          ┌──────────────────────┐
│ 1. get_anonym_token  │          │ 3. auth.anonymLogin  │
│    → access_token    │          │    → session_key     │
│                      │          │                      │
│ 2. getAnonymousToken │          │ 4. joinConversation  │
│    → anonymToken     │─────────►│    → TURN creds      │
└──────────────────────┘          └──────────────────────┘
```

All constants (app IDs, secrets, endpoints) are extracted from
VK's public frontend JavaScript and can be updated in `vk.rs`
if VK changes their app:

```rust
const VK_CLIENT_ID:     &str = "_______";
const VK_CLIENT_SECRET: &str = "_____________";
const OK_APP_KEY:       &str = "_________________";
```

## Status

**Beta** — core tunnel works, tested end-to-end with VK TURN servers.
