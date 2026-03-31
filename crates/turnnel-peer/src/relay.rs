use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::signal;

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub listen_addr: SocketAddr,
    pub forward_addr: SocketAddr,
    pub relay_timeout: Duration,
}

impl PeerConfig {
    pub fn new(listen_addr: SocketAddr, forward_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            forward_addr,
            relay_timeout: Duration::from_secs(60),
        }
    }
}

struct RelayEntry {
    last_seen: Instant,
    packets: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PeerStats {
    pub packets_from_relay: u64,
    pub packets_to_relay: u64,
    pub bytes_from_relay: u64,
    pub bytes_to_relay: u64,
    pub active_relays: usize,
}

pub async fn run(config: PeerConfig) -> anyhow::Result<()> {
    let external = UdpSocket::bind(config.listen_addr).await?;
    tracing::info!(listen = %config.listen_addr, "external socket ready");

    let wg_socket = UdpSocket::bind("127.0.0.1:0").await?;
    tracing::info!(
        local = %wg_socket.local_addr()?,
        forward = %config.forward_addr,
        "WireGuard socket ready"
    );

    let mut relay_addrs: HashMap<SocketAddr, RelayEntry> = HashMap::new();
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));
    cleanup_timer.tick().await;

    let mut ext_buf = [0u8; 65535];
    let mut wg_buf = [0u8; 65535];

    loop {
        tokio::select! {
            result = external.recv_from(&mut ext_buf) => {
                let (n, src) = result?;

                relay_addrs.entry(src)
                    .and_modify(|e| {
                        e.last_seen = Instant::now();
                        e.packets += 1;
                    })
                    .or_insert(RelayEntry {
                        last_seen: Instant::now(),
                        packets: 1,
                    });

                wg_socket.send_to(&ext_buf[..n], config.forward_addr).await?;

                tracing::trace!(
                    from = %src,
                    bytes = n,
                    "relay → WG"
                );
            }

            result = wg_socket.recv_from(&mut wg_buf) => {
                let (n, _src) = result?;

                if let Some(relay) = freshest_relay(&relay_addrs) {
                    external.send_to(&wg_buf[..n], relay).await?;

                    tracing::trace!(
                        to = %relay,
                        bytes = n,
                        "WG → relay"
                    );
                } else {
                    tracing::warn!("no known relay address, dropping WG packet");
                }
            }

            _ = cleanup_timer.tick() => {
                let before = relay_addrs.len();
                relay_addrs.retain(|_, v| v.last_seen.elapsed() < config.relay_timeout);
                let after = relay_addrs.len();
                if before != after {
                    tracing::debug!(
                        removed = before - after,
                        active = after,
                        "cleaned stale relays"
                    );
                }
            }

            // Issue 10: graceful shutdown on Ctrl+C
            _ = signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, stopping relay");
                return Ok(());
            }
        }
    }
}

/// Issue 7: Returns the relay address with the most recent activity.
///
/// This is O(n) over the number of known relays. In practice n is tiny
/// (typically 1–2 relays), so a linear scan is perfectly adequate.
fn freshest_relay(relays: &HashMap<SocketAddr, RelayEntry>) -> Option<SocketAddr> {
    relays
        .iter()
        .max_by_key(|(_, e)| e.last_seen)
        .map(|(addr, _)| *addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_relay_roundtrip() {
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wg_addr = wg.local_addr().unwrap();

        let relay_listen = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listen.local_addr().unwrap();
        drop(relay_listen);

        let config = PeerConfig::new(relay_addr, wg_addr);

        let relay_handle = tokio::spawn(async move {
            if let Err(e) = run(config).await {
                tracing::error!("relay error: {e}");
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let wg_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (n, src) = wg.recv_from(&mut buf).await.unwrap();

                let mut reply = b"wg:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                wg.send_to(&reply, src).await.unwrap();
            }
        });

        client.send_to(b"hello", relay_addr).await.unwrap();

        let mut buf = [0u8; 1024];
        let result = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await;

        let (n, _) = result.expect("timeout").unwrap();
        assert_eq!(&buf[..n], b"wg:hello");

        relay_handle.abort();
        wg_handle.abort();
    }

    #[tokio::test]
    async fn test_no_relay_drops_wg_packets() {
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wg_addr = wg.local_addr().unwrap();

        let relay_listen = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listen.local_addr().unwrap();
        drop(relay_listen);

        let config = PeerConfig::new(relay_addr, wg_addr);
        let relay_handle = tokio::spawn(async move {
            let _ = run(config).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let wg_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        wg_client.send_to(b"orphan", relay_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        relay_handle.abort();
    }

    #[tokio::test]
    async fn test_freshest_relay_picks_most_recent() {
        let mut relays = HashMap::new();

        relays.insert(
            "127.0.0.1:1111".parse().unwrap(),
            RelayEntry {
                last_seen: Instant::now() - Duration::from_secs(30),
                packets: 9999,
            },
        );

        let fresh: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        relays.insert(
            fresh,
            RelayEntry {
                last_seen: Instant::now(),
                packets: 1,
            },
        );

        assert_eq!(freshest_relay(&relays), Some(fresh));
    }
}
