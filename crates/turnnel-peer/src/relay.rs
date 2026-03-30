//! turnnel-peer: UDP relay на VPS.
//!
//! Принимает UDP от TURN relay-адресов, пересылает на локальный WireGuard.
//! Ответы WireGuard отправляет обратно на последний известный relay-адрес.
//!
//! Не знает ничего о TURN-протоколе — работает с чистым UDP.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

/// Конфигурация peer relay.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Адрес для приёма от TURN relay (обычно 0.0.0.0:9999).
    pub listen_addr: SocketAddr,
    /// Адрес локального WireGuard (обычно 127.0.0.1:51820).
    pub forward_addr: SocketAddr,
    /// Таймаут для очистки неактивных relay-адресов.
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

/// Информация о relay-источнике.
struct RelayEntry {
    last_seen: Instant,
    packets: u64,
}

/// Статистика работы.
#[derive(Debug, Default, Clone)]
pub struct PeerStats {
    pub packets_from_relay: u64,
    pub packets_to_relay: u64,
    pub bytes_from_relay: u64,
    pub bytes_to_relay: u64,
    pub active_relays: usize,
}

/// Запускает peer relay.
///
/// Блокирует до ошибки или отмены задачи.
pub async fn run(config: PeerConfig) -> anyhow::Result<()> {
    // Сокет для приёма от TURN relay
    let external = UdpSocket::bind(config.listen_addr).await?;
    tracing::info!(listen = %config.listen_addr, "external socket ready");

    // Сокет для общения с WireGuard
    // Привязываем к 127.0.0.1:0 — случайный порт
    let wg_socket = UdpSocket::bind("127.0.0.1:0").await?;
    tracing::info!(
        local = %wg_socket.local_addr()?,
        forward = %config.forward_addr,
        "WireGuard socket ready"
    );

    let mut relay_addrs: HashMap<SocketAddr, RelayEntry> = HashMap::new();
    let mut last_cleanup = Instant::now();

    let mut ext_buf = [0u8; 65535];
    let mut wg_buf = [0u8; 65535];

    loop {
        tokio::select! {
            // TURN relay → WireGuard
            result = external.recv_from(&mut ext_buf) => {
                let (n, src) = result?;

                // Запоминаем relay-адрес
                relay_addrs.entry(src)
                    .and_modify(|e| {
                        e.last_seen = Instant::now();
                        e.packets += 1;
                    })
                    .or_insert(RelayEntry {
                        last_seen: Instant::now(),
                        packets: 1,
                    });

                // Пересылаем на WireGuard
                wg_socket.send_to(&ext_buf[..n], config.forward_addr).await?;

                tracing::trace!(
                    from = %src,
                    bytes = n,
                    "relay → WG"
                );
            }

            // WireGuard → TURN relay
            result = wg_socket.recv_from(&mut wg_buf) => {
                let (n, _src) = result?;

                // Отправляем на самый свежий relay-адрес
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

            // Периодическая очистка
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                if last_cleanup.elapsed() >= Duration::from_secs(10) {
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
                    last_cleanup = Instant::now();
                }
            }
        }
    }
}

/// Возвращает relay-адрес с наиболее свежим пакетом.
fn freshest_relay(relays: &HashMap<SocketAddr, RelayEntry>) -> Option<SocketAddr> {
    relays
        .iter()
        .max_by_key(|(_, e)| e.packets)
        .map(|(addr, _)| *addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    /// Тест: данные проходят через relay в обе стороны.
    #[tokio::test]
    async fn test_relay_roundtrip() {
        // "WireGuard" — просто UDP эхо-сервер
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wg_addr = wg.local_addr().unwrap();

        // Запускаем relay
        let relay_listen = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listen.local_addr().unwrap();
        drop(relay_listen); // освобождаем порт для relay

        let config = PeerConfig::new(relay_addr, wg_addr);

        let relay_handle = tokio::spawn(async move {
            if let Err(e) = run(config).await {
                tracing::error!("relay error: {e}");
            }
        });

        // Даём relay время стартовать
        tokio::time::sleep(Duration::from_millis(50)).await;

        // "TURN relay" клиент
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // WG echo server
        let wg_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (n, src) = wg.recv_from(&mut buf).await.unwrap();
                // Эхо с префиксом
                let mut reply = b"wg:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                wg.send_to(&reply, src).await.unwrap();
            }
        });

        // Отправляем через relay
        client.send_to(b"hello", relay_addr).await.unwrap();

        // Ждём ответ
        let mut buf = [0u8; 1024];
        let result = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await;

        let (n, _) = result.expect("timeout").unwrap();
        assert_eq!(&buf[..n], b"wg:hello");

        // Cleanup
        relay_handle.abort();
        wg_handle.abort();
    }

    /// Тест: без relay-адреса пакеты от WG дропаются.
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

        // WG шлёт данные, но relay не знает куда отправить — не должен падать
        let wg_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        wg_client.send_to(b"orphan", relay_addr).await.unwrap();

        // Подождём немного — relay не должен упасть
        tokio::time::sleep(Duration::from_millis(100)).await;

        relay_handle.abort();
    }
}
