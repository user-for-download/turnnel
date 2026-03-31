use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::signal;
use turnnel_session::transport::TransportProtocol;

use turnnel_session::session::{
    SessionConfig, SessionError, TurnCredentials, TurnEvent, TurnSession,
};

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub credentials: TurnCredentials,
    pub peer_addr: SocketAddr,
    pub refresh_interval: Duration,
    pub protocol: TransportProtocol,
}

pub async fn run(config: ProxyConfig) -> anyhow::Result<()> {
    let wg_socket = UdpSocket::bind(config.listen_addr).await?;
    tracing::info!(listen = %config.listen_addr, "WireGuard proxy ready");
    run_inner(config, wg_socket).await
}

// Issue 5: validate that the pre-bound socket matches config.listen_addr
pub async fn run_with_listener(config: ProxyConfig, wg_socket: UdpSocket) -> anyhow::Result<()> {
    let actual = wg_socket.local_addr()?;
    if actual != config.listen_addr {
        tracing::warn!(
            configured = %config.listen_addr,
            actual = %actual,
            "listen address mismatch, using socket's actual address"
        );
    }
    tracing::info!(listen = %actual, "WireGuard proxy ready (pre-bound)");
    run_inner(config, wg_socket).await
}

async fn run_inner(config: ProxyConfig, wg_socket: UdpSocket) -> anyhow::Result<()> {
    let refresh_interval = config.refresh_interval;
    let peer_addr = config.peer_addr;

    let session_config = SessionConfig::new(config.credentials, config.protocol, peer_addr);

    let mut session = TurnSession::new(session_config).await?;
    session.establish().await?;

    let relay = session
        .relay_addr()
        .expect("must have relay after establish");
    tracing::info!(
        relay = %relay,
        peer = %peer_addr,
        "TURN tunnel established"
    );

    let result = run_data_loop(&mut session, &wg_socket, refresh_interval).await;

    tracing::info!("shutting down, releasing TURN allocation");
    if let Err(e) = session.deallocate().await {
        tracing::debug!("deallocate failed: {e}");
    }

    result
}

async fn run_data_loop(
    session: &mut TurnSession,
    wg_socket: &UdpSocket,
    refresh_interval: Duration,
) -> anyhow::Result<()> {
    let mut wg_client: Option<SocketAddr> = None;
    let mut wg_buf = [0u8; 65535];
    let mut refresh_timer = tokio::time::interval(refresh_interval);
    refresh_timer.tick().await;

    loop {
        tokio::select! {
            result = wg_socket.recv_from(&mut wg_buf) => {
                let (n, src) = result?;
                wg_client = Some(src);
                match session.send_data(&wg_buf[..n]).await {
                    Ok(()) => {}
                    Err(SessionError::Disconnected) => {
                        tracing::warn!("transport disconnected during send, attempting reconnect");
                        session.reconnect().await?;
                        session.send_data(&wg_buf[..n]).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            result = session.recv_event() => {
                match result {
                    Ok(TurnEvent::Data(data)) => {
                        if let Some(client) = wg_client {
                            wg_socket.send_to(&data, client).await?;
                        }
                    }
                    Ok(TurnEvent::StunResponse(msg)) => {
                        tracing::trace!(
                            method = ?msg.method,
                            class = ?msg.class,
                            "unexpected STUN response in data loop"
                        );
                    }
                    Err(SessionError::Disconnected) => {
                        tracing::warn!("transport disconnected during recv, attempting reconnect");
                        session.reconnect().await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            _ = refresh_timer.tick() => {
                if session.needs_allocation_refresh() {
                    tracing::debug!("refreshing allocation");
                    match session.refresh_allocation().await {
                        Ok(()) => {}
                        Err(SessionError::Disconnected) => {
                            tracing::warn!("disconnected during allocation refresh, reconnecting");
                            session.reconnect().await?;
                        }
                        Err(e) => tracing::warn!("allocation refresh failed: {e}"),
                    }
                }

                if session.needs_permission_refresh() {
                    tracing::debug!("refreshing permission");
                    match session.refresh_permission().await {
                        Ok(()) => {}
                        Err(SessionError::Disconnected) => {
                            tracing::warn!("disconnected during permission refresh, reconnecting");
                            session.reconnect().await?;
                        }
                        Err(e) => tracing::warn!("permission refresh failed: {e}"),
                    }
                }

                if session.needs_channel_refresh() {
                    tracing::debug!("refreshing channel");
                    match session.refresh_channel().await {
                        Ok(()) => {}
                        Err(SessionError::Disconnected) => {
                            tracing::warn!("disconnected during channel refresh, reconnecting");
                            session.reconnect().await?;
                        }
                        Err(e) => tracing::warn!("channel refresh failed: {e}"),
                    }
                }
            }

            _ = signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, stopping");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;
    use turnnel_stun::attribute::Attribute;
    use turnnel_stun::channel_data::ChannelData;
    use turnnel_stun::integrity::long_term_key;
    use turnnel_stun::message::StunMessage;
    use turnnel_stun::types::{Class, Method};
    use turnnel_stun::{demux, PacketType};

    const USER: &str = "user";
    const PASS: &str = "pass";
    const REALM: &str = "realm";

    async fn start_mock_turn() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let key = long_term_key(USER, REALM, PASS);
            let mut buf = [0u8; 65535];

            loop {
                let (n, client) = match socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };

                let frame = &buf[..n];
                match demux(frame) {
                    PacketType::Stun => {
                        let msg = match StunMessage::decode(frame) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        let resp = match msg.method {
                            Method::Allocate => {
                                let has_user = msg
                                    .attributes
                                    .iter()
                                    .any(|a| matches!(a, Attribute::Username(_)));
                                if !has_user {
                                    let mut r =
                                        StunMessage::new(Method::Allocate, Class::ErrorResponse);
                                    r.transaction_id = msg.transaction_id;
                                    r.add(Attribute::ErrorCode {
                                        code: 401,
                                        reason: "Unauthorized".into(),
                                    });
                                    r.add(Attribute::Realm(REALM.into()));
                                    r.add(Attribute::Nonce("nonce1".into()));
                                    r
                                } else {
                                    let mut r =
                                        StunMessage::new(Method::Allocate, Class::SuccessResponse);
                                    r.transaction_id = msg.transaction_id;
                                    r.add(Attribute::XorRelayedAddress(SocketAddr::new(
                                        Ipv4Addr::new(198, 51, 100, 1).into(),
                                        49152,
                                    )));
                                    r.add(Attribute::XorMappedAddress(SocketAddr::new(
                                        Ipv4Addr::new(203, 0, 113, 50).into(),
                                        12345,
                                    )));
                                    r.add(Attribute::Lifetime(600));
                                    r
                                }
                            }
                            Method::CreatePermission => {
                                let mut r = StunMessage::new(
                                    Method::CreatePermission,
                                    Class::SuccessResponse,
                                );
                                r.transaction_id = msg.transaction_id;
                                r
                            }
                            Method::ChannelBind => {
                                let mut r =
                                    StunMessage::new(Method::ChannelBind, Class::SuccessResponse);
                                r.transaction_id = msg.transaction_id;
                                r
                            }
                            Method::Refresh => {
                                let mut r =
                                    StunMessage::new(Method::Refresh, Class::SuccessResponse);
                                r.transaction_id = msg.transaction_id;
                                r.add(Attribute::Lifetime(msg.get_lifetime().unwrap_or(600)));
                                r
                            }
                            _ => continue,
                        };

                        let encoded = resp.encode(Some(&key), false);
                        let _ = socket.send_to(&encoded, client).await;
                    }
                    PacketType::ChannelData => {
                        let cd = match ChannelData::decode(frame) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let mut echo = b"echo:".to_vec();
                        echo.extend_from_slice(&cd.data);
                        if let Ok(reply) = ChannelData::new(cd.channel, Bytes::from(echo)) {
                            let _ = socket.send_to(&reply.encode(false), client).await;
                        }
                    }
                    _ => {}
                }
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_proxy_roundtrip() {
        let turn_addr = start_mock_turn().await;

        let wg_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = wg_socket.local_addr().unwrap();

        let config = ProxyConfig {
            listen_addr: proxy_addr,
            credentials: TurnCredentials {
                server_addr: turn_addr,
                username: USER.into(),
                password: PASS.into(),
                realm: None,
            },
            peer_addr: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 9999),
            refresh_interval: Duration::from_secs(30),
            protocol: TransportProtocol::Udp,
        };

        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = run_with_listener(config, wg_socket).await {
                tracing::error!("proxy error: {e}");
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        wg.send_to(b"wg-handshake", proxy_addr).await.unwrap();

        let mut buf = [0u8; 1024];
        let result = tokio::time::timeout(Duration::from_secs(2), wg.recv_from(&mut buf)).await;

        let (n, _) = result.expect("timeout").unwrap();
        assert_eq!(&buf[..n], b"echo:wg-handshake");

        proxy_handle.abort();
    }
}