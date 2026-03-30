//! Тесты TurnSession с мок-TURN-сервером.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;

use turnnel_stun::attribute::Attribute;
use turnnel_stun::channel_data::ChannelData;
use turnnel_stun::integrity::long_term_key;
use turnnel_stun::message::StunMessage;
use turnnel_stun::types::{Class, Method};
use turnnel_stun::{demux, PacketType};

use crate::session::{SessionConfig, SessionState, TurnCredentials, TurnSession};

// ── Мок TURN сервер ──

const TEST_USERNAME: &str = "testuser";
const TEST_PASSWORD: &str = "testpass";
const TEST_REALM: &str = "test.realm";
const TEST_NONCE: &str = "testnonce123";

/// Fake relay address, который "выделяет" наш мок-сервер.
fn fake_relay_addr() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(198, 51, 100, 1).into(), 49152)
}

/// Fake mapped address.
fn fake_mapped_addr() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(203, 0, 113, 50).into(), 12345)
}

/// Запускает минимальный мок TURN-сервер.
/// Возвращает адрес, на котором он слушает.
async fn start_mock_turn() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        mock_turn_loop(socket).await;
    });

    (addr, handle)
}

async fn mock_turn_loop(socket: UdpSocket) {
    let hmac_key = long_term_key(TEST_USERNAME, TEST_REALM, TEST_PASSWORD);
    let mut buf = [0u8; 65535];

    loop {
        let (n, client_addr) = match socket.recv_from(&mut buf).await {
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

                let response = handle_stun_request(&msg, &hmac_key);
                if let Some(resp) = response {
                    let encoded = resp.encode(Some(&hmac_key), false);
                    let _ = socket.send_to(&encoded, client_addr).await;
                }
            }
            PacketType::ChannelData => {
                // Эхо: отправляем обратно те же данные через ChannelData
                let cd = match ChannelData::decode(frame) {
                    Ok(cd) => cd,
                    Err(_) => continue,
                };

                // Эхо с префиксом "echo:"
                let mut echo_data = b"echo:".to_vec();
                echo_data.extend_from_slice(&cd.data);

                if let Ok(echo_cd) = ChannelData::new(cd.channel, Bytes::from(echo_data)) {
                    let encoded = echo_cd.encode(false);
                    let _ = socket.send_to(&encoded, client_addr).await;
                }
            }
            _ => {}
        }
    }
}

fn handle_stun_request(req: &StunMessage, hmac_key: &[u8]) -> Option<StunMessage> {
    match req.method {
        Method::Allocate => Some(handle_allocate(req, hmac_key)),
        Method::CreatePermission => Some(handle_create_permission(req, hmac_key)),
        Method::ChannelBind => Some(handle_channel_bind(req, hmac_key)),
        Method::Refresh => Some(handle_refresh(req, hmac_key)),
        _ => None,
    }
}

fn handle_allocate(req: &StunMessage, _hmac_key: &[u8]) -> StunMessage {
    // Проверяем наличие credentials
    let has_username = req
        .attributes
        .iter()
        .any(|a| matches!(a, Attribute::Username(_)));

    if !has_username {
        // Первый запрос без credentials → 401
        let mut resp = StunMessage::new(Method::Allocate, Class::ErrorResponse);
        resp.transaction_id = req.transaction_id;
        resp.add(Attribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".into(),
        });
        resp.add(Attribute::Realm(TEST_REALM.into()));
        resp.add(Attribute::Nonce(TEST_NONCE.into()));
        return resp;
    }

    // Проверяем MESSAGE-INTEGRITY (необязательно для мока, но полезно)
    // В реальном сервере здесь была бы полная проверка

    // Успешный Allocate
    let mut resp = StunMessage::new(Method::Allocate, Class::SuccessResponse);
    resp.transaction_id = req.transaction_id;
    resp.add(Attribute::XorRelayedAddress(fake_relay_addr()));
    resp.add(Attribute::XorMappedAddress(fake_mapped_addr()));
    resp.add(Attribute::Lifetime(600));
    resp
}

fn handle_create_permission(req: &StunMessage, _hmac_key: &[u8]) -> StunMessage {
    let mut resp = StunMessage::new(Method::CreatePermission, Class::SuccessResponse);
    resp.transaction_id = req.transaction_id;
    resp
}

fn handle_channel_bind(req: &StunMessage, _hmac_key: &[u8]) -> StunMessage {
    let mut resp = StunMessage::new(Method::ChannelBind, Class::SuccessResponse);
    resp.transaction_id = req.transaction_id;
    resp
}

fn handle_refresh(req: &StunMessage, _hmac_key: &[u8]) -> StunMessage {
    let lifetime = req.get_lifetime().unwrap_or(600);
    let mut resp = StunMessage::new(Method::Refresh, Class::SuccessResponse);
    resp.transaction_id = req.transaction_id;
    resp.add(Attribute::Lifetime(lifetime));
    resp
}

// ── Тесты ──

fn test_config(server_addr: SocketAddr) -> SessionConfig {
    let peer_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 9999);
    SessionConfig::new(
        TurnCredentials {
            server_addr,
            username: TEST_USERNAME.into(),
            password: TEST_PASSWORD.into(),
            realm: None, // будет получен из 401
        },
        crate::transport::TransportProtocol::Udp, // <--- ДОБАВЛЕНО
        peer_addr,
    )
}

#[tokio::test]
async fn test_full_session_establish() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    assert_eq!(session.state(), SessionState::Init);

    session.establish().await.unwrap();
    assert_eq!(session.state(), SessionState::Active);

    // Проверяем allocation info
    let info = session.allocation_info().unwrap();
    assert_eq!(info.relay_addr, fake_relay_addr());
    assert_eq!(info.mapped_addr, Some(fake_mapped_addr()));
    assert_eq!(info.lifetime, 600);
}

#[tokio::test]
async fn test_relay_addr_available_after_establish() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    assert!(session.relay_addr().is_none());

    session.establish().await.unwrap();
    assert_eq!(session.relay_addr(), Some(fake_relay_addr()));
}

#[tokio::test]
async fn test_send_recv_channel_data() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    // Отправляем данные
    session.send_data(b"hello").await.unwrap();

    // Мок-сервер эхоит с префиксом "echo:"
    let response = session.recv_data().await.unwrap();
    assert_eq!(&response[..], b"echo:hello");
}

#[tokio::test]
async fn test_send_data_before_establish_fails() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let session = TurnSession::new(config).await.unwrap();
    let result = session.send_data(b"too early").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_refresh_allocation() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    // Refresh должен пройти
    session.refresh_allocation().await.unwrap();

    // Состояние должно остаться Active
    assert_eq!(session.state(), SessionState::Active);
}

#[tokio::test]
async fn test_refresh_permission() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    session.refresh_permission().await.unwrap();
    assert_eq!(session.state(), SessionState::Active);
}

#[tokio::test]
async fn test_refresh_channel() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    session.refresh_channel().await.unwrap();
    assert_eq!(session.state(), SessionState::Active);
}

#[tokio::test]
async fn test_time_until_expiry() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    let remaining = session.time_until_expiry().unwrap();
    // Должно быть ~600с (минус несколько ms на тест)
    assert!(remaining > Duration::from_secs(599));
    assert!(remaining <= Duration::from_secs(600));
}

#[tokio::test]
async fn test_needs_refresh_initially_false() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    // Только что создали — refresh не нужен
    assert!(!session.needs_allocation_refresh());
    assert!(!session.needs_permission_refresh());
    assert!(!session.needs_channel_refresh());
}

#[tokio::test]
async fn test_multiple_send_recv() {
    let (server_addr, _handle) = start_mock_turn().await;
    let config = test_config(server_addr);

    let mut session = TurnSession::new(config).await.unwrap();
    session.establish().await.unwrap();

    for i in 0..10 {
        let msg = format!("packet-{i}");
        session.send_data(msg.as_bytes()).await.unwrap();

        let resp = session.recv_data().await.unwrap();
        let expected = format!("echo:{msg}");
        assert_eq!(&resp[..], expected.as_bytes());
    }
}

#[tokio::test]
async fn test_timeout_on_dead_server() {
    // Привязываем сокет, но НЕ запускаем сервер → timeout
    let dead_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_socket.local_addr().unwrap();
    drop(dead_socket);

    let mut config = test_config(dead_addr);
    config.stun_timeout = Duration::from_millis(200); // быстрый таймаут для теста

    let mut session = TurnSession::new(config).await.unwrap();
    let result = session.establish().await;

    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("timeout") || err_str.contains("Timeout"),
        "expected timeout error, got: {err_str}"
    );
}
