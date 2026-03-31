//! Интеграционные тесты для turnnel-stun.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::attribute::Attribute;
use crate::channel_data::ChannelData;
use crate::integrity::{long_term_key, verify_message_integrity};
use crate::message::StunMessage;
use crate::types::{Class, Method};
use crate::{demux, PacketType};
use bytes::Bytes;

// ── demux ──

#[test]
fn test_demux_stun() {
    // STUN: первые два бита = 0, первый байт 0x00 или 0x01
    assert_eq!(demux(&[0x00, 0x01]), PacketType::Stun);
    assert_eq!(demux(&[0x01, 0x01]), PacketType::Stun);
}

#[test]
fn test_demux_channel_data() {
    // ChannelData: первый байт 0x40..=0x7F
    assert_eq!(demux(&[0x40, 0x00]), PacketType::ChannelData);
    assert_eq!(demux(&[0x7F, 0xFF]), PacketType::ChannelData);
}

#[test]
fn test_demux_empty() {
    assert_eq!(demux(&[]), PacketType::Unknown);
}

// ── Allocate Request roundtrip ──

#[test]
fn test_allocate_request_roundtrip_no_integrity() {
    let mut msg = StunMessage::new(Method::Allocate, Class::Request);
    msg.add(Attribute::RequestedTransport(17)); // UDP
    msg.add(Attribute::Lifetime(3600));

    let encoded = msg.encode(None, false);
    let decoded = StunMessage::decode(&encoded).expect("decode failed");

    assert_eq!(decoded.method, Method::Allocate);
    assert_eq!(decoded.class, Class::Request);
    assert_eq!(decoded.transaction_id, msg.transaction_id);
    assert_eq!(decoded.get_lifetime(), Some(3600));

    // Проверяем RequestedTransport
    let has_transport = decoded
        .attributes
        .iter()
        .any(|a| matches!(a, Attribute::RequestedTransport(17)));
    assert!(has_transport);
}

#[test]
fn test_allocate_request_with_integrity_and_fingerprint() {
    let mut msg = StunMessage::new(Method::Allocate, Class::Request);
    msg.add(Attribute::RequestedTransport(17));
    msg.add(Attribute::Lifetime(3600));
    msg.add(Attribute::Username("testuser".into()));
    msg.add(Attribute::Realm("example.com".into()));
    msg.add(Attribute::Nonce("abc123nonce".into()));

    let key = long_term_key("testuser", "example.com", "password");
    let encoded = msg.encode(Some(&key), true);

    // Декодируем
    let decoded = StunMessage::decode(&encoded).expect("decode failed");
    assert_eq!(decoded.method, Method::Allocate);
    assert_eq!(decoded.class, Class::Request);
    assert_eq!(decoded.get_realm(), Some("example.com"));
    assert_eq!(decoded.get_nonce(), Some("abc123nonce"));
    assert_eq!(decoded.get_lifetime(), Some(3600));

    // Проверяем MESSAGE-INTEGRITY
    let mi_ok = verify_message_integrity(&encoded, &key);
    assert_eq!(mi_ok, Some(true), "MESSAGE-INTEGRITY verification failed");

    // Проверяем, что неправильный ключ не проходит
    let wrong_key = long_term_key("testuser", "example.com", "wrongpass");
    let mi_wrong = verify_message_integrity(&encoded, &wrong_key);
    assert_eq!(mi_wrong, Some(false), "wrong key should fail MI check");
}

// ── XOR Address roundtrip ──

#[test]
fn test_xor_peer_address_ipv4() {
    let addr = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 9999);
    let mut msg = StunMessage::new(Method::CreatePermission, Class::Request);
    msg.add(Attribute::XorPeerAddress(addr));

    let encoded = msg.encode(None, false);
    let decoded = StunMessage::decode(&encoded).unwrap();

    let found = decoded.attributes.iter().find_map(|a| match a {
        Attribute::XorPeerAddress(a) => Some(*a),
        _ => None,
    });
    assert_eq!(found, Some(addr));
}

#[test]
fn test_xor_mapped_address_ipv6() {
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let addr = SocketAddr::new(ip.into(), 443);
    let mut msg = StunMessage::new(Method::Binding, Class::SuccessResponse);
    msg.add(Attribute::XorMappedAddress(addr));

    let encoded = msg.encode(None, false);
    let decoded = StunMessage::decode(&encoded).unwrap();

    assert_eq!(decoded.get_xor_mapped_address(), Some(addr));
}

// ── ChannelBind request ──

#[test]
fn test_channel_bind_request() {
    let peer = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 1).into(), 9999);
    let mut msg = StunMessage::new(Method::ChannelBind, Class::Request);
    msg.add(Attribute::ChannelNumber(0x4000));
    msg.add(Attribute::XorPeerAddress(peer));

    let key = long_term_key("user", "realm", "pass");
    let encoded = msg.encode(Some(&key), true);

    let decoded = StunMessage::decode(&encoded).unwrap();
    assert_eq!(decoded.method, Method::ChannelBind);

    let ch = decoded.attributes.iter().find_map(|a| match a {
        Attribute::ChannelNumber(c) => Some(*c),
        _ => None,
    });
    assert_eq!(ch, Some(0x4000));

    let peer_addr = decoded.attributes.iter().find_map(|a| match a {
        Attribute::XorPeerAddress(a) => Some(*a),
        _ => None,
    });
    assert_eq!(peer_addr, Some(peer));

    assert_eq!(verify_message_integrity(&encoded, &key), Some(true));
}

// ── Error response ──

#[test]
fn test_error_response_401() {
    let mut msg = StunMessage::new(Method::Allocate, Class::ErrorResponse);
    msg.add(Attribute::ErrorCode {
        code: 401,
        reason: "Unauthorized".into(),
    });
    msg.add(Attribute::Realm("example.com".into()));
    msg.add(Attribute::Nonce("servernonce".into()));

    let encoded = msg.encode(None, false);
    let decoded = StunMessage::decode(&encoded).unwrap();

    assert_eq!(decoded.class, Class::ErrorResponse);
    let (code, reason) = decoded.get_error_code().unwrap();
    assert_eq!(code, 401);
    assert_eq!(reason, "Unauthorized");
    assert_eq!(decoded.get_realm(), Some("example.com"));
    assert_eq!(decoded.get_nonce(), Some("servernonce"));
}

// ── ChannelData + demux ──

#[test]
fn test_channel_data_demux() {
    let cd = ChannelData::new(0x4000, Bytes::from_static(b"wireguard-packet")).unwrap();
    let encoded = cd.encode(false);

    // demux должен определить как ChannelData
    assert_eq!(demux(&encoded), PacketType::ChannelData);

    // а STUN Binding Request — как Stun
    let stun_msg = StunMessage::new(Method::Binding, Class::Request);
    let stun_encoded = stun_msg.encode(None, false);
    assert_eq!(demux(&stun_encoded), PacketType::Stun);
}

// ── Refresh ──

#[test]
fn test_refresh_request() {
    let mut msg = StunMessage::new(Method::Refresh, Class::Request);
    msg.add(Attribute::Lifetime(600));

    let key = long_term_key("u", "r", "p");
    let encoded = msg.encode(Some(&key), false);
    let decoded = StunMessage::decode(&encoded).unwrap();

    assert_eq!(decoded.method, Method::Refresh);
    assert_eq!(decoded.get_lifetime(), Some(600));
    assert_eq!(verify_message_integrity(&encoded, &key), Some(true));
}

// ── Проверяем что fingerprint не ломает MI ──

#[test]
fn test_integrity_with_and_without_fingerprint() {
    let key = long_term_key("user", "realm", "pass");

    // Без fingerprint
    let mut msg1 = StunMessage::new(Method::Binding, Class::Request);
    msg1.add(Attribute::Username("user".into()));
    let enc1 = msg1.encode(Some(&key), false);
    assert_eq!(verify_message_integrity(&enc1, &key), Some(true));

    // С fingerprint
    let mut msg2 = StunMessage::new(Method::Binding, Class::Request);
    msg2.transaction_id = msg1.transaction_id; // тот же tid
    msg2.add(Attribute::Username("user".into()));
    let enc2 = msg2.encode(Some(&key), true);
    assert_eq!(verify_message_integrity(&enc2, &key), Some(true));

    // enc2 длиннее enc1 на 8 байт (fingerprint attr)
    assert_eq!(enc2.len(), enc1.len() + 8);
}

// ── Проверяем что decode не падает на мусоре ──

#[test]
fn test_decode_garbage() {
    assert!(StunMessage::decode(&[]).is_err());
    assert!(StunMessage::decode(&[0; 19]).is_err());
    assert!(StunMessage::decode(&[0xFF; 20]).is_err()); // bad magic cookie
}

// ── Проверяем что Software атрибут работает ──

#[test]
fn test_software_attribute() {
    let mut msg = StunMessage::new(Method::Binding, Class::Request);
    msg.add(Attribute::Software("turnnel/0.1.0".into()));

    let encoded = msg.encode(None, false);
    let decoded = StunMessage::decode(&encoded).unwrap();

    let sw = decoded.attributes.iter().find_map(|a| match a {
        Attribute::Software(s) => Some(s.as_str()),
        _ => None,
    });
    assert_eq!(sw, Some("turnnel/0.1.0"));
}
