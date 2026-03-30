//! STUN/TURN атрибуты — кодирование и декодирование.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, BytesMut};

use crate::error::StunError;
use crate::integrity::MAGIC_COOKIE;

// --- Attribute type constants (RFC 5389 + RFC 5766) ---

// Comprehension-required (0x0000–0x7FFF)
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// Comprehension-optional (0x8000–0xFFFF)
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

/// Поддерживаемые STUN/TURN атрибуты.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    // --- Строковые ---
    Username(String),
    Realm(String),
    Nonce(String),
    Software(String),

    // --- Адресные (XOR-encoded) ---
    XorMappedAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    XorPeerAddress(SocketAddr),

    // --- Числовые ---
    Lifetime(u32),
    ChannelNumber(u16),
    /// transport protocol number (17 = UDP, 6 = TCP)
    RequestedTransport(u8),

    // --- Сложные ---
    ErrorCode {
        code: u16,
        reason: String,
    },
    Data(Vec<u8>),

    // --- Integrity/Fingerprint (при декодировании) ---
    MessageIntegrity([u8; 20]),
    Fingerprint(u32),

    // --- Неизвестные (прозрачно пробрасываем) ---
    Unknown {
        attr_type: u16,
        data: Vec<u8>,
    },
}

impl Attribute {
    /// Кодирует атрибут в буфер.
    /// `transaction_id` нужен для XOR-адресов.
    pub fn encode(&self, buf: &mut BytesMut, transaction_id: &[u8; 12]) {
        match self {
            Attribute::Username(s) => encode_string(buf, ATTR_USERNAME, s),
            Attribute::Realm(s) => encode_string(buf, ATTR_REALM, s),
            Attribute::Nonce(s) => encode_string(buf, ATTR_NONCE, s),
            Attribute::Software(s) => encode_string(buf, ATTR_SOFTWARE, s),

            Attribute::XorMappedAddress(addr) => {
                encode_xor_addr(buf, ATTR_XOR_MAPPED_ADDRESS, addr, transaction_id);
            }
            Attribute::XorRelayedAddress(addr) => {
                encode_xor_addr(buf, ATTR_XOR_RELAYED_ADDRESS, addr, transaction_id);
            }
            Attribute::XorPeerAddress(addr) => {
                encode_xor_addr(buf, ATTR_XOR_PEER_ADDRESS, addr, transaction_id);
            }

            Attribute::Lifetime(val) => encode_u32(buf, ATTR_LIFETIME, *val),
            Attribute::ChannelNumber(ch) => {
                // RFC 5766 §11.1: channel number (2 bytes) + RFFU (2 bytes, must be 0)
                buf.put_u16(ATTR_CHANNEL_NUMBER);
                buf.put_u16(4); // attribute length = 4
                buf.put_u16(*ch);
                buf.put_u16(0); // RFFU
            }
            Attribute::RequestedTransport(proto) => {
                // RFC 5766 §14.7: protocol (1 byte) + RFFU (3 bytes)
                buf.put_u16(ATTR_REQUESTED_TRANSPORT);
                buf.put_u16(4);
                buf.put_u8(*proto);
                buf.put_bytes(0, 3); // RFFU
            }

            Attribute::ErrorCode { code, reason } => {
                let class = (code / 100) as u8;
                let number = (code % 100) as u8;
                let val_len = 4 + reason.len();

                buf.put_u16(ATTR_ERROR_CODE);
                buf.put_u16(val_len as u16);
                buf.put_u16(0); // reserved
                buf.put_u8(class);
                buf.put_u8(number);
                buf.put_slice(reason.as_bytes());
                pad4(buf, val_len);
            }
            Attribute::Data(data) => {
                buf.put_u16(ATTR_DATA);
                buf.put_u16(data.len() as u16);
                buf.put_slice(data);
                pad4(buf, data.len());
            }

            Attribute::MessageIntegrity(mac) => {
                buf.put_u16(ATTR_MESSAGE_INTEGRITY);
                buf.put_u16(20);
                buf.put_slice(mac);
                // 20 bytes, кратно 4 — padding не нужен
            }
            Attribute::Fingerprint(val) => {
                buf.put_u16(ATTR_FINGERPRINT);
                buf.put_u16(4);
                buf.put_u32(*val);
            }

            Attribute::Unknown { attr_type, data } => {
                buf.put_u16(*attr_type);
                buf.put_u16(data.len() as u16);
                buf.put_slice(data);
                pad4(buf, data.len());
            }
        }
    }

    /// Декодирует один атрибут из сырых данных.
    pub fn decode(
        attr_type: u16,
        data: &[u8],
        transaction_id: &[u8; 12],
    ) -> Result<Self, StunError> {
        match attr_type {
            ATTR_USERNAME => Ok(Attribute::Username(String::from_utf8(data.to_vec())?)),
            ATTR_REALM => Ok(Attribute::Realm(String::from_utf8(data.to_vec())?)),
            ATTR_NONCE => Ok(Attribute::Nonce(String::from_utf8(data.to_vec())?)),
            ATTR_SOFTWARE => Ok(Attribute::Software(String::from_utf8(data.to_vec())?)),

            ATTR_XOR_MAPPED_ADDRESS => Ok(Attribute::XorMappedAddress(decode_xor_addr(
                data,
                transaction_id,
            )?)),
            ATTR_XOR_RELAYED_ADDRESS => Ok(Attribute::XorRelayedAddress(decode_xor_addr(
                data,
                transaction_id,
            )?)),
            ATTR_XOR_PEER_ADDRESS => Ok(Attribute::XorPeerAddress(decode_xor_addr(
                data,
                transaction_id,
            )?)),

            ATTR_LIFETIME => {
                ensure_len(attr_type, data, 4)?;
                Ok(Attribute::Lifetime(u32::from_be_bytes([
                    data[0], data[1], data[2], data[3],
                ])))
            }
            ATTR_CHANNEL_NUMBER => {
                ensure_len(attr_type, data, 4)?;
                Ok(Attribute::ChannelNumber(u16::from_be_bytes([
                    data[0], data[1],
                ])))
            }
            ATTR_REQUESTED_TRANSPORT => {
                ensure_len(attr_type, data, 4)?;
                Ok(Attribute::RequestedTransport(data[0]))
            }

            ATTR_ERROR_CODE => {
                ensure_len(attr_type, data, 4)?;
                let class = (data[2] & 0x07) as u16;
                let number = data[3] as u16;
                let code = class * 100 + number;
                let reason = String::from_utf8(data[4..].to_vec()).unwrap_or_default();
                Ok(Attribute::ErrorCode { code, reason })
            }
            ATTR_DATA => Ok(Attribute::Data(data.to_vec())),

            ATTR_MESSAGE_INTEGRITY => {
                ensure_len(attr_type, data, 20)?;
                let mut mac = [0u8; 20];
                mac.copy_from_slice(&data[..20]);
                Ok(Attribute::MessageIntegrity(mac))
            }
            ATTR_FINGERPRINT => {
                ensure_len(attr_type, data, 4)?;
                Ok(Attribute::Fingerprint(u32::from_be_bytes([
                    data[0], data[1], data[2], data[3],
                ])))
            }

            _ => Ok(Attribute::Unknown {
                attr_type,
                data: data.to_vec(),
            }),
        }
    }
}

// ── Вспомогательные функции ──

fn ensure_len(attr_type: u16, data: &[u8], min: usize) -> Result<(), StunError> {
    if data.len() < min {
        Err(StunError::InvalidAttributeLength { attr_type })
    } else {
        Ok(())
    }
}

fn encode_string(buf: &mut BytesMut, attr_type: u16, s: &str) {
    buf.put_u16(attr_type);
    buf.put_u16(s.len() as u16);
    buf.put_slice(s.as_bytes());
    pad4(buf, s.len());
}

fn encode_u32(buf: &mut BytesMut, attr_type: u16, val: u32) {
    buf.put_u16(attr_type);
    buf.put_u16(4);
    buf.put_u32(val);
}

/// Добавляет padding до кратности 4.
fn pad4(buf: &mut BytesMut, value_len: usize) {
    let remainder = value_len % 4;
    if remainder != 0 {
        buf.put_bytes(0, 4 - remainder);
    }
}

/// Кодирует XOR-адрес (RFC 5389 §15.2).
fn encode_xor_addr(
    buf: &mut BytesMut,
    attr_type: u16,
    addr: &SocketAddr,
    transaction_id: &[u8; 12],
) {
    let xor_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf.put_u16(attr_type);
            buf.put_u16(8); // value length
            buf.put_u8(0); // reserved
            buf.put_u8(0x01); // family: IPv4
            buf.put_u16(xor_port);
            let xor_ip = u32::from(ipv4) ^ MAGIC_COOKIE;
            buf.put_u32(xor_ip);
        }
        IpAddr::V6(ipv6) => {
            buf.put_u16(attr_type);
            buf.put_u16(20); // value length
            buf.put_u8(0); // reserved
            buf.put_u8(0x02); // family: IPv6
            buf.put_u16(xor_port);
            let mut ip_bytes = ipv6.octets();
            let magic = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                ip_bytes[i] ^= magic[i];
            }
            for i in 0..12 {
                ip_bytes[i + 4] ^= transaction_id[i];
            }
            buf.put_slice(&ip_bytes);
        }
    }
}

/// Декодирует XOR-адрес (RFC 5389 §15.2).
fn decode_xor_addr(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if data.len() < 4 {
        return Err(StunError::InvalidAttributeLength { attr_type: 0 });
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return Err(StunError::InvalidAttributeLength { attr_type: 0 });
            }
            let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = Ipv4Addr::from(xor_ip ^ MAGIC_COOKIE);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(StunError::InvalidAttributeLength { attr_type: 0 });
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let magic = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                ip_bytes[i] ^= magic[i];
            }
            for i in 0..12 {
                ip_bytes[i + 4] ^= transaction_id[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => Err(StunError::InvalidAddressFamily(family)),
    }
}
