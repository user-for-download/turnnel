//! STUN Message — кодирование и декодирование.
//!
//! Формат (RFC 5389 §6):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use bytes::{BufMut, BytesMut};
use rand::Rng;

use crate::attribute::Attribute;
use crate::error::StunError;
use crate::integrity::{compute_fingerprint, compute_message_integrity, MAGIC_COOKIE};
use crate::types::{decode_message_type, encode_message_type, Class, Method};

/// STUN header size: type(2) + length(2) + cookie(4) + transaction_id(12) = 20.
pub const HEADER_SIZE: usize = 20;

#[derive(Debug, Clone)]
pub struct StunMessage {
    pub method: Method,
    pub class: Class,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    /// Создаёт новое сообщение со случайным transaction ID.
    pub fn new(method: Method, class: Class) -> Self {
        let mut tid = [0u8; 12];
        rand::thread_rng().fill(&mut tid);
        Self {
            method,
            class,
            transaction_id: tid,
            attributes: Vec::new(),
        }
    }

    /// Добавляет атрибут.
    pub fn add(&mut self, attr: Attribute) -> &mut Self {
        self.attributes.push(attr);
        self
    }

    /// Кодирует сообщение в байты.
    ///
    /// - Если `key` задан — добавляет MESSAGE-INTEGRITY.
    /// - Если `fingerprint` = true — добавляет FINGERPRINT.
    ///
    /// MESSAGE-INTEGRITY всегда идёт перед FINGERPRINT (RFC 5389 §15.4).
    pub fn encode(&self, key: Option<&[u8]>, fingerprint: bool) -> BytesMut {
        // 1. Кодируем все "обычные" атрибуты
        let mut attrs_buf = BytesMut::new();
        for attr in &self.attributes {
            attr.encode(&mut attrs_buf, &self.transaction_id);
        }

        // 2. Собираем header + attrs (без MI и FP)
        let mut msg = BytesMut::with_capacity(HEADER_SIZE + attrs_buf.len() + 32);
        msg.put_u16(encode_message_type(self.method, self.class));
        msg.put_u16(attrs_buf.len() as u16); // временный length
        msg.put_u32(MAGIC_COOKIE);
        msg.put_slice(&self.transaction_id);
        msg.put_slice(&attrs_buf);

        // 3. MESSAGE-INTEGRITY
        if let Some(k) = key {
            // compute_message_integrity хочет msg[..] — всё до MI
            let hmac = compute_message_integrity(&msg, k);

            // Добавляем MI атрибут
            let mi = Attribute::MessageIntegrity(hmac);
            mi.encode(&mut msg, &self.transaction_id);

            // Обновляем length в header
            set_length(&mut msg);
        }

        // 4. FINGERPRINT
        if fingerprint {
            // compute_fingerprint хочет msg[..] — всё до FP
            let crc = compute_fingerprint(&msg);

            let fp = Attribute::Fingerprint(crc);
            fp.encode(&mut msg, &self.transaction_id);

            set_length(&mut msg);
        }

        msg
    }

    /// Декодирует STUN сообщение из байтов.
    pub fn decode(buf: &[u8]) -> Result<Self, StunError> {
        if buf.len() < HEADER_SIZE {
            return Err(StunError::TooShort {
                expected: HEADER_SIZE,
                actual: buf.len(),
            });
        }

        // Проверяем два старших бита = 0
        if buf[0] & 0xC0 != 0 {
            return Err(StunError::InvalidMessageType(u16::from_be_bytes([
                buf[0], buf[1],
            ])));
        }

        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie(cookie));
        }

        let total = HEADER_SIZE + msg_len;
        if buf.len() < total {
            return Err(StunError::TooShort {
                expected: total,
                actual: buf.len(),
            });
        }

        let (method, class) =
            decode_message_type(msg_type).ok_or(StunError::InvalidMessageType(msg_type))?;

        let mut tid = [0u8; 12];
        tid.copy_from_slice(&buf[8..20]);

        let mut attributes = Vec::new();
        let mut offset = HEADER_SIZE;
        let end = total;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                // Обрезанный атрибут — прекращаем разбор
                break;
            }

            let attr_data = &buf[offset..offset + attr_len];
            let attr = Attribute::decode(attr_type, attr_data, &tid)?;
            attributes.push(attr);

            // Следующий атрибут начинается с выравнивания на 4
            let padded = attr_len + ((4 - (attr_len % 4)) % 4);
            offset += padded;
        }

        Ok(StunMessage {
            method,
            class,
            transaction_id: tid,
            attributes,
        })
    }

    // ── Convenience getters ──

    pub fn get_error_code(&self) -> Option<(u16, &str)> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::ErrorCode { code, reason } => Some((*code, reason.as_str())),
            _ => None,
        })
    }

    pub fn get_realm(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Realm(r) => Some(r.as_str()),
            _ => None,
        })
    }

    pub fn get_nonce(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Nonce(n) => Some(n.as_str()),
            _ => None,
        })
    }

    pub fn get_lifetime(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Lifetime(l) => Some(*l),
            _ => None,
        })
    }

    pub fn get_xor_mapped_address(&self) -> Option<SocketAddr> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::XorMappedAddress(addr) => Some(*addr),
            _ => None,
        })
    }

    pub fn get_xor_relayed_address(&self) -> Option<SocketAddr> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::XorRelayedAddress(addr) => Some(*addr),
            _ => None,
        })
    }
}

use std::net::SocketAddr;

/// Обновляет поле Message Length в header.
fn set_length(msg: &mut BytesMut) {
    let len = (msg.len() - HEADER_SIZE) as u16;
    msg[2] = (len >> 8) as u8;
    msg[3] = (len & 0xFF) as u8;
}
