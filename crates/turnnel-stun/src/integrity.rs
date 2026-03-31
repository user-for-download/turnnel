//! MESSAGE-INTEGRITY и FINGERPRINT по RFC 5389 §15.4–15.5.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// STUN Magic Cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Long-term credential key: MD5(username:realm:password).
/// RFC 5389 §15.4.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{username}:{realm}:{password}");
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

/// Вычисляет MESSAGE-INTEGRITY HMAC-SHA1.
///
/// `msg_prefix` — STUN сообщение от начала (включая 20-байтный header)
/// и ВСЕ атрибуты **до** MESSAGE-INTEGRITY (не включая сам MI).
///
/// Функция временно подменяет поле length в header, чтобы
/// оно указывало на конец MI атрибута (prefix_len - 20 + 24).
pub fn compute_message_integrity(msg_prefix: &[u8], key: &[u8]) -> [u8; 20] {
    assert!(
        msg_prefix.len() >= 20,
        "msg_prefix must include STUN header"
    );

    // Length field должен указывать так, будто MI — последний атрибут.
    // MI attribute = type(2) + length(2) + value(20) = 24 bytes.
    // Attrs перед MI занимают (msg_prefix.len() - 20) байт.
    // Итого: (msg_prefix.len() - 20) + 24.
    let adjusted_len = (msg_prefix.len() - 20 + 24) as u16;

    let mut buf = msg_prefix.to_vec();
    buf[2] = (adjusted_len >> 8) as u8;
    buf[3] = (adjusted_len & 0xFF) as u8;

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC-SHA1 accepts any key size");
    mac.update(&buf);

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// Вычисляет FINGERPRINT CRC-32.
///
/// `msg_prefix` — STUN сообщение от начала (включая header)
/// и ВСЕ атрибуты **до** FINGERPRINT (не включая сам FP).
///
/// Подменяет length, чтобы он указывал на конец FP атрибута.
/// FP attribute = type(2) + length(2) + value(4) = 8 bytes.
pub fn compute_fingerprint(msg_prefix: &[u8]) -> u32 {
    assert!(
        msg_prefix.len() >= 20,
        "msg_prefix must include STUN header"
    );

    let adjusted_len = (msg_prefix.len() - 20 + 8) as u16;

    let mut buf = msg_prefix.to_vec();
    buf[2] = (adjusted_len >> 8) as u8;
    buf[3] = (adjusted_len & 0xFF) as u8;

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&buf);
    hasher.finalize() ^ 0x5354_554E // XOR с "STUN"
}

/// Проверяет MESSAGE-INTEGRITY в полном STUN сообщении.
///
/// Ищет MI атрибут, вычисляет HMAC по данным до него,
/// сравнивает с сохранённым значением.
///
/// Возвращает `None` если MI атрибут не найден.
/// Возвращает `Some(true)` если проверка пройдена.
/// Возвращает `Some(false)` если HMAC не совпадает.
pub fn verify_message_integrity(raw_msg: &[u8], key: &[u8]) -> Option<bool> {
    if raw_msg.len() < 20 {
        return None;
    }

    let msg_len = u16::from_be_bytes([raw_msg[2], raw_msg[3]]) as usize;
    let total = 20 + msg_len;
    if raw_msg.len() < total {
        return None;
    }

    // Ищем MI атрибут
    let mut offset = 20usize;
    while offset + 4 <= total {
        let attr_type = u16::from_be_bytes([raw_msg[offset], raw_msg[offset + 1]]);
        let attr_len = u16::from_be_bytes([raw_msg[offset + 2], raw_msg[offset + 3]]) as usize;

        if attr_type == crate::attribute::ATTR_MESSAGE_INTEGRITY {
            if attr_len != 20 || offset + 4 + 20 > total {
                return Some(false);
            }

            // Извлекаем записанный HMAC
            let mut received = [0u8; 20];
            received.copy_from_slice(&raw_msg[offset + 4..offset + 24]);

            // Вычисляем ожидаемый: по msg[..offset] (всё до MI)
            let expected = compute_message_integrity(&raw_msg[..offset], key);

            return Some(expected == received);
        }

        let padded_len = attr_len + ((4 - (attr_len % 4)) % 4);
        offset += 4 + padded_len;
    }

    // MI не найден
    None
}

#[cfg(test)]
mod integrity_tests {
    use super::*;

    #[test]
    fn test_long_term_key_deterministic() {
        let k1 = long_term_key("user", "realm", "pass");
        let k2 = long_term_key("user", "realm", "pass");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 16); // MD5 = 128 bit
    }

    #[test]
    fn test_long_term_key_changes_with_input() {
        let k1 = long_term_key("user1", "realm", "pass");
        let k2 = long_term_key("user2", "realm", "pass");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_fingerprint_xor_constant() {
        // Проверяем, что XOR-константа — это ASCII "STUN"
        let stun_ascii = u32::from_be_bytes([b'S', b'T', b'U', b'N']);
        assert_eq!(stun_ascii, 0x5354_554E);
    }
}
