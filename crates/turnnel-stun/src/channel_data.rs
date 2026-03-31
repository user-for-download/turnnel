//! TURN ChannelData frame (RFC 5766 §11.4).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Channel Number        |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! /                       Application Data                        /
//! /                                                               /
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::StunError;

/// TURN channel number range.
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x7FFF;

/// ChannelData header size.
pub const CHANNEL_DATA_HEADER: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelData {
    pub channel: u16,
    pub data: Bytes,
}

impl ChannelData {
    /// Создаёт новый ChannelData. Проверяет валидность channel number.
    pub fn new(channel: u16, data: Bytes) -> Result<Self, StunError> {
        if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
            return Err(StunError::InvalidChannelNumber(channel));
        }
        Ok(Self { channel, data })
    }

    /// Кодирует в байты. Padding до 4 байт добавляется для TCP;
    /// для UDP padding не нужен, но добавляем для единообразия.
    pub fn encode(&self, pad: bool) -> BytesMut {
        let data_len = self.data.len();
        let pad_len = if pad { (4 - (data_len % 4)) % 4 } else { 0 };

        let mut buf = BytesMut::with_capacity(CHANNEL_DATA_HEADER + data_len + pad_len);
        buf.put_u16(self.channel);
        buf.put_u16(data_len as u16);
        buf.put_slice(&self.data);
        if pad_len > 0 {
            buf.put_bytes(0, pad_len);
        }
        buf
    }

    /// Декодирует из байтового среза.
    pub fn decode(buf: &[u8]) -> Result<Self, StunError> {
        if buf.len() < CHANNEL_DATA_HEADER {
            return Err(StunError::TooShort {
                expected: CHANNEL_DATA_HEADER,
                actual: buf.len(),
            });
        }

        let channel = u16::from_be_bytes([buf[0], buf[1]]);
        if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel) {
            return Err(StunError::InvalidChannelNumber(channel));
        }

        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < CHANNEL_DATA_HEADER + length {
            return Err(StunError::TooShort {
                expected: CHANNEL_DATA_HEADER + length,
                actual: buf.len(),
            });
        }

        Ok(Self {
            channel,
            data: Bytes::copy_from_slice(&buf[CHANNEL_DATA_HEADER..CHANNEL_DATA_HEADER + length]),
        })
    }

    /// Полный размер фрейма на проводе (с padding для TCP).
    pub fn wire_len(&self, pad: bool) -> usize {
        let data_len = self.data.len();
        let pad_len = if pad { (4 - (data_len % 4)) % 4 } else { 0 };
        CHANNEL_DATA_HEADER + data_len + pad_len
    }
}

#[cfg(test)]
mod channel_data_tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let payload = Bytes::from_static(b"hello TURN");
        let cd = ChannelData::new(0x4000, payload.clone()).unwrap();

        // Без padding (UDP)
        let encoded = cd.encode(false);
        let decoded = ChannelData::decode(&encoded).unwrap();
        assert_eq!(decoded.channel, 0x4000);
        assert_eq!(decoded.data, payload);

        // С padding (TCP)
        let encoded_padded = cd.encode(true);
        assert_eq!(encoded_padded.len() % 4, 0);
        let decoded2 = ChannelData::decode(&encoded_padded).unwrap();
        assert_eq!(decoded2.data, payload);
    }

    #[test]
    fn test_invalid_channel_low() {
        assert!(ChannelData::new(0x3FFF, Bytes::new()).is_err());
    }

    #[test]
    fn test_invalid_channel_high() {
        assert!(ChannelData::new(0x8000, Bytes::new()).is_err());
    }

    #[test]
    fn test_empty_payload() {
        let cd = ChannelData::new(0x4000, Bytes::new()).unwrap();
        let encoded = cd.encode(false);
        assert_eq!(encoded.len(), 4);
        let decoded = ChannelData::decode(&encoded).unwrap();
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_decode_truncated() {
        let result = ChannelData::decode(&[0x40, 0x00, 0x00]);
        assert!(result.is_err());
    }
}
