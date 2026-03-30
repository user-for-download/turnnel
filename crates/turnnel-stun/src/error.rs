use thiserror::Error;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("buffer too short: need {expected}, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid STUN magic cookie: {0:#010x}")]
    InvalidMagicCookie(u32),

    #[error("unknown STUN message type: {0:#06x}")]
    InvalidMessageType(u16),

    #[error("invalid attribute length for type {attr_type:#06x}")]
    InvalidAttributeLength { attr_type: u16 },

    #[error("invalid address family: {0}")]
    InvalidAddressFamily(u8),

    #[error("invalid channel number: {0:#06x} (must be 0x4000..=0x7FFF)")]
    InvalidChannelNumber(u16),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}
