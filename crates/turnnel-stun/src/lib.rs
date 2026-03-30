pub mod attribute;
pub mod channel_data;
pub mod error;
pub mod integrity;
pub mod message;
pub mod types;

#[cfg(test)]
mod tests;

/// Определяет тип пакета по первому байту.
/// RFC 5764 §5.1.2 — демультиплексирование STUN / DTLS / RTP / ChannelData.
#[derive(Debug, PartialEq, Eq)]
pub enum PacketType {
    Stun,
    ChannelData,
    Dtls,
    Rtp,
    Unknown,
}

pub fn demux(packet: &[u8]) -> PacketType {
    if packet.is_empty() {
        return PacketType::Unknown;
    }
    // Первый байт ChannelData — старший байт номера канала.
    // Каналы 0x4000–0x7FFF → первый байт 0x40–0x7F → десятичные 64–127.
    match packet[0] {
        0..=3 => PacketType::Stun,
        20..=63 => PacketType::Dtls,
        64..=127 => PacketType::ChannelData,
        128..=191 => PacketType::Rtp,
        _ => PacketType::Unknown,
    }
}
