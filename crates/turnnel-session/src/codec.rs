// FILE: crates/turnnel-session/src/codec.rs
use bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use turnnel_stun::channel_data::CHANNEL_DATA_HEADER;
use turnnel_stun::message::HEADER_SIZE;
use turnnel_stun::{demux, PacketType};

pub struct TurnCodec;

impl Decoder for TurnCodec {
    type Item = Bytes;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        match demux(src) {
            PacketType::Stun => {
                if src.len() < HEADER_SIZE {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([src[2], src[3]]) as usize;
                let total = HEADER_SIZE + len;

                if src.len() < total {
                    return Ok(None);
                }

                Ok(Some(src.split_to(total).freeze()))
            }
            PacketType::ChannelData => {
                if src.len() < CHANNEL_DATA_HEADER {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([src[2], src[3]]) as usize;

                let padding = (4 - (len % 4)) % 4;
                let total = CHANNEL_DATA_HEADER + len + padding;

                if src.len() < total {
                    return Ok(None);
                }

                Ok(Some(src.split_to(total).freeze()))
            }
            _ => {
                src.advance(1);
                Ok(None)
            }
        }
    }
}

impl Encoder<Bytes> for TurnCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}
