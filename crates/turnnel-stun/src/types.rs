/// STUN message class (RFC 5389 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

/// STUN/TURN methods мы поддерживаем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Binding,          // 0x001
    Allocate,         // 0x003
    Refresh,          // 0x004
    CreatePermission, // 0x008
    ChannelBind,      // 0x009
}

impl Method {
    fn raw(self) -> u16 {
        match self {
            Method::Binding => 0x0001,
            Method::Allocate => 0x0003,
            Method::Refresh => 0x0004,
            Method::CreatePermission => 0x0008,
            Method::ChannelBind => 0x0009,
        }
    }

    fn from_raw(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(Method::Binding),
            0x0003 => Some(Method::Allocate),
            0x0004 => Some(Method::Refresh),
            0x0008 => Some(Method::CreatePermission),
            0x0009 => Some(Method::ChannelBind),
            _ => None,
        }
    }
}

/// Кодирование message type по RFC 5389 §6.
///
/// Биты message type:
/// ```text
///   M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
///   13  12  11 10  9  8  7  6  5  4  3  2  1  0
/// ```
///
/// M = method bits, C = class bits.
pub fn encode_message_type(method: Method, class: Class) -> u16 {
    let m = method.raw();
    let c = match class {
        Class::Request => 0b00u16,
        Class::Indication => 0b01,
        Class::SuccessResponse => 0b10,
        Class::ErrorResponse => 0b11,
    };

    // method bits:  M0-M3   = m[0:3]   → bits [0:3]   сдвиг 0
    //               M4-M6   = m[4:6]   → bits [5:7]   сдвиг +1
    //               M7-M11  = m[7:11]  → bits [9:13]  сдвиг +2
    // class bits:   C0 → bit 4
    //               C1 → bit 8
    let m0_3 = m & 0x000F;
    let m4_6 = (m & 0x0070) << 1;
    let m7_11 = (m & 0x0F80) << 2;

    let c0 = (c & 1) << 4;
    let c1 = (c & 2) << 7; // bit 1 of c → bit 8

    m0_3 | m4_6 | m7_11 | c0 | c1
}

pub fn decode_message_type(msg_type: u16) -> Option<(Method, Class)> {
    // Извлекаем class
    let c0 = (msg_type >> 4) & 1;
    let c1 = (msg_type >> 8) & 1;
    let class_val = (c1 << 1) | c0;

    let class = match class_val {
        0b00 => Class::Request,
        0b01 => Class::Indication,
        0b10 => Class::SuccessResponse,
        0b11 => Class::ErrorResponse,
        _ => unreachable!(),
    };

    // Извлекаем method
    let m0_3 = msg_type & 0x000F;
    let m4_6 = (msg_type >> 1) & 0x0070;
    let m7_11 = (msg_type >> 2) & 0x0F80;
    let method_val = m0_3 | m4_6 | m7_11;

    let method = Method::from_raw(method_val)?;
    Some((method, class))
}

#[cfg(test)]
mod type_tests {
    use super::*;

    #[test]
    fn test_binding_request() {
        // Binding Request: method=0x0001, class=Request(0b00) → 0x0001
        let encoded = encode_message_type(Method::Binding, Class::Request);
        assert_eq!(encoded, 0x0001);
        let (m, c) = decode_message_type(encoded).unwrap();
        assert_eq!(m, Method::Binding);
        assert_eq!(c, Class::Request);
    }

    #[test]
    fn test_binding_success() {
        // Binding Success Response: method=0x0001, class=SuccessResponse(0b10)
        // C0=0, C1=1 → bit4=0, bit8=1 → 0x0101
        let encoded = encode_message_type(Method::Binding, Class::SuccessResponse);
        assert_eq!(encoded, 0x0101);
        let (m, c) = decode_message_type(encoded).unwrap();
        assert_eq!(m, Method::Binding);
        assert_eq!(c, Class::SuccessResponse);
    }

    #[test]
    fn test_allocate_error() {
        // Allocate Error Response: method=0x0003, class=ErrorResponse(0b11)
        // M0-M3=0x3, C0=1→bit4, C1=1→bit8 → 0x0113
        let encoded = encode_message_type(Method::Allocate, Class::ErrorResponse);
        assert_eq!(encoded, 0x0113);
        let (m, c) = decode_message_type(encoded).unwrap();
        assert_eq!(m, Method::Allocate);
        assert_eq!(c, Class::ErrorResponse);
    }

    #[test]
    fn test_all_methods_roundtrip() {
        let methods = [
            Method::Binding,
            Method::Allocate,
            Method::Refresh,
            Method::CreatePermission,
            Method::ChannelBind,
        ];
        let classes = [
            Class::Request,
            Class::Indication,
            Class::SuccessResponse,
            Class::ErrorResponse,
        ];

        for &method in &methods {
            for &class in &classes {
                let encoded = encode_message_type(method, class);
                // Два старших бита должны быть 0 (RFC 5389 §6)
                assert_eq!(encoded & 0xC000, 0, "top 2 bits must be 0");

                let (m, c) = decode_message_type(encoded).unwrap_or_else(|| {
                    panic!(
                        "failed to decode {:?}/{:?} = {:#06x}",
                        method, class, encoded
                    )
                });
                assert_eq!(m, method);
                assert_eq!(c, class);
            }
        }
    }
}
