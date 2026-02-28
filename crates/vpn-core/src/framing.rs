//! Wire-format framing for tunnel packets.
//!
//! ```text
//! ┌─────────┬──────────┬─────────────┬─────┐
//! │ Length   │ Type     │ Payload     │ Tag │
//! │ 2 bytes │ 1 byte   │ variable    │ 16B │
//! └─────────┴──────────┴─────────────┴─────┘
//! ```
//!
//! - Length: total size of (Type + Payload + Tag) as big-endian u16
//! - Max frame size: 65535 bytes total payload

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

/// Maximum allowed frame body size (Type + Payload + Tag).
pub const MAX_FRAME_BODY_SIZE: usize = 65535;

/// Maximum decoder buffer size (256 KB) — prevents OOM from malicious streams.
pub const MAX_BUFFER_SIZE: usize = 256 * 1024;

/// Size of the length header.
pub const LENGTH_HEADER_SIZE: usize = 2;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("frame too large: {size} bytes (max {MAX_FRAME_BODY_SIZE})")]
    FrameTooLarge { size: usize },
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    #[error("incomplete frame: need {needed} more bytes")]
    Incomplete { needed: usize },
    #[error("empty frame body")]
    EmptyBody,
    #[error("decoder buffer overflow: {size} bytes exceeds {MAX_BUFFER_SIZE} limit")]
    BufferOverflow { size: usize },
}

/// Frame type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Tunneled IP packet (encrypted).
    Data = 0x01,
    /// Keepalive ping.
    Ping = 0x02,
    /// Keepalive pong.
    Pong = 0x03,
    /// Handshake message.
    Handshake = 0x04,
}

impl TryFrom<u8> for FrameType {
    type Error = FramingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FrameType::Data),
            0x02 => Ok(FrameType::Ping),
            0x03 => Ok(FrameType::Pong),
            0x04 => Ok(FrameType::Handshake),
            other => Err(FramingError::UnknownFrameType(other)),
        }
    }
}

/// A decoded protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Encrypted IP packet data.
    Data(Vec<u8>),
    /// Keepalive ping (no payload).
    Ping,
    /// Keepalive pong (no payload).
    Pong,
    /// Handshake message payload.
    Handshake(Vec<u8>),
}

impl Frame {
    /// Returns the frame type.
    pub fn frame_type(&self) -> FrameType {
        match self {
            Frame::Data(_) => FrameType::Data,
            Frame::Ping => FrameType::Ping,
            Frame::Pong => FrameType::Pong,
            Frame::Handshake(_) => FrameType::Handshake,
        }
    }

    /// Returns the payload bytes (empty for Ping/Pong).
    pub fn payload(&self) -> &[u8] {
        match self {
            Frame::Data(data) | Frame::Handshake(data) => data,
            Frame::Ping | Frame::Pong => &[],
        }
    }
}

/// Encode a frame into bytes, writing to a `BytesMut` buffer.
///
/// Format: [length: u16 BE][type: u8][payload: variable]
/// Length = 1 (type) + payload.len()
pub fn encode(frame: &Frame, dst: &mut BytesMut) -> Result<(), FramingError> {
    let payload = frame.payload();
    let body_len = 1 + payload.len(); // type byte + payload

    if body_len > MAX_FRAME_BODY_SIZE {
        return Err(FramingError::FrameTooLarge { size: body_len });
    }

    dst.reserve(LENGTH_HEADER_SIZE + body_len);
    dst.put_u16(body_len as u16);
    dst.put_u8(frame.frame_type() as u8);
    dst.put_slice(payload);

    Ok(())
}

/// Streaming frame decoder with internal buffer.
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    /// Create a new decoder with default capacity.
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Feed raw bytes into the decoder.
    ///
    /// Returns `Err(BufferOverflow)` if the buffer would exceed `MAX_BUFFER_SIZE`.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), FramingError> {
        let new_len = self.buffer.len() + data.len();
        if new_len > MAX_BUFFER_SIZE {
            // Reset buffer to prevent permanent stuck state
            self.buffer.clear();
            return Err(FramingError::BufferOverflow { size: new_len });
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Try to decode the next frame from the buffer.
    ///
    /// Returns `Ok(Some(frame))` if a complete frame was decoded,
    /// `Ok(None)` if more data is needed,
    /// or `Err` if the data is malformed.
    pub fn decode(&mut self) -> Result<Option<Frame>, FramingError> {
        // Need at least the length header
        if self.buffer.len() < LENGTH_HEADER_SIZE {
            return Ok(None);
        }

        // Peek at the length without consuming
        let body_len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;

        if body_len == 0 {
            return Err(FramingError::EmptyBody);
        }

        if body_len > MAX_FRAME_BODY_SIZE {
            return Err(FramingError::FrameTooLarge { size: body_len });
        }

        let total_len = LENGTH_HEADER_SIZE + body_len;

        // Check if we have the complete frame
        if self.buffer.len() < total_len {
            return Ok(None);
        }

        // Consume length header
        self.buffer.advance(LENGTH_HEADER_SIZE);

        // Read type byte and payload length
        let type_byte = self.buffer[0];
        self.buffer.advance(1);
        let payload_len = body_len - 1;

        let frame_type = match FrameType::try_from(type_byte) {
            Ok(ft) => ft,
            Err(e) => {
                // Skip remaining payload to keep decoder synchronized
                self.buffer.advance(payload_len);
                return Err(e);
            }
        };

        // Read payload (body_len - 1 for the type byte)
        let payload = self.buffer[..payload_len].to_vec();
        self.buffer.advance(payload_len);

        let frame = match frame_type {
            FrameType::Data => Frame::Data(payload),
            FrameType::Ping => Frame::Ping,
            FrameType::Pong => Frame::Pong,
            FrameType::Handshake => Frame::Handshake(payload),
        };

        Ok(Some(frame))
    }

    /// Returns the number of buffered bytes.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_frame(frame: &Frame) -> BytesMut {
        let mut buf = BytesMut::new();
        encode(frame, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_roundtrip_data_frame() {
        let original = Frame::Data(vec![1, 2, 3, 4, 5]);
        let encoded = encode_frame(&original);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded).unwrap();
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_ping() {
        let original = Frame::Ping;
        let encoded = encode_frame(&original);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded).unwrap();
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_pong() {
        let original = Frame::Pong;
        let encoded = encode_frame(&original);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded).unwrap();
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_handshake() {
        let payload = b"handshake data here".to_vec();
        let original = Frame::Handshake(payload);
        let encoded = encode_frame(&original);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded).unwrap();
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_partial_reads_byte_by_byte() {
        let original = Frame::Data(vec![10, 20, 30, 40, 50]);
        let encoded = encode_frame(&original);

        let mut decoder = FrameDecoder::new();

        // Feed one byte at a time
        for i in 0..encoded.len() - 1 {
            decoder.feed(&encoded[i..i + 1]).unwrap();
            assert_eq!(decoder.decode().unwrap(), None, "Should need more data at byte {i}");
        }

        // Feed the last byte — now it should decode
        decoder.feed(&encoded[encoded.len() - 1..]).unwrap();
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multiple_frames_in_one_buffer() {
        let frame1 = Frame::Data(vec![1, 2, 3]);
        let frame2 = Frame::Ping;
        let frame3 = Frame::Handshake(b"hello".to_vec());

        let mut buf = BytesMut::new();
        encode(&frame1, &mut buf).unwrap();
        encode(&frame2, &mut buf).unwrap();
        encode(&frame3, &mut buf).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.feed(&buf).unwrap();

        assert_eq!(decoder.decode().unwrap().unwrap(), frame1);
        assert_eq!(decoder.decode().unwrap().unwrap(), frame2);
        assert_eq!(decoder.decode().unwrap().unwrap(), frame3);
        assert_eq!(decoder.decode().unwrap(), None);
    }

    #[test]
    fn test_oversized_frame_rejection() {
        // Manually craft a frame with a length exceeding MAX_FRAME_BODY_SIZE
        // MAX_FRAME_BODY_SIZE = 65535, but length field is u16 so max is 65535
        // This means max body is already capped by the format.
        // But we can test the encode side:
        let big_payload = vec![0u8; MAX_FRAME_BODY_SIZE]; // 1 byte for type goes over
        let frame = Frame::Data(big_payload);
        let mut buf = BytesMut::new();
        let result = encode(&frame, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_frame_type() {
        let mut buf = BytesMut::new();
        buf.put_u16(2); // length = 2 (type + 1 byte payload)
        buf.put_u8(0xFF); // unknown type
        buf.put_u8(0x00); // payload byte

        let mut decoder = FrameDecoder::new();
        decoder.feed(&buf).unwrap();
        let result = decoder.decode();
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_body_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u16(0); // length = 0

        let mut decoder = FrameDecoder::new();
        decoder.feed(&buf).unwrap();
        let result = decoder.decode();
        assert!(result.is_err());
    }

    #[test]
    fn test_incomplete_length_header() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[0x00]).unwrap(); // Only one byte of length header
        assert_eq!(decoder.decode().unwrap(), None);
    }

    #[test]
    fn test_buffer_overflow_rejected() {
        let mut decoder = FrameDecoder::new();
        let chunk = vec![0xAA; 64 * 1024]; // 64 KB chunks

        // Feed up to the limit — should succeed
        for _ in 0..3 {
            decoder.feed(&chunk).unwrap(); // 192 KB total — under 256 KB
        }

        // Feeding past MAX_BUFFER_SIZE triggers an error
        let result = decoder.feed(&chunk); // 256 KB total — at limit, next push should fail
        assert!(result.is_ok()); // exactly 256 KB is OK

        // One more byte should overflow
        let result = decoder.feed(&[0xFF]);
        assert!(result.is_err());
    }
}
