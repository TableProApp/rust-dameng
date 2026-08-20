//! 64-byte frame header for Dameng protocol messages.
//!
//! Layout (all multi-byte values are LITTLE ENDIAN):
//! ```text
//! Offset  Size  Field
//! 0       4     Handle (i32 LE)
//! 4       1     MsgType (u8)
//! 5       1     Reserved (0)
//! 6       4     BodyLen (i32 LE) - length of payload after header
//! 10      4     ResponseCode (i32 LE) - filled by server
//! 14      4     AffectedRows (i32 LE) - rows affected (for DML responses)
//! 18      1     CompressFlag (u8)
//! 19      1     Checksum (u8) - XOR of bytes 0-18
//! 20      44    Reserved for the message type (zeros on client messages)
//! 64      var   Payload body
//! ```
//!
//! The server reuses the reserved area, and each response type spells it differently.
//! The fields below overlap on purpose, so read the one that belongs to the message:
//! ```text
//! Offset  Size  Response      Field
//! 20      8     FETCH         fetch_total (i64 LE)
//! 22      2     EXEC/OPE ACK  column_count (u16 LE)
//! 24      8     EXEC/OPE ACK  update_count (i64 LE)
//! 28      4     FETCH         batch_row_count (i32 LE)
//! 28      4     STARTUP       server_encoding (i32 LE)
//! ```

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{Error, Result};

/// The size of the frame header in bytes.
pub const FRAME_HEADER_SIZE: usize = 64;

/// What the server writes in a row total it cannot state yet, because rows are still
/// queued behind the cursor. A total that is not this value is the final one.
pub const ROW_TOTAL_UNKNOWN: i64 = i64::MAX;

/// DM protocol frame header (64 bytes).
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Statement/connection handle.
    pub handle: u32,
    /// Message type identifier.
    pub msg_type: u8,
    /// Length of the payload following this header.
    pub body_len: i32,
    /// Response code from server (0 for client messages).
    pub response_code: i32,
    /// Number of rows affected (for DML responses like INSERT/UPDATE/DELETE).
    /// Set by the server in ACK/EXEC_RESPONSE frames; 0 for non-DML.
    pub affected_rows: i32,
    /// Compression flag (0=none, 1=snappy, 2=zlib).
    pub compress_flag: u8,
    /// Update count at header offset 24 (int64 LE): the affected count of a DML
    /// statement, and the row total of a result set. It is
    /// [`ROW_TOTAL_UNKNOWN`] while the server still holds rows for the cursor.
    pub update_count: u64,
    /// Number of columns in a statement response, header offset 22 (uint16 LE).
    pub column_count: u16,
    /// Row total a FETCH reply reports, header offset 20 (int64 LE).
    /// [`ROW_TOTAL_UNKNOWN`] until the batch that drains the cursor.
    pub fetch_total: i64,
    /// Number of rows a FETCH reply carries in its payload, header offset 28 (int32 LE).
    pub batch_row_count: i32,
    /// Server encoding from header offset 28 (int32 LE).
    /// Used in STARTUP_RESPONSE. 0=GB18030, 1=UTF-8, 2=EUC-KR.
    pub server_encoding: u8,
}

impl Frame {
    /// Create a new frame header for client messages.
    pub fn new(msg_type: u8, handle: u32, body_len: i32) -> Self {
        Self {
            handle,
            msg_type,
            body_len,
            response_code: 0,
            affected_rows: 0,
            compress_flag: 0,
            update_count: 0,
            column_count: 0,
            fetch_total: 0,
            batch_row_count: 0,
            server_encoding: 0,
        }
    }

    /// Parse a frame header from a buffer.
    ///
    /// Returns `Err(Error::Incomplete)` if fewer than 64 bytes are available.
    /// Parse a frame header from a buffer.
    ///
    /// Returns `Err(Error::Incomplete)` if fewer than 64 bytes are available.
    pub fn parse(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < FRAME_HEADER_SIZE {
            return Err(Error::Incomplete);
        }

        // Compute XOR checksum of bytes 0-18 BEFORE consuming
        let mut calc_xor: u8 = 0;
        for i in 0..19 {
            calc_xor ^= buf[i];
        }

        let handle = buf.get_u32_le();
        let msg_type = buf.get_u8();
        let _reserved = buf.get_u8();
        let body_len = buf.get_i32_le();
        let response_code = buf.get_i32_le();
        let affected_rows = buf.get_i32_le();
        let compress_flag = buf.get_u8();
        let checksum = buf.get_u8();

        if calc_xor != checksum {
            return Err(Error::ChecksumMismatch);
        }

        // The cursor sits at byte 20 now, so the reserved area starts at chunk()[0]
        // and every field below is read before the buffer advances past it.
        let reserved = if buf.remaining() >= 12 {
            let raw = &buf.chunk()[..12];
            let mut bytes = [0u8; 12];
            bytes.copy_from_slice(raw);
            bytes
        } else {
            [0u8; 12]
        };
        let fetch_total = i64::from_le_bytes([
            reserved[0],
            reserved[1],
            reserved[2],
            reserved[3],
            reserved[4],
            reserved[5],
            reserved[6],
            reserved[7],
        ]);
        let column_count = u16::from_le_bytes([reserved[2], reserved[3]]);
        let update_count = u64::from_le_bytes([
            reserved[4],
            reserved[5],
            reserved[6],
            reserved[7],
            reserved[8],
            reserved[9],
            reserved[10],
            reserved[11],
        ]);
        let batch_row_count =
            i32::from_le_bytes([reserved[8], reserved[9], reserved[10], reserved[11]]);
        let server_encoding = reserved[8];

        // Skip remaining 44 bytes of reserved
        buf.advance(44);

        Ok(Frame {
            handle,
            msg_type,
            body_len,
            response_code,
            affected_rows,
            compress_flag,
            update_count,
            column_count,
            fetch_total,
            batch_row_count,
            server_encoding,
        })
    }

    /// Encode this frame header into a `BytesMut` buffer.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE);

        buf.put_u32_le(self.handle);
        buf.put_u8(self.msg_type);
        buf.put_u8(0); // reserved
        buf.put_i32_le(self.body_len);
        buf.put_i32_le(self.response_code);
        buf.put_i32_le(0); // reserved
        buf.put_u8(self.compress_flag);
        buf.put_u8(0); // checksum placeholder

        // Compute and write checksum at offset 19
        let mut cs: u8 = 0;
        for i in 0..19 {
            cs ^= buf[i];
        }
        buf[19] = cs;

        // Fill remaining 44 bytes with zeros (20-63)
        buf.put_bytes(0, 44);

        debug_assert_eq!(buf.len(), FRAME_HEADER_SIZE);
        buf
    }

    /// Encode frame header + payload into a single BytesMut.
    pub fn encode_with_payload(&self, payload: &[u8]) -> BytesMut {
        let mut buf = self.encode();
        buf.extend_from_slice(payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_new_and_fields() {
        let frame = Frame::new(200, 0, 82);
        assert_eq!(frame.msg_type, 200);
        assert_eq!(frame.handle, 0);
        assert_eq!(frame.body_len, 82);
    }

    #[test]
    fn test_frame_encode_size() {
        let frame = Frame::new(1, 0, 59);
        let encoded = frame.encode();
        assert_eq!(encoded.len(), FRAME_HEADER_SIZE);
    }

    #[test]
    fn test_frame_roundtrip() {
        let original = Frame::new(6, 42, 128);
        let mut encoded = original.encode();
        let parsed = Frame::parse(&mut encoded).unwrap();
        assert_eq!(parsed.msg_type, 6);
        assert_eq!(parsed.handle, 42);
        assert_eq!(parsed.body_len, 128);
    }

    #[test]
    fn test_frame_parse_incomplete() {
        let mut buf = BytesMut::from(&[0u8; 32][..]);
        let result = Frame::parse(&mut buf);
        assert!(matches!(result, Err(Error::Incomplete)));
    }

    #[test]
    fn test_frame_encode_fields() {
        let frame = Frame::new(8, 7, 255);
        let encoded = frame.encode();
        let bytes = encoded.freeze();

        assert_eq!(
            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            7
        );
        assert_eq!(bytes[4], 8);
        assert_eq!(bytes[5], 0);
        assert_eq!(
            i32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            255
        );
        assert_eq!(bytes[18], 0);
    }

    #[test]
    fn test_frame_parse_fields() {
        let mut encoded = Frame::new(13, 3, 100).encode();
        let frame = Frame::parse(&mut encoded).unwrap();
        assert_eq!(frame.msg_type, 13);
        assert_eq!(frame.handle, 3);
        assert_eq!(frame.body_len, 100);
    }

    /// The reserved area carries several overlapping counts. Only the checksum over
    /// bytes 0-18 is fixed, so a reply can be forged by patching the tail.
    #[test]
    fn test_frame_parse_reserved_counts() {
        let mut encoded = Frame::new(187, 0, 64).encode();
        encoded[20..28].copy_from_slice(&20_000i64.to_le_bytes());
        encoded[28..32].copy_from_slice(&662i32.to_le_bytes());
        let frame = Frame::parse(&mut encoded).unwrap();
        assert_eq!(frame.fetch_total, 20_000);
        assert_eq!(frame.batch_row_count, 662);

        let mut encoded = Frame::new(187, 0, 64).encode();
        encoded[22..24].copy_from_slice(&5u16.to_le_bytes());
        encoded[24..32].copy_from_slice(&2i64.to_le_bytes());
        let frame = Frame::parse(&mut encoded).unwrap();
        assert_eq!(frame.column_count, 5);
        assert_eq!(frame.update_count, 2);
    }

    #[test]
    fn test_frame_parse_unknown_row_total() {
        let mut encoded = Frame::new(187, 0, 0).encode();
        encoded[24..32].copy_from_slice(&ROW_TOTAL_UNKNOWN.to_le_bytes());
        let frame = Frame::parse(&mut encoded).unwrap();
        assert_eq!(frame.update_count, ROW_TOTAL_UNKNOWN as u64);
    }
}
