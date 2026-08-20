//! FETCH message (type 7) for retrieving more rows from a result set.
//!
//! Based on Go driver wire format. The FETCH request uses absolute row positions
//! — the client specifies which row to start from, and the server returns a batch
//! of rows up to a byte budget.
//!
//! Request wire format (after 64-byte Frame header):
//! ```text
//! Offset  Size  Field
//! 0       20    Reserved (zeros)
//! 20      8     startRow (i64 LE) — starting row index (absolute, 0-based)
//! 28      8     endRow   (i64 LE) — ending row index (use i64::MAX for all remaining)
//! 36      2     cursorId (i16 LE) — result set cursor ID
//! 38      4     prefetchBytes (i32 LE) — max bytes to fetch, clamped [32, 65536]
//! ```
//!
//! DM 8.1.3.62 reads none of the three: it streams the next batch from wherever its
//! cursor stands, sized to its own budget, whatever the request asked for.
//!
//! The reply's payload is bare inline row data from byte 0, in the same format the
//! EXEC/OPE payload uses after its column descriptors. It carries no header and no
//! column metadata, so the columns of the statement that opened the cursor are what
//! the rows are parsed against. The counts travel in the frame header instead:
//! ```text
//! Offset  Size  Field
//! 20      8     fetch_total     (i64 LE) — rows in the whole result set,
//!                                          ROW_TOTAL_UNKNOWN until the last batch
//! 28      4     batch_row_count (i32 LE) — rows in this reply
//! ```
//! A reply with an empty body means the cursor is drained.

use bytes::{BufMut, BytesMut};

use crate::frame::Frame;
use dameng_types::encoding::ServerEncoding;

use super::response::{parse_inline_rows, Column, Row};

/// Default prefetch byte budget for FETCH requests.
pub const DEFAULT_PREFETCH_BYTES: i32 = 8192;

/// Minimum prefetch byte budget.
pub const MIN_PREFETCH_BYTES: i32 = 32;

/// Maximum prefetch byte budget.
pub const MAX_PREFETCH_BYTES: i32 = 65536;

/// Client->Server FETCH message (type 7).
///
/// Requests the next batch of rows from a previously executed query.
/// Uses absolute row positioning — `start_row` specifies which row to begin
/// fetching from, and the server returns up to `prefetch_bytes` of row data.
#[derive(Debug, Clone)]
pub struct FetchMessage {
    /// Starting row index (absolute, 0-based).
    pub start_row: i64,
    /// Ending row index (use i64::MAX to fetch all remaining).
    pub end_row: i64,
    /// Result set cursor ID.
    pub cursor_id: i16,
    /// Maximum bytes to fetch (clamped to [32, 65536]).
    pub prefetch_bytes: i32,
}

impl FetchMessage {
    /// Create a new fetch message.
    ///
    /// # Arguments
    /// * `start_row` — The row index to start fetching from (0-based, absolute).
    /// * `cursor_id` — The result set cursor ID from the initial query.
    /// * `prefetch_bytes` — The maximum bytes to fetch (clamped to [32, 65536]).
    pub fn new(start_row: i64, cursor_id: i16, prefetch_bytes: i32) -> Self {
        let clamped = prefetch_bytes.clamp(MIN_PREFETCH_BYTES, MAX_PREFETCH_BYTES);
        Self {
            start_row,
            end_row: i64::MAX, // Fetch all remaining rows
            cursor_id,
            prefetch_bytes: clamped,
        }
    }

    /// Create a new fetch message requesting from the given row, fetching all remaining.
    ///
    /// This is the most common case — fetch from a specific row position to the end.
    pub fn fetch_from(start_row: i64, cursor_id: i16) -> Self {
        Self::new(start_row, cursor_id, DEFAULT_PREFETCH_BYTES)
    }

    /// Encode to payload bytes.
    ///
    /// Wire format:
    /// - 20 bytes reserved (zeros)
    /// - startRow (i64 LE)
    /// - endRow (i64 LE)
    /// - cursorId (i16 LE)
    /// - prefetchBytes (i32 LE)
    pub fn encode_payload(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(42);
        // 20 bytes reserved
        buf.put_bytes(0, 20);
        // startRow (i64 LE)
        buf.put_i64_le(self.start_row);
        // endRow (i64 LE)
        buf.put_i64_le(self.end_row);
        // cursorId (i16 LE)
        buf.put_i16_le(self.cursor_id);
        // prefetchBytes (i32 LE)
        buf.put_i32_le(self.prefetch_bytes);
        buf
    }
}

/// Response from a FETCH request (msg_type=7).
#[derive(Debug, Clone)]
pub struct FetchResponse {
    /// Rows in the whole result set, or [`crate::frame::ROW_TOTAL_UNKNOWN`] while the
    /// server still holds rows for the cursor.
    pub total_row_count: i64,
    /// Rows this batch carried.
    pub rows: Vec<Row>,
}

impl FetchResponse {
    /// Parse a FETCH reply: the payload is bare inline rows, the counts are in `frame`.
    ///
    /// `columns` describes the result set the cursor belongs to. The reply repeats no
    /// metadata, so nothing else can say how wide a row is.
    pub fn from_frame(
        frame: &Frame,
        data: &[u8],
        columns: &[Column],
        server_encoding: ServerEncoding,
    ) -> Self {
        Self {
            total_row_count: frame.fetch_total,
            rows: parse_inline_rows(data, 0, columns, server_encoding),
        }
    }

    /// Check if there are more rows to fetch.
    pub fn has_more(&self, current_pos: usize) -> bool {
        current_pos < self.total_row_count as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_new() {
        let fetch = FetchMessage::new(0, 0, DEFAULT_PREFETCH_BYTES);
        assert_eq!(fetch.start_row, 0);
        assert_eq!(fetch.end_row, i64::MAX);
        assert_eq!(fetch.cursor_id, 0);
        assert_eq!(fetch.prefetch_bytes, DEFAULT_PREFETCH_BYTES);
    }

    #[test]
    fn test_fetch_payload_size() {
        let fetch = FetchMessage::new(100, 1, 4096);
        let payload = fetch.encode_payload();
        assert_eq!(payload.len(), 42); // 20 + 8 + 8 + 2 + 4
    }

    #[test]
    fn test_fetch_encode_decode() {
        let fetch = FetchMessage::new(42, 5, 8192);
        let payload = fetch.encode_payload();

        // Verify reserved bytes
        assert!(payload[..20].iter().all(|&b| b == 0));

        // Verify startRow at offset 20
        let start_row = i64::from_le_bytes([
            payload[20],
            payload[21],
            payload[22],
            payload[23],
            payload[24],
            payload[25],
            payload[26],
            payload[27],
        ]);
        assert_eq!(start_row, 42);

        // Verify endRow at offset 28
        let end_row = i64::from_le_bytes([
            payload[28],
            payload[29],
            payload[30],
            payload[31],
            payload[32],
            payload[33],
            payload[34],
            payload[35],
        ]);
        assert_eq!(end_row, i64::MAX);

        // Verify cursorId at offset 36
        let cursor_id = i16::from_le_bytes([payload[36], payload[37]]);
        assert_eq!(cursor_id, 5);

        // Verify prefetchBytes at offset 38
        let prefetch_bytes =
            i32::from_le_bytes([payload[38], payload[39], payload[40], payload[41]]);
        assert_eq!(prefetch_bytes, 8192);
    }

    #[test]
    fn test_fetch_prefetch_clamp_min() {
        let fetch = FetchMessage::new(0, 0, 1);
        assert_eq!(fetch.prefetch_bytes, MIN_PREFETCH_BYTES);
    }

    #[test]
    fn test_fetch_prefetch_clamp_max() {
        let fetch = FetchMessage::new(0, 0, i32::MAX);
        assert_eq!(fetch.prefetch_bytes, MAX_PREFETCH_BYTES);
    }

    #[test]
    fn test_fetch_prefetch_normal() {
        let fetch = FetchMessage::new(0, 0, 4096);
        assert_eq!(fetch.prefetch_bytes, 4096);
    }

    #[test]
    fn test_fetch_from() {
        let fetch = FetchMessage::fetch_from(50, 3);
        assert_eq!(fetch.start_row, 50);
        assert_eq!(fetch.cursor_id, 3);
        assert_eq!(fetch.prefetch_bytes, DEFAULT_PREFETCH_BYTES);
    }

    fn varchar_column() -> Column {
        Column {
            name: "NAME".to_string(),
            type_code: 3,
            type_name: "VARCHAR".to_string(),
            precision: 100,
            scale: 0,
            nullable: true,
            display_size: 0,
            table_name: "CUSTOMER".to_string(),
            schema_name: "APP".to_string(),
            lob_tab_id: 0,
            lob_col_id: 0,
        }
    }

    /// A drained cursor answers with an empty body. That is the end of the result set,
    /// not a truncated message.
    #[test]
    fn test_fetch_response_empty_body_ends_the_cursor() {
        let mut frame = Frame::new(7, 0, 0);
        frame.fetch_total = 2;
        let resp =
            FetchResponse::from_frame(&frame, &[], &[varchar_column()], ServerEncoding::Utf8);
        assert_eq!(resp.total_row_count, 2);
        assert!(resp.rows.is_empty());
        assert!(!resp.has_more(2));
    }

    /// Captured from DM 8.1.3.62: the payload is rows from byte 0, no header in front.
    #[test]
    fn test_fetch_response_parses_bare_rows() {
        let data: Vec<u8> = vec![
            0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x05, 0x00,
            0x41, 0x6c, 0x69, 0x63, 0x65, // "Alice"
            0x11, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x03, 0x00,
            0x42, 0x6f, 0x62, // "Bob"
        ];
        let mut frame = Frame::new(7, 0, data.len() as i32);
        frame.fetch_total = 2;
        frame.batch_row_count = 2;

        let resp =
            FetchResponse::from_frame(&frame, &data, &[varchar_column()], ServerEncoding::Utf8);

        assert_eq!(resp.rows.len(), frame.batch_row_count as usize);
        assert_eq!(resp.total_row_count, 2);
        assert_eq!(resp.rows[0].get_str(0).unwrap(), "Alice");
        assert_eq!(resp.rows[1].get_str(0).unwrap(), "Bob");
    }

    /// Every batch before the last one leaves the total unknown.
    #[test]
    fn test_fetch_response_unknown_total() {
        let mut frame = Frame::new(7, 0, 0);
        frame.fetch_total = crate::frame::ROW_TOTAL_UNKNOWN;
        let resp =
            FetchResponse::from_frame(&frame, &[], &[varchar_column()], ServerEncoding::Utf8);
        assert_eq!(resp.total_row_count, crate::frame::ROW_TOTAL_UNKNOWN);
        assert!(resp.has_more(662));
    }

    #[test]
    fn test_fetch_clone() {
        let fetch = FetchMessage::new(100, 2, 4096);
        let cloned = fetch.clone();
        assert_eq!(cloned.start_row, 100);
        assert_eq!(cloned.cursor_id, 2);
        assert_eq!(cloned.prefetch_bytes, 4096);
    }

    #[test]
    fn test_has_more() {
        let resp = FetchResponse {
            total_row_count: 1000,
            rows: vec![],
        };
        assert!(resp.has_more(0));
        assert!(resp.has_more(999));
        assert!(!resp.has_more(1000));
    }
}
