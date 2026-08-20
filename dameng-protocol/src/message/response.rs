//! EXEC_RESPONSE (type 0 / 187) - Statement execution results.
//!
//! Format verified against DM 8.1.3.62 live traffic and against the column reader in
//! the official JDBC driver (`dm.jdbc.a.a.f#a(int colNum, boolean rsBdta)`).
//! Used for both EXEC (type 5) and OPTIMIZED_PREPARE_EXEC (type 91) responses.
//!
//! === COLUMN DESCRIPTOR (32 bytes + strings, one per column, first included) ===
//!   0  u32  type code
//!   4  u32  precision (0x7FFFFFFF on a LOB column)
//!   8  i32  scale
//!  12  u32  nullable
//!  16  u16  item_flag (0x01 identity, 0x02 LOB, 0x04 readonly)
//!  18  6    reserved
//!  24  u16  name length
//!  26  u16  type name length
//!  28  u16  table name length
//!  30  u16  schema name length
//!  32  var  name, type name, table name, schema name, back to back
//!      6    lob_tab_id (i32) + lob_col_id (i16), only when item_flag has 0x02
//!
//! The descriptors start at payload byte 0. There is no result header in front of them,
//! and the column count travels in the frame header (offset 22) rather than the payload.
//!
//! === OPE INLINE ROW DATA (for OPTIMIZED_PREPARE_EXEC type 91) ===
//! After all column metadata, rows are embedded inline:
//!   u8  row_size_marker (total bytes for this row including marker)
//!   u8  flags
//!   u32 rec_id
//!   u32 padding (0)
//!   For each column: u16 col_offset_from_marker
//!   For each column: u16 value_size + value_size bytes of data
//!
//! A FETCH reply carries the same row data with no descriptors in front of it, so
//! [`parse_inline_rows`] serves both.

use crate::error::Result;
use dameng_types::encoding::{decode_from_server, ServerEncoding};

/// Fixed part of a column descriptor, before its four strings.
const COLUMN_DESCRIPTOR_SIZE: usize = 32;

/// `item_flag` bit that marks a column as a LOB, which adds a 6-byte trailer.
const ITEM_FLAG_LOB: u16 = 0x02;

/// Bytes the LOB trailer adds: lob_tab_id (i32) + lob_col_id (i16).
const LOB_TRAILER_SIZE: usize = 6;

/// Longest identifier DM accepts, used to tell a descriptor from row data when the
/// column count is unknown.
const MAX_IDENTIFIER_LEN: usize = 128;

/// Value size that marks the column NULL rather than a length.
const VALUE_SIZE_NULL: usize = 0xFFFE;

/// LOB_LOCATOR size: DM returns a 16-byte locator for large CLOB/BLOB values.
/// When the value size exceeds 2048 bytes, DM returns a locator instead of inline data.
/// The client must use LOBREAD/FETCH operations to retrieve the actual content.
pub const LOB_LOCATOR_SIZE: usize = 16;

/// Maximum inline data size before DM uses LOB_LOCATOR.
pub const LOB_LOCATOR_THRESHOLD: usize = 2048;

/// Check if the given raw data is a LOB_LOCATOR (16 bytes) for the specified column type.
/// DM uses LOB_LOCATOR for CLOB/BLOB values larger than 2048 bytes.
pub fn is_lob_locator(data: &[u8], col_type_code: i32) -> bool {
    let is_lob_type = matches!(col_type_code, 13 | 14); // BLOB=13, CLOB=14
    is_lob_type && data.len() == LOB_LOCATOR_SIZE
}

/// Check if the given raw data is an NBLOB_HEAD structure for the specified column type.
/// DM returns NBLOB_HEAD for ALL CLOB/BLOB values (both inline and out-of-row).
/// - in_row=0x01: inline data follows the header (13 bytes header + data)
/// - in_row=0x02: out-of-row LOB (25+ bytes header, needs LOBREAD protocol)
pub fn is_lob_head(data: &[u8], col_type_code: i32) -> bool {
    let is_lob_type = matches!(col_type_code, 13 | 14);
    is_lob_type && data.len() >= 13
}

use dameng_types::{DmValue, DmValueType};

/// Derive type_code from type_name string.
/// The column header type_code field (offset 16) is unreliable on DM 8.1 — it
/// often returns 4 (INT) for all types. type_name is the authoritative source.
fn type_name_to_code(name: &str) -> i32 {
    let upper = name.to_uppercase();
    // Check timezone variants first (longer match before shorter)
    if upper.contains("TIMESTAMP WITH TIME ZONE")
        || upper.contains("DATETIME WITH TIME ZONE")
        || upper.contains("DATETIME2_TZ")
    {
        12 // TIMESTAMP_TZ maps to TIMESTAMP (12)
    } else if upper.contains("TIME WITH TIME ZONE") {
        11 // TIME_TZ maps to TIME (11)
    } else if upper.contains("INTERVAL DAY")
        || upper.contains("INTERVAL_DS")
        || upper.contains("NUMTODSINTERVAL")
    {
        15 // INTERVAL_DT
    } else if upper.contains("INTERVAL YEAR")
        || upper.contains("INTERVAL_YM")
        || upper.contains("NUMTOYMINTERVAL")
    {
        15 // INTERVAL_YM
    } else {
        match upper.as_str() {
            "BIT" | "BOOLEAN" => 1,
            "TINYINT" => 2,
            "VARCHAR" | "CHAR" | "BANNECHAR" | "VARCHAR2" | "NVARCHAR" | "NVARCHAR2" => 3,
            "INT" | "INTEGER" | "NUMBER" => 4,
            "BIGINT" | "LONG" => 5,
            "SMALLINT" => 6,
            "FLOAT" => 7,
            "DOUBLE" | "DOUBLE PRECISION" => 8,
            "DEC" | "DECIMAL" | "NUMERIC" => 9,
            "DATE" => 10,
            "TIME" => 11,
            "TIMESTAMP" | "DATETIME" | "DATETIME2" => 12,
            "BLOB" | "RAW" | "LONG RAW" => 13,
            "CLOB" | "NCLOB" | "TEXT" => 14,
            "INTERVAL" => 15,
            "BINARY" | "VARBINARY" => 17,
            "ROWID" => 18,
            "XMLTYPE" => 14, // XML stored as CLOB-like
            _ => 0,
        }
    }
}

/// Column metadata from a query result.
#[derive(Debug, Clone)]
pub struct Column {
    /// Column name.
    pub name: String,
    /// DM type code.
    pub type_code: i32,
    /// Type name string (e.g., "INT", "VARCHAR").
    pub type_name: String,
    /// Precision for numeric types.
    pub precision: u32,
    /// Scale for decimal types.
    pub scale: i16,
    /// Whether the column can be NULL.
    pub nullable: bool,
    /// Display size.
    pub display_size: u32,
    /// Table name.
    pub table_name: String,
    /// Schema name.
    pub schema_name: String,
    /// LOB tab_id (only set for BLOB/CLOB columns).
    pub lob_tab_id: i32,
    /// LOB col_id (only set for BLOB/CLOB columns).
    pub lob_col_id: i16,
}

/// A single row of data from a query result.
#[derive(Debug, Clone)]
pub struct Row {
    /// Row ID from the database.
    pub row_id: u16,
    /// Column values as raw bytes.
    pub values: Vec<Option<Vec<u8>>>,
}

impl Row {
    /// Get an i32 value at the given column index.
    pub fn get_i32(&self, idx: usize) -> Result<i32> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        if val.len() < 4 {
            if val.len() == 1 {
                return Ok(val[0] as i32);
            }
            if val.len() == 2 {
                return Ok(i32::from(i16::from_le_bytes([val[0], val[1]])));
            }
            return Err(crate::error::Error::DecodeError(format!(
                "column {} too short for i32 ({} bytes)",
                idx,
                val.len()
            )));
        }
        Ok(i32::from_le_bytes([val[0], val[1], val[2], val[3]]))
    }

    /// Get an i64 value at the given column index.
    pub fn get_i64(&self, idx: usize) -> Result<i64> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        if val.len() < 8 {
            if val.len() >= 4 {
                return Ok(i64::from(i32::from_le_bytes([
                    val[0], val[1], val[2], val[3],
                ])));
            }
            return Err(crate::error::Error::DecodeError(format!(
                "column {} too short for i64",
                idx
            )));
        }
        Ok(i64::from_le_bytes([
            val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
        ]))
    }

    /// Get a &str value at the given column index.
    ///
    /// For text types (VARCHAR, CHAR, CLOB) this reads UTF-8 directly.
    pub fn get_str(&self, idx: usize) -> Result<&str> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        std::str::from_utf8(val)
            .map_err(|e| crate::error::Error::DecodeError(format!("invalid UTF-8: {}", e)))
    }

    /// Get a f64 value at the given column index.
    pub fn get_f64(&self, idx: usize) -> Result<f64> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        if val.len() < 8 {
            return Err(crate::error::Error::DecodeError(format!(
                "column {} too short for f64",
                idx
            )));
        }
        let bytes: [u8; 8] = val[..8].try_into().unwrap();
        Ok(f64::from_le_bytes(bytes))
    }

    /// Check if the value at the given column index is NULL.
    pub fn is_null(&self, idx: usize) -> bool {
        match self.values.get(idx) {
            None | Some(None) => true,
            Some(Some(v)) => v.is_empty(),
        }
    }

    /// Get a TIMESTAMP value at the given column index as a human-readable string.
    ///
    /// DM encodes TIMESTAMP as 11 bytes: year(2 BE) + month(1) + day(1) + hour(1) + minute(1) + second(1) + nanosecond(4 BE).
    /// Falls back to UTF-8/lossy if the data doesn't match binary format.
    pub fn get_timestamp(&self, idx: usize) -> Result<String> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;

        if val.len() == 11 {
            let year = u16::from_be_bytes([val[0], val[1]]) as i32;
            let month = val[2];
            let day = val[3];
            let hour = val[4];
            let minute = val[5];
            let second = val[6];
            let nano = u32::from_be_bytes([val[7], val[8], val[9], val[10]]);
            if nano > 0 {
                Ok(format!(
                    "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:09}",
                    year, month, day, hour, minute, second, nano
                ))
            } else {
                Ok(format!(
                    "{}-{:02}-{:02} {:02}:{:02}:{:02}",
                    year, month, day, hour, minute, second
                ))
            }
        } else if val.len() == 7 {
            // DATE format: year(2 BE) + month(1) + day(1) + hour(1) + minute(1) + second(1)
            let year = u16::from_be_bytes([val[0], val[1]]) as i32;
            let month = val[2];
            let day = val[3];
            let hour = val[4];
            let minute = val[5];
            let second = val[6];
            Ok(format!(
                "{}-{:02}-{:02} {:02}:{:02}:{:02}",
                year, month, day, hour, minute, second
            ))
        } else {
            // Fallback: UTF-8 or lossy via get_string
            self.get_string(idx)
        }
    }

    /// Get a DATE value at the given column index as a human-readable string.
    pub fn get_date(&self, idx: usize) -> Result<String> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;

        if val.len() == 7 {
            let year = u16::from_be_bytes([val[0], val[1]]) as i32;
            let month = val[2];
            let day = val[3];
            let hour = val[4];
            let minute = val[5];
            let second = val[6];
            Ok(format!(
                "{}-{:02}-{:02} {:02}:{:02}:{:02}",
                year, month, day, hour, minute, second
            ))
        } else {
            self.get_string(idx)
        }
    }

    /// Get the number of columns in this row.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if the row has no columns.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get a decoded DmValue at the given column index.
    /// Uses the column type_code to decode the raw bytes.
    pub fn get(&self, idx: usize, columns: &[Column]) -> Option<DmValue> {
        let data = self.values.get(idx)?.as_ref()?;
        if data.is_empty() {
            return Some(DmValue::Null);
        }
        let col = columns.get(idx)?;
        let dm_ty = DmValueType::from_type_code(col.type_code)?;
        dameng_types::decode_value(
            dm_ty,
            data,
            matches!(dm_ty, DmValueType::BLOB | DmValueType::CLOB)
                .then_some((col.lob_tab_id, col.lob_col_id)),
        )
    }

    /// Get an i16 value at the given column index.
    pub fn get_i16(&self, idx: usize) -> Result<i16> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        if val.len() < 2 {
            if val.len() == 1 {
                return Ok(val[0] as i16);
            }
            return Err(crate::error::Error::DecodeError(format!(
                "column {} too short for i16",
                idx
            )));
        }
        Ok(i16::from_le_bytes([val[0], val[1]]))
    }

    /// Get an i8 value at the given column index.
    pub fn get_i8(&self, idx: usize) -> Result<i8> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        if val.is_empty() {
            return Err(crate::error::Error::DecodeError(format!(
                "column {} is NULL",
                idx
            )));
        }
        Ok(val[0] as i8)
    }

    /// Get a f32 value at the given column index.
    pub fn get_f32(&self, idx: usize) -> Result<f32> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        if val.len() < 4 {
            return Err(crate::error::Error::DecodeError(format!(
                "column {} too short for f32",
                idx
            )));
        }
        Ok(f32::from_le_bytes([val[0], val[1], val[2], val[3]]))
    }

    /// Get raw bytes at the given column index.
    pub fn get_bytes(&self, idx: usize) -> Result<Vec<u8>> {
        match self.values.get(idx) {
            Some(Some(v)) => Ok(v.clone()),
            Some(None) => Ok(vec![]),
            None => Err(crate::error::Error::DecodeError(format!(
                "column {} out of range",
                idx
            ))),
        }
    }

    /// Get an Option<i32> at the given column index (NULL-safe).
    pub fn get_opt_i32(&self, idx: usize) -> Result<Option<i32>> {
        match self.values.get(idx) {
            Some(Some(v)) if !v.is_empty() => Ok(Some(self.get_i32(idx)?)),
            _ => Ok(None),
        }
    }

    /// Get an Option<i64> at the given column index (NULL-safe).
    pub fn get_opt_i64(&self, idx: usize) -> Result<Option<i64>> {
        match self.values.get(idx) {
            Some(Some(v)) if !v.is_empty() => Ok(Some(self.get_i64(idx)?)),
            _ => Ok(None),
        }
    }

    /// Get an Option<&str> at the given column index (NULL-safe).
    pub fn get_opt_str(&self, idx: usize) -> Result<Option<&str>> {
        match self.values.get(idx) {
            Some(Some(v)) if !v.is_empty() => {
                Ok(Some(std::str::from_utf8(v).map_err(|e| {
                    crate::error::Error::DecodeError(format!("invalid UTF-8: {}", e))
                })?))
            }
            _ => Ok(None),
        }
    }

    /// Get an Option<f64> at the given column index (NULL-safe).
    pub fn get_opt_f64(&self, idx: usize) -> Result<Option<f64>> {
        match self.values.get(idx) {
            Some(Some(v)) if !v.is_empty() => Ok(Some(self.get_f64(idx)?)),
            _ => Ok(None),
        }
    }

    /// Get an owned String at the given column index (uses lossy UTF-8 fallback).
    ///
    /// Unlike `get_str()` which returns a borrowed `&str` and fails on invalid UTF-8,
    /// this method always succeeds by replacing invalid sequences with U+FFFD.
    /// Useful for binary-ish data or server status strings.
    pub fn get_string(&self, idx: usize) -> Result<String> {
        let val = self.values.get(idx).and_then(|v| v.as_ref()).ok_or(
            crate::error::Error::DecodeError(format!("column {} is NULL or out of range", idx)),
        )?;
        Ok(String::from_utf8_lossy(val).into_owned())
    }

    /// Placeholder: find column index by name (case-insensitive match).
    pub fn column_index(&self, _columns: &[Column]) -> usize {
        0
    }
}

/// Server->Client EXEC_RESPONSE (type 0).
#[derive(Debug, Clone)]
pub struct ExecResponse {
    /// Number of column descriptors the payload carried.
    pub col_count: u16,
    /// Affected row count of a DML statement, from payload offset 12. It is not a row
    /// count for a result set: the frame header carries that one.
    pub row_count: u32,
    /// Column metadata.
    pub columns: Vec<Column>,
    /// Row data (column-major order).
    pub rows: Vec<Row>,
}

/// Decode DM binary DECIMAL to text representation.
fn decode_dm_decimal_to_text(data: &[u8], _scale: i16) -> Option<String> {
    const FLAG_ZERO: u8 = 0x80;
    const FLAG_POSITIVE: i32 = 0xC1;
    const FLAG_NEGTIVE: i32 = 0x3E;
    const NUM_POSITIVE: i32 = 1;
    const NUM_NEGTIVE: i32 = 101;
    if data.is_empty() || data.len() > 21 {
        return None;
    }
    if data[0] == FLAG_ZERO || data.len() == 1 {
        return Some("0".to_string());
    }
    let is_positive = data[0] & FLAG_ZERO != 0;
    let flag = data[0] as i32;
    let exponent = if is_positive {
        flag - FLAG_POSITIVE
    } else {
        FLAG_NEGTIVE - flag
    };
    let mut digits = Vec::with_capacity(data.len() - 1);
    for &b in &data[1..] {
        let digit = if is_positive {
            b as i32 - NUM_POSITIVE
        } else {
            NUM_NEGTIVE - b as i32
        };
        if digit < 0 || digit > 99 {
            break;
        }
        digits.push(digit);
    }
    if digits.is_empty() {
        return None;
    }

    let decimal_group = exponent + 1;
    let mut value = String::new();
    if !is_positive {
        value.push('-');
    }
    if decimal_group <= 0 {
        value.push_str("0.");
        for _ in 0..-decimal_group {
            value.push_str("00");
        }
        for digit in digits {
            value.push_str(&format!("{digit:02}"));
        }
    } else {
        for index in 0..decimal_group as usize {
            if index < digits.len() {
                if index == 0 {
                    value.push_str(&digits[index].to_string());
                } else {
                    value.push_str(&format!("{:02}", digits[index]));
                }
            } else {
                value.push_str("00");
            }
        }
        if (decimal_group as usize) < digits.len() {
            value.push('.');
            for digit in &digits[decimal_group as usize..] {
                value.push_str(&format!("{digit:02}"));
            }
        }
    }
    if value.contains('.') {
        while value.ends_with('0') {
            value.pop();
        }
        if value.ends_with('.') {
            value.pop();
        }
    }
    Some(value)
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Parse one column descriptor, returning it with the offset the next one starts at.
///
/// `sniffing` is set when the caller does not know how many columns to expect and has to
/// recognise the end of the descriptors by validating each one. With the count in hand,
/// only the buffer bounds decide.
fn parse_column_descriptor(
    data: &[u8],
    offset: usize,
    sniffing: bool,
    server_encoding: ServerEncoding,
) -> Option<(Column, usize)> {
    let strings_at = offset.checked_add(COLUMN_DESCRIPTOR_SIZE)?;
    if strings_at > data.len() {
        return None;
    }

    let type_code = u32_at(data, offset);
    let precision = u32_at(data, offset + 4);
    let scale = u32_at(data, offset + 8) as i32;
    let nullable = u32_at(data, offset + 12);
    let item_flag = u16_at(data, offset + 16);
    let name_len = u16_at(data, offset + 24) as usize;
    let type_name_len = u16_at(data, offset + 26) as usize;
    let table_name_len = u16_at(data, offset + 28) as usize;
    let schema_name_len = u16_at(data, offset + 30) as usize;

    if sniffing
        && (!(1..=31).contains(&type_code)
            || !(-1_000..=1_000).contains(&scale)
            || name_len == 0
            || type_name_len == 0
            || name_len > MAX_IDENTIFIER_LEN
            || type_name_len > MAX_IDENTIFIER_LEN
            || table_name_len > MAX_IDENTIFIER_LEN
            || schema_name_len > MAX_IDENTIFIER_LEN)
    {
        return None;
    }

    let strings_end =
        strings_at.checked_add(name_len + type_name_len + table_name_len + schema_name_len)?;
    if strings_end > data.len() {
        return None;
    }

    let mut cursor = strings_at;
    let mut take = |len: usize| {
        let text = decode_from_server(server_encoding, &data[cursor..cursor + len]);
        cursor += len;
        text
    };
    let name = take(name_len);
    let type_name = take(type_name_len);
    let table_name = take(table_name_len);
    let schema_name = take(schema_name_len);

    let mut next = strings_end;
    let (lob_tab_id, lob_col_id) = if item_flag & ITEM_FLAG_LOB != 0 {
        if next + LOB_TRAILER_SIZE > data.len() {
            return None;
        }
        let tab_id = u32_at(data, next) as i32;
        let col_id = u16_at(data, next + 4) as i16;
        next += LOB_TRAILER_SIZE;
        (tab_id, col_id)
    } else {
        (0, 0)
    };

    Some((
        Column {
            // The descriptor's type code disagrees with the type name on DM 8.1
            // (VARCHAR arrives as 2, INT as 7), and the name is the one that matches
            // the value encoding.
            type_code: type_name_to_code(&type_name),
            name,
            type_name,
            precision,
            scale: i16::try_from(scale).unwrap_or(0),
            nullable: nullable != 0,
            display_size: 0,
            table_name,
            schema_name,
            lob_tab_id,
            lob_col_id,
        },
        next,
    ))
}

/// Parse inline row data, shared by the EXEC/OPE payload (after its column descriptors)
/// and by a FETCH reply (from byte 0, since a FETCH carries rows only).
///
/// The leading row_size byte is not reliable enough to advance on its own, so the row
/// end comes from the column value offsets and sizes, with row_size as a lower bound.
pub(crate) fn parse_inline_rows(
    data: &[u8],
    mut offset: usize,
    columns: &[Column],
    server_encoding: ServerEncoding,
) -> Vec<Row> {
    let mut rows = Vec::new();
    if columns.is_empty() {
        return rows;
    }

    while offset + 10 <= data.len() {
        let row_start = offset;
        let row_size = data[offset] as usize;
        let rec_id = u32_at(data, offset + 2);

        let offsets_start = row_start + 10;
        let mut values = Vec::with_capacity(columns.len());
        let mut row_end = offsets_start + columns.len() * 2;
        for index in 0..columns.len() {
            let offset_slot = offsets_start + index * 2;
            if offset_slot + 2 > data.len() {
                values.push(None);
                continue;
            }
            let value_at = row_start + u16_at(data, offset_slot) as usize;
            if value_at + 2 > data.len() {
                values.push(None);
                continue;
            }
            let value_size = u16_at(data, value_at) as usize;
            if value_size == 0 || value_size == VALUE_SIZE_NULL {
                values.push(None);
            } else if value_at + 2 + value_size <= data.len() {
                values.push(Some(data[value_at + 2..value_at + 2 + value_size].to_vec()));
                row_end = row_end.max(value_at + 2 + value_size);
            } else {
                values.push(None);
            }
        }

        // row_end covers at least the offset table, so a row always advances the cursor.
        offset = row_end.max(row_start + row_size);

        for (index, column) in columns.iter().enumerate() {
            let Some(Some(raw)) = values.get(index) else {
                continue;
            };
            let decoded = if matches!(column.type_code, 3 | 14 | 16 | 23) {
                Some(decode_from_server(server_encoding, raw).into_bytes())
            } else if matches!(column.type_code, 9 | 20) {
                decode_dm_decimal_to_text(raw, column.scale).map(String::into_bytes)
            } else {
                None
            };
            if let Some(bytes) = decoded {
                values[index] = Some(bytes);
            }
        }

        rows.push(Row {
            row_id: rec_id as u16,
            values,
        });
    }

    rows
}

impl ExecResponse {
    /// Parse from raw payload bytes, inferring how many column descriptors the payload
    /// carries by validating each one.
    ///
    /// Prefer [`ExecResponse::from_bytes_with_col_count`] where the frame is at hand:
    /// the count it carries is exact, and inference can only guess where the
    /// descriptors stop and the rows begin.
    pub fn from_bytes(data: &[u8], server_encoding: ServerEncoding) -> Result<Self> {
        Self::parse(data, None, server_encoding)
    }

    /// Parse with the column count the frame header states at offset 22.
    pub fn from_bytes_with_col_count(
        data: &[u8],
        col_count: u16,
        server_encoding: ServerEncoding,
    ) -> Result<Self> {
        Self::parse(data, Some(usize::from(col_count)), server_encoding)
    }

    fn parse(
        data: &[u8],
        expected_columns: Option<usize>,
        server_encoding: ServerEncoding,
    ) -> Result<Self> {
        if data.len() < 16 {
            return Err(crate::error::Error::Incomplete);
        }

        // DML answers with a 16-byte payload whose last word is the affected count. A
        // result set spends those same bytes on its first column descriptor, so the
        // number means nothing there and only the DML path may read it.
        let header_row_count = u32_at(data, 12);

        let mut columns = Vec::new();
        let mut offset = 0;
        while expected_columns.map_or(true, |count| columns.len() < count) {
            match parse_column_descriptor(data, offset, expected_columns.is_none(), server_encoding)
            {
                Some((column, next)) => {
                    columns.push(column);
                    offset = next;
                }
                None => break,
            }
        }

        let rows = parse_inline_rows(data, offset, &columns, server_encoding);

        Ok(Self {
            col_count: u16::try_from(columns.len()).unwrap_or(u16::MAX),
            row_count: header_row_count,
            columns,
            rows,
        })
    }

    /// Check if this response contains result rows.
    pub fn has_rows(&self) -> bool {
        !self.rows.is_empty()
    }

    /// Get the number of columns.
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Get the number of rows.
    pub fn num_rows(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_row_get_i32() {
        let row = Row {
            row_id: 0,
            values: vec![Some(vec![1, 0, 0, 0])],
        };
        assert_eq!(row.get_i32(0).unwrap(), 1);
    }

    #[test]
    fn test_row_get_i32_single_byte() {
        let row = Row {
            row_id: 0,
            values: vec![Some(vec![42])],
        };
        assert_eq!(row.get_i32(0).unwrap(), 42);
    }

    #[test]
    fn test_row_get_str() {
        let row = Row {
            row_id: 0,
            values: vec![Some(b"hello".to_vec())],
        };
        assert_eq!(row.get_str(0).unwrap(), "hello");
    }

    #[test]
    fn test_row_is_null() {
        let row = Row {
            row_id: 0,
            values: vec![None, Some(vec![1, 2, 3])],
        };
        assert!(row.is_null(0));
        assert!(!row.is_null(1));
    }

    #[test]
    fn test_row_len() {
        let row = Row {
            row_id: 0,
            values: vec![Some(vec![1]), Some(vec![2]), Some(vec![3])],
        };
        assert_eq!(row.len(), 3);
        assert!(!row.is_empty());
    }

    #[test]
    fn test_row_get_i64() {
        let row = Row {
            row_id: 0,
            values: vec![Some(vec![42, 0, 0, 0, 0, 0, 0, 0])],
        };
        assert_eq!(row.get_i64(0).unwrap(), 42);
    }

    #[test]
    fn test_exec_response_has_rows() {
        let resp = ExecResponse {
            col_count: 0,
            row_count: 0,
            columns: vec![],
            rows: vec![],
        };
        assert!(!resp.has_rows());
    }

    #[test]
    fn test_exec_response_minimal_empty() {
        // Valid empty response: header(16) + col_header(16) + null_terminator(1)
        let data = [
            0x07, 0x00, 0x00, 0x00, // sub_type
            0x04, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // row_count = 0
            0x00, 0x00, 0x00, 0x00, // col_type = 0
            0x00, 0x00, // nullable
            0x00, 0x00, // display
            0x00, 0x00, // col_count = 0
            0x00, 0x00, // type_name_len
            0x00, 0x00, // table_name_len
            0x00, 0x00, // schema_name_len
        ];
        let resp = ExecResponse::from_bytes(&data, ServerEncoding::Utf8).unwrap();
        assert_eq!(resp.col_count, 0);
        assert_eq!(resp.num_columns(), 0);
        assert_eq!(resp.num_rows(), 0);
    }

    /// Captured from DM 8.1.3.62 for `SELECT "NOTE" FROM "APP"."CUSTOMER"`, where NOTE
    /// is a CLOB. The LOB descriptor is what the old "first column is a compact 16-byte
    /// header" model could not read: its precision is 0x7FFFFFFF and it carries a
    /// 6-byte lobTabId/lobColId trailer that shifts everything behind it.
    #[test]
    fn test_exec_response_lob_first_column() {
        let data: Vec<u8> = vec![
            0x13, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x08, 0x00, 0x03, 0x00, 0x4e, 0x4f, 0x54, 0x45, 0x43, 0x4c, 0x4f, 0x42, 0x43, 0x55,
            0x53, 0x54, 0x4f, 0x4d, 0x45, 0x52, 0x41, 0x50, 0x50, 0xf6, 0x03, 0x00, 0x00, 0x03,
            0x00, 0x23, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x15,
            0x00, 0x01, 0x69, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x6e, 0x6f, 0x74, 0x65, 0x20, 0x6f, 0x6e, 0x65, 0x0e, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0xfe, 0xff,
        ];

        let resp = ExecResponse::from_bytes_with_col_count(&data, 1, ServerEncoding::Utf8).unwrap();

        assert_eq!(resp.num_columns(), 1);
        assert_eq!(resp.columns[0].name, "NOTE");
        assert_eq!(resp.columns[0].type_name, "CLOB");
        assert_eq!(resp.columns[0].table_name, "CUSTOMER");
        assert_eq!(resp.columns[0].schema_name, "APP");
        assert_eq!(resp.columns[0].precision, 0x7FFF_FFFF);
        assert_eq!(resp.columns[0].lob_tab_id, 1014);
        assert_eq!(resp.columns[0].lob_col_id, 3);
        assert_eq!(resp.num_rows(), 2);
        assert!(!resp.rows[0].is_null(0));
        assert!(resp.rows[1].is_null(0));
    }

    /// Same server, `SELECT "ID", "NOTE" FROM "APP"."CUSTOMER"`. Inferring the column
    /// count has to walk past the LOB trailer to find the second descriptor.
    #[test]
    fn test_exec_response_lob_second_column() {
        let data: Vec<u8> = vec![
            0x07, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
            0x08, 0x00, 0x03, 0x00, 0x49, 0x44, 0x49, 0x4e, 0x54, 0x43, 0x55, 0x53, 0x54, 0x4f,
            0x4d, 0x45, 0x52, 0x41, 0x50, 0x50, 0x13, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x08, 0x00, 0x03, 0x00, 0x4e, 0x4f, 0x54, 0x45,
            0x43, 0x4c, 0x4f, 0x42, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x45, 0x52, 0x41, 0x50,
            0x50, 0xf6, 0x03, 0x00, 0x00, 0x03, 0x00, 0x2b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0e, 0x00, 0x14, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15,
            0x00, 0x01, 0x69, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x6e, 0x6f, 0x74, 0x65, 0x20, 0x6f, 0x6e, 0x65, 0x16, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x14, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
            0xfe, 0xff,
        ];

        let inferred = ExecResponse::from_bytes(&data, ServerEncoding::Utf8).unwrap();
        let stated =
            ExecResponse::from_bytes_with_col_count(&data, 2, ServerEncoding::Utf8).unwrap();

        for resp in [inferred, stated] {
            assert_eq!(resp.num_columns(), 2);
            assert_eq!(resp.columns[0].name, "ID");
            assert_eq!(resp.columns[1].name, "NOTE");
            assert_eq!(resp.columns[1].lob_tab_id, 1014);
            assert_eq!(resp.num_rows(), 2);
            assert_eq!(resp.rows[0].get_i32(0).unwrap(), 1);
            assert_eq!(resp.rows[1].get_i32(0).unwrap(), 2);
            assert!(!resp.rows[0].is_null(1));
            assert!(resp.rows[1].is_null(1));
        }
    }

    /// Captured for `SELECT BANNER FROM V$VERSION`. A single VARCHAR column used to take
    /// a "compact row format" path that scanned for a 0x0C marker; the rows are in the
    /// same format as every other result, and the marker it found was a column offset.
    #[test]
    fn test_exec_response_single_varchar_column() {
        let data: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x07, 0x00,
            0x09, 0x00, 0x03, 0x00, 0x42, 0x41, 0x4e, 0x4e, 0x45, 0x52, 0x56, 0x41, 0x52, 0x43,
            0x48, 0x41, 0x52, 0x56, 0x24, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e, 0x53, 0x59,
            0x53, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x18,
            0x00, 0x44, 0x4d, 0x20, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x20, 0x53,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x36, 0x34, 0x20, 0x56, 0x38, 0x21, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x13, 0x00, 0x44, 0x42, 0x20,
            0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x30, 0x78, 0x37, 0x30, 0x30,
            0x30, 0x63,
        ];

        let resp = ExecResponse::from_bytes_with_col_count(&data, 1, ServerEncoding::Utf8).unwrap();

        assert_eq!(resp.num_columns(), 1);
        assert_eq!(resp.columns[0].name, "BANNER");
        assert_eq!(resp.columns[0].type_name, "VARCHAR");
        assert_eq!(resp.columns[0].precision, 80);
        assert_eq!(resp.num_rows(), 2);
        assert_eq!(resp.rows[0].get_str(0).unwrap(), "DM Database Server 64 V8");
        assert_eq!(resp.rows[1].get_str(0).unwrap(), "DB Version: 0x7000c");
    }

    #[test]
    fn test_exec_response_select1_ope_no_null_term() {
        // Actual OPE response from DM 8.1.3.62 - no \0 terminator (58 bytes)
        let data: Vec<u8> = vec![
            0x07, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, // header (row_count=1)
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, // col1 header (type=4, nullable=0, col_count=1, col_name_len=1)
            // Strings: "1" + "INTEGER" (no \0 terminator!)
            0x31, 0x49, 0x4e, 0x54, 0x45, 0x47, 0x45, 0x52,
            // Row data: marker=18, flags=0, rec_id=0, padding=0, col_off=12, val_size=4, val=1
            0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ];
        let resp = ExecResponse::from_bytes(&data, ServerEncoding::Utf8).unwrap();
        assert_eq!(resp.col_count, 1);
        assert_eq!(resp.num_columns(), 1);
        assert_eq!(resp.num_rows(), 1);
        assert_eq!(resp.columns[0].name, "1");
        assert_eq!(resp.columns[0].type_name, "INTEGER");
        assert_eq!(resp.columns[0].type_code, 4);
        assert_eq!(resp.rows[0].get_i32(0).unwrap(), 1);
    }

    #[test]
    fn test_exec_response_subtype2_with_multiple_columns() {
        // Captured from DM8 for SELECT NAME, NAME FROM a one-row table. Nothing in the
        // payload states the count, so both descriptors have to be walked.
        let data: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x07, 0x00,
            0x11, 0x00, 0x06, 0x00, 0x4e, 0x41, 0x4d, 0x45, 0x56, 0x41, 0x52, 0x43, 0x48, 0x41,
            0x52, 0x54, 0x41, 0x42, 0x4c, 0x45, 0x50, 0x52, 0x4f, 0x5f, 0x4c, 0x4f, 0x42, 0x5f,
            0x54, 0x45, 0x53, 0x54, 0x53, 0x59, 0x53, 0x44, 0x42, 0x41, 0x02, 0x00, 0x00, 0x00,
            0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x07, 0x00, 0x11, 0x00, 0x06, 0x00,
            0x4e, 0x41, 0x4d, 0x45, 0x56, 0x41, 0x52, 0x43, 0x48, 0x41, 0x52, 0x54, 0x41, 0x42,
            0x4c, 0x45, 0x50, 0x52, 0x4f, 0x5f, 0x4c, 0x4f, 0x42, 0x5f, 0x54, 0x45, 0x53, 0x54,
            0x53, 0x59, 0x53, 0x44, 0x42, 0x41, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0e, 0x00, 0x15, 0x00, 0x05, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x05,
            0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        ];

        let resp = ExecResponse::from_bytes(&data, ServerEncoding::Utf8).unwrap();

        assert_eq!(resp.col_count, 2);
        assert_eq!(resp.num_columns(), 2);
        assert_eq!(resp.num_rows(), 1);
        assert_eq!(resp.rows[0].get_str(0).unwrap(), "hello");
        assert_eq!(resp.rows[0].get_str(1).unwrap(), "hello");
    }

    #[test]
    fn test_decode_dm_decimal_to_text_honors_exponent() {
        assert_eq!(
            decode_dm_decimal_to_text(&[0xc2, 0x02], 0).as_deref(),
            Some("100")
        );
        assert_eq!(
            decode_dm_decimal_to_text(&[0xc2, 0x52, 0x59], 0).as_deref(),
            Some("8188")
        );
        assert_eq!(
            decode_dm_decimal_to_text(&[0xc1, 0x02, 0x18], 0).as_deref(),
            Some("1.23")
        );
        assert_eq!(
            decode_dm_decimal_to_text(&[0x3e, 0x64, 0x4e, 0x66], 0).as_deref(),
            Some("-1.23")
        );
    }

    #[test]
    fn test_exec_response_incomplete() {
        let data = [0x00, 0x00, 0x00];
        let result = ExecResponse::from_bytes(&data, ServerEncoding::Utf8);
        assert!(matches!(result, Err(crate::error::Error::Incomplete)));
    }

    #[test]
    fn test_exec_response_short_payload_dml() {
        // INSERT/UPDATE/DELETE response with only 16-byte header (no column metadata).
        // The affected row count must still be extracted from the header.
        let data = [
            0x07, 0x00, 0x00, 0x00, // sub_type
            0x04, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // reserved
            0x01, 0x00, 0x00, 0x00, // row_count = 1 (affected rows)
        ];
        let resp = ExecResponse::from_bytes(&data, ServerEncoding::Utf8).unwrap();
        assert_eq!(resp.row_count, 1);
        assert_eq!(resp.col_count, 0);
        assert_eq!(resp.num_columns(), 0);
        assert_eq!(resp.num_rows(), 0);
    }

    #[test]
    fn test_row_get_i32_null() {
        let row = Row {
            row_id: 0,
            values: vec![None],
        };
        assert!(row.get_i32(0).is_err());
        assert!(row.is_null(0));
    }

    #[test]
    fn test_row_get_str_empty() {
        let row = Row {
            row_id: 0,
            values: vec![Some(vec![])],
        };
        let result = row.get_str(0).unwrap();
        assert_eq!(result, "");
    }
}
