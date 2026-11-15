//! Fixed-width UTC timestamps `YYYY-MM-DDTHH:MM:SS.sssZ` (lexicographically ordered).

use crate::error::{Result, VaultError};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

const FMT: &[time::format_description::BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

/// Formats Unix milliseconds as a fixed-width UTC timestamp.
pub fn format_ms(ms: i64) -> Result<String> {
    let dt = OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .map_err(|_| VaultError::Validation("timestamp"))?;
    if !(1970..=9999).contains(&dt.year()) {
        return Err(VaultError::Validation("timestamp"));
    }
    dt.format(FMT).map_err(|_| VaultError::Validation("timestamp"))
}

/// Validates the exact timestamp format.
pub fn validate(s: &str) -> Result<()> {
    if s.len() != 24 {
        return Err(VaultError::InvalidFormat("timestamp"));
    }
    PrimitiveDateTime::parse(s, FMT).map(|_| ()).map_err(|_| VaultError::InvalidFormat("timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        assert_eq!(format_ms(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_ms(1_763_150_400_123).unwrap(), "2025-11-14T20:00:00.123Z");
        validate("2025-11-14T20:00:00.123Z").unwrap();
        assert!(validate("2025-11-14T20:00:00Z").is_err());
        assert!(validate("2025-13-14T20:00:00.123Z").is_err());
        assert!(format_ms(-1).is_err());
    }
}
