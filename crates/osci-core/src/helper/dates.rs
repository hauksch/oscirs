//! ISO-8601 timestamp handling as required by OSCI 1.2
//! (port of `OSCIMessage.formatISO8601` / `parseISO8601`).
//!
//! Semantics pinned by the Java library:
//! - formatting truncates to whole seconds and renders the zone offset as
//!   `+hh:mm`, or `Z` when the offset is zero,
//! - parsing accepts `Z` and `+hh:mm` offsets and truncates sub-second
//!   precision (library changelog 2.4.7: fixed millisecond trimming).

use chrono::{DateTime, Offset, SubsecRound, TimeZone, Timelike, Utc};

#[derive(Debug, thiserror::Error)]
#[error("invalid ISO-8601 date: {0}")]
pub struct DateParseError(String);

/// Format in the style `2022-07-21T22:52:24+02:00` (or `...Z` for UTC).
/// Sub-second precision is truncated, mirroring the Java implementation.
pub fn format_iso8601<Tz>(dt: &DateTime<Tz>) -> String
where
    Tz: TimeZone,
    Tz::Offset: std::fmt::Display,
{
    let dt = dt.with_nanosecond(0).unwrap_or_else(|| dt.clone());
    let offset_minutes = dt.offset().fix().local_minus_utc() / 60;
    let offset = if offset_minutes == 0 {
        "Z".to_string()
    } else {
        let sign = if offset_minutes < 0 { '-' } else { '+' };
        let abs = offset_minutes.unsigned_abs();
        format!("{sign}{:02}:{:02}", abs / 60, abs % 60)
    };
    format!("{}{}", dt.format("%Y-%m-%dT%H:%M:%S"), offset)
}

/// Parse an ISO-8601 date-time with offset (`Z` or `±hh:mm`); sub-second
/// precision is truncated. The result is normalized to UTC.
pub fn parse_iso8601(date: &str) -> Result<DateTime<Utc>, DateParseError> {
    let dt = DateTime::parse_from_rfc3339(date)
        .or_else(|_| {
            DateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%S%.f%:z")
                .or_else(|_| DateTime::parse_from_str(date, "%Y-%m-%dT%H:%M%.f%:z"))
        })
        .map_err(|e| DateParseError(format!("{date}: {e}")))?;
    Ok(dt.trunc_subsecs(0).with_timezone(&Utc))
}
