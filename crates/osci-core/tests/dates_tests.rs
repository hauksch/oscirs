//! Port of `de.osci.osci12.messagetypes.TestIsoDateParsing`.

use chrono::{DateTime, FixedOffset, TimeZone, Utc};

use osci_core::helper::dates::{format_iso8601, parse_iso8601};

/// Port of `formatIsoStrings`, Berlin-offset branch: epoch millis
/// 1658436744000 renders as `2022-07-21T22:52:24+02:00`.
#[test]
fn formats_offset_string() {
    let plus2 = FixedOffset::east_opt(2 * 3600).unwrap();
    let dt: DateTime<FixedOffset> = plus2.timestamp_opt(1658436744, 0).unwrap();
    assert_eq!(format_iso8601(&dt), "2022-07-21T22:52:24+02:00");
}

/// Port of `formatIsoStrings`, UTC branch (`Z` for zero offset).
#[test]
fn formats_utc_as_z() {
    let dt: DateTime<Utc> = Utc.timestamp_opt(1658436744, 0).unwrap();
    assert_eq!(format_iso8601(&dt), "2022-07-21T20:52:24Z");
}

#[test]
fn formats_negative_offset() {
    let minus5 = FixedOffset::west_opt(5 * 3600).unwrap();
    let dt: DateTime<FixedOffset> = minus5.timestamp_opt(1658436744, 0).unwrap();
    assert_eq!(format_iso8601(&dt), "2022-07-21T15:52:24-05:00");
}

#[test]
fn formatting_truncates_subseconds() {
    let dt: DateTime<Utc> = Utc.timestamp_opt(1658436744, 950_000_000).unwrap();
    assert_eq!(format_iso8601(&dt), "2022-07-21T20:52:24Z");
}

/// Port of `parseIsoStrings`: both spellings are the same instant and match
/// the Java test date (1658436744000 ms).
#[test]
fn parses_both_offset_styles_to_same_instant() {
    let with_offset = parse_iso8601("2022-07-21T22:52:24+02:00").unwrap();
    let with_z = parse_iso8601("2022-07-21T20:52:24Z").unwrap();
    assert_eq!(with_offset, with_z);
    assert_eq!(with_offset.timestamp_millis(), 1_658_436_744_000);
}

/// Library changelog 2.4.7 fixed millisecond trimming on parse: sub-second
/// precision is truncated, not carried.
#[test]
fn parsing_truncates_milliseconds() {
    let dt = parse_iso8601("2022-07-21T22:52:24.950+02:00").unwrap();
    assert_eq!(dt.timestamp_millis(), 1_658_436_744_000);
}

/// Timestamps straight from the golden fixtures survive a
/// parse -> format roundtrip in their own zone.
#[test]
fn roundtrips_fixture_timestamps() {
    let cases = [
        ("2005-11-01T15:16:49+01:00", 3600),
        ("2022-07-21T20:52:24Z", 0),
    ];
    for (text, offset_secs) in cases {
        let dt = parse_iso8601(text).unwrap();
        let zone = FixedOffset::east_opt(offset_secs).unwrap();
        assert_eq!(
            format_iso8601(&dt.with_timezone(&zone)),
            text,
            "roundtrip changed {text}"
        );
    }
}

#[test]
fn rejects_garbage() {
    assert!(parse_iso8601("not-a-date").is_err());
    assert!(parse_iso8601("").is_err());
}
