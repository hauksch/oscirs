//! Weak-crypto policy (port of `Crypto.isWeak` and the `Constants.OUT_DATES`
//! table). Cutoff dates are Europe/Berlin like the Java originals; the
//! offsets below match Berlin standard/summer time for each date.

use chrono::{DateTime, NaiveDate, Utc};

use crate::algorithms::{
    DIGEST_RIPEMD160, DIGEST_SHA1, SIGNATURE_RSA_RIPEMD160, SIGNATURE_RSA_SHA1,
};

/// The date this library release considers "now" for checks without an
/// explicit date (Java `Constants.ACTUAL_DATE`: 2014-03-01 Berlin).
pub fn actual_date() -> DateTime<Utc> {
    berlin_date(2014, 3, 1, 1)
}

/// RSA keys below 1024 bits are always weak; 1024-bit keys became weak on
/// 2008-04-01 (`OUT_DATE_KEYSIZE_1024`). EC keys below 224 bits are weak.
/// Port of `Crypto.isWeak(Date, String, int)`; `date == None` uses
/// `ACTUAL_DATE`.
pub fn is_weak_key(date: Option<DateTime<Utc>>, key_algorithm: &str, key_size_bits: usize) -> bool {
    let date = date.unwrap_or_else(actual_date);
    if key_algorithm.eq_ignore_ascii_case("EC") {
        key_size_bits < 224
    } else {
        if key_size_bits < 1024 {
            return true;
        }
        if key_size_bits > 2048 {
            return false;
        }
        key_size_bits < 2048 && !(date < berlin_date(2008, 4, 1, 2))
    }
}

/// Algorithm out-dates: SHA-1 digest and `rsa-sha1` signatures since
/// 2008-07-01 (BSI recommendation); RIPEMD-160 digest and
/// `rsa-ripemd160` signatures since 2011-01-01. Port of the
/// `Constants.OUT_DATES` lookups.
pub fn algorithm_out_date(uri: &str) -> Option<DateTime<Utc>> {
    let (y, m, d, offset_hours) = match uri {
        DIGEST_SHA1 | SIGNATURE_RSA_SHA1 => (2008, 7, 1, 2),
        DIGEST_RIPEMD160 | SIGNATURE_RSA_RIPEMD160 => (2011, 1, 1, 1),
        _ => return None,
    };
    Some(berlin_date(y, m, d, offset_hours))
}

/// A signature or digest algorithm is weak at `date` when its out-date has
/// passed (`None` uses `ACTUAL_DATE`); mirrors
/// `!date.before(OUT_DATES.get(algorithm))`.
pub fn is_weak_algorithm(date: Option<DateTime<Utc>>, uri: &str) -> bool {
    let Some(out) = algorithm_out_date(uri) else {
        return false;
    };
    let date = date.unwrap_or_else(actual_date);
    !(date < out)
}

fn berlin_date(year: i32, month: u32, day: u32, offset_hours: i32) -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(year, month, day)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_local_timezone(chrono::FixedOffset::east_opt(3600 * offset_hours).unwrap())
        .unwrap()
        .with_timezone(&Utc)
}
