//! Scalar types with the schema `$defs` patterns and bounds.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ValidationError;

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_uuid_shape(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

fn is_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

fn is_metadata_ref(s: &str) -> bool {
    let b = s.as_bytes();
    is_uuid_shape(s) && b[14] == b'8' && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

fn is_key_id(s: &str) -> bool {
    s.strip_prefix("kid-")
        .is_some_and(|h| h.len() == 24 && is_lower_hex(h))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && is_lower_hex(s)
}

/// `^YYYY-MM-DDTHH:MM:SS(.f{1,9})?Z` plus calendar validity. Second 60 is rejected
/// (README m2: the wire never carries a leap second).
fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 || b[b.len() - 1] != b'Z' {
        return false;
    }
    let d = |i: usize| -> Option<u32> {
        b.get(i)
            .filter(|c| c.is_ascii_digit())
            .map(|c| u32::from(c - b'0'))
    };
    let num = |i: usize, n: usize| -> Option<u32> {
        (i..i + n).try_fold(0u32, |acc, k| d(k).map(|v| acc * 10 + v))
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(min), Some(sec)) = (
        num(0, 4),
        num(5, 2),
        num(8, 2),
        num(11, 2),
        num(14, 2),
        num(17, 2),
    ) else {
        return false;
    };
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return false;
    }
    match &b[19..b.len() - 1] {
        [] => {}
        [b'.', frac @ ..]
            if (1..=9).contains(&frac.len()) && frac.iter().all(u8::is_ascii_digit) => {}
        _ => return false,
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour <= 23 && min <= 59 && sec <= 59
}

macro_rules! string_scalar {
    ($(#[$m:meta])* $name:ident, $check:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validates against the schema pattern.
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                let check: fn(&str) -> bool = $check;
                if check(&value) {
                    Ok(Self(value))
                } else {
                    // The rejected value is never echoed.
                    Err(ValidationError::new(concat!("invalid ", $what)))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::new(raw).map_err(D::Error::custom)
            }
        }
    };
}

string_scalar!(
    /// Lowercase hyphenated UUID text (any version).
    Uuid, is_uuid_shape, "uuid"
);
string_scalar!(
    /// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`.
    Id, is_id, "id"
);
string_scalar!(
    /// Lowercase UUID with version nibble 8 and RFC 9562 variant.
    MetadataRef, is_metadata_ref, "metadata_ref"
);
string_scalar!(
    /// `kid-` followed by 24 lowercase hex digits.
    KeyId, is_key_id, "key_id"
);
string_scalar!(
    /// Keyed HMAC-SHA-256 hex (64 lowercase hex digits).
    Fingerprint, is_hex64, "fingerprint"
);
string_scalar!(
    /// SHA-256 hex of the applied config (64 lowercase hex digits).
    ConfigHash, is_hex64, "config_hash"
);
string_scalar!(
    /// UTC RFC 3339 text with uppercase `T`/`Z`. Kept verbatim: dedup compares
    /// code point for code point, so `08:00:00Z` and `08:00:00.0Z` differ.
    Timestamp, is_timestamp, "timestamp"
);

macro_rules! int_scalar {
    ($(#[$m:meta])* $name:ident, $min:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(i64);

        impl $name {
            pub const MIN: i64 = $min;

            pub fn new(value: i64) -> Result<Self, ValidationError> {
                if value >= Self::MIN {
                    Ok(Self(value))
                } else {
                    Err(ValidationError::new(concat!("invalid ", $what)))
                }
            }

            pub fn get(self) -> i64 {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_i64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                // i64 deserialization rejects floats (1.0, 1e0), booleans and values above 2^63-1.
                let raw = i64::deserialize(d)?;
                Self::new(raw).map_err(D::Error::custom)
            }
        }
    };
}

int_scalar!(
    /// Integer in `1..=2^63-1`.
    PositiveI64, 1, "positive integer"
);
int_scalar!(
    /// Integer in `0..=2^63-1`.
    NonNegativeI64, 0, "non-negative integer"
);

/// The constant `schema_version: 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SchemaVersion;

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match u64::deserialize(d)? {
            1 => Ok(SchemaVersion),
            _ => Err(D::Error::custom("unsupported schema_version")),
        }
    }
}
