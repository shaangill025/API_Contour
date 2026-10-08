use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use serde_json::value::RawValue;
use std::fmt;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarError {
    InvalidTimestamp,
    TimestampTooLong,
    InvalidUnsigned,
    TokenTooLong,
}
impl fmt::Display for ScalarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ScalarError {}

/// Checked timestamp. Bound the enclosing JSON input before serde decoding;
/// serde may scan and unescape the string before this type can validate its length.
#[derive(Clone)]
pub struct Timestamp {
    text: String,
    instant: OffsetDateTime,
}
impl Timestamp {
    pub(crate) fn from_instant(instant: OffsetDateTime) -> Result<Self, ScalarError> {
        let text = instant
            .to_offset(time::UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|_| ScalarError::InvalidTimestamp)?;
        Self::parse(&text)
    }
    pub fn parse(text: &str) -> Result<Self, ScalarError> {
        if text.len() > 35 {
            return Err(ScalarError::TimestampTooLong);
        }
        let bytes = text.as_bytes();
        if bytes.len() < 20 || !bytes.is_ascii() {
            return Err(ScalarError::InvalidTimestamp);
        }
        for (index, expected) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
            if bytes[index] != expected {
                return Err(ScalarError::InvalidTimestamp);
            }
        }
        if (0..19).any(|i| ![4, 7, 10, 13, 16].contains(&i) && !bytes[i].is_ascii_digit())
            || &bytes[..4] == b"0000"
            || &bytes[17..19] > b"59"
        {
            return Err(ScalarError::InvalidTimestamp);
        }
        let mut zone = 19;
        if bytes[zone] == b'.' {
            zone += 1;
            let start = zone;
            while zone < bytes.len() && bytes[zone].is_ascii_digit() {
                zone += 1;
            }
            if !(1..=9).contains(&(zone - start)) {
                return Err(ScalarError::InvalidTimestamp);
            }
        }
        let offset = &bytes[zone..];
        if offset != b"Z"
            && !(offset.len() == 6
                && matches!(offset[0], b'+' | b'-')
                && offset[3] == b':'
                && [1, 2, 4, 5].iter().all(|i| offset[*i].is_ascii_digit()))
        {
            return Err(ScalarError::InvalidTimestamp);
        }
        let instant =
            OffsetDateTime::parse(text, &Rfc3339).map_err(|_| ScalarError::InvalidTimestamp)?;
        Ok(Self {
            text: text.to_owned(),
            instant,
        })
    }
    pub fn as_str(&self) -> &str {
        &self.text
    }
    pub fn instant(&self) -> OffsetDateTime {
        self.instant
    }
}
impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Timestamp")
    }
}

/// Exact unsigned metadata. Bound the enclosing JSON input before serde decoding;
/// RawValue scans the token before this type receives it. Direct parse bounds first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnsignedInteger(u64);
impl UnsignedInteger {
    /// Accept one exact JSON number token, without surrounding whitespace.
    pub fn parse(token: &str) -> Result<Self, ScalarError> {
        if token.len() > 256 {
            return Err(ScalarError::TokenTooLong);
        }
        let raw: &RawValue =
            serde_json::from_str(token).map_err(|_| ScalarError::InvalidUnsigned)?;
        if raw.get() != token {
            return Err(ScalarError::InvalidUnsigned);
        }
        Self::checked_token(token)
    }
    fn checked_token(token: &str) -> Result<Self, ScalarError> {
        if token.len() > 256 {
            return Err(ScalarError::TokenTooLong);
        }
        if !matches!(token.as_bytes().first(), Some(b'-' | b'0'..=b'9')) {
            return Err(ScalarError::InvalidUnsigned);
        }
        let (coefficient, exponent) = token.split_once(['e', 'E']).unwrap_or((token, "0"));
        let digits = || coefficient.bytes().filter(u8::is_ascii_digit);
        if digits().all(|digit| digit == b'0') {
            return Ok(Self(0));
        }
        if coefficient.starts_with('-') {
            return Err(ScalarError::InvalidUnsigned);
        }
        let magnitude = exponent
            .trim_start_matches(['+', '-'])
            .bytes()
            .fold(0i32, |n, digit| {
                (n * 10 + i32::from(digit - b'0')).min(1024)
            });
        let exponent = if exponent.starts_with('-') {
            -magnitude
        } else {
            magnitude
        };
        let fraction = coefficient
            .split_once('.')
            .map_or(0, |(_, digits)| digits.len() as i32);
        let scale = exponent - fraction;
        let count = digits().count();
        let retained = if scale < 0 {
            let zeros = digits().rev().take_while(|digit| *digit == b'0').count();
            if zeros < (-scale) as usize {
                return Err(ScalarError::InvalidUnsigned);
            }
            count - (-scale) as usize
        } else {
            if scale > 19 {
                return Err(ScalarError::InvalidUnsigned);
            }
            count
        };
        let mut value = 0u64;
        for digit in digits().take(retained) {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(digit - b'0')))
                .ok_or(ScalarError::InvalidUnsigned)?;
        }
        for _ in 0..scale.max(0) {
            value = value.checked_mul(10).ok_or(ScalarError::InvalidUnsigned)?;
        }
        Ok(Self(value))
    }
    pub fn new(value: u64) -> Self {
        Self(value)
    }
    pub fn get(self) -> u64 {
        self.0
    }
}
impl fmt::Debug for UnsignedInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnsignedInteger")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}
impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct TimestampVisitor;
        impl Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("timestamp string")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Timestamp, E> {
                Timestamp::parse(text).map_err(|_| E::custom("invalid timestamp"))
            }
        }
        decoder
            .deserialize_str(TimestampVisitor)
            .map_err(|_| de::Error::custom("invalid timestamp"))
    }
}
impl Serialize for UnsignedInteger {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}
impl<'de> Deserialize<'de> for UnsignedInteger {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let raw = <&RawValue>::deserialize(decoder)
            .map_err(|_| de::Error::custom("invalid unsigned integer"))?;
        Self::checked_token(raw.get()).map_err(|_| de::Error::custom("invalid unsigned integer"))
    }
}
