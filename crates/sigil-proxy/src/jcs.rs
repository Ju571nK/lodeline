//! RFC 8785 JSON Canonicalization Scheme (JCS), for the metadata registry
//! (`contracts/registry.md`, README "D-05 metadata registry (N9)").
//!
//! This is NOT `sigil_proxy_api::canonical_json` (sorted by UTF-8 bytes, numbers
//! printed by serde_json); that one is an equality device for ledger dedup. The
//! fingerprint and `metadata_ref` derivations need the real thing:
//!
//! * object members sorted by the UTF-16 code units of their names;
//! * numbers printed as ECMAScript `Number::toString` of the IEEE double;
//! * strings escaped as `\b \t \n \f \r \" \\`, other C0 controls as lower-case
//!   `\u00xx`, everything else literal UTF-8.
//!
//! Inputs outside the domain are REFUSED, never approximated:
//!
//! * a duplicate object member name (when parsing text);
//! * an integer whose magnitude exceeds 2^53 (it would silently round in a
//!   double; JCS/I-JSON cannot represent it exactly);
//! * a non-finite number (cannot come out of a JSON parser, but a hand-built
//!   [`Value`] is checked too);
//! * nesting deeper than [`MAX_DEPTH`];
//! * text that is not valid JSON (this includes lone surrogate escapes).
//!
//! One residual: an integer literal beyond the `u64` range is read by
//! `serde_json` as an IEEE double (I-JSON behaviour) before this module sees it.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Deepest nesting accepted.
pub const MAX_DEPTH: usize = 128;

/// Largest integer magnitude that a double represents exactly (2^53).
const MAX_EXACT_INT: u64 = 1 << 53;

/// Why a value cannot be canonicalised. Carries no content: the value may be
/// untrusted tool-definition text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JcsError {
    /// Not valid JSON (or a lone surrogate escape, or nesting that is too deep
    /// for the parser).
    Syntax,
    /// A duplicate member name in one object.
    DuplicateKey,
    /// An integer beyond +-2^53, or a non-finite number.
    NumberOutOfDomain,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JcsError::Syntax => "not valid JSON",
            JcsError::DuplicateKey => "duplicate object member name",
            JcsError::NumberOutOfDomain => "number outside the JCS domain",
            JcsError::TooDeep => "nesting too deep",
        })
    }
}

impl std::error::Error for JcsError {}

/// JCS bytes of `value`.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_value(value, &mut out, 0)?;
    Ok(out)
}

/// Parse JSON text (rejecting duplicate member names) and canonicalise it.
pub fn canonicalize_str(text: &str) -> Result<Vec<u8>, JcsError> {
    canonicalize(&parse_strict(text)?)
}

/// Parse JSON text into a [`Value`], rejecting duplicate member names.
pub fn parse_strict(text: &str) -> Result<Value, JcsError> {
    let mut de = serde_json::Deserializer::from_str(text);
    let v = Strict::deserialize(&mut de).map_err(|e| {
        if e.to_string().contains(DUP_MARK) {
            JcsError::DuplicateKey
        } else {
            JcsError::Syntax
        }
    })?;
    de.end().map_err(|_| JcsError::Syntax)?;
    Ok(v.0)
}

const DUP_MARK: &str = "sigil-jcs-duplicate-key";

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(b)))
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(n)))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(n)))
            }
            fn visit_f64<E: de::Error>(self, n: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(n)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(s.to_owned())))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(s)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut v = Vec::new();
                while let Some(Strict(x)) = a.next_element()? {
                    v.push(x);
                }
                Ok(Strict(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut m = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if m.contains_key(&k) {
                        return Err(de::Error::custom(DUP_MARK));
                    }
                    let Strict(v) = a.next_value()?;
                    m.insert(k, v);
                }
                Ok(Strict(Value::Object(m)))
            }
        }
        d.deserialize_any(V)
    }
}

fn write_value(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), JcsError> {
    if depth > MAX_DEPTH {
        return Err(JcsError::TooDeep);
    }
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            let f = if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_EXACT_INT {
                    return Err(JcsError::NumberOutOfDomain);
                }
                i as f64
            } else if let Some(u) = n.as_u64() {
                if u > MAX_EXACT_INT {
                    return Err(JcsError::NumberOutOfDomain);
                }
                u as f64
            } else {
                n.as_f64().ok_or(JcsError::NumberOutOfDomain)?
            };
            out.extend_from_slice(es_number(f)?.as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(x, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut members: Vec<(Vec<u16>, &String, &Value)> = m
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (_, k, x)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(x, out, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// ECMAScript `Number::toString(x)` for a finite double (ECMA-262 6.1.6.1.20).
pub fn es_number(x: f64) -> Result<String, JcsError> {
    if !x.is_finite() {
        return Err(JcsError::NumberOutOfDomain);
    }
    if x == 0.0 {
        return Ok("0".to_string());
    }
    let (neg, x) = if x < 0.0 { (true, -x) } else { (false, x) };
    // `{:e}` prints the shortest digits that round-trip: "d.ddde<exp>". When two
    // k-digit candidates are equally short, ECMAScript takes the one closest to
    // the exact value (ties to even), which Rust's shortest printer does not
    // always pick; the exactly rounded k-digit form is that one whenever it
    // round-trips.
    let shortest = format!("{x:e}");
    let k = shortest
        .split_once('e')
        .map(|(m, _)| m.chars().filter(|c| *c != '.').count())
        .ok_or(JcsError::NumberOutOfDomain)?;
    let exact = format!("{:.*e}", k - 1, x);
    let sci = if exact.parse::<f64>() == Ok(x) {
        exact
    } else {
        shortest
    };
    let (mant, exp) = sci.split_once('e').ok_or(JcsError::NumberOutOfDomain)?;
    let exp: i32 = exp.parse().map_err(|_| JcsError::NumberOutOfDomain)?;
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1; // value = 0.DIGITS * 10^n
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if k <= n && n <= 21 {
        s.push_str(&digits);
        s.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        s.push_str(&digits[..n as usize]);
        s.push('.');
        s.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        s.push_str("0.");
        s.extend(std::iter::repeat_n('0', (-n) as usize));
        s.push_str(&digits);
    } else {
        let e = n - 1;
        s.push_str(&digits[..1]);
        if k > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        s.push('e');
        s.push(if e < 0 { '-' } else { '+' });
        s.push_str(&e.abs().to_string());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(text: &str) -> String {
        String::from_utf8(canonicalize_str(text).unwrap()).unwrap()
    }

    /// RFC 8785 appendix B (expected strings checked against V8).
    #[test]
    fn rfc8785_number_vectors() {
        let cases: &[(u64, &str)] = &[
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0x4340000000000001, "9007199254740994"),
            (0xc340000000000001, "-9007199254740994"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, want) in cases {
            assert_eq!(
                &es_number(f64::from_bits(*bits)).unwrap(),
                want,
                "{bits:#x}"
            );
        }
    }

    #[test]
    fn rfc8785_section_3_2_2_example() {
        let input = r#"{
            "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
            "literals": [null, true, false]
        }"#;
        assert_eq!(
            canon(input),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn rfc8785_section_3_2_3_utf16_key_order() {
        // Keys: U+20AC, U+000D, U+FB33, U+1F600, "1", U+0080, U+00F6.
        let input = "{\"\u{20ac}\":\"Euro\",\"\\r\":\"CR\",\"\u{fb33}\":\"Hebrew\",\"\u{1f600}\":\"Emoji\",\"1\":\"One\",\"\u{80}\":\"C1\",\"\u{f6}\":\"o\"}";
        let out = canon(input);
        let keys: Vec<String> = parse_strict(&out)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        // serde_json's Map is sorted by code point, so check the TEXT order.
        let pos = |k: &str| out.find(&format!("\"{k}\":")).unwrap();
        let order = [
            "\\r",
            "1",
            "\u{80}",
            "\u{f6}",
            "\u{20ac}",
            "\u{1f600}",
            "\u{fb33}",
        ];
        for w in order.windows(2) {
            assert!(pos(w[0]) < pos(w[1]), "{:?} before {:?}", w[0], w[1]);
        }
        assert_eq!(keys.len(), 7);
        // The point of UTF-16 order: U+1F600 (D83D DE00) sorts BEFORE U+FB33.
        assert!(pos("\u{1f600}") < pos("\u{fb33}"));
    }

    #[test]
    fn string_escapes_are_minimal() {
        assert_eq!(
            canon(r#""\u0000\u0007\b\t\n\u000b\f\r\u001f \u007f\u2028\/""#),
            "\"\\u0000\\u0007\\b\\t\\n\\u000b\\f\\r\\u001f \u{7f}\u{2028}/\""
        );
    }

    #[test]
    fn numbers_are_normalised_through_the_double() {
        assert_eq!(
            canon("[1.0, 1e2, -0, -0.0, 100, 0.5E1, 1E-7]"),
            "[1,100,0,0,100,5,1e-7]"
        );
        assert_eq!(canon("9007199254740992"), "9007199254740992");
        assert_eq!(canon("-9007199254740992"), "-9007199254740992");
    }

    #[test]
    fn refuses_what_it_cannot_represent() {
        for t in [
            "9007199254740993",
            "-9007199254740993",
            "9223372036854775807",
            "18446744073709551615",
        ] {
            assert_eq!(canonicalize_str(t), Err(JcsError::NumberOutOfDomain), "{t}");
        }
        assert_eq!(
            canonicalize_str(r#"{"a":1,"a":2}"#),
            Err(JcsError::DuplicateKey)
        );
        assert_eq!(
            canonicalize_str(r#"{"x":{"a":1,"b":2,"a":3}}"#),
            Err(JcsError::DuplicateKey)
        );
        for t in [
            r#""\ud800""#,
            "{",
            "",
            "nan",
            "[1,]",
            "01",
            "1 2",
            "\"a\" x",
        ] {
            assert_eq!(canonicalize_str(t), Err(JcsError::Syntax), "{t:?}");
        }
        assert!(es_number(f64::NAN).is_err());
        assert!(es_number(f64::INFINITY).is_err());
        // Hand-built values are checked too.
        assert_eq!(
            canonicalize(&json!(u64::MAX)),
            Err(JcsError::NumberOutOfDomain)
        );
        let mut deep = json!(1);
        for _ in 0..(MAX_DEPTH + 2) {
            deep = json!([deep]);
        }
        assert_eq!(canonicalize(&deep), Err(JcsError::TooDeep));
        // Parser-side nesting limit also refuses.
        let text = format!("{}1{}", "[".repeat(300), "]".repeat(300));
        assert!(canonicalize_str(&text).is_err());
    }

    #[test]
    fn error_text_carries_no_content() {
        let e = parse_strict(r#"{"secret-name":1,"secret-name":2}"#).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("secret"));
    }

    #[test]
    fn key_order_does_not_change_output() {
        assert_eq!(
            canon(r#"{"b":[{"y":1,"x":2}],"a":"é"}"#),
            canon(r#"{"a":"é","b":[{"x":2,"y":1}]}"#)
        );
    }
}
