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
//! * text that is not valid JSON (this includes lone surrogate escapes and
//!   numbers whose double is infinite).
//!
//! One residual: an integer literal beyond the `u64` range is read by
//! `serde_json` as an IEEE double (I-JSON behaviour) before this module sees it.

use std::fmt;

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

/// Parse JSON text (RFC 8259) into a [`Value`], rejecting duplicate member names.
///
/// This is a small parser of its own, not `serde_json`'s: RFC 8785 needs numbers
/// that are correctly rounded to the nearest double, and `serde_json` only does
/// that behind a feature (`float_roundtrip`) that cargo would unify across the
/// whole workspace. Here fractions and exponents go through `str::parse::<f64>`,
/// which is correctly rounded; plain integer literals are read as `i64`/`u64`
/// (and, beyond `u64`, as a double).
pub fn parse_strict(text: &str) -> Result<Value, JcsError> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(JcsError::Syntax);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> Result<(), JcsError> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(JcsError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JcsError> {
        if depth > MAX_DEPTH {
            return Err(JcsError::TooDeep);
        }
        match self.b.get(self.i).copied() {
            Some(b'n') => self.eat(b"null").map(|_| Value::Null),
            Some(b't') => self.eat(b"true").map(|_| Value::Bool(true)),
            Some(b'f') => self.eat(b"false").map(|_| Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Value::Array(v));
                }
                loop {
                    self.ws();
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Array(v));
                        }
                        _ => return Err(JcsError::Syntax),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m = Map::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Value::Object(m));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(JcsError::Syntax);
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(JcsError::Syntax);
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    if m.insert(k, v).is_some() {
                        return Err(JcsError::DuplicateKey);
                    }
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Object(m));
                        }
                        _ => return Err(JcsError::Syntax),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JcsError::Syntax),
        }
    }

    fn hex4(&mut self) -> Result<u32, JcsError> {
        let h = self.b.get(self.i..self.i + 4).ok_or(JcsError::Syntax)?;
        let mut n = 0u32;
        for c in h {
            n = n * 16 + (*c as char).to_digit(16).ok_or(JcsError::Syntax)?;
        }
        self.i += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, JcsError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(c) = self.b.get(self.i) {
                if *c == b'"' || *c == b'\\' || *c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // The input is a &str and we split only at ASCII bytes.
            out.push_str(
                std::str::from_utf8(&self.b[start..self.i]).map_err(|_| JcsError::Syntax)?,
            );
            match self.b.get(self.i).copied() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.b.get(self.i).copied().ok_or(JcsError::Syntax)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                // A high surrogate must be followed by a low one.
                                self.eat(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(JcsError::Syntax);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or(JcsError::Syntax)?);
                        }
                        _ => return Err(JcsError::Syntax),
                    }
                }
                _ => return Err(JcsError::Syntax), // control character or end of input
            }
        }
    }

    fn number(&mut self) -> Result<Value, JcsError> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(JcsError::Syntax),
        }
        let mut float = false;
        if self.b.get(self.i) == Some(&b'.') {
            float = true;
            self.i += 1;
            if !self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                return Err(JcsError::Syntax);
            }
            self.digits();
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            float = true;
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                return Err(JcsError::Syntax);
            }
            self.digits();
        }
        let t = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| JcsError::Syntax)?;
        if !float {
            if let Ok(n) = t.parse::<i64>() {
                return Ok(Value::from(n));
            }
            if let Ok(n) = t.parse::<u64>() {
                return Ok(Value::from(n));
            }
        }
        let f: f64 = t.parse().map_err(|_| JcsError::Syntax)?;
        serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or(JcsError::NumberOutOfDomain)
    }

    fn digits(&mut self) {
        while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
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
    fn own_parser_agrees_with_serde_json_and_is_strict() {
        for t in [
            r#"{"a":[1,2.5,-0.0,1e3,"xé😀\n\/"],"b":{"c":null,"d":true}}"#,
            " [ ] ",
            r#"{"":0}"#,
            "12345678901234567890",
            "-9223372036854775808",
        ] {
            let mine = parse_strict(t).unwrap();
            let theirs: Value = serde_json::from_str(t).unwrap();
            assert_eq!(mine, theirs, "{t}");
        }
        assert_eq!(
            parse_strict(r#""😀""#).unwrap(),
            Value::String("\u{1f600}".into())
        );
        for t in [
            "-",
            "1.",
            ".5",
            "+1",
            "1e",
            "1e+",
            "01",
            "[1,]",
            r#"{"a":1,}"#,
            "{a:1}",
            r#""\ud83d""#,
            r#""\ude00""#,
            r#""\x""#,
            "\"a\nb\"",
            "tru",
            "nul",
            "[1 2]",
            r#"{"a" 1}"#,
            "\"abc",
            "[",
            "]",
        ] {
            assert_eq!(parse_strict(t), Err(JcsError::Syntax), "{t:?}");
        }
        assert_eq!(parse_strict("1e400"), Err(JcsError::NumberOutOfDomain));
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert_eq!(parse_strict(&deep), Err(JcsError::TooDeep));
        // Correct rounding without serde_json's float_roundtrip feature.
        assert_eq!(
            canon("[333333333.33333329, 0.1, 2.2250738585072014e-308]"),
            "[333333333.3333333,0.1,2.2250738585072014e-308]"
        );
    }

    #[test]
    fn key_order_does_not_change_output() {
        assert_eq!(
            canon(r#"{"b":[{"y":1,"x":2}],"a":"é"}"#),
            canon(r#"{"a":"é","b":[{"x":2,"y":1}]}"#)
        );
    }
}
