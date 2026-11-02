//! Strip credentials from a URL before it is reported or logged.

/// Longest DNS name (RFC 1035); anything longer is not a host we can report.
const MAX_HOST_LEN: usize = 253;

/// `scheme://host[:port]` or `host[:port]`. `None` when the authority fails
/// validation, which is what stops an unencoded `/` in a password: the authority
/// then ends inside the userinfo, so what is left is not a host and port.
pub fn redact_url(raw: &str) -> Option<String> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => (Some(scheme), rest),
        _ => (None, raw),
    };
    // WHATWG parsers end the authority at `\` too, so `h\@evil` connects to `h`.
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if !is_host_port(host_port) {
        return None;
    }
    Some(scheme.map_or(host_port.to_string(), |s| format!("{s}://{host_port}")))
}

/// True when `raw` starts with `scheme://`, whether or not the rest parses.
pub fn has_url_scheme(raw: &str) -> bool {
    raw.split_once("://")
        .is_some_and(|(scheme, _)| is_scheme(scheme))
}

fn is_scheme(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_alphabetic())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

fn is_host_port(text: &str) -> bool {
    let (host, port) = match text.rsplit_once(':') {
        // The colon of a bracketed IPv6 literal with no port.
        Some((_, tail)) if tail.ends_with(']') => (text, None),
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(ip) => ip.parse::<std::net::Ipv6Addr>().is_ok(),
        None => {
            !host.is_empty()
                && host.len() <= MAX_HOST_LEN
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
    };
    host_ok
        && port.is_none_or(|p| p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    #[test]
    fn keeps_only_scheme_host_and_port() {
        let long_host = "a".repeat(254);
        let long_url = format!("https://{long_host}/x");
        let max_host = format!("https://{}", "a".repeat(253));
        for (raw, want) in [
            ("[::1]:8080", Some("[::1]:8080")),
            ("https://[::1]/p", Some("https://[::1]")),
            ("ws://u:p@h:9/p", Some("ws://h:9")),
            ("https://u%40x:p%2Fq@h.example/p", Some("https://h.example")),
            ("https://u:p@w@h.example/p", Some("https://h.example")),
            ("u:p@w@h.example", Some("h.example")),
            // WHATWG: `\` ends the authority, so the real host is `h.example`.
            (
                "https://h.example\\@evil.example/x",
                Some("https://h.example"),
            ),
            ("https://u:pw\\x@h.example/", None),
            (
                "https://h.example?u:p@evil.example",
                Some("https://h.example"),
            ),
            (
                "https://h.example#u:p@evil.example",
                Some("https://h.example"),
            ),
            ("", None),
            ("https://", None),
            ("https://h.example:", None),
            ("https://h.example:99999", None),
            ("https://h.example:+80", None),
            // IDN hosts are not punycode-encoded here; they are reported as unparseable.
            ("https://münchen.de", None),
            (long_url.as_str(), None),
            (max_host.as_str(), Some(max_host.as_str())),
        ] {
            assert_eq!(redact_url(raw).as_deref(), want, "{raw}");
        }
    }
}
