//! Strip credentials from a URL before it is reported or logged.

/// `scheme://host[:port]` or `host[:port]`. `None` when the authority fails
/// validation, which is what stops an unencoded `/` in a password: the authority
/// then ends inside the userinfo, so what is left is not a host and port.
pub fn redact_url(raw: &str) -> Option<String> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => (Some(scheme), rest),
        _ => (None, raw),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if !is_host_port(host_port) {
        return None;
    }
    Some(scheme.map_or(host_port.to_string(), |s| format!("{s}://{host_port}")))
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
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
    };
    host_ok && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}
