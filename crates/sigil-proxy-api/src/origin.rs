//! Origin and upstream-URL rules shared by the proxy and the server.
//!
//! [`normalize_origin`] has the SAME rules as `sigil_proxy::bootstrap::normalize_origin`
//! (decisions.md "P0 종료": default ports dropped, `http` only for loopback,
//! lowercase, no path, query, fragment or userinfo). `sigil-proxy` re-exports this
//! function as `bootstrap::normalize_origin`, so there is one implementation.
//!
//! [`parse_upstream_url`] adds the config-PUT rules of control-plane.md §6.1 (M-6)
//! and a literal-address SSRF screen (PX-014). The SSRF screen is a rule on the
//! URL string. It does not resolve DNS: a host name that resolves to a private
//! address passes here and is checked by the proxy at apply and per request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest accepted `upstream_url`.
pub const MAX_UPSTREAM_URL_LEN: usize = 2048;

/// `scheme://host[:port]` in canonical form, see the module docs.
pub fn normalize_origin(s: &str) -> Result<String, String> {
    let (scheme, rest) = s
        .split_once("://")
        .ok_or("origin must be scheme://host[:port]")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("origin scheme must be http or https".into());
    }
    if rest.contains(['/', '?', '#']) {
        return Err("origin must not contain a path, query or fragment".into());
    }
    let (host, port) = split_host_port(rest)?;
    if scheme == "http" && !is_loopback_host(&host) {
        return Err("http:// origins are allowed only for loopback hosts".into());
    }
    let default_port = if scheme == "http" { 80 } else { 443 };
    Ok(match port {
        Some(p) if p != default_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    })
}

pub fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    if authority.is_empty() {
        return Err("empty host".into());
    }
    if authority.contains('@') {
        return Err("userinfo is not allowed".into());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or("unterminated IPv6 literal")?;
        let host = &rest[..end];
        host.parse::<Ipv6Addr>()
            .map_err(|_| "invalid IPv6 literal")?;
        let after = &rest[end + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or("invalid authority")?),
        };
        (format!("[{}]", host.to_ascii_lowercase()), port)
    } else {
        let (h, p) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || h.starts_with(['.', '-'])
            || h.ends_with(['.', '-'])
        {
            return Err("invalid host".into());
        }
        (h.to_ascii_lowercase(), p)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid port".into());
            }
            let n: u16 = p.parse().map_err(|_| "invalid port")?;
            if n == 0 {
                return Err("invalid port".into());
            }
            Some(n)
        }
    };
    Ok((host, port))
}

/// Loopback host: 127.0.0.0/8, `::1` (bracketed) or `localhost`.
pub fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<Ipv6Addr>().is_ok_and(|a| a.is_loopback());
    }
    host.parse::<Ipv4Addr>().is_ok_and(|a| a.is_loopback())
}

/// A validated upstream URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUrl {
    /// Canonical origin (see [`normalize_origin`]).
    pub origin: String,
    /// Path including the leading `/`, or empty.
    pub path: String,
}

/// Validates an `upstream_url`: https, or http to loopback only; no userinfo,
/// query or fragment; no literal private/link-local/metadata address; no
/// numeric host spelling that a resolver would read as an address.
///
/// Error texts are fixed and never contain the input.
pub fn parse_upstream_url(s: &str) -> Result<UpstreamUrl, String> {
    if s.is_empty() || s.len() > MAX_UPSTREAM_URL_LEN {
        return Err("upstream_url length out of range".into());
    }
    if s.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\') {
        return Err("upstream_url contains a forbidden character".into());
    }
    if s.contains('?') || s.contains('#') {
        return Err("upstream_url must not contain a query or fragment".into());
    }
    let (scheme, rest) = s
        .split_once("://")
        .ok_or("upstream_url must be scheme://host[:port][/path]")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return Err("upstream_url must not contain userinfo".into());
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("upstream_url path must not contain dot segments".into());
    }
    let origin = normalize_origin(&format!("{scheme}://{authority}"))?;
    let (host, _) = split_host_port(authority)?;
    screen_host(&host)?;
    Ok(UpstreamUrl {
        origin,
        path: path.to_string(),
    })
}

/// Rejects literal addresses that are not a public or loopback destination, and
/// numeric spellings (`2130706433`, `0x7f.1`, `127.1`) that only a lenient
/// resolver would read as an address.
fn screen_host(host: &str) -> Result<(), String> {
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip: Ipv6Addr = v6.parse().map_err(|_| "invalid IPv6 literal")?;
        return screen_ip(IpAddr::V6(ip));
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return screen_ip(IpAddr::V4(ip));
    }
    let last = host.rsplit('.').next().unwrap_or("");
    let numeric_tail = !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit());
    if numeric_tail || last.starts_with("0x") {
        return Err("host looks like a non-canonical IP address".into());
    }
    Ok(())
}

fn screen_ip(ip: IpAddr) -> Result<(), String> {
    let blocked = match ip {
        IpAddr::V4(a) => blocked_v4(a),
        IpAddr::V6(a) => {
            if let Some(m) = a.to_ipv4_mapped() {
                blocked_v4(m)
            } else {
                let s = a.segments();
                a.is_unspecified()
                    || a.is_multicast()
                    || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                    || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                    || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                    || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64
            }
        }
    };
    if blocked {
        Err("upstream address is not a permitted destination".into())
    } else {
        Ok(())
    }
}

fn blocked_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    if a.is_loopback() {
        return false;
    }
    a.is_unspecified()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 shared address space
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || o[0] >= 240
}

#[cfg(test)]
mod tests {
    use super::*;

    // Copied from sigil-proxy bootstrap.rs `upstream_origin_shape`.
    #[test]
    fn upstream_origin_shape() {
        for ok in [
            "https://api.example.com",
            "http://127.0.0.1:9000",
            "https://[::1]:8443",
        ] {
            assert!(normalize_origin(ok).is_ok(), "{ok}");
        }
        for (input, want) in [
            ("HTTPS://API.Example.com:443", "https://api.example.com"),
            ("https://api.example.com", "https://api.example.com"),
            (
                "https://api.example.com:8443",
                "https://api.example.com:8443",
            ),
            ("http://127.0.0.1:80", "http://127.0.0.1"),
            ("http://localhost:8080", "http://localhost:8080"),
            ("http://LOCALHOST", "http://localhost"),
            ("http://[::1]:80", "http://[::1]"),
            ("https://[::1]:443", "https://[::1]"),
            ("http://127.5.5.5:9", "http://127.5.5.5:9"),
        ] {
            assert_eq!(normalize_origin(input).unwrap(), want, "{input}");
        }
        assert_eq!(
            normalize_origin("https://a.example:443"),
            normalize_origin("https://a.example")
        );
        for bad in [
            "http://api.example.com",
            "http://192.0.2.1",
            "http://10.0.0.1:80",
            "http://[2001:db8::1]",
            "http://localhost.example.com",
            "http://128.0.0.1",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
        for bad in [
            "https://api.example.com/",
            "https://api.example.com/path",
            "https://api.example.com?x=1",
            "https://api.example.com#f",
            "https://user:pw@api.example.com",
            "https://user@api.example.com",
            "ftp://api.example.com",
            "api.example.com",
            "https://",
            "https://api.example.com:",
            "https://api.example.com:0",
            "https://api.example.com:99999",
            "https://exa mple.com",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn upstream_url_accepts_and_canonicalises() {
        let u = parse_upstream_url("HTTPS://Api.Example.com:443/mcp/v1").unwrap();
        assert_eq!(u.origin, "https://api.example.com");
        assert_eq!(u.path, "/mcp/v1");
        let u = parse_upstream_url("http://127.0.0.1:9000").unwrap();
        assert_eq!(
            (u.origin.as_str(), u.path.as_str()),
            ("http://127.0.0.1:9000", "")
        );
        assert!(parse_upstream_url("http://localhost/x").is_ok());
        assert!(parse_upstream_url("https://[::1]:8443/x").is_ok());
        assert!(parse_upstream_url("https://203.0.114.1/x").is_ok());
    }

    #[test]
    fn upstream_url_rejections() {
        for bad in [
            "",
            "api.example.com/x",
            "ftp://api.example.com/x",
            "http://api.example.com/x",
            "http://10.0.0.1/x",
            "https://user:pw@api.example.com/x",
            "https://user@api.example.com/x",
            "https://api.example.com/x?token=1",
            "https://api.example.com/x#frag",
            "https://api.example.com?x",
            "https://api.example.com/a/../b",
            "https://api.example.com/./b",
            "https://api.example.com/a b",
            "https://api.example.com\\x",
            "https://api.example.com:0/x",
            // literal private, link-local, metadata, reserved
            "https://10.1.2.3/x",
            "https://172.16.0.1/x",
            "https://192.168.1.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/x",
            "https://0.0.0.0/x",
            "https://224.0.0.1/x",
            "https://255.255.255.255/x",
            "https://[fd00::1]/x",
            "https://[fe80::1]/x",
            "https://[::]/x",
            "https://[::ffff:10.0.0.1]/x",
            "https://[::ffff:169.254.169.254]/x",
            "https://[64:ff9b::a00:1]/x",
            // numeric spellings
            "https://2130706433/x",
            "https://0x7f000001/x",
            "https://127.1/x",
            "https://0177.0.0.1/x",
        ] {
            assert!(parse_upstream_url(bad).is_err(), "{bad}");
        }
        let long = format!("https://a.example/{}", "a".repeat(MAX_UPSTREAM_URL_LEN));
        assert!(parse_upstream_url(&long).is_err());
    }

    #[test]
    fn error_text_never_echoes_input() {
        for bad in [
            "https://user:SECRETPW@a.example/x",
            "https://a.example/x?token=SECRETTOKEN",
            "https://10.9.9.9/SECRETPATH",
        ] {
            let e = parse_upstream_url(bad).unwrap_err();
            assert!(!e.contains("SECRET") && !e.contains("10.9.9.9"), "{e}");
        }
    }
}
