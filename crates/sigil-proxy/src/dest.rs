//! Destination protection (PX-014, AC-08). The upstream host is resolved,
//! every RESOLVED address is checked, and the connection goes to a checked
//! address. The name is never resolved a second time for the same request, so
//! DNS cannot change between the check and the connect.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use crate::route::Upstream;

/// Name resolution hook. Production uses the system resolver; tests inject a
/// fixed table.
pub trait Resolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, port)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestError {
    /// Name did not resolve (or resolved to nothing).
    Unresolved,
    /// At least one resolved address is not allowed for this route.
    Refused(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    Loopback,
    /// 169.254.0.0/16 (includes cloud metadata 169.254.169.254) and fe80::/10.
    LinkLocal,
    /// fd00::/8 (includes the IPv6 metadata address of some clouds).
    UlaMetadata,
    /// RFC 1918, 100.64.0.0/10 CGNAT, fc00::/7 other than fd00::/8.
    Private,
    Public,
    /// Never a valid upstream: unspecified, multicast, broadcast, 0/8, 240/4.
    Never,
}

pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(a: Ipv4Addr) -> AddrClass {
    let o = a.octets();
    if a.is_unspecified() || a.is_broadcast() || a.is_multicast() || o[0] == 0 || o[0] >= 240 {
        AddrClass::Never
    } else if a.is_loopback() {
        AddrClass::Loopback
    } else if a.is_link_local() {
        AddrClass::LinkLocal
    } else if a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64) {
        AddrClass::Private
    } else {
        AddrClass::Public
    }
}

fn classify_v6(a: Ipv6Addr) -> AddrClass {
    let s = a.segments();
    if a.is_unspecified() || a.is_multicast() {
        AddrClass::Never
    } else if a.is_loopback() {
        AddrClass::Loopback
    } else if (s[0] & 0xffc0) == 0xfe80 {
        AddrClass::LinkLocal
    } else if (s[0] & 0xff00) == 0xfd00 {
        AddrClass::UlaMetadata
    } else if (s[0] & 0xfe00) == 0xfc00 {
        AddrClass::Private
    } else {
        AddrClass::Public
    }
}

/// Apply the route's destination policy to every resolved address.
///
/// - `http` upstream: every address must be loopback. (`normalize_origin` has
///   already limited http to loopback host NAMES at table build; this closes
///   the name-resolves-elsewhere gap.)
/// - `https` upstream: public addresses are allowed. Loopback and private
///   ranges need the route's explicit `allow_private` flag. Link-local, the
///   metadata range and fd00::/8 additionally need the address to be the
///   configured upstream host literal itself. Unspecified, multicast and
///   broadcast are never allowed.
// OPEN: contract text only says private destinations need an explicit
// management flag (control-plane.md §6.1); the literal-address rule for
// link-local/metadata is this slice's reading of "unless explicitly the
// configured upstream".
pub fn check_addresses(
    up: &Upstream,
    allow_private: bool,
    addrs: &[IpAddr],
) -> Result<Vec<SocketAddr>, DestError> {
    if addrs.is_empty() {
        return Err(DestError::Unresolved);
    }
    for ip in addrs {
        let class = classify(*ip);
        let ok = match (up.https, class) {
            (_, AddrClass::Never) => false,
            (false, AddrClass::Loopback) => true,
            (false, _) => false,
            (true, AddrClass::Public) => true,
            (true, AddrClass::Loopback | AddrClass::Private) => allow_private,
            (true, AddrClass::LinkLocal | AddrClass::UlaMetadata) => {
                allow_private && up.host_literal == Some(*ip)
            }
        };
        if !ok {
            return Err(DestError::Refused(match class {
                AddrClass::Loopback => "loopback",
                AddrClass::LinkLocal => "link-local",
                AddrClass::UlaMetadata => "ula-metadata",
                AddrClass::Private => "private",
                AddrClass::Public => "public-on-http",
                AddrClass::Never => "never-allowed",
            }));
        }
    }
    Ok(addrs
        .iter()
        .map(|ip| SocketAddr::new(*ip, up.port))
        .collect())
}

/// Resolve (an IP literal skips DNS) and check. One resolution per request.
pub async fn resolve_checked(
    resolver: &dyn Resolver,
    up: &Upstream,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, DestError> {
    let addrs = match up.host_literal {
        Some(ip) => vec![ip],
        None => resolver
            .resolve(&up.host, up.port)
            .await
            .map_err(|_| DestError::Unresolved)?,
    };
    check_addresses(up, allow_private, &addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(https: bool, lit: Option<&str>) -> Upstream {
        Upstream {
            https,
            host: "h".into(),
            port: 443,
            path: "/".into(),
            host_literal: lit.map(|s| s.parse().unwrap()),
            host_header: "h".into(),
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classification_table() {
        use AddrClass::*;
        for (a, c) in [
            ("127.0.0.1", Loopback),
            ("127.9.9.9", Loopback),
            ("::1", Loopback),
            ("::ffff:127.0.0.1", Loopback),
            ("169.254.169.254", LinkLocal),
            ("169.254.0.1", LinkLocal),
            ("fe80::1", LinkLocal),
            ("::ffff:169.254.169.254", LinkLocal),
            ("fd00:ec2::254", UlaMetadata),
            ("fc00::1", Private),
            ("10.1.2.3", Private),
            ("172.16.0.1", Private),
            ("172.32.0.1", Public),
            ("192.168.1.1", Private),
            ("100.64.0.1", Private),
            ("100.128.0.1", Public),
            ("8.8.8.8", Public),
            ("2606:4700::1111", Public),
            ("0.0.0.0", Never),
            ("::", Never),
            ("224.0.0.1", Never),
            ("255.255.255.255", Never),
            ("ff02::1", Never),
        ] {
            assert_eq!(classify(ip(a)), c, "{a}");
        }
    }

    /// AC-08: an http upstream resolving to anything but loopback is refused,
    /// including a mixed answer.
    #[test]
    fn http_requires_all_loopback() {
        let u = up(false, None);
        assert!(check_addresses(&u, false, &[ip("127.0.0.1")]).is_ok());
        assert!(check_addresses(&u, false, &[ip("::1"), ip("127.0.0.2")]).is_ok());
        for bad in ["10.0.0.5", "8.8.8.8", "169.254.169.254", "0.0.0.0"] {
            assert!(check_addresses(&u, false, &[ip(bad)]).is_err(), "{bad}");
            assert!(check_addresses(&u, true, &[ip(bad)]).is_err(), "{bad} flag");
            assert!(
                check_addresses(&u, false, &[ip("127.0.0.1"), ip(bad)]).is_err(),
                "mixed {bad}"
            );
        }
        assert_eq!(check_addresses(&u, false, &[]), Err(DestError::Unresolved));
    }

    /// AC-08: https destinations. Private needs the flag; link-local/metadata
    /// also need to be the literal configured host; some ranges never pass.
    #[test]
    fn https_policy() {
        let u = up(true, None);
        assert!(check_addresses(&u, false, &[ip("8.8.8.8")]).is_ok());
        for a in ["10.0.0.5", "127.0.0.1", "192.168.0.1", "fc00::1"] {
            assert!(check_addresses(&u, false, &[ip(a)]).is_err(), "{a}");
            assert!(check_addresses(&u, true, &[ip(a)]).is_ok(), "{a} flag");
        }
        for a in ["169.254.169.254", "fe80::1", "fd00:ec2::254"] {
            assert!(check_addresses(&u, false, &[ip(a)]).is_err(), "{a}");
            assert!(
                check_addresses(&u, true, &[ip(a)]).is_err(),
                "{a} flag, name-resolved"
            );
            let lit = up(true, Some(a));
            assert!(
                check_addresses(&lit, false, &[ip(a)]).is_err(),
                "{a} literal, no flag"
            );
            assert!(
                check_addresses(&lit, true, &[ip(a)]).is_ok(),
                "{a} literal+flag"
            );
        }
        // a name that resolves to metadata is refused even with a literal-less flag route
        assert!(check_addresses(&u, true, &[ip("8.8.8.8"), ip("169.254.169.254")]).is_err());
        for a in ["0.0.0.0", "224.0.0.1", "ff02::1"] {
            assert!(
                check_addresses(&up(true, Some(a)), true, &[ip(a)]).is_err(),
                "{a}"
            );
        }
    }

    #[test]
    fn checked_addresses_carry_the_upstream_port() {
        let u = up(true, None);
        let v = check_addresses(&u, false, &[ip("8.8.8.8")]).unwrap();
        assert_eq!(v, vec!["8.8.8.8:443".parse::<SocketAddr>().unwrap()]);
    }
}
