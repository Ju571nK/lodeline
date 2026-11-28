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
    /// Always refused, including unspecified, multicast, broadcast and shared-range metadata.
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
    if o == [100, 100, 100, 200] // Cloud metadata in the shared IPv4 range.
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || o[0] == 0
        || o[0] >= 240
    {
        AddrClass::Never
    } else if a.is_loopback() {
        AddrClass::Loopback
    } else if a.is_link_local() {
        AddrClass::LinkLocal
    } else if a.is_private()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
    // 198.18.0.0/15 benchmarking
    {
        AddrClass::Private
    } else {
        AddrClass::Public
    }
}

fn classify_v6(a: Ipv6Addr) -> AddrClass {
    let s = a.segments();
    let v4_from =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if a.is_unspecified() || a.is_multicast() {
        AddrClass::Never
    } else if a.is_loopback() {
        AddrClass::Loopback
    } else if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        // NAT64 64:ff9b::/96: the embedded IPv4 decides.
        classify_v4(v4_from(s[6], s[7]))
    } else if s[0] == 0x2002 {
        // 6to4 2002::/16: the embedded IPv4 decides.
        classify_v4(v4_from(s[1], s[2]))
    } else if s[..6] == [0, 0, 0, 0, 0, 0] {
        // IPv4-compatible ::/96 (deprecated): the embedded IPv4 decides.
        classify_v4(v4_from(s[6], s[7]))
    } else if (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1) // 64:ff9b:1::/48 local-use NAT64
        || (s[0] == 0x2001 && s[1] == 0) // 2001::/32 Teredo
        || (s[0] == 0x2001 && s[1] == 0x0db8)
    // 2001:db8::/32 documentation
    {
        AddrClass::Never
    } else if (s[0] & 0xffc0) == 0xfe80 {
        AddrClass::LinkLocal
    } else if (s[0] & 0xffc0) == 0xfec0 {
        AddrClass::Private // fec0::/10 deprecated site-local
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
/// - `https` upstream: public addresses are allowed. Private addresses need
///   the route's `allow_private` flag. Loopback, link-local, cloud metadata
///   (including fd00::/8), unspecified, multicast and broadcast are refused
///   for either flag value.
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
            (false, AddrClass::Loopback) | (true, AddrClass::Public) => true,
            (true, AddrClass::Private) => allow_private,
            _ => false,
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
            ("192.0.0.1", Private),
            ("192.0.1.1", Public),
            ("198.18.0.1", Private),
            ("198.19.255.255", Private),
            ("198.20.0.1", Public),
            // NAT64 / 6to4 / IPv4-compatible: the embedded v4 decides
            ("64:ff9b::7f00:1", Loopback),
            ("64:ff9b::a9fe:a9fe", LinkLocal),
            ("64:ff9b::a00:5", Private),
            ("64:ff9b::808:808", Public),
            ("2002:7f00:1::", Loopback),
            ("2002:a9fe:a9fe::1", LinkLocal),
            ("2002:0a00:0005::1", Private),
            ("2002:0808:0808::1", Public),
            ("::7f00:1", Loopback),
            ("::a9fe:a9fe", LinkLocal),
            ("::a00:5", Private),
            ("::808:808", Public),
            ("64:ff9b:1::1", Never),
            ("2001::1", Never),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Never),
            ("2001:db8::1", Never),
            ("fec0::1", Private),
            ("2001:4860:4860::8888", Public),
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
        let loopbacks = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
        assert!(check_addresses(&u, true, &loopbacks).is_ok());
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

    #[test]
    fn https_policy() {
        let u = up(true, None);
        assert!(check_addresses(&u, false, &[ip("8.8.8.8")]).is_ok());
        assert!(check_addresses(&u, true, &[ip("203.0.113.1")]).is_ok());
        let private = Ipv4Addr::new(10, 0, 0, 5);
        for a in [
            private.into(),
            Ipv4Addr::new(192, 168, 0, 1).into(),
            Ipv4Addr::new(100, 64, 0, 1).into(),
            private.to_ipv6_mapped().into(),
            ip("fc00::1"),
        ] {
            assert_eq!(
                check_addresses(&u, false, &[a]),
                Err(DestError::Refused("private")),
                "{a}"
            );
            assert!(check_addresses(&u, true, &[a]).is_ok(), "{a} flag");
        }
        // a name that resolves to metadata is refused even with a literal-less flag route
        assert!(check_addresses(&u, true, &[ip("8.8.8.8"), ip("169.254.169.254")]).is_err());
    }

    fn assert_https_refuses(addresses: &[IpAddr], reason: &'static str) {
        for &addr in addresses {
            let literal = addr.to_string();
            for host_literal in [None, Some(literal.as_str())] {
                for allow_private in [true, false] {
                    assert_eq!(
                        check_addresses(&up(true, host_literal), allow_private, &[addr]),
                        Err(DestError::Refused(reason)),
                        "{addr} literal={host_literal:?} allow_private={allow_private}"
                    );
                }
            }
        }
    }

    #[test]
    fn https_refuses_loopback_even_with_private_opt_in() {
        assert_https_refuses(
            &[
                Ipv4Addr::LOCALHOST.into(),
                Ipv6Addr::LOCALHOST.into(),
                Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
            ],
            "loopback",
        );
    }

    #[test]
    fn https_refuses_link_local_even_with_private_opt_in() {
        let metadata = Ipv4Addr::new(169, 254, 169, 254);
        assert_https_refuses(
            &[
                metadata.into(),
                ip("fe80::1"),
                metadata.to_ipv6_mapped().into(),
            ],
            "link-local",
        );
    }

    #[test]
    fn https_refuses_fd00_range_even_with_private_opt_in() {
        assert_https_refuses(&[ip("fd00:ec2::254"), ip("fd7a::1")], "ula-metadata");
    }

    #[test]
    fn https_refuses_shared_range_metadata_even_with_private_opt_in() {
        let metadata: Ipv4Addr = "100.100.100.200".parse().unwrap();
        assert_https_refuses(
            &[
                metadata.into(),
                metadata.to_ipv6_mapped().into(),
                ip(&format!("64:ff9b::{metadata}")),
                ip("2002:6464:64c8::1"),
                ip(&format!("::{metadata}")),
            ],
            "never-allowed",
        );
    }

    #[test]
    fn https_refuses_never_allowed_addresses_even_with_private_opt_in() {
        assert_https_refuses(
            &[
                Ipv4Addr::UNSPECIFIED.into(),
                Ipv6Addr::UNSPECIFIED.into(),
                Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().into(),
                Ipv4Addr::new(224, 0, 0, 1).into(),
                ip("ff02::1"),
            ],
            "never-allowed",
        );
    }

    #[test]
    fn checked_addresses_carry_the_upstream_port() {
        let u = up(true, None);
        let v = check_addresses(&u, false, &[ip("8.8.8.8")]).unwrap();
        assert_eq!(v, vec!["8.8.8.8:443".parse::<SocketAddr>().unwrap()]);
    }
}
