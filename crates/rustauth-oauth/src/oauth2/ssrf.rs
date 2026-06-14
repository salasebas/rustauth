//! SSRF protection for outbound OAuth/OIDC HTTP requests.
//!
//! OIDC SSO providers can be registered with manual, attacker-influenced
//! endpoint URLs (`tokenEndpoint`, `jwksEndpoint`, `userInfoEndpoint`,
//! discovery). Without a guard, the server can be coerced into issuing requests
//! to internal addresses such as cloud metadata services
//! (`169.254.169.254`), loopback admin APIs, or private network services.
//!
//! The protection is layered because `reqwest` only routes hostnames through a
//! custom DNS resolver; literal IP URLs (for example `http://169.254.169.254/`)
//! connect directly without resolution:
//!
//! * [`SsrfGuardResolver`] rejects hostnames that resolve to non-public
//!   addresses. Filtering happens at connection time on the resolved addresses,
//!   so a hostname cannot bypass the guard by rebinding to a public address
//!   during validation and an internal address at connection time.
//! * [`ssrf_guarded_client_builder`] additionally installs a redirect policy
//!   that refuses to follow redirects whose target host is a blocked literal
//!   IP (hostname redirect targets are re-checked by the resolver).
//! * [`url_host_is_blocked_ip`] lets request boundaries reject an initial URL
//!   whose host is already a blocked literal IP, closing the literal-IP gap the
//!   resolver cannot see.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect;
use url::{Host, Url};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const MAX_REDIRECTS: usize = 10;

/// Returns `true` when `ip` must not be the target of an outbound request
/// because it is not a routable public address.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_blocked_ipv4(ip),
        IpAddr::V6(ip) => {
            // IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`)
            // addresses must be classified by their embedded IPv4 address.
            if let Some(embedded) = ip.to_ipv4() {
                if is_blocked_ipv4(embedded) {
                    return true;
                }
            }
            is_blocked_ipv6(ip)
        }
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback() // 127.0.0.0/8
        || ip.is_private() // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local() // 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
        || ip.is_broadcast() // 255.255.255.255
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_unspecified() // 0.0.0.0
        // 0.0.0.0/8 "this network" (RFC 1122)
        || octets[0] == 0
        // 100.64.0.0/10 carrier-grade NAT (RFC 6598)
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        // 198.18.0.0/15 benchmarking (RFC 2544)
        || (octets[0] == 198 && (octets[1] & 0b1111_1110) == 18)
        // 240.0.0.0/4 reserved for future use (RFC 1112)
        || octets[0] >= 240
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback() // ::1
        || ip.is_unspecified() // ::
        // fc00::/7 unique local addresses
        || (segments[0] & 0xfe00) == 0xfc00
        // fe80::/10 link-local unicast
        || (segments[0] & 0xffc0) == 0xfe80
        // 2001:db8::/32 documentation
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

/// A `reqwest` DNS resolver that drops resolved addresses pointing at private
/// or otherwise non-public IPs, failing closed when nothing public remains.
#[derive(Debug, Clone, Default)]
pub struct SsrfGuardResolver;

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let resolved = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0_u16)
                    .to_socket_addrs()
                    .map(|addresses| addresses.collect::<Vec<_>>())
            })
            .await
            .map_err(|error| Box::new(error) as BoxError)?
            .map_err(|error| Box::new(error) as BoxError)?;

            let allowed: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|address| !is_blocked_ip(address.ip()))
                .collect();

            if allowed.is_empty() {
                return Err(BoxError::from(
                    "refusing to connect: host resolves only to private or internal IP addresses",
                ));
            }

            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// Returns `true` when `url`'s host is a literal IP address that is blocked.
///
/// Returns `false` for hostnames (which the DNS resolver enforces at connection
/// time) and for URLs that cannot be parsed or have no host. Use this at
/// outbound request boundaries to reject an initial URL that already points at
/// a private or internal IP, since `reqwest` does not run such URLs through the
/// custom DNS resolver.
pub fn url_host_is_blocked_ip(url: &str) -> bool {
    Url::parse(url)
        .ok()
        .is_some_and(|url| url_target_is_blocked_ip(&url))
}

fn url_target_is_blocked_ip(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => is_blocked_ip(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => is_blocked_ip(IpAddr::V6(ip)),
        _ => false,
    }
}

/// Builds a `reqwest::ClientBuilder` that mitigates SSRF by blocking private and
/// otherwise non-public IP addresses during DNS resolution and refusing
/// redirects to blocked literal IPs.
pub fn ssrf_guarded_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(SsrfGuardResolver))
        .redirect(redirect::Policy::custom(|attempt| {
            if url_target_is_blocked_ip(attempt.url()) {
                attempt.error(BoxError::from(
                    "refusing to follow redirect to a private or internal IP address",
                ))
            } else if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error(BoxError::from("too many redirects"))
            } else {
                attempt.follow()
            }
        }))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn blocks_private_and_internal_ipv4_ranges() -> Result<(), std::net::AddrParseError> {
        for address in [
            "127.0.0.1",
            "127.10.20.30",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // carrier-grade NAT
            "192.0.0.1",       // IETF protocol assignments
            "198.18.0.1",      // benchmarking
            "240.0.0.1",       // reserved
            "0.0.0.0",
            "255.255.255.255",
        ] {
            let ip = IpAddr::V4(address.parse::<Ipv4Addr>()?);
            assert!(is_blocked_ip(ip), "expected {address} blocked");
        }
        Ok(())
    }

    #[test]
    fn allows_public_ipv4_addresses() -> Result<(), std::net::AddrParseError> {
        for address in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "203.0.114.1"] {
            let ip = IpAddr::V4(address.parse::<Ipv4Addr>()?);
            assert!(!is_blocked_ip(ip), "expected {address} allowed");
        }
        Ok(())
    }

    #[test]
    fn blocks_private_and_internal_ipv6_ranges() -> Result<(), std::net::AddrParseError> {
        for address in [
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
            "::ffff:10.0.0.1",  // IPv4-mapped private
        ] {
            let ip = IpAddr::V6(address.parse::<Ipv6Addr>()?);
            assert!(is_blocked_ip(ip), "expected {address} blocked");
        }
        Ok(())
    }

    #[test]
    fn allows_public_ipv6_addresses() -> Result<(), std::net::AddrParseError> {
        for address in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let ip = IpAddr::V6(address.parse::<Ipv6Addr>()?);
            assert!(!is_blocked_ip(ip), "expected {address} allowed");
        }
        Ok(())
    }

    #[test]
    fn url_host_check_blocks_literal_private_ips_only() {
        for url in [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5:8443/token",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://0.0.0.0/",
        ] {
            assert!(url_host_is_blocked_ip(url), "expected {url} blocked");
        }
        for url in [
            "https://idp.example.com/.well-known/openid-configuration",
            "http://1.1.1.1/",
            "https://[2606:4700:4700::1111]/",
            "not a url",
        ] {
            assert!(!url_host_is_blocked_ip(url), "expected {url} allowed");
        }
    }

    #[tokio::test]
    async fn resolver_blocks_hostnames_that_resolve_to_loopback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // `localhost` resolves only to loopback addresses, so the guard must
        // refuse to hand back any socket address.
        let resolved = SsrfGuardResolver
            .resolve(Name::from_str("localhost")?)
            .await;
        assert!(
            resolved.is_err(),
            "expected localhost resolution to be refused"
        );
        Ok(())
    }

    #[tokio::test]
    async fn guarded_client_refuses_redirect_to_literal_private_ip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The server redirects to a loopback literal IP. The guarded client must
        // refuse to follow it even though the initial host is also loopback;
        // here we use a permissive initial connection and assert the redirect is
        // what fails by inspecting the error.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 256];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
                    let response = "HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let client = ssrf_guarded_client_builder().build()?;
        let error = match client.get(format!("http://{address}/")).send().await {
            Ok(_) => return Err("expected redirect to private IP to be refused".into()),
            Err(error) => error,
        };
        assert!(
            error.is_redirect() || error.to_string().contains("redirect"),
            "unexpected error: {error}"
        );
        Ok(())
    }
}
