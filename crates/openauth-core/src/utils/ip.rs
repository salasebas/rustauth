use std::net::{IpAddr, Ipv6Addr};

/// IPv6 subnet prefix used for normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Subnet {
    Prefix32,
    Prefix48,
    Prefix64,
    Full,
}

impl Ipv6Subnet {
    const fn bits(self) -> u8 {
        match self {
            Self::Prefix32 => 32,
            Self::Prefix48 => 48,
            Self::Prefix64 => 64,
            Self::Full => 128,
        }
    }
}

/// Options for IP normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizeIpOptions {
    pub ipv6_subnet: Ipv6Subnet,
}

impl Default for NormalizeIpOptions {
    fn default() -> Self {
        Self {
            ipv6_subnet: Ipv6Subnet::Prefix64,
        }
    }
}

/// Returns true when the value is a valid IPv4 or IPv6 literal.
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Normalize an IP address for rate limiting using OpenAuth defaults.
pub fn normalize_ip(ip: &str) -> String {
    normalize_ip_with_options(ip, NormalizeIpOptions::default())
}

/// Normalize an IP address for rate limiting.
pub fn normalize_ip_with_options(ip: &str, options: NormalizeIpOptions) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.to_string(),
        Ok(IpAddr::V6(ip)) => normalize_ipv6(ip, options.ipv6_subnet),
        Err(_) => ip.to_ascii_lowercase(),
    }
}

/// Create a rate limit key from a normalized IP and request path.
pub fn create_rate_limit_key(ip: &str, path: &str) -> String {
    format!("{ip}|{path}")
}

/// Create a rate limit key with an additional opaque scope segment.
///
/// The suffix must not contain raw secrets (for example a challenge cookie value);
/// callers should pass a keyed digest such as [`hash_rate_limit_scope`].
pub fn create_rate_limit_key_with_suffix(ip: &str, path: &str, suffix: &str) -> String {
    format!("{}|{}", create_rate_limit_key(ip, path), suffix)
}

fn normalize_ipv6(ip: Ipv6Addr, subnet: Ipv6Subnet) -> String {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return mapped.to_string();
    }

    format_ipv6_segments(mask_ipv6_segments(ip.segments(), subnet.bits()))
}

fn mask_ipv6_segments(mut segments: [u16; 8], prefix_bits: u8) -> [u16; 8] {
    let mut bits_remaining = prefix_bits;

    for segment in &mut segments {
        if bits_remaining >= 16 {
            bits_remaining -= 16;
            continue;
        }

        if bits_remaining == 0 {
            *segment = 0;
            continue;
        }

        let mask = u16::MAX << (16 - bits_remaining);
        *segment &= mask;
        bits_remaining = 0;
    }

    segments
}

fn format_ipv6_segments(segments: [u16; 8]) -> String {
    segments
        .iter()
        .map(|segment| format!("{segment:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}
