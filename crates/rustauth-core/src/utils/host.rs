use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Network classification used for security-sensitive host checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Public,
    Localhost,
    Loopback,
    Private,
    LinkLocal,
    CloudMetadata,
    Documentation,
    SharedAddressSpace,
    Benchmarking,
    Multicast,
    Broadcast,
    Unspecified,
    Reserved,
}

/// Literal shape of the normalized host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLiteral {
    Ipv4,
    Ipv6,
    Fqdn,
}

/// Result of normalizing and classifying a host value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostClassification {
    pub original: String,
    pub canonical: String,
    pub literal: HostLiteral,
    pub kind: HostKind,
}

/// Normalize and classify a host or host:port string.
pub fn classify_host(host: &str) -> HostClassification {
    let original = host.to_owned();
    let canonical = normalize_host(host);

    if canonical.is_empty() {
        return HostClassification {
            original,
            canonical,
            literal: HostLiteral::Fqdn,
            kind: HostKind::Reserved,
        };
    }

    if let Ok(ip) = canonical.parse::<IpAddr>() {
        return classify_ip(original, ip);
    }

    let kind = classify_domain(&canonical);
    HostClassification {
        original,
        canonical,
        literal: HostLiteral::Fqdn,
        kind,
    }
}

/// Returns true only for loopback IP literals.
pub fn is_loopback_ip(host: &str) -> bool {
    let classification = classify_host(host);
    matches!(
        classification.literal,
        HostLiteral::Ipv4 | HostLiteral::Ipv6
    ) && classification.kind == HostKind::Loopback
}

/// Returns true for localhost names and loopback IP literals.
pub fn is_loopback_host(host: &str) -> bool {
    matches!(
        classify_host(host).kind,
        HostKind::Localhost | HostKind::Loopback
    )
}

/// Returns true only when the host is structurally valid and publicly routable.
pub fn is_public_routable_host(host: &str) -> bool {
    classify_host(host).kind == HostKind::Public
}

fn normalize_host(host: &str) -> String {
    let mut value = host.trim().to_ascii_lowercase();
    if value.is_empty() {
        return value;
    }

    if let Some(stripped) = value
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        value = stripped.0.to_owned();
    } else if value.matches(':').count() == 1 {
        if let Some((without_port, port)) = value.rsplit_once(':') {
            if !without_port.is_empty() && port.chars().all(|character| character.is_ascii_digit())
            {
                value = without_port.to_owned();
            }
        }
    }

    if let Some((without_zone, _)) = value.split_once('%') {
        value = without_zone.to_owned();
    }

    value.trim_end_matches('.').to_owned()
}

fn classify_ip(original: String, ip: IpAddr) -> HostClassification {
    match ip {
        IpAddr::V4(ip) => HostClassification {
            original,
            canonical: ip.to_string(),
            literal: HostLiteral::Ipv4,
            kind: classify_ipv4(ip),
        },
        IpAddr::V6(ip) => HostClassification {
            original,
            canonical: ip.to_string(),
            literal: HostLiteral::Ipv6,
            kind: classify_ipv6(ip),
        },
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> HostKind {
    let octets = ip.octets();

    if ip.is_loopback() {
        HostKind::Loopback
    } else if ip.is_unspecified() {
        HostKind::Unspecified
    } else if ip == Ipv4Addr::BROADCAST {
        HostKind::Broadcast
    } else if ip.is_private() {
        HostKind::Private
    } else if ip.is_link_local() {
        HostKind::LinkLocal
    } else if ip.is_documentation() {
        HostKind::Documentation
    } else if ip.is_multicast() {
        HostKind::Multicast
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        HostKind::SharedAddressSpace
    } else if octets[0] == 198 && matches!(octets[1], 18 | 19) {
        HostKind::Benchmarking
    } else if octets[0] == 0 || octets[0] >= 240 {
        HostKind::Reserved
    } else {
        HostKind::Public
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> HostKind {
    let segments = ip.segments();
    let first_segment = segments[0];

    if ip.is_loopback() {
        HostKind::Loopback
    } else if ip.is_unspecified() {
        HostKind::Unspecified
    } else if ip.is_multicast() {
        HostKind::Multicast
    } else if (first_segment & 0xfe00) == 0xfc00 {
        HostKind::Private
    } else if (first_segment & 0xffc0) == 0xfe80 {
        HostKind::LinkLocal
    } else if first_segment == 0x2001 && segments[1] == 0x0db8 {
        HostKind::Documentation
    } else {
        HostKind::Public
    }
}

fn classify_domain(host: &str) -> HostKind {
    if host == "localhost" || host.ends_with(".localhost") {
        HostKind::Localhost
    } else if matches!(
        host,
        "metadata.google.internal"
            | "metadata.goog"
            | "instance-data.ec2.internal"
            | "169.254.169.254"
    ) {
        HostKind::CloudMetadata
    } else {
        HostKind::Public
    }
}
