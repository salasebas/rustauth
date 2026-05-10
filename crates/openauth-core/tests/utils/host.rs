use openauth_core::utils::host::{
    classify_host, is_loopback_host, is_loopback_ip, is_public_routable_host, HostKind, HostLiteral,
};

#[test]
fn classify_host_normalizes_ipv4_with_port() {
    let host = classify_host("127.0.0.1:3000");

    assert_eq!(host.canonical, "127.0.0.1");
    assert_eq!(host.kind, HostKind::Loopback);
}

#[test]
fn classify_host_normalizes_bracketed_ipv6_with_port() {
    let host = classify_host("[::1]:8080");

    assert_eq!(host.literal, HostLiteral::Ipv6);
    assert_eq!(host.kind, HostKind::Loopback);
}

#[test]
fn classify_host_treats_empty_input_as_reserved() {
    let host = classify_host("   ");

    assert_eq!(host.kind, HostKind::Reserved);
    assert!(!is_public_routable_host("   "));
}

#[test]
fn classify_host_identifies_localhost_domains() {
    assert_eq!(classify_host("localhost.").kind, HostKind::Localhost);
    assert_eq!(classify_host("tenant.localhost").kind, HostKind::Localhost);
}

#[test]
fn classify_host_identifies_cloud_metadata_domains() {
    assert_eq!(
        classify_host("metadata.google.internal.").kind,
        HostKind::CloudMetadata
    );
    assert_eq!(
        classify_host("instance-data.ec2.internal").kind,
        HostKind::CloudMetadata
    );
}

#[test]
fn classify_host_identifies_private_ipv4_ranges() {
    assert_eq!(classify_host("10.0.0.1").kind, HostKind::Private);
    assert_eq!(classify_host("172.31.255.255").kind, HostKind::Private);
    assert_eq!(classify_host("192.168.0.1").kind, HostKind::Private);
}

#[test]
fn classify_host_identifies_link_local_metadata_ip() {
    assert_eq!(classify_host("169.254.169.254").kind, HostKind::LinkLocal);
}

#[test]
fn classify_host_identifies_public_hosts() {
    assert_eq!(classify_host("8.8.8.8").kind, HostKind::Public);
    assert_eq!(classify_host("example.com").kind, HostKind::Public);
}

#[test]
fn loopback_helpers_are_strict() {
    assert!(is_loopback_ip("127.0.0.1"));
    assert!(is_loopback_host("localhost"));
    assert!(!is_loopback_ip("localhost"));
    assert!(!is_loopback_host("example.com"));
}
