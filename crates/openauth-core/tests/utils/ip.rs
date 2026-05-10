use openauth_core::utils::ip::{
    create_rate_limit_key, is_valid_ip, normalize_ip, normalize_ip_with_options, Ipv6Subnet,
    NormalizeIpOptions,
};

#[test]
fn is_valid_ip_accepts_ipv4_and_ipv6() {
    assert!(is_valid_ip("192.0.2.1"));
    assert!(is_valid_ip("2001:db8::1"));
}

#[test]
fn is_valid_ip_rejects_invalid_values() {
    assert!(!is_valid_ip("example.com"));
    assert!(!is_valid_ip("999.999.999.999"));
}

#[test]
fn normalize_ip_leaves_ipv4_unchanged() {
    assert_eq!(normalize_ip("192.0.2.1"), "192.0.2.1");
}

#[test]
fn normalize_ip_converts_ipv4_mapped_ipv6_to_ipv4() {
    assert_eq!(normalize_ip("::ffff:192.0.2.1"), "192.0.2.1");
    assert_eq!(normalize_ip("::ffff:c000:0201"), "192.0.2.1");
}

#[test]
fn normalize_ip_uses_ipv6_64_subnet_by_default() {
    assert_eq!(
        normalize_ip("2001:DB8::1"),
        "2001:0db8:0000:0000:0000:0000:0000:0000"
    );
}

#[test]
fn normalize_ip_can_keep_full_ipv6_address() {
    assert_eq!(
        normalize_ip_with_options(
            "2001:DB8::1",
            NormalizeIpOptions {
                ipv6_subnet: Ipv6Subnet::Full,
            },
        ),
        "2001:0db8:0000:0000:0000:0000:0000:0001"
    );
}

#[test]
fn normalize_ip_can_apply_ipv6_48_subnet() {
    assert_eq!(
        normalize_ip_with_options(
            "2001:db8:abcd:1234::1",
            NormalizeIpOptions {
                ipv6_subnet: Ipv6Subnet::Prefix48,
            },
        ),
        "2001:0db8:abcd:0000:0000:0000:0000:0000"
    );
}

#[test]
fn normalize_ip_lowercases_invalid_values() {
    assert_eq!(normalize_ip("Not-An-IP"), "not-an-ip");
}

#[test]
fn create_rate_limit_key_uses_collision_safe_separator() {
    assert_eq!(
        create_rate_limit_key("192.0.2.1", "/sign-in"),
        "192.0.2.1|/sign-in"
    );
}
