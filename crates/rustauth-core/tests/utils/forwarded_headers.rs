use rustauth_core::utils::url::{is_valid_forwarded_host, is_valid_forwarded_proto};

#[test]
fn forwarded_proto_rejects_unsafe_values() {
    for proto in ["javascript", "file", "ftp", "ws", "data", ""] {
        assert!(!is_valid_forwarded_proto(proto));
    }
    assert!(is_valid_forwarded_proto("http"));
    assert!(is_valid_forwarded_proto("HTTPS"));
}

#[test]
fn forwarded_host_rejects_malicious_values() {
    for host in [
        "",
        "   ",
        "../../../etc/passwd",
        "<script>alert('xss')</script>",
        ".evil.com",
        "evil.com\u{0000}.example.com",
        "example.com:999999",
    ] {
        assert!(!is_valid_forwarded_host(host), "expected reject: {host:?}");
    }
}

#[test]
fn forwarded_host_accepts_valid_values() {
    for host in [
        "example.com",
        "example.com:8080",
        "192.168.1.1",
        "192.168.1.1:3000",
        "[2001:db8::1]",
        "[2001:db8::1]:443",
        "localhost",
        "localhost:8080",
    ] {
        assert!(is_valid_forwarded_host(host), "expected accept: {host:?}");
    }
}
