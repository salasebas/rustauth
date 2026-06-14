use rustauth_core::crypto::random::generate_random_string;

#[test]
fn generate_random_string_respects_requested_length() {
    let value = generate_random_string(48);

    assert_eq!(value.len(), 48);
}

#[test]
fn generate_random_string_uses_rustauth_charset() {
    let value = generate_random_string(512);

    assert!(value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
}

#[test]
fn generate_random_string_differs_across_calls() {
    let first = generate_random_string(64);
    let second = generate_random_string(64);

    assert_ne!(first, second);
}
