use rustauth_core::crypto::buffer::constant_time_equal;

#[test]
fn constant_time_equal_accepts_equal_strings() {
    assert!(constant_time_equal("session-token", "session-token"));
}

#[test]
fn constant_time_equal_rejects_different_content() {
    assert!(!constant_time_equal("session-token", "session-other"));
}

#[test]
fn constant_time_equal_rejects_different_lengths() {
    assert!(!constant_time_equal("token", "token-extra"));
}

#[test]
fn constant_time_equal_accepts_equal_byte_slices() {
    assert!(constant_time_equal([1_u8, 2, 3], [1_u8, 2, 3]));
}
