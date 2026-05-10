use openauth_core::crypto::password::{hash_password, verify_password};

#[test]
fn hash_password_returns_salt_and_hash() -> Result<(), Box<dyn std::error::Error>> {
    let hash = hash_password("mySecurePassword123!")?;

    assert_eq!(hash.split(':').count(), 2);
    Ok(())
}

#[test]
fn verify_password_accepts_correct_password() -> Result<(), Box<dyn std::error::Error>> {
    let password = "correctPassword123!";
    let hash = hash_password(password)?;

    assert!(verify_password(&hash, password)?);
    Ok(())
}

#[test]
fn verify_password_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
    let hash = hash_password("correctPassword123!")?;

    assert!(!verify_password(&hash, "wrongPassword456!")?);
    Ok(())
}

#[test]
fn hash_password_generates_different_hashes_for_same_password(
) -> Result<(), Box<dyn std::error::Error>> {
    let password = "samePassword123!";

    assert_ne!(hash_password(password)?, hash_password(password)?);
    Ok(())
}

#[test]
fn verify_password_handles_unicode_passwords() -> Result<(), Box<dyn std::error::Error>> {
    let password = "비밀번호🔑密码🔒パスワード";
    let hash = hash_password(password)?;

    assert!(verify_password(&hash, password)?);
    Ok(())
}

#[test]
fn verify_password_rejects_malformed_hash() {
    assert!(verify_password("not-a-valid-hash", "password").is_err());
}
