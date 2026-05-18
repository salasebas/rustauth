use openauth_cli::secret::{assess_secret, generate_secret, SecretSeverity};

#[test]
fn generated_secret_passes_strength_check() {
    let secret = generate_secret(32);
    let assessment = assess_secret(&secret, true);

    assert_eq!(assessment.severity, SecretSeverity::Ok);
}

#[test]
fn weak_secret_is_rejected_for_production() {
    let assessment = assess_secret("secret-a-at-least-32-chars-long!!", true);

    assert_eq!(assessment.severity, SecretSeverity::Error);
}
