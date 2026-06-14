#![allow(clippy::expect_used)]

#[test]
fn readme_documents_cli_telemetry() {
    let readme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let contents = std::fs::read_to_string(readme).expect("rustauth-cli README");

    assert!(
        contents.contains("## Telemetry"),
        "expected Telemetry section in rustauth-cli README"
    );
    assert!(
        contents.contains("`cli_generate`"),
        "expected cli_generate event documented in rustauth-cli README"
    );
    assert!(
        contents.contains("`cli_migrate`"),
        "expected cli_migrate event documented in rustauth-cli README"
    );
    assert!(
        contents.contains("`init`"),
        "expected init bootstrap event documented in rustauth-cli README"
    );
    assert!(
        contents.contains("RUSTAUTH_TELEMETRY"),
        "expected RUSTAUTH_TELEMETRY documented in rustauth-cli README"
    );
    assert!(
        contents.contains("RUSTAUTH_TELEMETRY_DEBUG"),
        "expected RUSTAUTH_TELEMETRY_DEBUG documented in rustauth-cli README"
    );
    assert!(
        contents.contains("RUSTAUTH_TELEMETRY_ENDPOINT"),
        "expected RUSTAUTH_TELEMETRY_ENDPOINT documented in rustauth-cli README"
    );
    assert!(
        contents.contains("db generate") && contents.contains("db migrate"),
        "expected db command aliases documented in rustauth-cli README"
    );
    assert!(
        contents.contains("Opt-out") || contents.contains("opt-out"),
        "expected opt-out guidance documented in rustauth-cli README"
    );
    assert!(
        contents.contains("Excluded:") || contents.contains("redact"),
        "expected redaction guidance documented in rustauth-cli README"
    );
}
