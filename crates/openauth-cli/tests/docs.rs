#![allow(clippy::expect_used)]

#[test]
fn readme_documents_cli_telemetry() {
    let readme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let contents = std::fs::read_to_string(readme).expect("openauth-cli README");

    assert!(
        contents.contains("## Telemetry"),
        "expected Telemetry section in openauth-cli README"
    );
    assert!(
        contents.contains("`cli_generate`"),
        "expected cli_generate event documented in openauth-cli README"
    );
    assert!(
        contents.contains("`cli_migrate`"),
        "expected cli_migrate event documented in openauth-cli README"
    );
    assert!(
        contents.contains("OPENAUTH_TELEMETRY"),
        "expected OPENAUTH_TELEMETRY documented in openauth-cli README"
    );
    assert!(
        contents.contains("OPENAUTH_TELEMETRY_DEBUG"),
        "expected OPENAUTH_TELEMETRY_DEBUG documented in openauth-cli README"
    );
    assert!(
        contents.contains("OPENAUTH_TELEMETRY_ENDPOINT"),
        "expected OPENAUTH_TELEMETRY_ENDPOINT documented in openauth-cli README"
    );
    assert!(
        contents.contains("db generate") && contents.contains("db migrate"),
        "expected db command aliases documented in openauth-cli README"
    );
    assert!(
        contents.contains("Opt-out") || contents.contains("opt-out"),
        "expected opt-out guidance documented in openauth-cli README"
    );
    assert!(
        contents.contains("Excluded:") || contents.contains("redact"),
        "expected redaction guidance documented in openauth-cli README"
    );
}
