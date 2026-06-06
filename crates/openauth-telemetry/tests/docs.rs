#![allow(clippy::expect_used)]

#[test]
fn readme_documents_oauth_feature_for_social_provider_snapshots() {
    let readme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let contents = std::fs::read_to_string(readme).expect("openauth-telemetry README");

    assert!(
        contents.contains("## Feature Flags"),
        "expected Feature Flags section in openauth-telemetry README"
    );
    assert!(
        contents.contains("`oauth`"),
        "expected oauth feature documented in openauth-telemetry README"
    );
    assert!(
        contents.contains("socialProviders"),
        "expected socialProviders field documented in openauth-telemetry README"
    );
    assert!(
        contents.contains("openauth-telemetry/oauth"),
        "expected umbrella telemetry wiring documented in openauth-telemetry README"
    );
}
