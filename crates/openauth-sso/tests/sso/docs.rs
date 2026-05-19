#[test]
fn sso_spec_docs_are_checked_in() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("docs/superpowers/specs/openauth-sso");

    assert!(root.join("requirements.md").is_file());
    assert!(root.join("design.md").is_file());
    assert!(root.join("tasks.md").is_file());
    assert!(root.join("gap-analysis.md").is_file());
}
