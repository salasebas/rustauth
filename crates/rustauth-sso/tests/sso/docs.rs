#[test]
fn sso_readme_documents_better_auth_compatibility() {
    let readme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let contents = std::fs::read_to_string(readme).expect("rustauth-sso README");
    assert!(
        contents.contains("## Better Auth compatibility"),
        "expected Better Auth compatibility section in rustauth-sso README"
    );
    assert!(
        contents.contains("[UPSTREAM.md](./UPSTREAM.md)"),
        "expected README to link to UPSTREAM.md"
    );
}
