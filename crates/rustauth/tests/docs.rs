#![allow(clippy::expect_used)]

#[test]
fn readme_sql_adapter_example_uses_umbrella_sqlx_reexport() {
    let readme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let contents = std::fs::read_to_string(readme).expect("rustauth README");

    assert!(
        contents.contains("rustauth::sqlx::SqliteAdapter"),
        "expected umbrella SQLx adapter import in rustauth README"
    );
    assert!(
        !contents.contains("use rustauth_sqlx::"),
        "rustauth README should not bypass the umbrella crate with direct rustauth_sqlx imports"
    );
    assert!(
        contents.contains("features = [\"sqlx-sqlite\"]"),
        "expected sqlx-sqlite feature documented alongside the adapter example"
    );
    assert!(
        contents.contains("rustauth::prelude"),
        "expected prelude import in rustauth README quick start"
    );
    assert!(
        contents.contains(".build()\n        .await?"),
        "expected async build in rustauth README quick start"
    );
}
