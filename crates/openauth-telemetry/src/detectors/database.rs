use crate::types::DetectionInfo;

use super::cargo_manifest::detect_from_current_manifest;

/// Rust database crate ids, following upstream's "first known dependency wins" detector shape.
const DATABASES: &[(&str, &str)] = &[
    ("sqlx", "sqlx"),
    ("diesel", "diesel"),
    ("sea-orm", "sea-orm"),
    ("tokio-postgres", "postgresql"),
    ("postgres", "postgresql"),
    ("deadpool-postgres", "postgresql"),
    ("bb8-postgres", "postgresql"),
    ("mysql", "mysql"),
    ("mysql_async", "mysql"),
    ("rusqlite", "sqlite"),
    ("sqlite", "sqlite"),
    ("mongodb", "mongodb"),
    ("surrealdb", "surrealdb"),
];

pub fn detect_database() -> Option<DetectionInfo> {
    detect_from_current_manifest(DATABASES)
}

#[cfg(test)]
fn detect_database_from_manifest(manifest: &str) -> Option<DetectionInfo> {
    super::cargo_manifest::detect_from_manifest(manifest, DATABASES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_inline_table_database_dependency_from_manifest() {
        let manifest = r#"
            [package]
            name = "app"

            [dependencies]
            sqlx = { version = "0.8", features = ["postgres"] }
        "#;

        assert_eq!(
            detect_database_from_manifest(manifest),
            Some(DetectionInfo {
                name: "sqlx".to_owned(),
                version: Some("0.8".to_owned()),
            })
        );
    }

    #[test]
    fn detects_workspace_database_dependency_from_manifest() {
        let manifest = r#"
            [package]
            name = "app"

            [dependencies]
            tokio-postgres.workspace = true
        "#;

        assert_eq!(
            detect_database_from_manifest(manifest),
            Some(DetectionInfo {
                name: "postgresql".to_owned(),
                version: Some("workspace".to_owned()),
            })
        );
    }
}
