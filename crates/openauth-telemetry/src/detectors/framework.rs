use crate::types::DetectionInfo;

use super::cargo_manifest::detect_from_current_manifest;

/// Rust web framework crate ids, following upstream's "first known dependency wins" detector shape.
const FRAMEWORKS: &[(&str, &str)] = &[
    ("axum", "axum"),
    ("actix-web", "actix-web"),
    ("rocket", "rocket"),
    ("poem", "poem"),
    ("warp", "warp"),
    ("tide", "tide"),
    ("salvo", "salvo"),
    ("hono", "hono"),
];

pub fn detect_framework() -> Option<DetectionInfo> {
    detect_from_current_manifest(FRAMEWORKS)
}

#[cfg(test)]
fn detect_framework_from_manifest(manifest: &str) -> Option<DetectionInfo> {
    super::cargo_manifest::detect_from_manifest(manifest, FRAMEWORKS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_rust_framework_from_manifest() {
        let manifest = r#"
            [package]
            name = "app"

            [dependencies]
            axum = "0.8"
        "#;

        assert_eq!(
            detect_framework_from_manifest(manifest),
            Some(DetectionInfo {
                name: "axum".to_owned(),
                version: Some("0.8".to_owned()),
            })
        );
    }

    #[test]
    fn returns_none_when_manifest_has_no_known_framework() {
        let manifest = r#"
            [package]
            name = "app"

            [dependencies]
            serde = "1"
        "#;

        assert_eq!(detect_framework_from_manifest(manifest), None);
    }
}
