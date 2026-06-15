use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_metadata::{Metadata, MetadataCommand};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("failed to inspect Cargo metadata: {0}")]
    Metadata(#[from] cargo_metadata::Error),
    #[error("failed to run {program}: {source}")]
    Command {
        program: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInfo {
    pub root: PathBuf,
    pub packages: Vec<PackageInfo>,
    pub detected_frameworks: Vec<DetectedItem>,
    pub detected_databases: Vec<DetectedItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<String>,
    pub features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectedItem {
    pub name: String,
    pub confidence: DetectionConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionConfidence {
    High,
    Medium,
    Low,
}

pub fn inspect(cwd: &Path) -> Result<WorkspaceInfo, WorkspaceError> {
    let metadata = MetadataCommand::new().current_dir(cwd).no_deps().exec()?;
    Ok(WorkspaceInfo {
        root: metadata.workspace_root.as_std_path().to_path_buf(),
        packages: package_info(&metadata),
        detected_frameworks: detect_frameworks(&metadata),
        detected_databases: detect_databases(&metadata),
    })
}

pub fn command_version(program: &str) -> Result<String, WorkspaceError> {
    let output = Command::new(program)
        .arg("--version")
        .output()
        .map_err(|source| WorkspaceError::Command {
            program: program.to_owned(),
            source,
        })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Ok("not available".to_owned())
    }
}

fn package_info(metadata: &Metadata) -> Vec<PackageInfo> {
    metadata
        .packages
        .iter()
        .map(|package| PackageInfo {
            name: package.name.clone(),
            version: package.version.to_string(),
            dependencies: package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.clone())
                .collect(),
            features: package.features.clone(),
        })
        .collect()
}

fn dependency_names(metadata: &Metadata) -> BTreeSet<String> {
    metadata
        .packages
        .iter()
        .flat_map(|package| {
            package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.clone())
        })
        .collect()
}

fn package_names(metadata: &Metadata) -> BTreeSet<String> {
    metadata
        .packages
        .iter()
        .map(|package| package.name.clone())
        .collect()
}

fn has_dep_or_package(metadata: &Metadata, name: &str) -> bool {
    let deps = dependency_names(metadata);
    let packages = package_names(metadata);
    deps.contains(name) || packages.contains(name)
}

fn detect_frameworks(metadata: &Metadata) -> Vec<DetectedItem> {
    let mut frameworks = Vec::new();
    let has_axum = has_dep_or_package(metadata, "axum");
    let has_rustauth_axum = has_dep_or_package(metadata, "rustauth-axum");
    if has_axum && has_rustauth_axum {
        frameworks.push(detected("axum", DetectionConfidence::High));
    } else if has_axum {
        frameworks.push(detected("axum", DetectionConfidence::Medium));
    }
    let has_actix_web = has_dep_or_package(metadata, "actix-web");
    let has_rustauth_actix_web = has_dep_or_package(metadata, "rustauth-actix-web");
    if has_actix_web && has_rustauth_actix_web {
        frameworks.push(detected("actix-web", DetectionConfidence::High));
    } else if has_actix_web {
        frameworks.push(detected("actix-web", DetectionConfidence::Medium));
    }
    for framework in ["rocket", "poem", "warp"] {
        if has_dep_or_package(metadata, framework) {
            frameworks.push(detected(framework, DetectionConfidence::Low));
        }
    }
    frameworks
}

fn detect_databases(metadata: &Metadata) -> Vec<DetectedItem> {
    let mut databases = Vec::new();
    if has_dep_or_package(metadata, "rustauth-sqlx") || has_dep_or_package(metadata, "sqlx") {
        databases.push(detected("sqlx", DetectionConfidence::High));
    }
    if has_dep_or_package(metadata, "rustauth-tokio-postgres") {
        databases.push(detected("tokio-postgres", DetectionConfidence::High));
    }
    if has_dep_or_package(metadata, "rustauth-deadpool-postgres") {
        databases.push(detected("deadpool-postgres", DetectionConfidence::High));
    }
    if has_dep_or_package(metadata, "rustauth-diesel") {
        databases.push(detected("diesel", DetectionConfidence::High));
    }
    databases
}

fn detected(name: &str, confidence: DetectionConfidence) -> DetectedItem {
    DetectedItem {
        name: name.to_owned(),
        confidence,
    }
}

pub fn package_has_dependency(info: &WorkspaceInfo, dependency: &str) -> bool {
    info.packages
        .iter()
        .any(|package| package.dependencies.iter().any(|name| name == dependency))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_manifest(dir: &TempDir, manifest: &str) {
        fs::create_dir_all(dir.path().join("src")).expect("create src");
        fs::write(dir.path().join("src/lib.rs"), "").expect("write lib");
        fs::write(dir.path().join("Cargo.toml"), manifest).expect("write manifest");
    }

    fn inspect_manifest(dir: &TempDir) -> WorkspaceInfo {
        inspect(dir.path()).expect("inspect workspace")
    }

    #[test]
    fn detects_actix_web_with_high_confidence_when_rustauth_adapter_present() {
        let dir = TempDir::new().expect("tempdir");
        write_manifest(
            &dir,
            r#"
[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
rustauth-actix-web = "0.2"
"#,
        );

        let info = inspect_manifest(&dir);
        let actix = info
            .detected_frameworks
            .iter()
            .find(|item| item.name == "actix-web")
            .expect("actix-web detection");

        assert_eq!(actix.confidence, DetectionConfidence::High);
    }

    #[test]
    fn detects_actix_web_with_medium_confidence_without_rustauth_adapter() {
        let dir = TempDir::new().expect("tempdir");
        write_manifest(
            &dir,
            r#"
[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
"#,
        );

        let info = inspect_manifest(&dir);
        let actix = info
            .detected_frameworks
            .iter()
            .find(|item| item.name == "actix-web")
            .expect("actix-web detection");

        assert_eq!(actix.confidence, DetectionConfidence::Medium);
    }
}
