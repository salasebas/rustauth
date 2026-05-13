use crate::utils::hash::hash_to_base64;
use crate::utils::id::generate_id;

fn parse_package_name_from_manifest(content: &str) -> Option<String> {
    let mut in_package = false;
    for raw_line in content.lines() {
        let line = raw_line.split('#').next()?.trim();
        if line == "[package]" {
            in_package = true;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_package = false;
            continue;
        }
        if !in_package {
            continue;
        }
        let line = line.strip_prefix("name")?;
        let line = line.trim_start().strip_prefix('=')?.trim();
        let line = line.strip_prefix('"').or_else(|| line.strip_prefix('\''))?;
        let end = line.find(['"', '\''])?;
        return Some(line[..end].to_owned());
    }
    None
}

fn try_read_cargo_package_name() -> Option<String> {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    let path = dir.join("Cargo.toml");
    let content = std::fs::read_to_string(path).ok()?;
    parse_package_name_from_manifest(&content)
}

/// Anonymous project id (SHA-256 base64 or random), mirroring upstream `getProjectId`.
pub fn resolve_project_id(base_url: Option<&str>) -> String {
    if let Some(project_name) = try_read_cargo_package_name() {
        let material = match base_url {
            Some(url) => format!("{url}{project_name}"),
            None => project_name,
        };
        return hash_to_base64(material.as_bytes());
    }
    if let Some(url) = base_url {
        return hash_to_base64(url.as_bytes());
    }
    generate_id(32)
}
