use std::path::PathBuf;

use crate::types::DetectionInfo;

pub(super) fn detect_from_current_manifest(
    candidates: &[(&'static str, &'static str)],
) -> Option<DetectionInfo> {
    let manifest = std::fs::read_to_string(current_manifest_path()?).ok()?;
    detect_from_manifest(&manifest, candidates)
}

pub(super) fn detect_from_manifest(
    manifest: &str,
    candidates: &[(&'static str, &'static str)],
) -> Option<DetectionInfo> {
    candidates.iter().find_map(|(package, name)| {
        dependency_version(manifest, package).map(|version| DetectionInfo {
            name: (*name).to_owned(),
            version: Some(version),
        })
    })
}

fn current_manifest_path() -> Option<PathBuf> {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    Some(dir.join("Cargo.toml"))
}

fn dependency_version(manifest: &str, package: &str) -> Option<String> {
    let mut in_dependency_section = false;
    for raw_line in manifest.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = section_name(line) {
            in_dependency_section = is_dependency_section(section);
            continue;
        }
        if !in_dependency_section {
            continue;
        }
        if let Some(version) = parse_dependency_line(line, package) {
            return Some(version);
        }
    }
    None
}

fn section_name(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']').map(str::trim)
}

fn is_dependency_section(section: &str) -> bool {
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    ) || (section.starts_with("target.") && section.ends_with(".dependencies"))
}

fn parse_dependency_line(line: &str, package: &str) -> Option<String> {
    let rest = line.strip_prefix(package)?.trim_start();
    if let Some(rest) = rest.strip_prefix(".workspace") {
        return parse_workspace_assignment(rest);
    }
    let value = rest.strip_prefix('=')?.trim();
    parse_dependency_value(value)
}

fn parse_dependency_value(value: &str) -> Option<String> {
    if let Some(version) = parse_quoted(value) {
        return Some(version.to_owned());
    }
    if value.starts_with('{') {
        if let Some(version) = table_string_value(value, "version") {
            return Some(version.to_owned());
        }
        if table_bool_value(value, "workspace") == Some(true) {
            return Some("workspace".to_owned());
        }
    }
    None
}

fn parse_workspace_assignment(rest: &str) -> Option<String> {
    let value = rest.trim_start().strip_prefix('=')?.trim();
    (value == "true").then(|| "workspace".to_owned())
}

fn table_string_value<'a>(table: &'a str, key: &str) -> Option<&'a str> {
    let value = table_value(table, key)?;
    parse_quoted(value)
}

fn table_bool_value(table: &str, key: &str) -> Option<bool> {
    let value = table_value(table, key)?;
    match value {
        value if value.starts_with("true") => Some(true),
        value if value.starts_with("false") => Some(false),
        _ => None,
    }
}

fn table_value<'a>(table: &'a str, key: &str) -> Option<&'a str> {
    let fields = table.trim_start_matches('{').trim_end_matches('}');
    for field in fields.split(',') {
        let field = field.trim();
        let Some(rest) = field.strip_prefix(key) else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        return Some(value.trim_start());
    }
    None
}

fn parse_quoted(value: &str) -> Option<&str> {
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = value.get(quote.len_utf8()..)?;
    let end = rest.find(quote)?;
    rest.get(..end)
}

fn strip_comment(line: &str) -> &str {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            '#' if !in_single_quote && !in_double_quote => return &line[..index],
            _ => {}
        }
    }
    line
}
