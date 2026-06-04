use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::app::AppError;

/// Loads `.env` / `.env.local` for the CLI with deterministic precedence.
///
/// Weakest to strongest among files (process environment always wins and is
/// never overwritten):
///
/// 1. `<config-dir>/.env`
/// 2. `<config-dir>/.env.local`
/// 3. `<cwd>/.env`
/// 4. `<cwd>/.env.local`
///
/// When the config file lives in `cwd` (default `openauth.toml`), only `cwd` is
/// scanned once.
pub fn load_project_env(cwd: &Path, config_path: &Path) -> Result<(), AppError> {
    let values = collect_env_file_values(cwd, config_path)?;
    for (key, value) in values {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(key, value);
        }
    }
    Ok(())
}

fn collect_env_file_values(
    cwd: &Path,
    config_path: &Path,
) -> Result<BTreeMap<String, String>, AppError> {
    let mut values = BTreeMap::new();
    let config_dir = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(cwd);

    let dirs = env_source_dirs(cwd, config_dir);
    for dir in dirs {
        for file in [".env", ".env.local"] {
            merge_env_file(&dir.join(file), &mut values)?;
        }
    }
    Ok(values)
}

fn env_source_dirs(cwd: &Path, config_dir: &Path) -> Vec<PathBuf> {
    if paths_same_directory(config_dir, cwd) {
        vec![cwd.to_path_buf()]
    } else {
        vec![config_dir.to_path_buf(), cwd.to_path_buf()]
    }
}

fn merge_env_file(path: &Path, values: &mut BTreeMap<String, String>) -> Result<(), AppError> {
    if !path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(path).map_err(|source| AppError::Io {
        context: format!("failed to read {}", path.display()),
        source,
    })?;
    parse_env_file(&content, values);
    Ok(())
}

fn paths_same_directory(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(left), Ok(right)) => left == right,
        _ => a == b,
    }
}

fn parse_env_file(content: &str, values: &mut BTreeMap<String, String>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        values.insert(key.to_owned(), unquote_env_value(value.trim()));
    }
}

fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        let quote = bytes[0];
        if (quote == b'\'' || quote == b'"') && bytes[value.len() - 1] == quote {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cwd_env_local_overrides_cwd_env() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("openauth.toml");
        fs::write(&config, "").expect("write config");
        fs::write(temp.path().join(".env"), "FOO=from-env\n").expect("write env");
        fs::write(temp.path().join(".env.local"), "FOO=from-local\n").expect("write local");

        let values = collect_env_file_values(temp.path(), &config).expect("collect");
        assert_eq!(values.get("FOO").map(String::as_str), Some("from-local"));
    }

    #[test]
    fn cwd_env_overrides_config_dir_env() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        let config = config_dir.join("auth.toml");
        fs::write(&config, "").expect("write config");
        fs::write(config_dir.join(".env"), "FOO=from-config\n").expect("write config env");
        fs::write(temp.path().join(".env"), "FOO=from-cwd\n").expect("write cwd env");

        let values = collect_env_file_values(temp.path(), &config).expect("collect");
        assert_eq!(values.get("FOO").map(String::as_str), Some("from-cwd"));
    }

    #[test]
    fn config_dir_env_local_overrides_config_dir_env() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        let config = config_dir.join("auth.toml");
        fs::write(&config, "").expect("write config");
        fs::write(config_dir.join(".env"), "FOO=from-config-env\n").expect("write env");
        fs::write(config_dir.join(".env.local"), "FOO=from-config-local\n").expect("write local");

        let values = collect_env_file_values(temp.path(), &config).expect("collect");
        assert_eq!(
            values.get("FOO").map(String::as_str),
            Some("from-config-local")
        );
    }
}
