use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::app::AppError;

pub fn load_project_env(cwd: &Path) -> Result<(), AppError> {
    let mut values = BTreeMap::new();
    for file in [".env", ".env.local"] {
        let path = cwd.join(file);
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path).map_err(|source| AppError::Io {
            context: format!("failed to read {}", path.display()),
            source,
        })?;
        parse_env_file(&content, &mut values);
    }
    for (key, value) in values {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(key, value);
        }
    }
    Ok(())
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
