use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use toml_edit::{value, Array, DocumentMut};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse RustAuth config: {0}")]
    ParseToml(#[from] toml_edit::de::Error),
    #[error("failed to parse RustAuth config document: {0}")]
    ParseDocument(#[from] toml_edit::TomlError),
    #[error("failed to render RustAuth config: {0}")]
    SerializeToml(#[from] toml_edit::ser::Error),
    #[error("plugins.enabled must be an array")]
    InvalidPlugins,
    #[error(
        "database.adapter is required; set it explicitly in rustauth.toml \
         (e.g. sqlx, diesel, tokio-postgres, deadpool-postgres)"
    )]
    MissingDatabaseAdapter,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CliConfig {
    pub project: ProjectConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub plugins: PluginsConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub framework: Option<String>,
    pub base_url: String,
    pub base_path: String,
    pub production: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub adapter: Option<String>,
    pub provider: Option<String>,
    pub url_env: String,
    pub migrations_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub secret_env: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PluginsConfig {
    pub enabled: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            framework: None,
            base_url: "http://localhost:3000/api/auth".to_owned(),
            base_path: "/api/auth".to_owned(),
            production: false,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            adapter: None,
            provider: None,
            url_env: "DATABASE_URL".to_owned(),
            migrations_dir: "migrations/rustauth".to_owned(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            secret_env: "RUSTAUTH_SECRET".to_owned(),
        }
    }
}

impl CliConfig {
    pub fn parse_str(source: &str) -> Result<Self, ConfigError> {
        source.parse()
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config = Self::parse_str(&source)?;
        config.validate_loaded_fields()?;
        Ok(config)
    }

    pub fn database_adapter(&self) -> Option<&str> {
        self.database
            .adapter
            .as_deref()
            .filter(|adapter| !adapter.trim().is_empty())
    }

    pub fn validate_loaded_fields(&self) -> Result<(), ConfigError> {
        if self.database_adapter().is_none() {
            return Err(ConfigError::MissingDatabaseAdapter);
        }
        Ok(())
    }

    pub fn load_optional(path: &Path) -> Result<Option<Self>, ConfigError> {
        if !path.exists() {
            return Ok(None);
        }
        Self::load(path).map(Some)
    }

    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        Ok(toml_edit::ser::to_string_pretty(self)?)
    }

    pub fn write(&self, path: &Path) -> Result<(), ConfigError> {
        let rendered = self.to_toml_string()?;
        fs::write(path, rendered).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn add_plugin_to_document(source: &str, plugin: &str) -> Result<String, ConfigError> {
        let mut document = source.parse::<DocumentMut>()?;
        ensure_plugin_array(&mut document)?;
        let enabled = document["plugins"]["enabled"]
            .as_array_mut()
            .ok_or(ConfigError::InvalidPlugins)?;
        if !enabled.iter().any(|item| item.as_str() == Some(plugin)) {
            enabled.push(plugin);
        }
        Ok(document.to_string())
    }

    pub fn remove_plugin_from_document(source: &str, plugin: &str) -> Result<String, ConfigError> {
        let mut document = source.parse::<DocumentMut>()?;
        ensure_plugin_array(&mut document)?;
        let enabled = document["plugins"]["enabled"]
            .as_array_mut()
            .ok_or(ConfigError::InvalidPlugins)?;
        enabled.retain(|item| item.as_str() != Some(plugin));
        Ok(document.to_string())
    }
}

impl std::str::FromStr for CliConfig {
    type Err = ConfigError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Ok(toml_edit::de::from_str(source)?)
    }
}

fn ensure_plugin_array(document: &mut DocumentMut) -> Result<(), ConfigError> {
    if document["plugins"].is_none() {
        document["plugins"] = toml_edit::table();
    }
    if document["plugins"]["enabled"].is_none() {
        document["plugins"]["enabled"] = value(Array::default());
    }
    if !document["plugins"]["enabled"].is_array() {
        return Err(ConfigError::InvalidPlugins);
    }
    Ok(())
}
