use std::env;
use std::net::SocketAddr;

use rustauth_core::options::DeploymentMode;

use crate::error::{AppError, AppResult};

/// Default auth mount path used when `RUSTAUTH_AUTH_BASE_PATH` is unset.
pub const AUTH_BASE_PATH: &str = "/api/auth";
pub const DEFAULT_SECRET: &str = "rustauth-backend-reference-secret-32ch";
pub const DEFAULT_DATABASE_URL: &str = "postgres://user:password@127.0.0.1:5432/rustauth";

/// Runtime configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub auth_base_path: String,
    pub base_url: String,
    pub secret: String,
    pub database_url: String,
    pub trusted_origins: Vec<String>,
    pub cognito_domain: String,
    pub cognito_region: String,
    pub cognito_user_pool_id: String,
}

impl AppConfig {
    pub fn from_env() -> AppResult<Self> {
        let host = env_or("RUSTAUTH_HOST", "127.0.0.1");
        let port = env_or("RUSTAUTH_PORT", "3000")
            .parse::<u16>()
            .map_err(|error| AppError::Config(format!("RUSTAUTH_PORT is invalid: {error}")))?;
        let auth_base_path = env_or("RUSTAUTH_AUTH_BASE_PATH", AUTH_BASE_PATH);
        let default_base_url = format!("http://{host}:{port}{auth_base_path}");
        let base_url = env::var("RUSTAUTH_BASE_URL").unwrap_or(default_base_url);
        let secret = env::var("RUSTAUTH_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_owned());
        let database_url =
            env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned());
        let trusted_origins = env::var("RUSTAUTH_TRUSTED_ORIGINS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|origin| !origin.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_else(|_| vec![format!("http://{host}:{port}")]);
        let cognito_domain = env_or("COGNITO_DOMAIN", "rustauth-reference.auth.example.com");
        let cognito_region = env_or("COGNITO_REGION", "us-east-1");
        let cognito_user_pool_id = env_or("COGNITO_USER_POOL_ID", "us-east-1_rustauth_reference");

        Ok(Self {
            host,
            port,
            auth_base_path,
            base_url,
            secret,
            database_url,
            trusted_origins,
            cognito_domain,
            cognito_region,
            cognito_user_pool_id,
        })
    }

    pub fn socket_addr(&self) -> AppResult<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|error| AppError::Config(format!("listen address is invalid: {error}")))
    }

    pub fn deployment_mode() -> DeploymentMode {
        match env::var("RUST_ENV").ok().as_deref() {
            Some("production") => DeploymentMode::Production,
            Some("development") | Some("test") => DeploymentMode::Development,
            _ => DeploymentMode::Auto,
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_url_uses_auth_base_path() {
        let config = AppConfig {
            host: "127.0.0.1".to_owned(),
            port: 3000,
            auth_base_path: AUTH_BASE_PATH.to_owned(),
            base_url: format!("http://127.0.0.1:3000{AUTH_BASE_PATH}"),
            secret: DEFAULT_SECRET.to_owned(),
            database_url: String::new(),
            trusted_origins: vec!["http://127.0.0.1:3000".to_owned()],
            cognito_domain: String::new(),
            cognito_region: String::new(),
            cognito_user_pool_id: String::new(),
        };

        assert_eq!(config.auth_base_path, AUTH_BASE_PATH);
        assert!(config.base_url.ends_with(&config.auth_base_path));
    }
}
