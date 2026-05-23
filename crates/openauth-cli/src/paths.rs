use std::path::{Path, PathBuf};

use crate::app::AppError;

pub fn absolute_cwd(cwd: &Path) -> Result<PathBuf, AppError> {
    let path = if cwd.is_absolute() {
        cwd.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| AppError::Io {
                context: "failed to read current directory".to_owned(),
                source,
            })?
            .join(cwd)
    };
    if path.exists() {
        Ok(path)
    } else {
        Err(AppError::Message(format!(
            "The directory {} does not exist.",
            path.display()
        )))
    }
}

pub fn resolve_project_path(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

pub fn resolve_config_path(cwd: &Path, config: Option<&Path>) -> PathBuf {
    config
        .map(|path| resolve_project_path(cwd, path))
        .unwrap_or_else(|| cwd.join("openauth.toml"))
}
