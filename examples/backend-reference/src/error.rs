use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Config(String),
    Io(std::io::Error),
    RustAuth(rustauth::error::RustAuthError),
    Axum(rustauth_axum::RustAuthAxumError),
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::RustAuth(error) => write!(formatter, "{error}"),
            Self::Axum(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustauth::error::RustAuthError> for AppError {
    fn from(error: rustauth::error::RustAuthError) -> Self {
        Self::RustAuth(error)
    }
}

impl From<rustauth_axum::RustAuthAxumError> for AppError {
    fn from(error: rustauth_axum::RustAuthAxumError) -> Self {
        Self::Axum(error)
    }
}

pub type AppResult<T> = Result<T, AppError>;
