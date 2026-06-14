use std::sync::Arc;

/// Log severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Success,
    Warn,
    Error,
}

impl LogLevel {
    const fn rank(self) -> u8 {
        match self {
            Self::Debug => 0,
            Self::Info | Self::Success => 1,
            Self::Warn => 2,
            Self::Error => 3,
        }
    }

    const fn handler_level(self) -> Self {
        match self {
            Self::Success => Self::Info,
            level => level,
        }
    }
}

type LogHandler = dyn Fn(LogLevel, &str, &[&str]) + Send + Sync;

/// Logger configuration.
#[derive(Clone)]
pub struct LoggerOptions {
    level: LogLevel,
    disabled: bool,
    handler: Option<Arc<LogHandler>>,
}

impl LoggerOptions {
    pub fn new(level: LogLevel) -> Self {
        Self {
            level,
            disabled: false,
            handler: None,
        }
    }

    /// Whether logging is disabled.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Configured minimum log level.
    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// Whether a custom log handler is configured.
    pub fn has_custom_handler(&self) -> bool {
        self.handler.is_some()
    }

    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    pub fn with_handler(
        mut self,
        handler: impl Fn(LogLevel, &str, &[&str]) + Send + Sync + 'static,
    ) -> Self {
        self.handler = Some(Arc::new(handler));
        self
    }
}

impl Default for LoggerOptions {
    fn default() -> Self {
        Self::new(LogLevel::Warn)
    }
}

/// Core logger.
#[derive(Clone)]
pub struct Logger {
    options: LoggerOptions,
}

impl Logger {
    pub fn level(&self) -> LogLevel {
        self.options.level
    }

    pub fn debug(&self, message: &str, args: &[&str]) {
        self.log(LogLevel::Debug, message, args);
    }

    pub fn info(&self, message: &str, args: &[&str]) {
        self.log(LogLevel::Info, message, args);
    }

    pub fn success(&self, message: &str, args: &[&str]) {
        self.log(LogLevel::Success, message, args);
    }

    pub fn warn(&self, message: &str, args: &[&str]) {
        self.log(LogLevel::Warn, message, args);
    }

    pub fn error(&self, message: &str, args: &[&str]) {
        self.log(LogLevel::Error, message, args);
    }

    fn log(&self, level: LogLevel, message: &str, args: &[&str]) {
        if self.options.disabled || !should_publish_log(self.options.level, level) {
            return;
        }

        if let Some(handler) = &self.options.handler {
            handler(level.handler_level(), message, args);
        }
    }
}

/// Create a logger from options.
pub fn create_logger(options: LoggerOptions) -> Logger {
    Logger { options }
}

/// Return whether a log event should be published for the configured level.
pub fn should_publish_log(current_log_level: LogLevel, log_level: LogLevel) -> bool {
    log_level.rank() >= current_log_level.rank()
}
