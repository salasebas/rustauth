//! Options for the Have I Been Pwned plugin.

use std::sync::Arc;

use super::checker::{HaveIBeenPwnedChecker, ReqwestHaveIBeenPwnedChecker};

#[derive(Clone)]
pub struct HaveIBeenPwnedOptions {
    pub custom_password_compromised_message: Option<String>,
    pub paths: Vec<String>,
    pub enabled: bool,
    pub checker: Option<Arc<dyn HaveIBeenPwnedChecker>>,
}

impl std::fmt::Debug for HaveIBeenPwnedOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HaveIBeenPwnedOptions")
            .field(
                "custom_password_compromised_message",
                &self.custom_password_compromised_message,
            )
            .field("paths", &self.paths)
            .field("enabled", &self.enabled)
            .field("checker", &self.checker.as_ref().map(|_| "<checker>"))
            .finish()
    }
}

impl Default for HaveIBeenPwnedOptions {
    fn default() -> Self {
        Self {
            custom_password_compromised_message: None,
            paths: vec![
                "/sign-up/email".to_owned(),
                "/change-password".to_owned(),
                "/reset-password".to_owned(),
            ],
            enabled: false,
            checker: None,
        }
    }
}

impl HaveIBeenPwnedOptions {
    #[must_use]
    pub fn builder() -> HaveIBeenPwnedOptionsBuilder {
        HaveIBeenPwnedOptionsBuilder::default()
    }

    #[must_use]
    pub fn checker(mut self, checker: Arc<dyn HaveIBeenPwnedChecker>) -> Self {
        self.checker = Some(checker);
        self
    }

    pub(crate) fn resolved_checker(&self) -> Arc<dyn HaveIBeenPwnedChecker> {
        self.checker
            .clone()
            .unwrap_or_else(|| Arc::new(ReqwestHaveIBeenPwnedChecker::new()))
    }
}

#[derive(Clone, Default)]
pub struct HaveIBeenPwnedOptionsBuilder {
    custom_password_compromised_message: Option<Option<String>>,
    paths: Option<Vec<String>>,
    enabled: Option<bool>,
    checker: Option<Arc<dyn HaveIBeenPwnedChecker>>,
}

impl HaveIBeenPwnedOptionsBuilder {
    #[must_use]
    pub fn custom_password_compromised_message(mut self, message: impl Into<String>) -> Self {
        self.custom_password_compromised_message = Some(Some(message.into()));
        self
    }

    #[must_use]
    pub fn paths(mut self, paths: Vec<String>) -> Self {
        self.paths = Some(paths);
        self
    }

    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.paths
            .get_or_insert_with(|| HaveIBeenPwnedOptions::default().paths)
            .push(path.into());
        self
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    #[must_use]
    pub fn checker(mut self, checker: Arc<dyn HaveIBeenPwnedChecker>) -> Self {
        self.checker = Some(checker);
        self
    }

    #[must_use]
    pub fn build(self) -> HaveIBeenPwnedOptions {
        let defaults = HaveIBeenPwnedOptions::default();
        HaveIBeenPwnedOptions {
            custom_password_compromised_message: self
                .custom_password_compromised_message
                .unwrap_or(defaults.custom_password_compromised_message),
            paths: self.paths.unwrap_or(defaults.paths),
            enabled: self.enabled.unwrap_or(defaults.enabled),
            checker: self.checker.or(defaults.checker),
        }
    }
}
