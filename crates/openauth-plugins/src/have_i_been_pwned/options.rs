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
            enabled: true,
            checker: None,
        }
    }
}

impl HaveIBeenPwnedOptions {
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
