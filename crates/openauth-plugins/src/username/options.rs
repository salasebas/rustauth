use std::sync::Arc;

pub type UsernameValidator = Arc<dyn Fn(&str) -> bool + Send + Sync>;
pub type UsernameNormalizer = Arc<dyn Fn(&str) -> String + Send + Sync>;

#[derive(Clone)]
pub struct UsernameOptions {
    pub min_username_length: usize,
    pub max_username_length: usize,
    pub username_validator: UsernameValidator,
    pub display_username_validator: Option<UsernameValidator>,
    pub username_normalization: Option<UsernameNormalizer>,
    pub display_username_normalization: Option<UsernameNormalizer>,
    pub validation_order: ValidationOrder,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        Self {
            min_username_length: 3,
            max_username_length: 30,
            username_validator: Arc::new(default_username_validator),
            display_username_validator: None,
            username_normalization: Some(Arc::new(|username| username.to_lowercase())),
            display_username_normalization: None,
            validation_order: ValidationOrder::default(),
        }
    }
}

impl UsernameOptions {
    pub fn normalize_username(&self, username: &str) -> String {
        self.username_normalization
            .as_ref()
            .map(|normalizer| normalizer(username))
            .unwrap_or_else(|| username.to_owned())
    }

    pub fn normalize_display_username(&self, display_username: &str) -> String {
        self.display_username_normalization
            .as_ref()
            .map(|normalizer| normalizer(display_username))
            .unwrap_or_else(|| display_username.to_owned())
    }

    pub fn username_for_validation(&self, username: &str) -> String {
        if self.validation_order.username == ValidationPhase::PostNormalization {
            self.normalize_username(username)
        } else {
            username.to_owned()
        }
    }

    pub fn display_username_for_validation(&self, display_username: &str) -> String {
        if self.validation_order.display_username == ValidationPhase::PostNormalization {
            self.normalize_display_username(display_username)
        } else {
            display_username.to_owned()
        }
    }

    pub fn validate_username(
        &self,
        username: &str,
        _phase: ValidationPhase,
    ) -> Result<(), UsernameValidationError> {
        if username.len() < self.min_username_length {
            return Err(UsernameValidationError::TooShort);
        }
        if username.len() > self.max_username_length {
            return Err(UsernameValidationError::TooLong);
        }
        if !(self.username_validator)(username) {
            return Err(UsernameValidationError::Invalid);
        }
        Ok(())
    }

    pub fn validate_display_username(
        &self,
        display_username: &str,
    ) -> Result<(), UsernameValidationError> {
        if let Some(validator) = &self.display_username_validator {
            if !validator(display_username) {
                return Err(UsernameValidationError::InvalidDisplay);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationOrder {
    pub username: ValidationPhase,
    pub display_username: ValidationPhase,
}

impl Default for ValidationOrder {
    fn default() -> Self {
        Self {
            username: ValidationPhase::PreNormalization,
            display_username: ValidationPhase::PreNormalization,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationPhase {
    PreNormalization,
    PostNormalization,
    Endpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameValidationError {
    TooShort,
    TooLong,
    Invalid,
    InvalidDisplay,
}

fn default_username_validator(username: &str) -> bool {
    username
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '.')
}
