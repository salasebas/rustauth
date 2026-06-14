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
    pub schema: super::schema::UsernameSchemaOptions,
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
            schema: super::schema::UsernameSchemaOptions::default(),
        }
    }
}

impl UsernameOptions {
    #[must_use]
    pub fn builder() -> UsernameOptionsBuilder {
        UsernameOptionsBuilder::default()
    }

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

#[derive(Clone, Default)]
pub struct UsernameOptionsBuilder {
    min_username_length: Option<usize>,
    max_username_length: Option<usize>,
    username_validator: Option<UsernameValidator>,
    display_username_validator: Option<Option<UsernameValidator>>,
    username_normalization: Option<Option<UsernameNormalizer>>,
    display_username_normalization: Option<Option<UsernameNormalizer>>,
    validation_order: Option<ValidationOrder>,
    schema: Option<super::schema::UsernameSchemaOptions>,
}

impl UsernameOptionsBuilder {
    #[must_use]
    pub fn min_username_length(mut self, length: usize) -> Self {
        self.min_username_length = Some(length);
        self
    }

    #[must_use]
    pub fn max_username_length(mut self, length: usize) -> Self {
        self.max_username_length = Some(length);
        self
    }

    #[must_use]
    pub fn username_validator(mut self, validator: UsernameValidator) -> Self {
        self.username_validator = Some(validator);
        self
    }

    #[must_use]
    pub fn display_username_validator(mut self, validator: UsernameValidator) -> Self {
        self.display_username_validator = Some(Some(validator));
        self
    }

    #[must_use]
    pub fn username_normalization(mut self, normalizer: UsernameNormalizer) -> Self {
        self.username_normalization = Some(Some(normalizer));
        self
    }

    #[must_use]
    pub fn display_username_normalization(mut self, normalizer: UsernameNormalizer) -> Self {
        self.display_username_normalization = Some(Some(normalizer));
        self
    }

    #[must_use]
    pub fn validation_order(mut self, validation_order: ValidationOrder) -> Self {
        self.validation_order = Some(validation_order);
        self
    }

    #[must_use]
    pub fn schema(mut self, schema: super::schema::UsernameSchemaOptions) -> Self {
        self.schema = Some(schema);
        self
    }

    #[must_use]
    pub fn build(self) -> UsernameOptions {
        let defaults = UsernameOptions::default();
        UsernameOptions {
            min_username_length: self
                .min_username_length
                .unwrap_or(defaults.min_username_length),
            max_username_length: self
                .max_username_length
                .unwrap_or(defaults.max_username_length),
            username_validator: self
                .username_validator
                .unwrap_or(defaults.username_validator),
            display_username_validator: self
                .display_username_validator
                .unwrap_or(defaults.display_username_validator),
            username_normalization: self
                .username_normalization
                .unwrap_or(defaults.username_normalization),
            display_username_normalization: self
                .display_username_normalization
                .unwrap_or(defaults.display_username_normalization),
            validation_order: self.validation_order.unwrap_or(defaults.validation_order),
            schema: self.schema.unwrap_or(defaults.schema),
        }
    }
}
