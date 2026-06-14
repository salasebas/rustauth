use std::sync::Arc;
use time::Duration;

use super::resolve::LoginMethodContext;

pub const DEFAULT_COOKIE_NAME: &str = "better-auth.last_used_login_method";
pub const DEFAULT_COOKIE_MAX_AGE: Duration = Duration::days(30);
pub const DEFAULT_DATABASE_FIELD_NAME: &str = "last_login_method";

type LoginMethodResolver =
    Arc<dyn Fn(&LoginMethodContext) -> Option<String> + Send + Sync + 'static>;

/// Configuration for tracking the most recent successful login method.
#[derive(Clone, Default)]
pub struct LastLoginMethodOptions {
    pub cookie_name: Option<String>,
    pub max_age: Option<Duration>,
    pub resolver: Option<LoginMethodResolver>,
    pub store_in_database: bool,
    pub database_field_name: Option<String>,
}

impl LastLoginMethodOptions {
    #[must_use]
    pub fn builder() -> LastLoginMethodOptionsBuilder {
        LastLoginMethodOptionsBuilder::default()
    }

    pub fn cookie_name(mut self, cookie_name: impl Into<String>) -> Self {
        self.cookie_name = Some(cookie_name.into());
        self
    }

    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    pub fn with_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&LoginMethodContext) -> Option<String> + Send + Sync + 'static,
    {
        self.resolver = Some(Arc::new(resolver));
        self
    }

    pub fn store_in_database(mut self, store_in_database: bool) -> Self {
        self.store_in_database = store_in_database;
        self
    }

    pub fn database_field_name(mut self, field_name: impl Into<String>) -> Self {
        self.database_field_name = Some(field_name.into());
        self
    }

    pub fn effective_cookie_name(&self) -> &str {
        self.cookie_name.as_deref().unwrap_or(DEFAULT_COOKIE_NAME)
    }

    pub fn effective_max_age(&self) -> u64 {
        self.max_age
            .unwrap_or(DEFAULT_COOKIE_MAX_AGE)
            .whole_seconds() as u64
    }

    pub fn effective_database_field_name(&self) -> &str {
        self.database_field_name
            .as_deref()
            .unwrap_or(DEFAULT_DATABASE_FIELD_NAME)
    }

    pub fn resolve_login_method(&self, context: &LoginMethodContext) -> Option<String> {
        self.resolver
            .as_ref()
            .and_then(|resolver| resolver(context))
            .or_else(|| super::resolve::default_login_method(context))
    }
}

#[derive(Clone, Default)]
pub struct LastLoginMethodOptionsBuilder {
    cookie_name: Option<String>,
    max_age: Option<Duration>,
    resolver: Option<LoginMethodResolver>,
    store_in_database: Option<bool>,
    database_field_name: Option<String>,
}

impl LastLoginMethodOptionsBuilder {
    #[must_use]
    pub fn cookie_name(mut self, cookie_name: impl Into<String>) -> Self {
        self.cookie_name = Some(cookie_name.into());
        self
    }

    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    #[must_use]
    pub fn with_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&LoginMethodContext) -> Option<String> + Send + Sync + 'static,
    {
        self.resolver = Some(Arc::new(resolver));
        self
    }

    #[must_use]
    pub fn store_in_database(mut self, store_in_database: bool) -> Self {
        self.store_in_database = Some(store_in_database);
        self
    }

    #[must_use]
    pub fn database_field_name(mut self, field_name: impl Into<String>) -> Self {
        self.database_field_name = Some(field_name.into());
        self
    }

    #[must_use]
    pub fn build(self) -> LastLoginMethodOptions {
        let defaults = LastLoginMethodOptions::default();
        LastLoginMethodOptions {
            cookie_name: self.cookie_name.or(defaults.cookie_name),
            max_age: self.max_age.or(defaults.max_age),
            resolver: self.resolver.or(defaults.resolver),
            store_in_database: self.store_in_database.unwrap_or(defaults.store_in_database),
            database_field_name: self.database_field_name.or(defaults.database_field_name),
        }
    }
}
