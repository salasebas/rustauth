use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_core::error::RustAuthError;

use super::hooks::AnonymousLinkAccount;

pub type AnonymousOptionFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
pub type GenerateRandomEmail = Arc<dyn Fn() -> AnonymousOptionFuture<String> + Send + Sync>;
pub type GenerateName = Arc<dyn Fn() -> AnonymousOptionFuture<String> + Send + Sync>;
pub type OnLinkAccount = Arc<
    dyn Fn(AnonymousLinkAccount) -> AnonymousOptionFuture<Result<(), RustAuthError>> + Send + Sync,
>;

#[derive(Clone, Default)]
pub struct AnonymousOptions {
    pub email_domain_name: Option<String>,
    pub generate_random_email: Option<GenerateRandomEmail>,
    pub generate_name: Option<GenerateName>,
    pub disable_delete_anonymous_user: bool,
    pub on_link_account: Option<OnLinkAccount>,
    pub field_name: Option<String>,
}

impl AnonymousOptions {
    #[must_use]
    pub fn builder() -> AnonymousOptionsBuilder {
        AnonymousOptionsBuilder::default()
    }

    pub(crate) fn storage_field_name(&self) -> &str {
        self.field_name.as_deref().unwrap_or("is_anonymous")
    }

    #[must_use]
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(domain.into());
        self
    }

    #[must_use]
    pub fn generate_random_email<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.generate_random_email = Some(Arc::new(move || {
            let value = generator();
            Box::pin(std::future::ready(value))
        }));
        self
    }

    #[must_use]
    pub fn generate_random_email_async<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        self.generate_random_email = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    #[must_use]
    pub fn generate_name<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.generate_name = Some(Arc::new(move || {
            let value = generator();
            Box::pin(std::future::ready(value))
        }));
        self
    }

    #[must_use]
    pub fn generate_name_async<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        self.generate_name = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    #[must_use]
    pub fn disable_delete_anonymous_user(mut self, disabled: bool) -> Self {
        self.disable_delete_anonymous_user = disabled;
        self
    }

    #[must_use]
    pub fn on_link_account<F>(mut self, callback: F) -> Self
    where
        F: Fn(AnonymousLinkAccount) -> Result<(), RustAuthError> + Send + Sync + 'static,
    {
        self.on_link_account = Some(Arc::new(move |data| {
            let result = callback(data);
            Box::pin(std::future::ready(result))
        }));
        self
    }

    #[must_use]
    pub fn on_link_account_async<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(AnonymousLinkAccount) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), RustAuthError>> + Send + 'static,
    {
        self.on_link_account = Some(Arc::new(move |data| Box::pin(callback(data))));
        self
    }

    #[must_use]
    pub fn field_name(mut self, field_name: impl Into<String>) -> Self {
        self.field_name = Some(field_name.into());
        self
    }
}

#[derive(Clone, Default)]
pub struct AnonymousOptionsBuilder {
    email_domain_name: Option<String>,
    generate_random_email: Option<GenerateRandomEmail>,
    generate_name: Option<GenerateName>,
    disable_delete_anonymous_user: Option<bool>,
    on_link_account: Option<OnLinkAccount>,
    field_name: Option<String>,
}

impl AnonymousOptionsBuilder {
    #[must_use]
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(domain.into());
        self
    }

    #[must_use]
    pub fn generate_random_email(mut self, generator: GenerateRandomEmail) -> Self {
        self.generate_random_email = Some(generator);
        self
    }

    #[must_use]
    pub fn generate_name(mut self, generator: GenerateName) -> Self {
        self.generate_name = Some(generator);
        self
    }

    #[must_use]
    pub fn disable_delete_anonymous_user(mut self, disabled: bool) -> Self {
        self.disable_delete_anonymous_user = Some(disabled);
        self
    }

    #[must_use]
    pub fn on_link_account(mut self, callback: OnLinkAccount) -> Self {
        self.on_link_account = Some(callback);
        self
    }

    #[must_use]
    pub fn field_name(mut self, field_name: impl Into<String>) -> Self {
        self.field_name = Some(field_name.into());
        self
    }

    #[must_use]
    pub fn build(self) -> AnonymousOptions {
        let defaults = AnonymousOptions::default();
        AnonymousOptions {
            email_domain_name: self.email_domain_name.or(defaults.email_domain_name),
            generate_random_email: self
                .generate_random_email
                .or(defaults.generate_random_email),
            generate_name: self.generate_name.or(defaults.generate_name),
            disable_delete_anonymous_user: self
                .disable_delete_anonymous_user
                .unwrap_or(defaults.disable_delete_anonymous_user),
            on_link_account: self.on_link_account.or(defaults.on_link_account),
            field_name: self.field_name.or(defaults.field_name),
        }
    }
}
