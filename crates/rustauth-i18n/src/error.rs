//! Configuration errors for the i18n plugin.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum I18nConfigError {
    #[error("i18n plugin: translations object is empty. At least one locale must be provided.")]
    EmptyTranslations,

    #[error("i18n plugin: defaultLocale `{0}` is not present in translations")]
    UnknownDefaultLocale(String),

    #[error("i18n plugin: duplicate locale `{0}` after case-insensitive normalization")]
    DuplicateLocale(String),

    #[error("i18n plugin: localeCookie cannot be empty when cookie detection is enabled")]
    EmptyLocaleCookie,

    #[error("i18n plugin: userLocaleField cannot be empty when session detection is enabled")]
    EmptyUserLocaleField,
}
