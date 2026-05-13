//! Configuration errors for the i18n plugin.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum I18nConfigError {
    #[error("i18n plugin: translations object is empty. At least one locale must be provided.")]
    EmptyTranslations,

    #[error("i18n plugin: defaultLocale `{0}` is not present in translations")]
    UnknownDefaultLocale(String),
}
