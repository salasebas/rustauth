//! Internationalization plugin for OpenAuth (Better Auth `i18n` parity).

mod accept_language;
mod cookie;
mod error;
mod locale;
mod locale_state;
mod plugin;
mod response;
pub mod types;

pub use error::I18nConfigError;
pub use plugin::i18n;
pub use types::{
    translation_dictionary, AsyncLocaleResolver, I18nOptions, LocaleDetectionStrategy,
    LocaleResolver, TranslationDictionary, TranslationKey,
};

/// Crate version (matches Better Auth package `version.ts` intent).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
