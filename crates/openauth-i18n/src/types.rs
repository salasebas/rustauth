//! Options for the OpenAuth i18n plugin (parity with `@better-auth/i18n`).

use indexmap::IndexMap;
use openauth_core::api::{ApiErrorCode, ApiRequest};
use openauth_core::auth::email_password::AuthFlowErrorCode;
use openauth_core::context::AuthContext;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Sync resolver for locale from the incoming request (callback / session hooks).
pub type LocaleResolver = Arc<dyn Fn(&AuthContext, &ApiRequest) -> Option<String> + Send + Sync>;

/// Locale detection strategy order (checked in sequence until one yields a locale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocaleDetectionStrategy {
    Header,
    Cookie,
    Session,
    Callback,
}

/// Translation map: error code → localized message.
pub type TranslationDictionary = IndexMap<String, String>;

/// Value that can be used as an i18n translation error-code key.
pub trait TranslationKey {
    fn into_translation_key(self) -> String;
}

impl TranslationKey for String {
    fn into_translation_key(self) -> String {
        self
    }
}

impl TranslationKey for &str {
    fn into_translation_key(self) -> String {
        self.to_owned()
    }
}

impl TranslationKey for &String {
    fn into_translation_key(self) -> String {
        self.clone()
    }
}

impl TranslationKey for ApiErrorCode {
    fn into_translation_key(self) -> String {
        self.as_str().to_owned()
    }
}

impl TranslationKey for AuthFlowErrorCode {
    fn into_translation_key(self) -> String {
        self.as_str().to_owned()
    }
}

/// Build a translation dictionary from string keys or typed OpenAuth error-code enums.
pub fn translation_dictionary<K, V, I>(entries: I) -> TranslationDictionary
where
    K: TranslationKey,
    V: Into<String>,
    I: IntoIterator<Item = (K, V)>,
{
    entries
        .into_iter()
        .map(|(key, value)| (key.into_translation_key(), value.into()))
        .collect()
}

/// Options for [`crate::i18n`].
#[derive(Clone)]
pub struct I18nOptions {
    /// Translation dictionaries keyed by locale code (insertion order matters when picking a fallback locale).
    pub translations: IndexMap<String, TranslationDictionary>,
    /// Default locale when detection fails. Must exist in `translations` when set.
    pub default_locale: Option<String>,
    /// Strategies tried in order. Defaults to `[Header]`.
    pub detection: Vec<LocaleDetectionStrategy>,
    /// Cookie name when using [`LocaleDetectionStrategy::Cookie`]. Default: `"locale"`.
    pub locale_cookie: String,
    /// Session user field name for applications that map custom user locale fields. Default: `"locale"`.
    pub user_locale_field: String,
    /// Used when [`LocaleDetectionStrategy::Callback`] is enabled (sync only; Better Auth allows async).
    pub get_locale: Option<LocaleResolver>,
    /// Used when [`LocaleDetectionStrategy::Session`] is enabled — return the user’s stored locale (e.g. after loading session).
    pub resolve_user_locale: Option<LocaleResolver>,
}

impl I18nOptions {
    /// Build options with the given translation tables; other fields use defaults matching Better Auth.
    pub fn new(translations: IndexMap<String, TranslationDictionary>) -> Self {
        Self {
            translations,
            default_locale: None,
            detection: vec![LocaleDetectionStrategy::Header],
            locale_cookie: "locale".to_owned(),
            user_locale_field: "locale".to_owned(),
            get_locale: None,
            resolve_user_locale: None,
        }
    }
}
