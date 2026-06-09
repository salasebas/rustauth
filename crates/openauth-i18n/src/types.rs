//! Options for the OpenAuth i18n plugin (parity with `@better-auth/i18n`).

use indexmap::IndexMap;
use openauth_core::api::{ApiErrorCode, ApiRequest};
use openauth_core::auth::email_password::AuthFlowErrorCode;
use openauth_core::context::AuthContext;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Sync resolver for locale from the incoming request (callback / session hooks).
pub type LocaleResolver = Arc<dyn Fn(&AuthContext, &ApiRequest) -> Option<String> + Send + Sync>;

/// Async resolver for locale from the incoming request (callback strategy on async router paths).
pub type AsyncLocaleResolver = Arc<
    dyn for<'a> Fn(
            &'a AuthContext,
            &'a ApiRequest,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>>
        + Send
        + Sync,
>;

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
///
/// # Examples
///
/// ```rust
/// use openauth_i18n::translation_dictionary;
///
/// let dictionary = translation_dictionary([("INVALID_EMAIL", "Invalid email")]);
///
/// assert_eq!(
///     dictionary.get("INVALID_EMAIL").map(String::as_str),
///     Some("Invalid email")
/// );
/// ```
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
#[non_exhaustive]
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
    /// Used when [`LocaleDetectionStrategy::Callback`] is enabled on synchronous router paths.
    pub get_locale: Option<LocaleResolver>,
    /// Used when [`LocaleDetectionStrategy::Callback`] is enabled on [`AuthRouter::handle_async`](openauth_core::api::AuthRouter::handle_async).
    pub get_locale_async: Option<AsyncLocaleResolver>,
    /// Used when [`LocaleDetectionStrategy::Session`] is enabled — return the user’s stored locale (e.g. after loading session).
    pub resolve_user_locale: Option<LocaleResolver>,
}

impl Default for I18nOptions {
    fn default() -> Self {
        Self {
            translations: IndexMap::new(),
            default_locale: None,
            detection: vec![LocaleDetectionStrategy::Header],
            locale_cookie: "locale".to_owned(),
            user_locale_field: "locale".to_owned(),
            get_locale: None,
            get_locale_async: None,
            resolve_user_locale: None,
        }
    }
}

impl I18nOptions {
    /// Build options with defaults matching Better Auth; add locales via [`.locale`](Self::locale).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openauth_i18n::{
    ///     translation_dictionary, I18nOptions, LocaleDetectionStrategy,
    /// };
    ///
    /// let options = I18nOptions::new()
    ///     .locale("fr", [("INVALID_EMAIL", "Email invalide")])
    ///     .default_locale("fr")
    ///     .detection([LocaleDetectionStrategy::Cookie, LocaleDetectionStrategy::Header])
    ///     .locale_cookie("lang");
    ///
    /// assert_eq!(options.default_locale.as_deref(), Some("fr"));
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a locale dictionary.
    pub fn locale<K, V, I>(mut self, code: impl Into<String>, entries: I) -> Self
    where
        K: TranslationKey,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.translations
            .insert(code.into(), translation_dictionary(entries));
        self
    }

    /// Build options from a pre-built locale map (used by migrations and tests).
    pub fn from_translations(translations: IndexMap<String, TranslationDictionary>) -> Self {
        Self {
            translations,
            ..Self::default()
        }
    }

    /// Set the default/fallback locale.
    pub fn default_locale(mut self, locale: impl Into<String>) -> Self {
        self.default_locale = Some(locale.into());
        self
    }

    /// Set locale detection strategies in priority order.
    pub fn detection<I>(mut self, detection: I) -> Self
    where
        I: IntoIterator<Item = LocaleDetectionStrategy>,
    {
        self.detection = detection.into_iter().collect();
        self
    }

    /// Set the cookie name used by [`LocaleDetectionStrategy::Cookie`].
    pub fn locale_cookie(mut self, name: impl Into<String>) -> Self {
        self.locale_cookie = name.into();
        self
    }

    /// Set the user field read by [`LocaleDetectionStrategy::Session`].
    pub fn user_locale_field(mut self, field: impl Into<String>) -> Self {
        self.user_locale_field = field.into();
        self
    }

    /// Set the synchronous callback resolver used by [`LocaleDetectionStrategy::Callback`].
    pub fn get_locale(mut self, resolver: LocaleResolver) -> Self {
        self.get_locale = Some(resolver);
        self
    }

    /// Set the async callback resolver used by [`LocaleDetectionStrategy::Callback`].
    pub fn get_locale_async(mut self, resolver: AsyncLocaleResolver) -> Self {
        self.get_locale_async = Some(resolver);
        self
    }

    /// Set the session locale resolver used by [`LocaleDetectionStrategy::Session`].
    pub fn resolve_user_locale(mut self, resolver: LocaleResolver) -> Self {
        self.resolve_user_locale = Some(resolver);
        self
    }
}

impl fmt::Debug for I18nOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("I18nOptions")
            .field("translations", &self.translations)
            .field("default_locale", &self.default_locale)
            .field("detection", &self.detection)
            .field("locale_cookie", &self.locale_cookie)
            .field("user_locale_field", &self.user_locale_field)
            .field(
                "get_locale",
                &self.get_locale.as_ref().map(|_| "<locale-resolver>"),
            )
            .field(
                "get_locale_async",
                &self
                    .get_locale_async
                    .as_ref()
                    .map(|_| "<async-locale-resolver>"),
            )
            .field(
                "resolve_user_locale",
                &self
                    .resolve_user_locale
                    .as_ref()
                    .map(|_| "<locale-resolver>"),
            )
            .finish()
    }
}
