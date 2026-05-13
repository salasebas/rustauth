//! i18n plugin: translate API error JSON using locale detection.

use std::collections::HashSet;
use std::sync::Arc;

use openauth_core::api::{ApiErrorResponse, ApiRequest};
use openauth_core::context::request_state::current_session_user;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;

use crate::accept_language::parse_accept_language;
use crate::cookie::cookie_value;
use crate::error::I18nConfigError;
use crate::types::{I18nOptions, LocaleDetectionStrategy};

fn strategy_name(strategy: LocaleDetectionStrategy) -> &'static str {
    match strategy {
        LocaleDetectionStrategy::Header => "header",
        LocaleDetectionStrategy::Cookie => "cookie",
        LocaleDetectionStrategy::Session => "session",
        LocaleDetectionStrategy::Callback => "callback",
    }
}

struct I18nPluginState {
    translations: Arc<indexmap::IndexMap<String, indexmap::IndexMap<String, String>>>,
    default_locale: String,
    detection: Vec<LocaleDetectionStrategy>,
    locale_cookie: String,
    user_locale_field: String,
    get_locale: Option<crate::types::LocaleResolver>,
    resolve_user_locale: Option<crate::types::LocaleResolver>,
}

fn resolve_default_locale(options: &I18nOptions) -> Result<String, I18nConfigError> {
    if options.translations.is_empty() {
        return Err(I18nConfigError::EmptyTranslations);
    }
    if let Some(d) = options.default_locale.as_ref() {
        if options.translations.contains_key(d) {
            return Ok(d.clone());
        }
        return Err(I18nConfigError::UnknownDefaultLocale(d.clone()));
    }
    if options.translations.contains_key("en") {
        return Ok("en".to_owned());
    }
    options
        .translations
        .keys()
        .next()
        .cloned()
        .ok_or(I18nConfigError::EmptyTranslations)
}

fn detect_locale(state: &I18nPluginState, context: &AuthContext, request: &ApiRequest) -> String {
    let available: HashSet<&str> = state.translations.keys().map(String::as_str).collect();

    for strategy in &state.detection {
        let found: Option<String> = match strategy {
            LocaleDetectionStrategy::Header => {
                let header = request
                    .headers()
                    .get("accept-language")
                    .and_then(|v| v.to_str().ok());
                parse_accept_language(header)
                    .into_iter()
                    .find(|l| available.contains(l.as_str()))
            }
            LocaleDetectionStrategy::Cookie => {
                let cookie_header = request
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|v| v.to_str().ok());
                cookie_value(cookie_header, &state.locale_cookie)
                    .filter(|v| available.contains(v.as_str()))
            }
            LocaleDetectionStrategy::Session => state
                .resolve_user_locale
                .as_ref()
                .and_then(|f| f(context, request))
                .or_else(|| {
                    current_session_user()
                        .ok()
                        .flatten()
                        .as_ref()?
                        .get(&state.user_locale_field)?
                        .as_str()
                        .map(str::to_owned)
                })
                .filter(|l| available.contains(l.as_str())),
            LocaleDetectionStrategy::Callback => state
                .get_locale
                .as_ref()
                .and_then(|f| f(context, request))
                .filter(|l| available.contains(l.as_str())),
        };
        if let Some(locale) = found {
            return locale;
        }
    }
    state.default_locale.clone()
}

/// i18n plugin for OpenAuth: translates `message` on JSON error responses using `code` as the lookup key.
///
/// Behavior matches Better Auth `@better-auth/i18n` 1.6.9 (locale detection + `originalMessage` on translate).
pub fn i18n(options: I18nOptions) -> Result<AuthPlugin, I18nConfigError> {
    let default_locale = resolve_default_locale(&options)?;
    let detection = if options.detection.is_empty() {
        vec![LocaleDetectionStrategy::Header]
    } else {
        options.detection.clone()
    };
    let options_metadata = serde_json::json!({
        "defaultLocale": default_locale,
        "detection": detection.iter().copied().map(strategy_name).collect::<Vec<_>>(),
        "localeCookie": options.locale_cookie,
        "userLocaleField": options.user_locale_field,
        "translationLocales": options.translations.keys().cloned().collect::<Vec<_>>(),
    });
    let state = Arc::new(I18nPluginState {
        translations: Arc::new(options.translations),
        default_locale: default_locale.clone(),
        detection,
        locale_cookie: options.locale_cookie,
        user_locale_field: options.user_locale_field,
        get_locale: options.get_locale,
        resolve_user_locale: options.resolve_user_locale,
    });

    let state_hook = Arc::clone(&state);
    Ok(AuthPlugin::new("i18n")
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(options_metadata)
        .with_on_response(move |context, request, mut response| {
            if response.status().is_success() {
                return Ok(response);
            }
            let body = response.body();
            if body.is_empty() {
                return Ok(response);
            }
            let mut err: ApiErrorResponse = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => return Ok(response),
            };
            if err.code.is_empty() {
                return Ok(response);
            }
            let locale = detect_locale(state_hook.as_ref(), context, request);
            let Some(translated) = state_hook
                .translations
                .get(&locale)
                .and_then(|m| m.get(&err.code))
                .cloned()
            else {
                return Ok(response);
            };
            let previous = err.message.clone();
            err.message = translated;
            err.original_message = Some(previous);
            let new_body =
                serde_json::to_vec(&err).map_err(|e| OpenAuthError::Api(e.to_string()))?;
            *response.body_mut() = new_body;
            Ok(response)
        }))
}
