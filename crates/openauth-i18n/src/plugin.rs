//! i18n plugin: translate API error JSON using locale detection.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::api::ApiRequest;
use openauth_core::context::request_state::current_session_user;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;

use crate::accept_language::parse_accept_language;
use crate::cookie::cookie_value;
use crate::error::I18nConfigError;
use crate::locale::LocaleCatalog;
use crate::locale_state::{detected_locale, set_detected_locale};
use crate::response::translate_response;
use crate::types::{AsyncLocaleResolver, I18nOptions, LocaleDetectionStrategy, LocaleResolver};

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
    locale_catalog: LocaleCatalog,
    default_locale: String,
    detection: Vec<LocaleDetectionStrategy>,
    locale_cookie: String,
    user_locale_field: String,
    get_locale: Option<LocaleResolver>,
    get_locale_async: Option<AsyncLocaleResolver>,
    resolve_user_locale: Option<LocaleResolver>,
}

fn resolve_default_locale(
    options: &I18nOptions,
    locale_catalog: &LocaleCatalog,
) -> Result<String, I18nConfigError> {
    if let Some(d) = options.default_locale.as_ref() {
        if let Some(locale) = locale_catalog.match_locale(d) {
            return Ok(locale.to_owned());
        }
        return Err(I18nConfigError::UnknownDefaultLocale(d.clone()));
    }
    if let Some(locale) = locale_catalog.match_locale("en") {
        return Ok(locale.to_owned());
    }
    options
        .translations
        .keys()
        .next()
        .cloned()
        .ok_or(I18nConfigError::EmptyTranslations)
}

fn validate_options(
    options: &I18nOptions,
    detection: &[LocaleDetectionStrategy],
) -> Result<(), I18nConfigError> {
    if detection.contains(&LocaleDetectionStrategy::Cookie)
        && options.locale_cookie.trim().is_empty()
    {
        return Err(I18nConfigError::EmptyLocaleCookie);
    }
    if detection.contains(&LocaleDetectionStrategy::Session)
        && options.user_locale_field.trim().is_empty()
    {
        return Err(I18nConfigError::EmptyUserLocaleField);
    }
    Ok(())
}

fn header_locale(state: &I18nPluginState, request: &ApiRequest) -> Option<String> {
    let header = request
        .headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok());
    parse_accept_language(header)
        .into_iter()
        .find_map(|locale| {
            state
                .locale_catalog
                .match_locale(&locale)
                .map(str::to_owned)
        })
}

fn cookie_locale(state: &I18nPluginState, request: &ApiRequest) -> Option<String> {
    let cookie_header = request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok());
    cookie_value(cookie_header, &state.locale_cookie).and_then(|locale| {
        state
            .locale_catalog
            .match_locale(&locale)
            .map(str::to_owned)
    })
}

fn session_locale(
    state: &I18nPluginState,
    context: &AuthContext,
    request: &ApiRequest,
) -> Option<String> {
    state
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
        .and_then(|locale| {
            state
                .locale_catalog
                .match_locale(&locale)
                .map(str::to_owned)
        })
}

fn callback_locale_sync(
    state: &I18nPluginState,
    context: &AuthContext,
    request: &ApiRequest,
) -> Option<String> {
    state
        .get_locale
        .as_ref()
        .and_then(|f| f(context, request))
        .and_then(|locale| {
            state
                .locale_catalog
                .match_locale(&locale)
                .map(str::to_owned)
        })
}

fn callback_locale_async<'a>(
    state: &'a I18nPluginState,
    context: &'a AuthContext,
    request: &'a ApiRequest,
) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
    let resolver = state.get_locale_async.clone();
    let locale_catalog = state.locale_catalog.clone();
    Box::pin(async move {
        let resolver = resolver?;
        let locale = resolver(context, request).await?;
        locale_catalog.match_locale(&locale).map(str::to_owned)
    })
}

fn detect_locale(state: &I18nPluginState, context: &AuthContext, request: &ApiRequest) -> String {
    if let Ok(Some(locale)) = detected_locale() {
        return locale;
    }
    for strategy in &state.detection {
        let found = match strategy {
            LocaleDetectionStrategy::Header => header_locale(state, request),
            LocaleDetectionStrategy::Cookie => cookie_locale(state, request),
            LocaleDetectionStrategy::Session => session_locale(state, context, request),
            LocaleDetectionStrategy::Callback => callback_locale_sync(state, context, request),
        };
        if let Some(locale) = found {
            return locale;
        }
    }
    state.default_locale.clone()
}

async fn detect_locale_async(
    state: &I18nPluginState,
    context: &AuthContext,
    request: &ApiRequest,
) -> String {
    for strategy in &state.detection {
        let found = match strategy {
            LocaleDetectionStrategy::Header => header_locale(state, request),
            LocaleDetectionStrategy::Cookie => cookie_locale(state, request),
            LocaleDetectionStrategy::Session => session_locale(state, context, request),
            LocaleDetectionStrategy::Callback => {
                callback_locale_async(state, context, request).await
            }
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
    let locale_catalog = LocaleCatalog::new(&options.translations)?;
    let detection = if options.detection.is_empty() {
        vec![LocaleDetectionStrategy::Header]
    } else {
        options.detection.clone()
    };
    validate_options(&options, &detection)?;
    let default_locale = resolve_default_locale(&options, &locale_catalog)?;
    let options_metadata = serde_json::json!({
        "defaultLocale": default_locale,
        "detection": detection.iter().copied().map(strategy_name).collect::<Vec<_>>(),
        "localeCookie": options.locale_cookie,
        "userLocaleField": options.user_locale_field,
        "translationLocales": options.translations.keys().cloned().collect::<Vec<_>>(),
    });
    let state = Arc::new(I18nPluginState {
        translations: Arc::new(options.translations),
        locale_catalog,
        default_locale: default_locale.clone(),
        detection,
        locale_cookie: options.locale_cookie,
        user_locale_field: options.user_locale_field,
        get_locale: options.get_locale,
        get_locale_async: options.get_locale_async,
        resolve_user_locale: options.resolve_user_locale,
    });

    let state_hook = Arc::clone(&state);
    let mut plugin = AuthPlugin::new("i18n")
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(options_metadata)
        .with_on_response(move |context, request, mut response| {
            if response.status().is_success() {
                return Ok(response);
            }
            let locale = detect_locale(state_hook.as_ref(), context, request);
            let Some(dictionary) = state_hook.translations.get(&locale) else {
                return Ok(response);
            };
            translate_response(&mut response, dictionary)?;
            Ok(response)
        });

    if state.get_locale_async.is_some() {
        let state_async = Arc::clone(&state);
        plugin = plugin.with_on_response_async(
            move |context, request, response| -> Pin<Box<dyn Future<Output = Result<(), OpenAuthError>> + Send + '_>> {
                let state_async = Arc::clone(&state_async);
                Box::pin(async move {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    let locale =
                        detect_locale_async(state_async.as_ref(), context, request).await;
                    set_detected_locale(locale)?;
                    Ok(())
                })
            },
        );
    }

    Ok(plugin)
}
