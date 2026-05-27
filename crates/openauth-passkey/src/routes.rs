use std::sync::Arc;

use http::header;
use openauth_core::api::{ApiRequest, AsyncAuthEndpoint};
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::options::{PasskeyExtensionsInput, PasskeyOptions};
use crate::webauthn::WebAuthnConfig;

mod authentication;
mod management;
mod registration;

pub fn endpoints(options: Arc<PasskeyOptions>) -> Vec<AsyncAuthEndpoint> {
    vec![
        registration::generate_register_options_endpoint(Arc::clone(&options)),
        authentication::generate_authenticate_options_endpoint(Arc::clone(&options)),
        registration::verify_registration_endpoint(Arc::clone(&options)),
        authentication::verify_authentication_endpoint(Arc::clone(&options)),
        management::list_passkeys_endpoint(Arc::clone(&options)),
        management::delete_passkey_endpoint(Arc::clone(&options)),
        management::update_passkey_endpoint(options),
    ]
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyRegistrationBody {
    pub response: Value,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyAuthenticationBody {
    pub response: Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IdBody {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdatePasskeyBody {
    pub id: String,
    pub name: String,
}

pub(crate) fn adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("passkey requires a database adapter".to_owned())
    })
}

pub(crate) fn webauthn_config(
    context: &AuthContext,
    options: &PasskeyOptions,
    request: &ApiRequest,
) -> Result<WebAuthnConfig, OpenAuthError> {
    let origins = if options.origin.is_empty() {
        request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(|origin| vec![origin.trim_end_matches('/').to_owned()])
            .or_else(|| (!context.base_url.is_empty()).then(|| vec![context.base_url.clone()]))
            .unwrap_or_else(|| vec!["http://localhost".to_owned()])
    } else {
        options.origin.clone()
    };
    let rp_id = options
        .rp_id
        .clone()
        .or_else(|| host_from_url(context.base_url.as_str()))
        .or_else(|| origins.first().and_then(|origin| host_from_url(origin)))
        .unwrap_or_else(|| "localhost".to_owned());
    Ok(WebAuthnConfig {
        rp_id,
        rp_name: options
            .rp_name
            .clone()
            .unwrap_or_else(|| context.app_name.clone()),
        origins,
    })
}

pub(crate) fn verification_webauthn_config(
    context: &AuthContext,
    options: &PasskeyOptions,
    request: &ApiRequest,
) -> Result<Option<WebAuthnConfig>, OpenAuthError> {
    let origins = if options.origin.is_empty() {
        let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        else {
            return Ok(None);
        };
        vec![origin.trim_end_matches('/').to_owned()]
    } else {
        options.origin.clone()
    };
    let rp_id = options
        .rp_id
        .clone()
        .or_else(|| host_from_url(context.base_url.as_str()))
        .or_else(|| origins.first().and_then(|origin| host_from_url(origin)))
        .unwrap_or_else(|| "localhost".to_owned());
    Ok(Some(WebAuthnConfig {
        rp_id,
        rp_name: options
            .rp_name
            .clone()
            .unwrap_or_else(|| context.app_name.clone()),
        origins,
    }))
}

fn host_from_url(value: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

pub(crate) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
    })
}

pub(crate) async fn resolve_extensions(
    resolver: &Option<crate::options::PasskeyExtensionsResolver>,
    input: PasskeyExtensionsInput,
) -> Option<Value> {
    match resolver {
        Some(resolver) => resolver(input).await,
        None => None,
    }
}
