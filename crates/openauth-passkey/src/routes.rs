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

const PASSKEY_ORIGIN_REQUIRED: &str =
    "passkey requires an explicit origin, a request Origin header, or a configured base_url";
const PASSKEY_RP_ID_REQUIRED: &str =
    "passkey requires an explicit rp_id or a host derivable from base_url or origin";

fn resolve_passkey_origins(
    context: &AuthContext,
    options: &PasskeyOptions,
    request: &ApiRequest,
) -> Result<Vec<String>, OpenAuthError> {
    if !options.origin.is_empty() {
        return Ok(options.origin.clone());
    }
    if let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return Ok(vec![origin.trim_end_matches('/').to_owned()]);
    }
    if !context.base_url.is_empty() {
        return Ok(vec![context.base_url.trim_end_matches('/').to_owned()]);
    }
    Err(OpenAuthError::InvalidConfig(
        PASSKEY_ORIGIN_REQUIRED.to_owned(),
    ))
}

fn resolve_passkey_rp_id(
    context: &AuthContext,
    options: &PasskeyOptions,
    origins: &[String],
) -> Result<String, OpenAuthError> {
    if let Some(rp_id) = &options.rp_id {
        return Ok(rp_id.clone());
    }
    if let Some(host) = host_from_url(context.base_url.as_str()) {
        return Ok(host);
    }
    if let Some(host) = origins.first().and_then(|origin| host_from_url(origin)) {
        return Ok(host);
    }
    Err(OpenAuthError::InvalidConfig(
        PASSKEY_RP_ID_REQUIRED.to_owned(),
    ))
}

fn passkey_webauthn_config(
    context: &AuthContext,
    options: &PasskeyOptions,
    origins: Vec<String>,
) -> Result<WebAuthnConfig, OpenAuthError> {
    let rp_id = resolve_passkey_rp_id(context, options, &origins)?;
    Ok(WebAuthnConfig {
        rp_id,
        rp_name: options
            .rp_name
            .clone()
            .unwrap_or_else(|| context.app_name.clone()),
        origins,
    })
}

pub(crate) fn webauthn_config(
    context: &AuthContext,
    options: &PasskeyOptions,
    request: &ApiRequest,
) -> Result<WebAuthnConfig, OpenAuthError> {
    let origins = resolve_passkey_origins(context, options, request)?;
    passkey_webauthn_config(context, options, origins)
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
    Ok(Some(passkey_webauthn_config(context, options, origins)?))
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

#[cfg(test)]
mod config_tests {
    use http::{Method, Request};
    use openauth_core::context::create_auth_context;
    use openauth_core::error::OpenAuthError;
    use openauth_core::options::OpenAuthOptions;

    use super::*;
    use crate::options::PasskeyOptions;

    fn test_context(base_url: Option<&str>) -> AuthContext {
        create_auth_context(OpenAuthOptions {
            base_url: base_url.map(str::to_owned),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        })
        .expect("test auth context")
    }

    fn test_request(origin: Option<&str>) -> ApiRequest {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri("http://example.test/api/auth/passkey/generate-register-options");
        if let Some(origin) = origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        builder.body(Vec::new()).expect("test request")
    }

    #[test]
    fn missing_origin_and_base_url_is_invalid_config() {
        let context = test_context(None);
        let options = PasskeyOptions::default();
        let request = test_request(None);

        assert_eq!(
            webauthn_config(&context, &options, &request).unwrap_err(),
            OpenAuthError::InvalidConfig(PASSKEY_ORIGIN_REQUIRED.to_owned())
        );
    }

    #[test]
    fn missing_rp_id_derivation_is_invalid_config() {
        let context = test_context(None);
        let options = PasskeyOptions::default().origin("not-a-valid-url");
        let request = test_request(None);

        assert_eq!(
            webauthn_config(&context, &options, &request).unwrap_err(),
            OpenAuthError::InvalidConfig(PASSKEY_RP_ID_REQUIRED.to_owned())
        );
    }

    #[test]
    fn production_like_explicit_origin_and_rp_id() {
        let context = test_context(None);
        let options = PasskeyOptions::default()
            .origin("https://auth.example.com")
            .rp_id("example.com")
            .rp_name("Example");
        let request = test_request(None);

        let config = webauthn_config(&context, &options, &request).expect("config");
        assert_eq!(config.rp_id, "example.com");
        assert_eq!(config.rp_name, "Example");
        assert_eq!(config.origins, vec!["https://auth.example.com"]);
    }

    #[test]
    fn base_url_derives_origin_and_rp_id_for_local_dev() {
        let context = test_context(Some("http://localhost:3000"));
        let options = PasskeyOptions::default();
        let request = test_request(None);

        let config = webauthn_config(&context, &options, &request).expect("config");
        assert_eq!(config.origins, vec!["http://localhost:3000"]);
        assert_eq!(config.rp_id, "localhost");
    }

    #[test]
    fn request_origin_header_overrides_empty_plugin_origin() {
        let context = test_context(None);
        let options = PasskeyOptions::default();
        let request = test_request(Some("https://auth.example.com/"));

        let config = webauthn_config(&context, &options, &request).expect("config");
        assert_eq!(config.origins, vec!["https://auth.example.com"]);
        assert_eq!(config.rp_id, "auth.example.com");
    }

    #[test]
    fn verification_without_origin_returns_none() {
        let context = test_context(Some("http://localhost:3000"));
        let options = PasskeyOptions::default();
        let request = test_request(None);

        assert!(verification_webauthn_config(&context, &options, &request)
            .expect("verification config")
            .is_none());
    }

    #[test]
    fn verification_rejects_missing_rp_id_derivation() {
        let context = test_context(None);
        let options = PasskeyOptions::default();
        let request = test_request(Some("not-a-valid-url"));

        let error = verification_webauthn_config(&context, &options, &request).unwrap_err();
        assert_eq!(
            error,
            OpenAuthError::InvalidConfig(PASSKEY_RP_ID_REQUIRED.to_owned())
        );
    }
}
