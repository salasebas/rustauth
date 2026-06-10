use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::Method;
use openauth_core::api::{
    create_auth_endpoint, session_cookies, ApiRequest, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use openauth_core::auth::oauth::{
    handle_oauth_user_info, parse_oauth_state_with_input, HandleOAuthUserInfoInput,
    OAuthAccountInput, OAuthStateParseInput, OAuthUserInfo,
};
use openauth_core::context::AuthContext;
use openauth_core::cookies::parse_cookies;
use openauth_oauth::oauth2::{
    exchange_authorization_code, AuthorizationCodeRequest, ClientAuthentication, ClientId,
    ClientSecret as OAuthClientSecret, OAuth2Tokens, ProviderOptions,
};
use openidconnect::core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet};
use openidconnect::{
    ClientId as OidcClientId, ClientSecret, IssuerUrl, JsonWebKeySetUrl, Nonce, NonceVerifier,
};
use serde_json::Value;
use std::str::FromStr;

use crate::linking_impl::{
    assign_organization_from_provider, provider_matches_email_domain, provision_sso_user,
    NormalizedSsoProfile,
};
use crate::oidc_impl::discovery::ensure_runtime_oidc_config_with_origin_validator;
pub(super) use crate::oidc_impl::discovery::OidcRuntimeRequirement;
use crate::oidc_impl::flow::oidc_redirect_uri;
use crate::openapi::redirect_response;
use crate::options::{OidcConfig, OidcMapping, SsoOptions, TokenEndpointAuthentication};
use crate::store::SsoProviderStore;
use crate::utils;

use super::support::{
    path_param, query_param, redirect, redirect_with_cookies, redirect_with_error,
};

pub(super) fn callback_endpoint(options: Arc<SsoOptions>, path: &'static str) -> AsyncAuthEndpoint {
    let operation_id = if path == "/sso/callback" {
        "handleSSOCallbackShared"
    } else {
        "handleSSOCallback"
    };
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id(operation_id)
            .openapi(
                OpenApiOperation::new(operation_id)
                    .tag("SSO")
                    .response("302", redirect_response("OIDC callback redirect")),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move { callback(context, &options, request).await })
        },
    )
}

async fn callback(
    context: &AuthContext,
    options: &SsoOptions,
    request: ApiRequest,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let default_error_url = format!("{}/error", context.base_url.trim_end_matches('/'));
    let Some(state) = query_param(&request, "state") else {
        return redirect(&default_error_url);
    };
    let Some(adapter) = context.adapter.as_deref() else {
        return redirect_with_error(&default_error_url, "invalid_state");
    };
    let oauth_state = oauth_state_cookie_value(context, &request);
    // SSO OIDC callbacks may be delivered as cross-site requests where
    // SameSite=Lax cookies are not sent. Validate the nonce whenever the cookie
    // is available, while preserving OIDC cross-site callback compatibility.
    let state_data = match parse_oauth_state_with_input(
        context,
        Some(adapter),
        OAuthStateParseInput {
            state: &state,
            oauth_state: oauth_state.as_deref(),
            skip_state_cookie_check: context.options.account.skip_state_cookie_check
                || oauth_state.is_none(),
        },
    )
    .await
    {
        Ok(data) => data,
        Err(_) => return redirect_with_error(&default_error_url, "invalid_state"),
    };
    let error_url = state_data
        .error_url
        .as_deref()
        .unwrap_or(&default_error_url);
    let error_url = utils::safe_redirect_url(context, error_url).unwrap_or(default_error_url);
    if let Some(error) = query_param(&request, "error") {
        return redirect_with_error(&error_url, &error);
    }
    if query_param(&request, "code").is_none() {
        return redirect_with_error(&error_url, "no_code");
    }
    let code = query_param(&request, "code").unwrap_or_default();

    let provider = match callback_provider(context, options, &request, &state_data).await? {
        CallbackProviderResult::Found(provider) => *provider,
        CallbackProviderResult::Missing => {
            return redirect_with_error(&error_url, "provider_not_found");
        }
        CallbackProviderResult::StateMismatch => {
            return redirect_with_error(&error_url, "invalid_state");
        }
    };
    let Some(config) = provider
        .oidc_config
        .as_deref()
        .and_then(|value| serde_json::from_str::<OidcConfig>(value).ok())
    else {
        return redirect_with_error(&error_url, "oidc_provider_not_configured");
    };
    let config = match ensure_runtime_oidc_config(
        context,
        &request,
        &provider.issuer,
        config,
        options,
        OidcRuntimeRequirement::Callback,
    )
    .await
    {
        Ok(config) => config,
        Err(error) => return redirect_with_error(&error_url, error.code()),
    };
    let Some(token_endpoint) = config.token_endpoint.clone() else {
        return redirect_with_error(&error_url, "invalid_oidc_config");
    };
    let allow_private_ips = options.oidc.allow_private_endpoint_ips;
    if ensure_oidc_endpoint_allowed(&token_endpoint, allow_private_ips).is_err() {
        return redirect_with_error(&error_url, "invalid_oidc_config");
    }
    let tokens = match exchange_authorization_code(
        &token_endpoint,
        AuthorizationCodeRequest {
            code,
            redirect_uri: oidc_redirect_uri(&context.base_url, &provider.provider_id, options),
            options: ProviderOptions {
                client_id: Some(ClientId::Single(config.client_id.clone())),
                client_secret: OAuthClientSecret::new(config.client_secret.expose_secret()).ok(),
                ..ProviderOptions::default()
            },
            code_verifier: config.pkce.then_some(state_data.code_verifier.clone()),
            authentication: oidc_client_authentication(&config),
            ..AuthorizationCodeRequest::default()
        },
        utils::oauth_http_client(allow_private_ips),
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(_) => return redirect_with_error(&error_url, "invalid_code"),
    };
    // Validate the OIDC authentication response before trusting any profile
    // source. OpenAuth always sends a `nonce` on the authorization request, so
    // the IdP MUST return a valid, nonce-bound ID token; validating it here
    // enforces issuer, audience, expiration, subject, nonce, and `azp`
    // regardless of whether a UserInfo endpoint is configured, instead of
    // completing the login from a UserInfo fetch alone.
    let id_token_payload = match validate_oidc_id_token(
        &tokens,
        &config,
        &provider.issuer,
        state_data
            .additional_data
            .get("oidcNonce")
            .and_then(Value::as_str),
        allow_private_ips,
    )
    .await
    {
        Ok(Some(payload)) => payload,
        _ => return redirect_with_error(&error_url, "invalid_id_token"),
    };
    let raw_user_info = if let Some(user_info_endpoint) = config.user_info_endpoint.as_deref() {
        let (user_info, user_info_subject) = match fetch_oidc_user_info(
            user_info_endpoint,
            &tokens,
            config.mapping.as_ref(),
            allow_private_ips,
        )
        .await
        {
            Ok(user_info) => user_info,
            Err(_) => return redirect_with_error(&error_url, "unable_to_get_user_info"),
        };
        // OIDC Core 5.3.2: when the UserInfo response carries a `sub`, it MUST
        // match the validated ID token subject before its claims are trusted.
        if let (Some(id_token_subject), Some(user_info_subject)) = (
            json_string(&id_token_payload, "sub"),
            user_info_subject.as_deref(),
        ) {
            if id_token_subject != user_info_subject {
                return redirect_with_error(&error_url, "invalid_id_token");
            }
        }
        user_info
    } else {
        match oauth_user_info_from_json(&id_token_payload, config.mapping.as_ref()) {
            Ok(user_info) => user_info,
            Err(_) => return redirect_with_error(&error_url, "unable_to_get_user_info"),
        }
    };
    if !provider_matches_email_domain(&provider, &raw_user_info.email) {
        return redirect_with_error(&error_url, "invalid_email_domain");
    }
    let is_trusted_provider = is_trusted_sso_provider(options, &provider, &raw_user_info);
    let user_info = effective_oidc_user_info(raw_user_info, is_trusted_provider);

    let result = handle_oauth_user_info(
        context,
        adapter,
        HandleOAuthUserInfoInput {
            user_info: user_info.clone(),
            account: oidc_account(&provider.provider_id, &user_info, &tokens),
            callback_url: Some(state_data.callback_url.clone()),
            disable_sign_up: options.disable_implicit_sign_up && !state_data.request_sign_up,
            override_user_info: config.override_user_info,
            is_trusted_provider,
            require_trusted_provider_for_implicit_link: true,
        },
    )
    .await?;
    let Some(data) = result.data else {
        return redirect_with_error(&error_url, "oauth_sign_in_failed");
    };
    let profile = NormalizedSsoProfile {
        provider_type: "oidc".to_owned(),
        provider_id: provider.provider_id.clone(),
        account_id: user_info.id.clone(),
        email: user_info.email.clone(),
        email_verified: user_info.email_verified,
        name: Some(user_info.name.clone()),
        image: user_info.image.clone(),
        raw_attributes: user_info.raw_attributes.clone(),
        token_data: Some(tokens.clone()),
    };
    provision_sso_user(
        options,
        &data.user,
        &profile,
        &provider,
        Some(tokens.clone()),
        result.is_register,
    )
    .await?;
    assign_organization_from_provider(
        context,
        adapter,
        &options.organization_provisioning,
        &data.user,
        &profile,
        &provider,
        Some(tokens.clone()),
    )
    .await?;
    let cookies = session_cookies(context, &data.session, &data.user, false)?;
    let target_url = if result.is_register {
        state_data
            .new_user_url
            .as_deref()
            .unwrap_or(&state_data.callback_url)
    } else {
        &state_data.callback_url
    };
    let target_url =
        utils::safe_redirect_url(context, target_url).unwrap_or_else(|| context.base_url.clone());
    redirect_with_cookies(&target_url, cookies)
}

fn oauth_state_cookie_value(context: &AuthContext, request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| {
            parse_cookies(header)
                .get(&context.auth_cookies.oauth_state.name)
                .cloned()
        })
}

fn is_trusted_sso_provider(
    options: &SsoOptions,
    provider: &crate::SsoProviderRecord,
    user_info: &OAuthUserInfo,
) -> bool {
    // Implicit account linking and email-verification trust both require the
    // IdP to actually attest the email (`email_verified`). DNS domain
    // verification only proves the operator controls the provider config for
    // the domain; on its own it is not proof that this specific email address
    // was verified by the IdP, so it must not bypass the `email_verified`
    // requirement.
    user_info.email_verified
        && (options.trust_email_verified
            || (provider.domain_verified.unwrap_or(false)
                && provider_matches_email_domain(provider, &user_info.email)))
}

fn effective_oidc_user_info(
    mut user_info: OAuthUserInfo,
    is_trusted_provider: bool,
) -> OAuthUserInfo {
    // Only honor `email_verified` when the provider is trusted to assert this
    // identity. `is_trusted_sso_provider` already requires the IdP-attested
    // `email_verified`, so domain verification alone can never upgrade an
    // unverified email to verified.
    user_info.email_verified = is_trusted_provider;
    user_info
}

enum CallbackProviderResult {
    Found(Box<crate::SsoProviderRecord>),
    Missing,
    StateMismatch,
}

async fn callback_provider(
    context: &AuthContext,
    options: &SsoOptions,
    request: &ApiRequest,
    state_data: &openauth_core::auth::oauth::OAuthStateData,
) -> Result<CallbackProviderResult, openauth_core::error::OpenAuthError> {
    let path_provider_id = path_param(request, "providerId");
    let state_provider_id = state_data
        .additional_data
        .get("ssoProviderId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if let (Some(path_provider_id), Some(state_provider_id)) =
        (path_provider_id.as_deref(), state_provider_id.as_deref())
    {
        if path_provider_id != state_provider_id {
            return Ok(CallbackProviderResult::StateMismatch);
        }
    }
    let provider_id = path_provider_id.or(state_provider_id);
    let Some(provider_id) = provider_id else {
        return Ok(CallbackProviderResult::Missing);
    };
    if let Some(provider) = super::sign_in::default_sso_by_provider_id(options, &provider_id)? {
        return Ok(CallbackProviderResult::Found(Box::new(provider)));
    }
    let Some(adapter) = context.adapter.as_deref() else {
        return Ok(CallbackProviderResult::Missing);
    };
    SsoProviderStore::new_with_options(adapter, options)
        .find_by_provider_id(&provider_id)
        .await
        .map(|provider| {
            provider.map_or(CallbackProviderResult::Missing, |provider| {
                CallbackProviderResult::Found(Box::new(provider))
            })
        })
}

fn oidc_client_authentication(config: &OidcConfig) -> ClientAuthentication {
    match config.token_endpoint_authentication {
        Some(TokenEndpointAuthentication::ClientSecretPost) => ClientAuthentication::Post,
        Some(TokenEndpointAuthentication::ClientSecretBasic) | None => ClientAuthentication::Basic,
    }
}

async fn validate_oidc_id_token(
    tokens: &OAuth2Tokens,
    config: &OidcConfig,
    provider_issuer: &str,
    expected_nonce: Option<&str>,
    allow_private_ips: bool,
) -> Result<Option<Value>, openauth_core::error::OpenAuthError> {
    let Some(id_token) = tokens.id_token.as_deref() else {
        return Ok(None);
    };
    let Some(jwks_endpoint) = config.jwks_endpoint.as_deref() else {
        return Err(openauth_core::error::OpenAuthError::OAuth(
            "missing OIDC JWKS endpoint".to_owned(),
        ));
    };
    ensure_oidc_endpoint_allowed(jwks_endpoint, allow_private_ips)?;
    let mut issuers = vec![provider_issuer.to_owned()];
    if config.issuer != provider_issuer {
        issuers.push(config.issuer.clone());
    }
    let jwks_url = JsonWebKeySetUrl::new(jwks_endpoint.to_owned())
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?;
    let jwks = CoreJsonWebKeySet::fetch_async(&jwks_url, utils::http_client(allow_private_ips))
        .await
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?;
    let raw_payload = jwt_payload_json(id_token)?;
    let id_token = CoreIdToken::from_str(id_token)
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?;
    let mut last_error = None;
    for issuer in issuers {
        let issuer = IssuerUrl::new(issuer)
            .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?;
        let verifier = CoreIdTokenVerifier::new_confidential_client(
            OidcClientId::new(config.client_id.clone()),
            ClientSecret::new(config.client_secret.expose_secret().to_owned()),
            issuer,
            jwks.clone(),
        )
        .set_other_audience_verifier_fn(|_| true);
        match id_token.claims(&verifier, OptionalNonceVerifier(expected_nonce)) {
            Ok(_) => {
                validate_oidc_authorized_party(&raw_payload, &config.client_id)?;
                return Ok(Some(raw_payload));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(openauth_core::error::OpenAuthError::OAuth(
        last_error.unwrap_or_else(|| "OIDC issuer mismatch".to_owned()),
    ))
}

struct OptionalNonceVerifier<'a>(Option<&'a str>);

impl NonceVerifier for OptionalNonceVerifier<'_> {
    fn verify(self, nonce: Option<&Nonce>) -> Result<(), String> {
        // Fail closed: OpenAuth always sends a `nonce` on OIDC authorization
        // requests, so per OIDC Core the ID token MUST carry a matching
        // `nonce` claim. Reject a missing or mismatched nonce; only skip when
        // no nonce was expected for this flow.
        let Some(expected_nonce) = self.0 else {
            return Ok(());
        };
        match nonce {
            Some(nonce) if nonce.secret() == expected_nonce => Ok(()),
            Some(_) => Err("OIDC nonce mismatch".to_owned()),
            None => Err("missing OIDC nonce claim".to_owned()),
        }
    }
}

fn jwt_payload_json(token: &str) -> Result<Value, openauth_core::error::OpenAuthError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| openauth_core::error::OpenAuthError::OAuth("invalid JWT".to_owned()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?;
    serde_json::from_slice(&decoded)
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))
}

fn validate_oidc_authorized_party(
    payload: &Value,
    client_id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    let Some(audiences) = payload.get("aud").and_then(Value::as_array) else {
        return Ok(());
    };
    let distinct_audience_count = audiences
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if distinct_audience_count <= 1 {
        return Ok(());
    }
    let authorized_party = payload.get("azp").and_then(Value::as_str);
    if authorized_party == Some(client_id) {
        return Ok(());
    }
    Err(openauth_core::error::OpenAuthError::OAuth(
        "OIDC authorized party mismatch".to_owned(),
    ))
}

async fn fetch_oidc_user_info(
    endpoint: &str,
    tokens: &OAuth2Tokens,
    mapping: Option<&OidcMapping>,
    allow_private_ips: bool,
) -> Result<(OAuthUserInfo, Option<String>), openauth_core::error::OpenAuthError> {
    let access_token = tokens.access_token.as_deref().ok_or_else(|| {
        openauth_core::error::OpenAuthError::Api("missing access token".to_owned())
    })?;
    ensure_oidc_endpoint_allowed(endpoint, allow_private_ips)?;
    let value = utils::http_client(allow_private_ips)
        .get(endpoint)
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?
        .error_for_status()
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?
        .json::<Value>()
        .await
        .map_err(|error| openauth_core::error::OpenAuthError::OAuth(error.to_string()))?;

    // The raw `sub` claim is reconciled against the validated ID token subject
    // by the caller (OIDC Core 5.3.2), independently of any custom `id` mapping.
    let subject = json_string(&value, "sub");
    Ok((oauth_user_info_from_json(&value, mapping)?, subject))
}

fn oauth_user_info_from_json(
    value: &Value,
    mapping: Option<&OidcMapping>,
) -> Result<OAuthUserInfo, openauth_core::error::OpenAuthError> {
    let id_key = mapping
        .and_then(|mapping| mapping.id.as_deref())
        .unwrap_or("sub");
    let email_key = mapping
        .and_then(|mapping| mapping.email.as_deref())
        .unwrap_or("email");
    let name_key = mapping
        .and_then(|mapping| mapping.name.as_deref())
        .unwrap_or("name");
    let image_key = mapping
        .and_then(|mapping| mapping.image.as_deref())
        .unwrap_or("picture");
    let email_verified_key = mapping
        .and_then(|mapping| mapping.email_verified.as_deref())
        .unwrap_or("email_verified");

    let id = json_string(value, id_key).ok_or_else(|| {
        openauth_core::error::OpenAuthError::Api("missing OIDC user id".to_owned())
    })?;
    let email = json_string(value, email_key)
        .ok_or_else(|| openauth_core::error::OpenAuthError::Api("missing OIDC email".to_owned()))?
        .to_lowercase();
    let name = json_string(value, name_key).unwrap_or_else(|| email.clone());
    let image = json_string(value, image_key);
    let email_verified = value
        .get(email_verified_key)
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(OAuthUserInfo {
        id,
        name,
        email,
        image,
        email_verified,
        raw_attributes: mapped_extra_fields(
            value,
            mapping.and_then(|mapping| mapping.extra_fields.as_ref()),
        ),
    })
}

fn mapped_extra_fields(
    value: &Value,
    mapping: Option<&std::collections::BTreeMap<String, String>>,
) -> Option<Value> {
    let mapping = mapping?;
    let object = mapping
        .iter()
        .filter_map(|(output_key, source_key)| {
            value
                .get(source_key)
                .cloned()
                .map(|value| (output_key.clone(), value))
        })
        .collect::<serde_json::Map<_, _>>();
    (!object.is_empty()).then_some(Value::Object(object))
}

pub(super) async fn ensure_runtime_oidc_config(
    context: &AuthContext,
    request: &ApiRequest,
    issuer: &str,
    config: OidcConfig,
    options: &SsoOptions,
    requirement: OidcRuntimeRequirement,
) -> Result<OidcConfig, crate::oidc_impl::discovery::OidcDiscoveryError> {
    let config = oidc_config_to_impl(config);
    let allow_private_ips = options.oidc.allow_private_endpoint_ips;
    ensure_runtime_oidc_config_with_origin_validator(
        issuer,
        config,
        requirement,
        ssrf_aware_oidc_origin_validator(context, request, allow_private_ips),
        options.oidc.strict_manual_endpoint_origins,
        utils::http_client(allow_private_ips),
    )
    .await
    .map(oidc_config_from_impl)
}

fn oidc_config_to_impl(config: OidcConfig) -> openauth_oidc::OidcConfig {
    openauth_oidc::OidcConfig {
        issuer: config.issuer,
        pkce: config.pkce,
        client_id: config.client_id,
        client_secret: openauth_oidc::SecretString::new(config.client_secret.into_inner()),
        discovery_endpoint: config.discovery_endpoint,
        authorization_endpoint: config.authorization_endpoint,
        token_endpoint: config.token_endpoint,
        user_info_endpoint: config.user_info_endpoint,
        jwks_endpoint: config.jwks_endpoint,
        revocation_endpoint: config.revocation_endpoint,
        end_session_endpoint: config.end_session_endpoint,
        introspection_endpoint: config.introspection_endpoint,
        token_endpoint_authentication: config.token_endpoint_authentication,
        scopes: config.scopes,
        mapping: config.mapping.map(oidc_mapping_to_impl),
        override_user_info: config.override_user_info,
    }
}

fn oidc_config_from_impl(config: openauth_oidc::OidcConfig) -> OidcConfig {
    OidcConfig {
        issuer: config.issuer,
        pkce: config.pkce,
        client_id: config.client_id,
        client_secret: config.client_secret.into_inner().into(),
        discovery_endpoint: config.discovery_endpoint,
        authorization_endpoint: config.authorization_endpoint,
        token_endpoint: config.token_endpoint,
        user_info_endpoint: config.user_info_endpoint,
        jwks_endpoint: config.jwks_endpoint,
        revocation_endpoint: config.revocation_endpoint,
        end_session_endpoint: config.end_session_endpoint,
        introspection_endpoint: config.introspection_endpoint,
        token_endpoint_authentication: config.token_endpoint_authentication,
        scopes: config.scopes,
        mapping: config.mapping.map(oidc_mapping_from_impl),
        override_user_info: config.override_user_info,
    }
}

fn oidc_mapping_to_impl(mapping: OidcMapping) -> openauth_oidc::OidcMapping {
    openauth_oidc::OidcMapping {
        id: mapping.id,
        email: mapping.email,
        email_verified: mapping.email_verified,
        name: mapping.name,
        image: mapping.image,
        extra_fields: mapping.extra_fields,
    }
}

fn oidc_mapping_from_impl(mapping: openauth_oidc::OidcMapping) -> OidcMapping {
    OidcMapping {
        id: mapping.id,
        email: mapping.email,
        email_verified: mapping.email_verified,
        name: mapping.name,
        image: mapping.image,
        extra_fields: mapping.extra_fields,
    }
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn oidc_account(
    provider_id: &str,
    user_info: &OAuthUserInfo,
    tokens: &OAuth2Tokens,
) -> OAuthAccountInput {
    OAuthAccountInput {
        provider_id: provider_id.to_owned(),
        account_id: user_info.id.clone(),
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        id_token: tokens.id_token.clone(),
        access_token_expires_at: tokens.access_token_expires_at,
        refresh_token_expires_at: tokens.refresh_token_expires_at,
        scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
    }
}

pub(super) fn is_trusted_oidc_url(context: &AuthContext, request: &ApiRequest, url: &str) -> bool {
    context
        .is_trusted_origin_for_request(url, None, Some(request))
        .unwrap_or(false)
}

/// Rejects an OIDC endpoint URL whose host is a literal private/internal IP
/// before an outbound request is issued, unless `allow_private_ips` opts out.
///
/// Used at runtime request boundaries (JWKS, userinfo) where the endpoint may
/// come from a manually configured provider that never passed through discovery
/// origin validation.
fn ensure_oidc_endpoint_allowed(
    endpoint: &str,
    allow_private_ips: bool,
) -> Result<(), openauth_core::error::OpenAuthError> {
    if !allow_private_ips && openauth_oauth::oauth2::url_host_is_blocked_ip(endpoint) {
        return Err(openauth_core::error::OpenAuthError::OAuth(
            "refusing to connect: OIDC endpoint resolves to a private or internal IP address"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Builds an OIDC endpoint origin validator that first rejects literal
/// private/internal IP hosts (unless `allow_private_ips` opts out), then applies
/// the trusted-origin check.
///
/// `reqwest` connects to literal-IP URLs without consulting the SSRF DNS guard,
/// so this closure blocks SSRF to literal IPs (for example cloud metadata
/// services) during OIDC discovery and endpoint validation.
pub(super) fn ssrf_aware_oidc_origin_validator<'a>(
    context: &'a AuthContext,
    request: &'a ApiRequest,
    allow_private_ips: bool,
) -> impl Fn(&str) -> bool + Copy + 'a {
    move |url| {
        if !allow_private_ips && openauth_oauth::oauth2::url_host_is_blocked_ip(url) {
            return false;
        }
        is_trusted_oidc_url(context, request, url)
    }
}
