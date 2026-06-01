//! OAuth 2.0 structure for OpenAuth.
//!
//! This module is intentionally structure-only in the initial core port.

pub mod authorization_url;
#[cfg(feature = "jose")]
pub mod claims;
pub mod client_credentials_token;
pub mod error;
pub mod http;
#[cfg(feature = "jose")]
pub mod introspection;
#[cfg(feature = "jose")]
pub mod jwks;
pub mod provider;
pub mod refresh_access_token;
pub mod request;
pub mod ssrf;
#[cfg(feature = "jose")]
pub mod token_validation;
pub mod tokens;
pub mod types;
pub mod utils;
pub mod validate_authorization_code;
#[cfg(feature = "jose")]
pub mod verify;

pub use authorization_url::{create_authorization_url, AuthorizationUrlRequest};
#[cfg(feature = "jose")]
pub use claims::TokenValidationOptions;
pub use client_credentials_token::{
    client_credentials_token, client_credentials_token_request,
    client_credentials_token_with_client, create_client_credentials_token_request,
    ClientCredentialsGrant, ClientCredentialsTokenRequest,
};
pub use error::OAuthError;
pub use http::{OAuthHttpClient, OAuthHttpClientConfig};
pub use provider::{
    OAuthProviderContract, OAuthProviderMetadata, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
pub use refresh_access_token::{
    create_refresh_access_token_request, refresh_access_token, refresh_access_token_request,
    refresh_access_token_with_client, RefreshAccessTokenRequest,
};
pub use request::{ClientAuthentication, OAuthFormRequest};
pub use ssrf::{
    is_blocked_ip, ssrf_guarded_client_builder, url_host_is_blocked_ip, SsrfGuardResolver,
};
#[cfg(feature = "jose")]
pub use token_validation::{
    validate_token, validate_token_with_client, verify_jws_with_jwks, TokenValidationResult,
};
pub use tokens::{
    get_oauth2_tokens, get_primary_client_id, ClientId, OAuth2Tokens, OAuth2UserInfo,
    ProviderOptions,
};
pub use types::{AuthorizationEndpoint, ClientSecret, RedirectUri, TokenEndpoint};
pub use utils::{generate_code_challenge, validate_code_verifier};
pub use validate_authorization_code::{
    authorization_code_request, create_authorization_code_request, validate_authorization_code,
    validate_authorization_code_with_client, AuthorizationCodeRequest, ClientTokenRequest,
};
#[cfg(feature = "jose")]
pub use verify::{
    clear_jwks_cache, get_jwks, get_jwks_with_client, verify_access_token,
    verify_access_token_with_client, verify_jws_access_token,
    verify_jws_access_token_with_cache_config, verify_jws_access_token_with_client,
    verify_jws_access_token_with_client_and_cache_config, OAuthJwksCacheConfig,
    VerifyAccessTokenOptions, VerifyAccessTokenRemote,
};
