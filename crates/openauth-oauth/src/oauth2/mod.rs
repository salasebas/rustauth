//! OAuth 2.0 structure for OpenAuth.
//!
//! This module is intentionally structure-only in the initial core port.

pub mod authorization_url;
pub mod client_credentials_token;
pub mod error;
pub mod provider;
pub mod refresh_access_token;
pub mod request;
pub mod tokens;
pub mod utils;
pub mod validate_authorization_code;
pub mod verify;

pub use authorization_url::{create_authorization_url, AuthorizationUrlRequest};
pub use client_credentials_token::{
    client_credentials_token, client_credentials_token_request,
    create_client_credentials_token_request, ClientCredentialsGrant, ClientCredentialsTokenRequest,
};
pub use error::OAuthError;
pub use provider::{
    OAuthProviderContract, OAuthProviderMetadata, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
pub use refresh_access_token::{
    create_refresh_access_token_request, refresh_access_token, refresh_access_token_request,
    RefreshAccessTokenRequest,
};
pub use request::{ClientAuthentication, OAuthFormRequest};
pub use tokens::{
    get_oauth2_tokens, get_primary_client_id, ClientId, OAuth2Tokens, OAuth2UserInfo,
    ProviderOptions,
};
pub use utils::generate_code_challenge;
pub use validate_authorization_code::{
    authorization_code_request, create_authorization_code_request, validate_authorization_code,
    validate_token, verify_jws_with_jwks, AuthorizationCodeRequest, ClientTokenRequest,
    TokenValidationOptions, TokenValidationResult,
};
pub use verify::{
    get_jwks, verify_access_token, verify_jws_access_token, VerifyAccessTokenOptions,
    VerifyAccessTokenRemote,
};
