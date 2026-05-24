use std::sync::Arc;

use http::{header, Method, Response, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions,
};
use openauth_core::context::AuthContext;
use openauth_core::crypto::buffer::constant_time_equal;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, Session, User};
use openauth_core::error::OpenAuthError;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;

use crate::authorize::{decide_authorize, prompt_validation_error, AuthorizeDecision};
use crate::client::{
    check_oauth_client, create_oauth_client, get_client_cached, schema_to_oauth, update_client,
    CreateOAuthClientInput, OAuthClient,
};
use crate::consent::{consent_from_record, upsert_consent, ConsentGrantInput};
use crate::error::OAuthProviderError;
use crate::metadata::{auth_server_metadata, oidc_server_metadata};
use crate::options::{
    ClientPrivilegeAction, ClientPrivilegesInput, ClientReferenceInput, CustomUserInfoClaimsInput,
    GrantType, PromptRedirectInput, RequestUriResolverInput, ResolvedOAuthProviderOptions,
};
use crate::schema::{OAUTH_CLIENT_MODEL, OAUTH_CONSENT_MODEL};
use crate::token::{
    create_authorization_code_token, create_client_credentials_token, create_refresh_token_grant,
    introspect_token_with_hint, revoke_token_with_hint, store_token, validate_access_token,
    validate_client_credentials, validate_id_token_hint, AuthorizationCodeValue,
    RefreshTokenGrantInput, TokenRequest,
};
use crate::utils::{
    basic_credentials, bearer_token, current_session, error_response, find_by_string,
    find_many_by_string, hmac_sha256_base64, is_loopback_redirect_match, json_response, no_content,
    parse_body, parse_query, query_param, redirect_response, split_scope, update_by_string,
};

mod authorization;
mod clients;
mod consent;
mod introspection;
mod logout;
mod metadata;
mod token;
mod userinfo;

use authorization::*;
use clients::*;
use consent::*;
use introspection::*;
use logout::*;
use metadata::*;
use token::*;
use userinfo::*;

pub(crate) fn oauth_provider_endpoints(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> Vec<AsyncAuthEndpoint> {
    vec![
        metadata_endpoint(
            "/.well-known/oauth-authorization-server",
            Arc::clone(&options),
            false,
        ),
        metadata_endpoint(
            "/.well-known/openid-configuration",
            Arc::clone(&options),
            true,
        ),
        authorize_endpoint(Arc::clone(&options)),
        consent_endpoint(Arc::clone(&options)),
        continue_endpoint(Method::GET, Arc::clone(&options)),
        continue_endpoint(Method::POST, Arc::clone(&options)),
        token_endpoint(Arc::clone(&options)),
        introspect_endpoint(Arc::clone(&options)),
        revoke_endpoint(Arc::clone(&options)),
        userinfo_endpoint(Arc::clone(&options)),
        logout_endpoint(Arc::clone(&options)),
        register_endpoint(Arc::clone(&options)),
        create_client_endpoint("/admin/oauth2/create-client", Arc::clone(&options)),
        create_client_endpoint("/oauth2/create-client", Arc::clone(&options)),
        get_client_endpoint(Arc::clone(&options)),
        public_client_endpoint("/oauth2/public-client", Arc::clone(&options)),
        public_client_prelogin_endpoint(Arc::clone(&options)),
        get_clients_endpoint(Arc::clone(&options)),
        update_client_endpoint("/admin/oauth2/update-client", Arc::clone(&options)),
        update_client_endpoint("/oauth2/update-client", Arc::clone(&options)),
        rotate_secret_endpoint(Arc::clone(&options)),
        delete_client_endpoint(Arc::clone(&options)),
        get_consent_endpoint(Arc::clone(&options)),
        get_consents_endpoint(Arc::clone(&options)),
        update_consent_endpoint(Arc::clone(&options)),
        delete_consent_endpoint(options),
    ]
}
