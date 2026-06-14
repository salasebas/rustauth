use base64::Engine;
#[cfg(feature = "saml")]
use flate2::read::DeflateDecoder;
use http::{header, Method, StatusCode};
use rustauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter, Update, User, Where};
use rustauth_core::plugin::AuthPlugin;
use rustauth_sso::{
    CreateSsoProviderInput, OidcConfig, SsoOptions, SsoProvider, SsoProviderStore,
    TokenEndpointAuthentication,
};
#[cfg(feature = "saml")]
use rustauth_sso::{DeprecatedAlgorithmBehavior, SamlConfig, SamlSpMetadata};
use serde_json::json;
#[cfg(feature = "saml")]
use std::io::Read;
use time::OffsetDateTime;

#[cfg(feature = "saml")]
use super::support::router_with_options_and_origin_security;
use super::support::{
    form_request, json_body, json_request, router_with_adapter_and_options, router_with_options,
    router_with_options_and_account_linking, router_with_options_and_extra_plugins,
    router_with_options_and_secondary_storage, router_with_options_and_trusted_origins,
    router_with_options_blocking_private_endpoints, seed_session, seed_session_for_adapter,
    TestSecondaryStorage,
};

#[path = "endpoints/audit.rs"]
mod audit;
#[path = "endpoints/domain_verification.rs"]
mod domain_verification;
#[path = "endpoints/non_sso_linking.rs"]
mod non_sso_linking;
#[cfg(feature = "oidc")]
#[path = "endpoints/oidc_callback.rs"]
mod oidc_callback;
#[cfg(feature = "oidc")]
#[path = "endpoints/oidc_upstream_parity.rs"]
mod oidc_upstream_parity;
#[path = "endpoints/provider_update.rs"]
mod provider_update;
#[path = "endpoints/providers.rs"]
mod providers;
#[path = "endpoints/registration.rs"]
mod registration;
#[cfg(feature = "saml")]
#[path = "endpoints/saml.rs"]
mod saml;
#[path = "endpoints/sign_in.rs"]
mod sign_in;

#[path = "endpoints/helpers.rs"]
mod helpers;
use helpers::*;
