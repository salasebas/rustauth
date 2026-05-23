use base64::Engine;
use flate2::read::DeflateDecoder;
use http::{header, Method, StatusCode};
use openauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter, Update, User, Where};
use openauth_core::plugin::AuthPlugin;
use openauth_sso::{
    CreateSsoProviderInput, DeprecatedAlgorithmBehavior, OidcConfig, SamlConfig, SamlSpMetadata,
    SsoOptions, SsoProvider, SsoProviderStore, TokenEndpointAuthentication,
};
use serde_json::json;
use std::io::Read;
use time::OffsetDateTime;

use super::support::{
    form_request, json_body, json_request, router_with_adapter_and_options, router_with_options,
    router_with_options_and_extra_plugins, router_with_options_and_origin_security,
    router_with_options_and_secondary_storage, router_with_options_and_trusted_origins,
    seed_session, seed_session_for_adapter, TestSecondaryStorage,
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
