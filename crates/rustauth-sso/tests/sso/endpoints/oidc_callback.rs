use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "oidc_callback/discovery.rs"]
mod discovery;
#[path = "oidc_callback/errors.rs"]
mod errors;
#[path = "oidc_callback/id_token_linking.rs"]
mod id_token_linking;
#[path = "oidc_callback/mapping_signup.rs"]
mod mapping_signup;
#[path = "oidc_callback/provider_fixtures.rs"]
mod provider_fixtures;
#[path = "oidc_callback/provisioning.rs"]
mod provisioning;
#[path = "oidc_callback/token_auth.rs"]
mod token_auth;
