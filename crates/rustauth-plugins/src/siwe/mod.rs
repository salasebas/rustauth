//! Sign-In with Ethereum plugin.

mod address;
mod endpoints;
mod schema;
mod store;
mod types;

use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::AuthPlugin;

pub use address::{checksum_address, SiweAddressError};
pub use schema::SiweSchemaOptions;
pub use types::{
    Cacao, CacaoHeader, CacaoPayload, CacaoSignature, EnsLookupArgs, EnsLookupResult, SiweOptions,
    SiweOptionsBuilder, SiweVerifyMessageArgs, WalletAddress,
};

pub const UPSTREAM_PLUGIN_ID: &str = "siwe";

/// Development only — do not use in production.
///
/// Uses domain `localhost`, an in-memory nonce counter, and accepts every SIWE signature.
pub fn siwe_dev() -> Result<AuthPlugin, RustAuthError> {
    siwe_dev_domain("localhost")
}

/// Development only — same as [`siwe_dev`] with an explicit domain.
pub fn siwe_dev_domain(domain: impl Into<String>) -> Result<AuthPlugin, RustAuthError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(0);
    siwe(SiweOptions::new(
        domain,
        || async {
            let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
            Ok(format!("dev-nonce-{nonce}"))
        },
        |_args| async { Ok(true) },
    ))
}

pub fn siwe(options: SiweOptions) -> Result<AuthPlugin, RustAuthError> {
    options.validate()?;
    Ok(AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(options.metadata())
        .with_schema(schema::wallet_address_schema(options.schema_options()))
        .with_endpoint(endpoints::nonce_endpoint(options.clone()))
        .with_endpoint(endpoints::verify_endpoint(options)))
}
