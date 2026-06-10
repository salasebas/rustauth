//! Sign-In with Ethereum plugin.

mod address;
mod endpoints;
mod schema;
mod store;
mod types;

use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;

pub use address::{checksum_address, SiweAddressError};
pub use schema::SiweSchemaOptions;
pub use types::{
    Cacao, CacaoHeader, CacaoPayload, CacaoSignature, EnsLookupArgs, EnsLookupResult, SiweOptions,
    SiweVerifyMessageArgs, WalletAddress,
};

pub const UPSTREAM_PLUGIN_ID: &str = "siwe";

pub fn siwe_with(options: SiweOptions) -> Result<AuthPlugin, OpenAuthError> {
    options.validate()?;
    Ok(AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(options.metadata())
        .with_schema(schema::wallet_address_schema(options.schema_options()))
        .with_endpoint(endpoints::nonce_endpoint(options.clone()))
        .with_endpoint(endpoints::verify_endpoint(options)))
}
