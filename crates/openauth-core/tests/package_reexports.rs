#![cfg(all(feature = "oauth", feature = "social-providers"))]

use openauth_core::{oauth, social_providers};

#[test]
fn core_reexports_oauth_and_social_provider_packages() {
    let provider = oauth::oauth2::OAuthProviderMetadata::new("example", "Example");

    assert_eq!(provider.id(), "example");
    assert!(social_providers::PROVIDER_IDS.contains(&"github"));
}
