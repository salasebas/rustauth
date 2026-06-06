use openauth_core::options::{EmailPasswordOptions, OpenAuthOptions};

/// Apply development defaults for integration tests unless production mode is
/// explicitly requested.
#[allow(dead_code)]
pub fn with_test_defaults(mut options: OpenAuthOptions) -> OpenAuthOptions {
    if !options.production {
        options.development = true;
    }
    if !options.email_password.enabled {
        options.email_password = EmailPasswordOptions::new().enabled(true);
    }
    options
}
