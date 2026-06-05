use openauth_core::options::OpenAuthOptions;

/// Apply development defaults for integration tests unless production mode is
/// explicitly requested.
pub fn with_test_defaults(mut options: OpenAuthOptions) -> OpenAuthOptions {
    if !options.production {
        options.development = true;
    }
    options
}
