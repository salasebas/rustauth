use openauth_plugins::username::{
    UsernameOptions, UsernameValidationError, ValidationOrder, ValidationPhase,
};

#[test]
fn username_options_validate_default_format_and_length() {
    let options = UsernameOptions {
        min_username_length: 4,
        max_username_length: 12,
        ..UsernameOptions::default()
    };

    assert_eq!(
        options.validate_username("abc", ValidationPhase::Endpoint),
        Err(UsernameValidationError::TooShort)
    );
    assert_eq!(
        options.validate_username("abcdefghijklm", ValidationPhase::Endpoint),
        Err(UsernameValidationError::TooLong)
    );
    assert_eq!(
        options.validate_username("bad name", ValidationPhase::Endpoint),
        Err(UsernameValidationError::Invalid)
    );
    assert!(options
        .validate_username("good.name", ValidationPhase::Endpoint)
        .is_ok());
}

#[test]
fn username_options_support_custom_normalization_and_post_validation() {
    let options = UsernameOptions {
        validation_order: ValidationOrder {
            username: ValidationPhase::PostNormalization,
            display_username: ValidationPhase::PreNormalization,
        },
        username_normalization: Some(std::sync::Arc::new(|username: &str| {
            username.replace(' ', "_").to_lowercase()
        })),
        ..UsernameOptions::default()
    };

    let normalized = options.username_for_validation("Ada Lovelace");
    assert_eq!(normalized, "ada_lovelace");
    assert!(options
        .validate_username(&normalized, ValidationPhase::Endpoint)
        .is_ok());
}
