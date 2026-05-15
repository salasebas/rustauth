use super::*;

#[test]
fn default_options_match_upstream_defaults() {
    let options = DeviceAuthorizationOptions::default();

    assert_eq!(options.expires_in, Duration::minutes(30));
    assert_eq!(options.interval, Duration::seconds(5));
    assert_eq!(options.device_code_length, 40);
    assert_eq!(options.user_code_length, 8);
    assert_eq!(options.verification_uri, "/device");
}

#[test]
fn custom_options_validate() -> Result<(), Box<dyn std::error::Error>> {
    let options = DeviceAuthorizationOptions::new()
        .expires_in(Duration::minutes(1))
        .interval(Duration::seconds(2))
        .device_code_length(50)
        .user_code_length(10);

    options.validate()?;
    Ok(())
}

#[test]
fn zero_lengths_are_rejected() {
    assert!(DeviceAuthorizationOptions::new()
        .device_code_length(0)
        .validate()
        .is_err());
    assert!(DeviceAuthorizationOptions::new()
        .user_code_length(0)
        .validate()
        .is_err());
}

#[test]
fn non_positive_durations_are_rejected() {
    assert!(DeviceAuthorizationOptions::new()
        .expires_in(Duration::ZERO)
        .validate()
        .is_err());
    assert!(DeviceAuthorizationOptions::new()
        .interval(Duration::seconds(-1))
        .validate()
        .is_err());
}
