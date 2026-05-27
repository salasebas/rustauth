use openauth_scim::mappings::ScimEmail;
use openauth_scim::validation::{is_valid_email, validate_emails, validate_scim_user_identity};

#[test]
fn is_valid_email_accepts_common_addresses() {
    assert!(is_valid_email("ada@example.com"));
    assert!(is_valid_email("  Ada@Example.com  "));
}

#[test]
fn is_valid_email_rejects_missing_domain_and_whitespace() {
    assert!(!is_valid_email(""));
    assert!(!is_valid_email("ada"));
    assert!(!is_valid_email("ada@"));
    assert!(!is_valid_email("ada @example.com"));
    assert!(!is_valid_email("@example.com"));
}

#[test]
fn validate_scim_user_identity_requires_email_shaped_user_name_or_emails() {
    let email = validate_scim_user_identity("ada@example.com", &[]).expect("userName should work");
    assert_eq!(email, "ada@example.com");

    let email = validate_scim_user_identity(
        "ignored",
        &[ScimEmail {
            value: "primary@example.com".to_owned(),
            primary: true,
        }],
    )
    .expect("primary email should win");
    assert_eq!(email, "primary@example.com");

    let error = validate_scim_user_identity("ada", &[]).expect_err("bare userName must fail");
    assert_eq!(error.scim_type.as_deref(), Some("invalidValue"));

    let error = validate_scim_user_identity("   ", &[]).expect_err("empty userName must fail");
    assert_eq!(error.detail.as_deref(), Some("userName is required"));
}

#[test]
fn validate_emails_rejects_invalid_and_duplicate_primary_values() {
    validate_emails(&[ScimEmail {
        value: "ada@example.com".to_owned(),
        primary: true,
    }])
    .expect("single primary email should pass");

    let error = validate_emails(&[ScimEmail {
        value: "not-an-email".to_owned(),
        primary: false,
    }])
    .expect_err("invalid email must fail");
    assert_eq!(
        error.detail.as_deref(),
        Some("emails.value must be a valid email address")
    );

    let error = validate_emails(&[
        ScimEmail {
            value: "one@example.com".to_owned(),
            primary: true,
        },
        ScimEmail {
            value: "two@example.com".to_owned(),
            primary: true,
        },
    ])
    .expect_err("duplicate primary must fail");
    assert_eq!(
        error.detail.as_deref(),
        Some("Only one emails value can be primary")
    );
}
