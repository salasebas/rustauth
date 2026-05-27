//! SCIM request validation helpers.

use crate::errors::ScimError;
use crate::mappings::{primary_email, ScimEmail};

/// Returns true when `value` looks like a usable email address for provisioning.
pub fn is_valid_email(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.contains(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

/// Validates `userName` and optional `emails`, returning the canonical lowercased email.
pub fn validate_scim_user_identity(
    user_name: &str,
    emails: &[ScimEmail],
) -> Result<String, ScimError> {
    let user_name = user_name.trim();
    if user_name.is_empty() {
        return Err(ScimError::bad_request("userName is required").with_scim_type("invalidValue"));
    }
    let email = primary_email(user_name, emails).to_ascii_lowercase();
    if !is_valid_email(&email) {
        return Err(ScimError::bad_request(
            "userName and emails.value must resolve to a valid email address",
        )
        .with_scim_type("invalidValue"));
    }
    Ok(email)
}

/// Validates a SCIM `emails` array.
pub fn validate_emails(emails: &[ScimEmail]) -> Result<(), ScimError> {
    if emails.iter().filter(|email| email.primary).count() > 1 {
        return Err(
            ScimError::bad_request("Only one emails value can be primary")
                .with_scim_type("invalidValue"),
        );
    }
    for email in emails {
        if !is_valid_email(&email.value) {
            return Err(
                ScimError::bad_request("emails.value must be a valid email address")
                    .with_scim_type("invalidValue"),
            );
        }
    }
    Ok(())
}
