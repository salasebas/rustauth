use rustauth_core::db::User;
use rustauth_scim::patch::{build_user_patch, PatchOperation};
use time::OffsetDateTime;

#[test]
fn patch_supports_dot_notation_and_case_insensitive_ops() {
    let user = user("Original Name", "user@example.com");
    let patch = build_user_patch(
        &user,
        &[
            PatchOperation::new("REPLACE", Some("name.familyName"), "Lovelace"),
            PatchOperation::new("add", Some("name.givenName"), "Ada"),
            PatchOperation::new("ADD", Some("userName"), "ADA@EXAMPLE.COM"),
        ],
    )
    .expect("patch should build");

    assert_eq!(
        patch.user.get("name").and_then(|v| v.as_str()),
        Some("Ada Lovelace")
    );
    assert_eq!(
        patch.user.get("email").and_then(|v| v.as_str()),
        Some("ada@example.com")
    );
}

#[test]
fn patch_supports_omitted_path_object_values() {
    let user = user("Original", "user@example.com");
    let patch = build_user_patch(
        &user,
        &[PatchOperation::replace_json(
            None,
            serde_json::json!({
                "name": { "formatted": "No Path Name" },
                "userName": "Username"
            }),
        )],
    )
    .expect("patch should build");

    assert_eq!(
        patch.user.get("name").and_then(|v| v.as_str()),
        Some("No Path Name")
    );
    assert_eq!(
        patch.user.get("email").and_then(|v| v.as_str()),
        Some("username")
    );
}

#[test]
fn patch_returns_error_when_no_valid_fields_remain() {
    let user = user("Existing Name", "user@example.com");
    let error = build_user_patch(
        &user,
        &[PatchOperation::new(
            "add",
            Some("/name/formatted"),
            "Existing Name",
        )],
    )
    .expect_err("same add should be a no-op");

    assert_eq!(error.detail.as_deref(), Some("No valid fields to update"));
}

fn user(name: &str, email: &str) -> User {
    User {
        id: "user_1".to_owned(),
        name: name.to_owned(),
        email: email.to_owned(),
        email_verified: false,
        image: None,
        username: None,
        display_username: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}
