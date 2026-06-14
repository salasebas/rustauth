use rustauth_scim::mappings::{account_id, primary_email, user_full_name, ScimEmail, ScimName};

#[test]
fn account_id_prefers_external_id_over_user_name() {
    assert_eq!(account_id("user@example.com", Some("external")), "external");
    assert_eq!(account_id("user@example.com", None), "user@example.com");
}

#[test]
fn primary_email_prefers_primary_then_first_then_user_name() {
    let emails = [
        ScimEmail {
            value: "secondary@example.com".to_owned(),
            primary: false,
        },
        ScimEmail {
            value: "primary@example.com".to_owned(),
            primary: true,
        },
    ];

    assert_eq!(primary_email("user", &emails), "primary@example.com");
    assert_eq!(primary_email("user", &emails[..1]), "secondary@example.com");
    assert_eq!(primary_email("user", &[]), "user");
}

#[test]
fn user_full_name_prefers_formatted_then_name_parts_then_email() {
    assert_eq!(
        user_full_name(
            "ada@example.com",
            Some(&ScimName {
                formatted: Some("  Ada Lovelace  ".to_owned()),
                given_name: Some("Ignored".to_owned()),
                family_name: Some("Ignored".to_owned()),
            }),
        ),
        "Ada Lovelace"
    );
    assert_eq!(
        user_full_name(
            "ada@example.com",
            Some(&ScimName {
                formatted: Some("   ".to_owned()),
                given_name: Some("Ada".to_owned()),
                family_name: Some("Lovelace".to_owned()),
            }),
        ),
        "Ada Lovelace"
    );
    assert_eq!(user_full_name("ada@example.com", None), "ada@example.com");
}
