use openauth_core::db::{Account, User};
use openauth_scim::resources::user_resource;
use time::OffsetDateTime;

#[test]
fn user_resource_projects_core_user_and_provider_account() {
    let resource = user_resource("http://localhost:3000/api/auth", &user(), Some(&account()));

    assert_eq!(resource.id, "user_1");
    assert_eq!(resource.external_id.as_deref(), Some("external_1"));
    assert_eq!(resource.user_name, "ada@example.com");
    assert_eq!(resource.name.formatted, "Ada Lovelace");
    assert_eq!(resource.display_name, "Ada Lovelace");
    assert!(resource.active);
    assert_eq!(resource.emails[0].value, "ada@example.com");
    assert!(resource.emails[0].primary);
    assert_eq!(
        resource.meta.location,
        "http://localhost:3000/api/auth/scim/v2/Users/user_1"
    );
}

fn user() -> User {
    User {
        id: "user_1".to_owned(),
        name: "Ada Lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn account() -> Account {
    Account {
        id: "account_1".to_owned(),
        provider_id: "provider_1".to_owned(),
        account_id: "external_1".to_owned(),
        user_id: "user_1".to_owned(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}
