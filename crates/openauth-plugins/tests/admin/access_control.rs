use openauth_plugins::admin::{access_control, PermissionMap};

#[test]
fn admin_access_default_statements_include_user_and_session() {
    let statements = access_control::default_statements();

    assert!(statements["user"].contains("set-role"));
    assert!(statements["session"].contains("revoke"));
}

#[test]
fn admin_default_roles_include_admin_and_user() {
    let roles = access_control::default_roles();

    assert!(roles.contains_key("admin"));
    assert!(roles.contains_key("user"));
}

#[test]
fn admin_role_allows_set_role_but_not_impersonate_admins() {
    let roles = access_control::default_roles();
    let admin = &roles["admin"];

    assert!(admin.allows(&PermissionMap::from([(
        "user".to_string(),
        vec!["set-role".to_string()]
    )])));
    assert!(!admin.allows(&PermissionMap::from([(
        "user".to_string(),
        vec!["impersonate-admins".to_string()]
    )])));
}

#[test]
fn user_role_has_no_admin_permissions() {
    let roles = access_control::default_roles();
    let user = &roles["user"];

    assert!(!user.allows(&PermissionMap::from([(
        "session".to_string(),
        vec!["list".to_string()]
    )])));
}

#[test]
fn default_access_control_accepts_admin_statements(
) -> Result<(), openauth_plugins::access::AccessError> {
    let control = access_control::default_access_control()?;

    assert!(control.statements()["user"].contains("impersonate-admins"));
    Ok(())
}
