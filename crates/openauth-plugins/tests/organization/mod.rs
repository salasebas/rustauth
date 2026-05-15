#[test]
fn exposes_organization_placeholder() {
    assert_eq!(
        openauth_plugins::organization::UPSTREAM_PLUGIN_ID,
        "organization"
    );
}

#[test]
fn organization_default_roles_include_upstream_roles(
) -> Result<(), openauth_plugins::access::AccessError> {
    let roles = openauth_plugins::organization::access::default_roles()?;

    assert!(roles.contains_key("admin"));
    assert!(roles.contains_key("owner"));
    assert!(roles.contains_key("member"));
    Ok(())
}

#[test]
fn organization_owner_can_delete_organization() -> Result<(), openauth_plugins::access::AccessError>
{
    let owner = openauth_plugins::organization::access::owner_role()?;

    assert_eq!(
        owner.authorize_all(openauth_plugins::access::request([(
            "organization",
            ["delete"]
        )])),
        Ok(())
    );
    Ok(())
}

#[test]
fn organization_admin_can_update_but_not_delete_organization(
) -> Result<(), openauth_plugins::access::AccessError> {
    let admin = openauth_plugins::organization::access::admin_role()?;

    assert_eq!(
        admin.authorize_all(openauth_plugins::access::request([(
            "organization",
            ["update"]
        )])),
        Ok(())
    );
    assert_eq!(
        admin.authorize_all(openauth_plugins::access::request([(
            "organization",
            ["delete"]
        )])),
        Err(
            openauth_plugins::access::AccessError::UnauthorizedResource {
                resource: "organization".to_string()
            }
        )
    );
    Ok(())
}

#[test]
fn organization_member_can_read_access_control_only(
) -> Result<(), openauth_plugins::access::AccessError> {
    let member = openauth_plugins::organization::access::member_role()?;

    assert_eq!(
        member.authorize_all(openauth_plugins::access::request([("ac", ["read"])])),
        Ok(())
    );
    assert_eq!(
        member.authorize_all(openauth_plugins::access::request([("member", ["create"])])),
        Err(
            openauth_plugins::access::AccessError::UnauthorizedResource {
                resource: "member".to_string()
            }
        )
    );
    Ok(())
}
