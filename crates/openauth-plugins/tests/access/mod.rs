use openauth_plugins::access::{
    create_access_control, request, role as access_role, statements, AccessControl, AccessError,
    Connector, ResourceRequest, UPSTREAM_PLUGIN_ID,
};

fn access_control() -> Result<AccessControl, AccessError> {
    AccessControl::new(statements([
        ("project", ["create", "update", "delete", "delete-many"]),
        ("ui", ["view", "edit", "comment", "hide"]),
    ]))
}

fn role() -> Result<openauth_plugins::access::Role, AccessError> {
    access_control()?.new_role(statements([
        ("project", ["create", "update", "delete"]),
        ("ui", ["view", "edit", "comment"]),
    ]))
}

#[test]
fn exposes_access_plugin_id() {
    assert_eq!(UPSTREAM_PLUGIN_ID, "access");
}

#[test]
fn allows_defined_statements_directly_in_new_role() -> Result<(), AccessError> {
    let control = access_control()?;
    let role = control.new_role(control.statements().clone())?;

    assert_eq!(
        role.authorize(request([("project", ["create"])]), Connector::And),
        Ok(())
    );
    Ok(())
}

#[test]
fn validates_permissions() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(request([("project", ["create"])]), Connector::And),
        Ok(())
    );
    assert_eq!(
        role()?.authorize(request([("project", ["delete-many"])]), Connector::And),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn validates_or_connector_for_specific_resource() -> Result<(), AccessError> {
    let mut allowed = openauth_plugins::access::AccessRequest::new();
    allowed.insert(
        "project".to_string(),
        ResourceRequest::any(["create", "delete-many"]),
    );
    allowed.insert("ui".to_string(), ResourceRequest::all(["view", "edit"]));
    assert_eq!(role()?.authorize(allowed, Connector::And), Ok(()));

    let mut denied = openauth_plugins::access::AccessRequest::new();
    denied.insert("project".to_string(), ResourceRequest::any(["delete-many"]));
    denied.insert("ui".to_string(), ResourceRequest::all(["view", "edit"]));
    assert_eq!(
        role()?.authorize(denied, Connector::And),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn authorizes_allowed_action() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(request([("project", ["create"])]), Connector::And),
        Ok(())
    );
    Ok(())
}

#[test]
fn create_access_control_helper_builds_policy() -> Result<(), AccessError> {
    let control = create_access_control(statements([("project", ["create"])]))?;
    let role = control.new_role(statements([("project", ["create"])]))?;

    assert_eq!(
        role.authorize_all(request([("project", ["create"])])),
        Ok(())
    );
    Ok(())
}

#[test]
fn role_helper_builds_role_without_base_policy() {
    let role = access_role(statements([("project", ["create"])]));

    assert_eq!(
        role.authorize_all(request([("project", ["create"])])),
        Ok(())
    );
}

#[test]
fn authorize_all_uses_and_connector() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize_all(request([("project", ["create"]), ("ui", ["hide"])])),
        Err(AccessError::UnauthorizedResource {
            resource: "ui".to_string()
        })
    );
    Ok(())
}

#[test]
fn authorize_any_uses_or_connector() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize_any(request([("project", ["delete-many"]), ("ui", ["view"])])),
        Ok(())
    );
    Ok(())
}

#[test]
fn authorize_any_returns_not_authorized_when_no_resource_passes() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize_any(request([("project", ["delete-many"]), ("ui", ["hide"])])),
        Err(AccessError::NotAuthorized)
    );
    Ok(())
}

#[test]
fn authorize_any_rejects_unknown_resource() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize_any(request([("billing", ["read"]), ("project", ["create"])])),
        Err(AccessError::ResourceDenied {
            resource: "billing".to_string()
        })
    );
    Ok(())
}

#[test]
fn authorize_any_short_circuits_after_allowed_resource() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize_any(request([("project", ["create"]), ("z_unknown", ["read"])])),
        Ok(())
    );
    Ok(())
}

#[test]
fn rejects_disallowed_action() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(request([("project", ["delete-many"])]), Connector::And),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn authorizes_multiple_resources_with_and_connector() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(
            request([("project", ["create"]), ("ui", ["view"])]),
            Connector::And
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn rejects_multiple_resources_when_one_fails_with_and_connector() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(
            request([("project", ["delete-many"]), ("ui", ["view"])]),
            Connector::And
        ),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn authorizes_multiple_resources_when_one_passes_with_or_connector() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(
            request([("project", ["delete-many"]), ("ui", ["view"])]),
            Connector::Or
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn authorizes_multiple_actions_for_resource_with_all_request() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(request([("project", ["create", "delete"])]), Connector::And),
        Ok(())
    );
    Ok(())
}

#[test]
fn rejects_all_request_when_one_action_is_missing() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(
            request([("project", ["create", "delete-many"])]),
            Connector::And
        ),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn authorizes_resource_with_any_request() -> Result<(), AccessError> {
    let mut request = openauth_plugins::access::AccessRequest::new();
    request.insert(
        "project".to_string(),
        ResourceRequest::any(["create", "delete-many"]),
    );
    request.insert("ui".to_string(), ResourceRequest::all(["view", "edit"]));

    assert_eq!(role()?.authorize(request, Connector::And), Ok(()));
    Ok(())
}

#[test]
fn rejects_any_request_when_no_action_is_allowed() -> Result<(), AccessError> {
    let mut request = openauth_plugins::access::AccessRequest::new();
    request.insert("project".to_string(), ResourceRequest::any(["delete-many"]));

    assert_eq!(
        role()?.authorize(request, Connector::And),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn rejects_resource_missing_from_role() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize_all(request([("billing", ["read"])])),
        Err(AccessError::ResourceDenied {
            resource: "billing".to_string()
        })
    );
    Ok(())
}

#[test]
fn rejects_role_with_unknown_resource() -> Result<(), AccessError> {
    assert_eq!(
        access_control()?.new_role(statements([("billing", ["read"])])),
        Err(AccessError::UnknownResource {
            resource: "billing".to_string()
        })
    );
    Ok(())
}

#[test]
fn rejects_role_with_action_outside_base_statements() -> Result<(), AccessError> {
    assert_eq!(
        access_control()?.new_role(statements([("project", ["archive"])])),
        Err(AccessError::UnknownAction {
            resource: "project".to_string(),
            action: "archive".to_string()
        })
    );
    Ok(())
}

#[test]
fn all_request_with_empty_actions_passes_like_upstream_every() -> Result<(), AccessError> {
    let mut request = openauth_plugins::access::AccessRequest::new();
    request.insert(
        "project".to_string(),
        ResourceRequest::all(Vec::<&str>::new()),
    );

    assert_eq!(role()?.authorize_all(request), Ok(()));
    Ok(())
}

#[test]
fn any_request_with_empty_actions_fails_like_upstream_some() -> Result<(), AccessError> {
    let mut request = openauth_plugins::access::AccessRequest::new();
    request.insert(
        "project".to_string(),
        ResourceRequest::any(Vec::<&str>::new()),
    );

    assert_eq!(
        role()?.authorize_all(request),
        Err(AccessError::UnauthorizedResource {
            resource: "project".to_string()
        })
    );
    Ok(())
}

#[test]
fn rejects_empty_requests() -> Result<(), AccessError> {
    assert_eq!(
        role()?.authorize(
            openauth_plugins::access::AccessRequest::new(),
            Connector::And
        ),
        Err(AccessError::EmptyRequest)
    );
    Ok(())
}
