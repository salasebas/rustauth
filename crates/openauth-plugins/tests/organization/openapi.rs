use std::collections::BTreeSet;

use openauth_plugins::organization::{
    organization_with, DynamicAccessControlOptions, OrganizationOptions, TeamOptions,
};

#[test]
fn organization_endpoints_register_operation_ids_without_path_conflicts(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OrganizationOptions::builder()
        .teams(TeamOptions {
            enabled: true,
            create_default_team: true,
            maximum_teams: None,
            maximum_members_per_team: None,
            allow_removing_all_teams: false,
            ..Default::default()
        })
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: None,
        })
        .build();
    let plugin = organization_with(options);
    let mut paths = BTreeSet::new();
    let mut operation_ids = BTreeSet::new();

    for endpoint in &plugin.endpoints {
        assert!(
            paths.insert((endpoint.method.as_str().to_owned(), endpoint.path.clone())),
            "duplicate endpoint {} {}",
            endpoint.method,
            endpoint.path
        );
        let operation_id = endpoint
            .options
            .operation_id
            .as_ref()
            .ok_or_else(|| format!("missing operation id for {}", endpoint.path))?;
        assert!(
            operation_ids.insert(operation_id.clone()),
            "duplicate operation id {operation_id}"
        );
    }

    for path in [
        "/organization/create",
        "/organization/set-active",
        "/organization/invite-member",
        "/organization/create-team",
        "/organization/create-role",
    ] {
        assert!(plugin
            .endpoints
            .iter()
            .any(|endpoint| endpoint.path == path));
    }
    Ok(())
}
