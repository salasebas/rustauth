use std::collections::BTreeMap;

use crate::access::{
    create_access_control, request as access_request, role as access_role, statements,
    AccessControl, AccessError, Role as AccessRole, Statements,
};

use super::options::AdminOptions;

pub type PermissionMap = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    access_role: AccessRole,
}

impl Role {
    pub fn new(permissions: PermissionMap) -> Self {
        let permissions = permissions
            .into_iter()
            .map(|(resource, actions)| (resource, actions.into_iter().collect()))
            .collect::<Statements>();
        let access_role = access_role(permissions);

        Self { access_role }
    }

    pub fn allows(&self, requested: &PermissionMap) -> bool {
        if requested.is_empty() {
            return true;
        }

        self.access_role
            .authorize_all(access_request(
                requested
                    .iter()
                    .map(|(resource, actions)| (resource.clone(), actions.clone())),
            ))
            .is_ok()
    }
}

pub fn has_permission(
    user_id: Option<&str>,
    role: Option<&str>,
    options: &AdminOptions,
    permissions: &PermissionMap,
) -> bool {
    if user_id.is_some_and(|id| options.admin_user_ids.iter().any(|admin_id| admin_id == id)) {
        return true;
    }

    let role = role.unwrap_or(&options.default_role);
    for role_name in role
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if options
            .roles
            .get(role_name)
            .is_some_and(|role| role.allows(permissions))
        {
            return true;
        }
    }
    false
}

pub fn default_roles() -> BTreeMap<String, Role> {
    let mut roles = BTreeMap::new();
    roles.insert("admin".to_owned(), admin_role());
    roles.insert("user".to_owned(), Role::new(PermissionMap::new()));
    roles
}

pub fn default_statements() -> Statements {
    statements([
        (
            "user",
            vec![
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "impersonate-admins",
                "delete",
                "set-password",
                "get",
                "update",
            ],
        ),
        ("session", vec!["list", "revoke", "delete"]),
    ])
}

pub fn default_access_control() -> Result<AccessControl, AccessError> {
    create_access_control(default_statements())
}

fn admin_role() -> Role {
    Role::new(PermissionMap::from([
        (
            "user".to_owned(),
            vec![
                "create".to_owned(),
                "list".to_owned(),
                "set-role".to_owned(),
                "ban".to_owned(),
                "impersonate".to_owned(),
                "delete".to_owned(),
                "set-password".to_owned(),
                "get".to_owned(),
                "update".to_owned(),
            ],
        ),
        (
            "session".to_owned(),
            vec!["list".to_owned(), "revoke".to_owned(), "delete".to_owned()],
        ),
    ]))
}
