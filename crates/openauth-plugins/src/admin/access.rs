use std::collections::{BTreeMap, BTreeSet};

use super::options::AdminOptions;

pub type PermissionMap = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    permissions: BTreeMap<String, BTreeSet<String>>,
}

impl Role {
    pub fn new(permissions: PermissionMap) -> Self {
        Self {
            permissions: permissions
                .into_iter()
                .map(|(resource, actions)| (resource, actions.into_iter().collect()))
                .collect(),
        }
    }

    pub fn allows(&self, requested: &PermissionMap) -> bool {
        requested.iter().all(|(resource, actions)| {
            self.permissions
                .get(resource)
                .is_some_and(|allowed| actions.iter().all(|action| allowed.contains(action)))
        })
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
