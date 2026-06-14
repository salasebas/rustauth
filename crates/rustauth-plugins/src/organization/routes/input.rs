use serde::Deserialize;

use crate::organization::permissions::parse_roles;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub(super) fn normalized(&self) -> String {
        match self {
            Self::One(role) => parse_roles(role),
            Self::Many(roles) => parse_roles(roles.join(",")),
        }
    }
}
