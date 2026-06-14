use super::error::AccessError;
use super::types::{AccessRequest, ResourceRequest, Role, Statements};
use std::collections::{BTreeMap, BTreeSet};

/// Access-control policy used to create validated roles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessControl {
    statements: Statements,
}

impl AccessControl {
    /// Create an access-control policy from base statements.
    pub fn new(statements: Statements) -> Result<Self, AccessError> {
        Ok(Self { statements })
    }

    /// Create a role after validating it against the base statements.
    pub fn new_role(&self, statements: Statements) -> Result<Role, AccessError> {
        self.validate_role_statements(&statements)?;
        Ok(Role::new(statements))
    }

    /// Return the base statements for this access-control policy.
    pub fn statements(&self) -> &Statements {
        &self.statements
    }

    fn validate_role_statements(&self, statements: &Statements) -> Result<(), AccessError> {
        for (resource, actions) in statements {
            let allowed_actions =
                self.statements
                    .get(resource)
                    .ok_or_else(|| AccessError::UnknownResource {
                        resource: resource.clone(),
                    })?;

            for action in actions {
                if !allowed_actions.contains(action) {
                    return Err(AccessError::UnknownAction {
                        resource: resource.clone(),
                        action: action.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Create an access-control policy from base statements.
pub fn create_access_control(statements: Statements) -> Result<AccessControl, AccessError> {
    AccessControl::new(statements)
}

/// Create a role directly from statements.
pub fn role(statements: Statements) -> Role {
    Role::new(statements)
}

/// Build resource-to-actions statements from iterable pairs.
pub fn statements<I, R, A, S>(entries: I) -> Statements
where
    I: IntoIterator<Item = (R, A)>,
    R: Into<String>,
    A: IntoIterator<Item = S>,
    S: Into<String>,
{
    entries
        .into_iter()
        .map(|(resource, actions)| {
            (
                resource.into(),
                actions.into_iter().map(Into::into).collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>()
}

/// Build an access request where each resource requires all listed actions.
pub fn request<I, R, A, S>(entries: I) -> AccessRequest
where
    I: IntoIterator<Item = (R, A)>,
    R: Into<String>,
    A: IntoIterator<Item = S>,
    S: Into<String>,
{
    entries
        .into_iter()
        .map(|(resource, actions)| (resource.into(), ResourceRequest::all(actions)))
        .collect()
}
