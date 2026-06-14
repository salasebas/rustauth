use std::fmt;

/// Access-control validation or authorization error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// Authorization requests must contain at least one resource.
    EmptyRequest,
    /// A role or request referenced a resource that is not part of the policy.
    UnknownResource { resource: String },
    /// A role referenced an action that is not part of the base policy.
    UnknownAction { resource: String, action: String },
    /// The role has no permission for the requested resource.
    ResourceDenied { resource: String },
    /// The role is missing one or more requested actions for the resource.
    UnauthorizedResource { resource: String },
    /// No requested resource was authorized.
    NotAuthorized,
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRequest => f.write_str("access request must include at least one resource"),
            Self::UnknownResource { resource } => {
                write!(f, "unknown access resource `{resource}`")
            }
            Self::UnknownAction { resource, action } => {
                write!(
                    f,
                    "unknown action `{action}` for access resource `{resource}`"
                )
            }
            Self::ResourceDenied { resource } => {
                write!(f, "not allowed to access resource `{resource}`")
            }
            Self::UnauthorizedResource { resource } => {
                write!(f, "unauthorized to access resource `{resource}`")
            }
            Self::NotAuthorized => f.write_str("not authorized"),
        }
    }
}

impl std::error::Error for AccessError {}
