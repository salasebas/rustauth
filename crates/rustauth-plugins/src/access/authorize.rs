use super::error::AccessError;
use super::types::{AccessRequest, Connector, ResourceRequest, Role};

impl Role {
    /// Authorize a request requiring every requested resource to pass.
    pub fn authorize_all(&self, request: AccessRequest) -> Result<(), AccessError> {
        self.authorize(request, Connector::And)
    }

    /// Authorize a request requiring at least one requested resource to pass.
    pub fn authorize_any(&self, request: AccessRequest) -> Result<(), AccessError> {
        self.authorize(request, Connector::Or)
    }

    /// Authorize a request against this role's statements.
    pub fn authorize(
        &self,
        request: AccessRequest,
        connector: Connector,
    ) -> Result<(), AccessError> {
        if request.is_empty() {
            return Err(AccessError::EmptyRequest);
        }

        for (resource, resource_request) in request {
            match self.authorize_resource(&resource, &resource_request) {
                Ok(()) if connector == Connector::Or => return Ok(()),
                Ok(()) => {}
                Err(error) if connector == Connector::And => return Err(error),
                Err(error @ AccessError::ResourceDenied { .. }) => return Err(error),
                Err(_) => {}
            }
        }

        if connector == Connector::Or {
            Err(AccessError::NotAuthorized)
        } else {
            Ok(())
        }
    }

    fn authorize_resource(
        &self,
        resource: &str,
        request: &ResourceRequest,
    ) -> Result<(), AccessError> {
        let allowed_actions =
            self.statements
                .get(resource)
                .ok_or_else(|| AccessError::ResourceDenied {
                    resource: resource.to_string(),
                })?;

        match request.connector() {
            Connector::And if request.actions().is_subset(allowed_actions) => Ok(()),
            Connector::Or
                if request
                    .actions()
                    .iter()
                    .any(|action| allowed_actions.contains(action)) =>
            {
                Ok(())
            }
            _ => Err(AccessError::UnauthorizedResource {
                resource: resource.to_string(),
            }),
        }
    }
}
