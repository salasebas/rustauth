/// Minimal OAuth provider metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderMetadata {
    id: String,
    name: String,
}

impl OAuthProviderMetadata {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
