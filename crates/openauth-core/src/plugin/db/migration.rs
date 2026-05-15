/// Plugin migration metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMigration {
    pub name: String,
}

impl PluginMigration {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}
