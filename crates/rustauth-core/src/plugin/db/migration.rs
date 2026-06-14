/// Plugin migration metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMigration {
    pub name: String,
    pub body: Option<PluginMigrationBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginMigrationBody {
    Sql(String),
    Plan(Vec<PluginMigrationStep>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMigrationStep {
    pub description: String,
    pub sql: Option<String>,
}

impl PluginMigration {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: None,
        }
    }

    #[must_use]
    pub fn body(mut self, body: PluginMigrationBody) -> Self {
        self.body = Some(body);
        self
    }
}

impl PluginMigrationStep {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            sql: None,
        }
    }

    #[must_use]
    pub fn sql(mut self, sql: impl Into<String>) -> Self {
        self.sql = Some(sql.into());
        self
    }
}
