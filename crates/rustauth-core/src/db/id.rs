use super::{DbField, DbFieldType};
use serde::{Deserialize, Serialize};

/// ID generation strategy for core database models.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdGeneration {
    /// RustAuth generates string IDs.
    #[default]
    Random,
    /// Database generates IDs.
    Disabled,
    /// Database generates numeric serial IDs.
    Serial,
    /// UUID IDs are used. The database may generate them natively.
    Uuid,
}

/// Normalized ID value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdValue {
    String(String),
    Number(i64),
}

/// ID field and transform policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdPolicy {
    generation: IdGeneration,
    database_supports_uuid: bool,
    force_allow_id: bool,
}

impl IdPolicy {
    pub fn new(generation: IdGeneration) -> Self {
        Self {
            generation,
            database_supports_uuid: false,
            force_allow_id: false,
        }
    }

    pub fn with_database_uuid_support(mut self, supports_uuid: bool) -> Self {
        self.database_supports_uuid = supports_uuid;
        self
    }

    pub fn with_force_allow_id(mut self, force_allow_id: bool) -> Self {
        self.force_allow_id = force_allow_id;
        self
    }

    pub fn field(self) -> DbField {
        let field_type = match self.generation {
            IdGeneration::Serial => DbFieldType::Number,
            IdGeneration::Random | IdGeneration::Disabled | IdGeneration::Uuid => {
                DbFieldType::String
            }
        };

        let mut field = DbField::new("id", field_type).generated();
        field.required = self.should_generate_id();
        if self.database_generates_id() {
            field.generated_id = Some(self.generation);
        }
        field
    }

    pub fn transform_input(self, value: Option<&str>) -> Option<IdValue> {
        let value = value.filter(|value| !value.is_empty())?;

        match self.generation {
            IdGeneration::Disabled => None,
            IdGeneration::Serial => value.parse::<i64>().ok().map(IdValue::Number),
            IdGeneration::Random => Some(IdValue::String(value.to_owned())),
            IdGeneration::Uuid => self.transform_uuid_input(value),
        }
    }

    pub fn transform_output(self, value: Option<IdValue>) -> Option<String> {
        match value? {
            IdValue::String(value) => Some(value),
            IdValue::Number(value) => Some(value.to_string()),
        }
    }

    fn should_generate_id(self) -> bool {
        match self.generation {
            IdGeneration::Random => true,
            IdGeneration::Disabled | IdGeneration::Serial => false,
            IdGeneration::Uuid => !self.database_supports_uuid,
        }
    }

    fn database_generates_id(self) -> bool {
        match self.generation {
            IdGeneration::Disabled | IdGeneration::Serial => true,
            IdGeneration::Uuid => self.database_supports_uuid,
            IdGeneration::Random => false,
        }
    }

    fn transform_uuid_input(self, value: &str) -> Option<IdValue> {
        if self.force_allow_id {
            return is_uuid(value).then(|| IdValue::String(value.to_owned()));
        }

        if self.database_supports_uuid {
            None
        } else {
            Some(IdValue::String(value.to_owned()))
        }
    }
}

impl Default for IdPolicy {
    fn default() -> Self {
        Self::new(IdGeneration::Random)
    }
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
            continue;
        }

        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }

    matches!(bytes[14], b'1'..=b'5') && matches!(bytes[19], b'8' | b'9' | b'a' | b'A' | b'b' | b'B')
}
