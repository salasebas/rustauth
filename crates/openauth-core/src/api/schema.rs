use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonSchemaType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

impl JsonSchemaType {
    fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyField {
    pub name: String,
    pub schema_type: JsonSchemaType,
    pub required: bool,
    pub format: Option<String>,
    pub description: Option<String>,
}

impl BodyField {
    pub fn new(name: impl Into<String>, schema_type: JsonSchemaType) -> Self {
        Self {
            name: name.into(),
            schema_type,
            required: true,
            format: None,
            description: None,
        }
    }

    pub fn optional(name: impl Into<String>, schema_type: JsonSchemaType) -> Self {
        Self {
            required: false,
            ..Self::new(name, schema_type)
        }
    }

    #[must_use]
    pub fn format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodySchema {
    pub fields: Vec<BodyField>,
}

impl BodySchema {
    pub fn object(fields: impl IntoIterator<Item = BodyField>) -> Self {
        Self {
            fields: fields.into_iter().collect(),
        }
    }

    pub(super) fn validate(&self, value: &Value) -> Result<(), String> {
        let Some(object) = value.as_object() else {
            return Err("request body must be an object".to_owned());
        };
        for field in &self.fields {
            let Some(value) = object.get(&field.name) else {
                if field.required {
                    return Err(format!("missing required field `{}`", field.name));
                }
                continue;
            };
            if !field.required && value.is_null() {
                continue;
            }
            if !json_type_matches(value, field.schema_type) {
                return Err(format!(
                    "field `{}` must be {}",
                    field.name,
                    field.schema_type.as_str()
                ));
            }
        }
        Ok(())
    }

    pub(super) fn openapi_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();
        for field in &self.fields {
            let mut schema = serde_json::Map::new();
            schema.insert(
                "type".to_owned(),
                Value::String(field.schema_type.as_str().to_owned()),
            );
            if let Some(format) = &field.format {
                schema.insert("format".to_owned(), Value::String(format.clone()));
            }
            if let Some(description) = &field.description {
                schema.insert("description".to_owned(), Value::String(description.clone()));
            }
            properties.insert(field.name.clone(), Value::Object(schema));
            if field.required {
                required.push(Value::String(field.name.clone()));
            }
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }
}

fn json_type_matches(value: &Value, schema_type: JsonSchemaType) -> bool {
    match schema_type {
        JsonSchemaType::String => value.is_string(),
        JsonSchemaType::Number => value.is_number(),
        JsonSchemaType::Boolean => value.is_boolean(),
        JsonSchemaType::Array => value.is_array(),
        JsonSchemaType::Object => value.is_object(),
    }
}
