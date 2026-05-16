use super::*;

pub fn select_fields<'a>(
    table: &'a DbTable,
    select: &[String],
) -> Result<Vec<(&'a str, &'a DbField)>, OpenAuthError> {
    if select.is_empty() {
        return Ok(table
            .fields
            .iter()
            .map(|(logical_name, field)| (logical_name.as_str(), field))
            .collect());
    }

    select
        .iter()
        .map(|field| resolve_field(table, field))
        .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn selected_fields(
    table: &DbTable,
    select: &[String],
) -> Result<Vec<SqlSelectedField>, OpenAuthError> {
    select_fields(table, select)?
        .into_iter()
        .map(|(logical_name, field)| {
            Ok(SqlSelectedField {
                logical_name: logical_name.to_owned(),
                field: field.clone(),
                alias: field.name.clone(),
            })
        })
        .collect()
}

pub fn select_record(record: DbRecord, select: &[String]) -> DbRecord {
    if select.is_empty() {
        return record;
    }
    select
        .iter()
        .filter_map(|field| {
            record
                .get(field)
                .cloned()
                .map(|value| (field.clone(), value))
        })
        .collect()
}

pub fn resolve_table<'a>(schema: &'a DbSchema, model: &str) -> Result<&'a DbTable, OpenAuthError> {
    resolve_table_with_logical(schema, model).map(|(_, table)| table)
}

pub fn resolve_table_with_logical<'a>(
    schema: &'a DbSchema,
    model: &str,
) -> Result<(&'a str, &'a DbTable), OpenAuthError> {
    schema
        .tables()
        .find(|(logical_name, table)| *logical_name == model || table.name == model)
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: model.to_owned(),
        })
}

pub fn resolve_field<'a>(
    table: &'a DbTable,
    field: &str,
) -> Result<(&'a str, &'a DbField), OpenAuthError> {
    table
        .fields
        .iter()
        .find_map(|(logical_name, metadata)| {
            (logical_name == field || metadata.name == field)
                .then_some((logical_name.as_str(), metadata))
        })
        .ok_or_else(|| OpenAuthError::FieldNotFound {
            table: table.name.clone(),
            field: field.to_owned(),
        })
}

pub fn resolve_field_from_selection<'a>(
    selection: &'a [(&str, &'a DbField)],
    field: &str,
) -> Result<&'a DbField, OpenAuthError> {
    selection
        .iter()
        .find_map(|(logical_name, metadata)| {
            (*logical_name == field || metadata.name == field).then_some(*metadata)
        })
        .ok_or_else(|| OpenAuthError::FieldNotFound {
            table: "joined base selection".to_owned(),
            field: field.to_owned(),
        })
}
