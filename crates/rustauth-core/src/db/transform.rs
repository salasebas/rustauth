use indexmap::IndexMap;

use super::{
    AdapterCapabilities, Count, Create, DbField, DbFieldType, DbRecord, DbSchema, DbTable, DbValue,
    Delete, DeleteMany, FindMany, FindOne, JoinConfig, JoinOption, JoinRelation, JoinResolution,
    Sort, Update, UpdateMany, Where,
};
use crate::error::RustAuthError;

pub fn transform_create_query(schema: &DbSchema, query: Create) -> Result<Create, RustAuthError> {
    transform_create_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_create_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: Create,
) -> Result<Create, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let data = transform_record(schema, capabilities, &query.model, query.data)?;
    let select = transform_select(schema, &query.model, query.select)?;

    Ok(Create {
        model,
        data,
        select,
        force_allow_id: query.force_allow_id,
    })
}

pub fn transform_find_one_query(
    schema: &DbSchema,
    query: FindOne,
) -> Result<FindOne, RustAuthError> {
    transform_find_one_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_find_one_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: FindOne,
) -> Result<FindOne, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;
    let select = transform_select(schema, &query.model, query.select)?;

    Ok(FindOne {
        model,
        where_clauses,
        select,
        joins: query.joins,
    })
}

pub fn transform_find_many_query(
    schema: &DbSchema,
    query: FindMany,
) -> Result<FindMany, RustAuthError> {
    transform_find_many_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_find_many_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: FindMany,
) -> Result<FindMany, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;
    let sort_by = query
        .sort_by
        .map(|sort| transform_sort(schema, &query.model, sort))
        .transpose()?;
    let select = transform_select(schema, &query.model, query.select)?;

    Ok(FindMany {
        model,
        where_clauses,
        limit: query.limit,
        offset: query.offset,
        sort_by,
        select,
        joins: query.joins,
    })
}

pub fn transform_count_query(schema: &DbSchema, query: Count) -> Result<Count, RustAuthError> {
    transform_count_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_count_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: Count,
) -> Result<Count, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;

    Ok(Count {
        model,
        where_clauses,
    })
}

pub fn transform_update_query(schema: &DbSchema, query: Update) -> Result<Update, RustAuthError> {
    transform_update_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_update_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: Update,
) -> Result<Update, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;
    let data = transform_record(schema, capabilities, &query.model, query.data)?;

    Ok(Update {
        model,
        where_clauses,
        data,
    })
}

pub fn transform_update_many_query(
    schema: &DbSchema,
    query: UpdateMany,
) -> Result<UpdateMany, RustAuthError> {
    transform_update_many_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_update_many_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: UpdateMany,
) -> Result<UpdateMany, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;
    let data = transform_record(schema, capabilities, &query.model, query.data)?;

    Ok(UpdateMany {
        model,
        where_clauses,
        data,
    })
}

pub fn transform_delete_query(schema: &DbSchema, query: Delete) -> Result<Delete, RustAuthError> {
    transform_delete_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_delete_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: Delete,
) -> Result<Delete, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;

    Ok(Delete {
        model,
        where_clauses,
    })
}

pub fn transform_delete_many_query(
    schema: &DbSchema,
    query: DeleteMany,
) -> Result<DeleteMany, RustAuthError> {
    transform_delete_many_query_with_capabilities(schema, &AdapterCapabilities::new("core"), query)
}

pub fn transform_delete_many_query_with_capabilities(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    query: DeleteMany,
) -> Result<DeleteMany, RustAuthError> {
    let model = schema.table_name(&query.model)?.to_owned();
    let where_clauses =
        transform_where_clauses(schema, capabilities, &query.model, query.where_clauses)?;

    Ok(DeleteMany {
        model,
        where_clauses,
    })
}

pub fn resolve_join_options(
    schema: &DbSchema,
    base_model: &str,
    joins: IndexMap<String, JoinOption>,
    select: Vec<String>,
    default_limit: usize,
) -> Result<JoinResolution, RustAuthError> {
    let base_table = schema
        .table(base_model)
        .ok_or_else(|| RustAuthError::TableNotFound {
            table: base_model.to_owned(),
        })?;
    let mut resolution = JoinResolution::new(select);

    for (join_model, option) in joins {
        if !option.enabled {
            continue;
        }

        let join_table = schema
            .table(&join_model)
            .ok_or_else(|| RustAuthError::TableNotFound {
                table: join_model.clone(),
            })?;
        let resolved = resolve_join_config(
            schema,
            base_model,
            base_table,
            &join_model,
            join_table,
            option,
            default_limit,
        )?;

        if !resolution.select.is_empty() && !resolution.select.contains(&resolved.required_select) {
            resolution.select.push(resolved.required_select);
        }
        resolution
            .joins
            .insert(join_table.name.clone(), resolved.config);
    }

    Ok(resolution)
}

struct ResolvedJoinConfig {
    config: JoinConfig,
    required_select: String,
}

fn resolve_join_config(
    schema: &DbSchema,
    base_model: &str,
    base_table: &DbTable,
    join_model: &str,
    join_table: &DbTable,
    option: JoinOption,
    default_limit: usize,
) -> Result<ResolvedJoinConfig, RustAuthError> {
    let mut foreign_keys = foreign_keys_to_table(join_table, &base_table.name);
    let is_forward_join = !foreign_keys.is_empty();

    if foreign_keys.is_empty() {
        foreign_keys = foreign_keys_to_table(base_table, &join_table.name);
    }

    let [(foreign_key, field)] =
        foreign_keys
            .as_slice()
            .try_into()
            .map_err(|_| match foreign_keys.len() {
                0 => RustAuthError::JoinForeignKeyNotFound {
                    base_model: base_model.to_owned(),
                    join_model: join_model.to_owned(),
                },
                _ => RustAuthError::JoinForeignKeyAmbiguous {
                    base_model: base_model.to_owned(),
                    join_model: join_model.to_owned(),
                },
            })?;
    let reference =
        field
            .foreign_key
            .as_ref()
            .ok_or_else(|| RustAuthError::JoinForeignKeyNotFound {
                base_model: base_model.to_owned(),
                join_model: join_model.to_owned(),
            })?;

    let (from, to, required_select, relation_field) = if is_forward_join {
        let from = schema.field_name(base_model, &reference.field)?.to_owned();
        let to = schema.field_name(join_model, foreign_key)?.to_owned();
        let required_select = from.clone();
        (from, to, required_select, field)
    } else {
        let from = schema.field_name(base_model, foreign_key)?.to_owned();
        let to = schema.field_name(join_model, &reference.field)?.to_owned();
        (from.clone(), to, from, field)
    };

    let is_unique = to == "id" || relation_field.unique;
    let limit = if is_unique {
        1
    } else {
        option.limit.unwrap_or(default_limit)
    };
    let relation = if is_unique {
        JoinRelation::OneToOne
    } else {
        JoinRelation::OneToMany
    };

    Ok(ResolvedJoinConfig {
        config: JoinConfig::new(from, to).limit(limit).relation(relation),
        required_select,
    })
}

fn foreign_keys_to_table<'a>(
    table: &'a DbTable,
    target_table: &str,
) -> Vec<(&'a str, &'a DbField)> {
    table
        .fields
        .iter()
        .filter_map(|(logical_name, field)| {
            field
                .foreign_key
                .as_ref()
                .filter(|foreign_key| foreign_key.table == target_table)
                .map(|_| (logical_name.as_str(), field))
        })
        .collect()
}

fn transform_record(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    model: &str,
    record: DbRecord,
) -> Result<DbRecord, RustAuthError> {
    record
        .into_iter()
        .map(|(field, value)| {
            let field_metadata = schema.field(model, &field)?;
            let value = transform_value(capabilities, field_metadata, value);
            Ok((field_metadata.name.clone(), value))
        })
        .collect::<Result<IndexMap<_, _>, _>>()
}

fn transform_select(
    schema: &DbSchema,
    model: &str,
    select: Vec<String>,
) -> Result<Vec<String>, RustAuthError> {
    select
        .into_iter()
        .map(|field| {
            schema
                .field_name(model, &field)
                .map(|field_name| field_name.to_owned())
        })
        .collect()
}

fn transform_where_clauses(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    model: &str,
    where_clauses: Vec<Where>,
) -> Result<Vec<Where>, RustAuthError> {
    where_clauses
        .into_iter()
        .map(|where_clause| transform_where_clause(schema, capabilities, model, where_clause))
        .collect()
}

fn transform_where_clause(
    schema: &DbSchema,
    capabilities: &AdapterCapabilities,
    model: &str,
    where_clause: Where,
) -> Result<Where, RustAuthError> {
    let field_metadata = schema.field(model, &where_clause.field)?;
    let value = transform_value(capabilities, field_metadata, where_clause.value);

    Ok(Where {
        field: field_metadata.name.clone(),
        value,
        operator: where_clause.operator,
        connector: where_clause.connector,
        mode: where_clause.mode,
    })
}

fn transform_sort(schema: &DbSchema, model: &str, sort: Sort) -> Result<Sort, RustAuthError> {
    let field = schema.field_name(model, &sort.field)?.to_owned();

    Ok(Sort {
        field,
        direction: sort.direction,
    })
}

fn transform_value(capabilities: &AdapterCapabilities, field: &DbField, value: DbValue) -> DbValue {
    match (&field.field_type, value) {
        (DbFieldType::Boolean, DbValue::String(value)) => {
            transform_value(capabilities, field, DbValue::Boolean(value == "true"))
        }
        (DbFieldType::Boolean, DbValue::Boolean(value)) if !capabilities.supports_booleans => {
            DbValue::Number(i64::from(value))
        }
        (DbFieldType::Number, DbValue::String(value)) => value
            .parse::<i64>()
            .map(DbValue::Number)
            .unwrap_or(DbValue::String(value)),
        (DbFieldType::Timestamp, DbValue::Timestamp(value)) if !capabilities.supports_dates => {
            DbValue::String(value.to_string())
        }
        (DbFieldType::Json, DbValue::Json(value)) if !capabilities.supports_json => {
            DbValue::String(value.to_string())
        }
        (DbFieldType::StringArray, DbValue::StringArray(value))
            if !capabilities.supports_arrays =>
        {
            let value = value.into_iter().map(serde_json::Value::String).collect();
            DbValue::String(serde_json::Value::Array(value).to_string())
        }
        (DbFieldType::NumberArray, DbValue::NumberArray(value))
            if !capabilities.supports_arrays =>
        {
            let value = value
                .into_iter()
                .map(|number| serde_json::Value::Number(number.into()))
                .collect();
            DbValue::String(serde_json::Value::Array(value).to_string())
        }
        (_, value) => value,
    }
}
