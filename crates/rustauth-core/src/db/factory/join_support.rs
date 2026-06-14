use super::super::{
    DbAdapter, DbField, DbRecord, DbSchema, DbTable, DbValue, FindMany, JoinRelation, Where,
    WhereOperator,
};
use crate::error::RustAuthError;

#[derive(Debug, Clone)]
pub(super) struct FallbackJoin {
    model: String,
    from: String,
    to: String,
    relation: JoinRelation,
    limit: usize,
}

pub(super) async fn attach_joins<A>(
    adapter: &A,
    records: &mut [&mut DbRecord],
    joins: &[FallbackJoin],
) -> Result<(), RustAuthError>
where
    A: DbAdapter,
{
    for join in joins {
        for record in records.iter_mut() {
            initialize_join_value(record, join);
        }

        let values = records
            .iter()
            .filter_map(|record| record.get(&join.from))
            .cloned()
            .collect::<Vec<_>>();
        let Some(where_value) = in_value(values) else {
            continue;
        };

        let related =
            adapter
                .find_many(FindMany::new(join.model.clone()).where_clause(
                    Where::new(join.to.clone(), where_value).operator(WhereOperator::In),
                ))
                .await?;

        for record in records.iter_mut() {
            let Some(base_value) = record.get(&join.from).cloned() else {
                continue;
            };
            let mut matching = related
                .iter()
                .filter(|related| related.get(&join.to) == Some(&base_value))
                .cloned()
                .collect::<Vec<_>>();

            if join.relation == JoinRelation::OneToOne {
                let value = matching
                    .into_iter()
                    .next()
                    .map(DbValue::Record)
                    .unwrap_or(DbValue::Null);
                record.insert(join.model.clone(), value);
            } else {
                matching.truncate(join.limit);
                record.insert(join.model.clone(), DbValue::RecordArray(matching));
            }
        }
    }

    Ok(())
}

pub(super) fn trim_joined_record(
    record: &mut DbRecord,
    original_select: &[String],
    joins: &[FallbackJoin],
) {
    if original_select.is_empty() {
        return;
    }
    record.retain(|field, _| {
        original_select.contains(field) || joins.iter().any(|join| join.model == *field)
    });
}

pub(super) fn extend_select_for_joins(select: &mut Vec<String>, joins: &[FallbackJoin]) {
    if select.is_empty() {
        return;
    }
    for join in joins {
        if !select.contains(&join.from) {
            select.push(join.from.clone());
        }
    }
}

pub(super) fn resolve_fallback_joins(
    schema: &DbSchema,
    base_model: &str,
    joins: &indexmap::IndexMap<String, super::super::JoinOption>,
    default_limit: usize,
) -> Result<Vec<FallbackJoin>, RustAuthError> {
    let (_, base_table) =
        find_table(schema, base_model).ok_or_else(|| RustAuthError::TableNotFound {
            table: base_model.to_owned(),
        })?;
    let mut resolved = Vec::new();

    for (join_model, option) in joins {
        if !option.enabled {
            continue;
        }
        let (join_logical, join_table) =
            find_table(schema, join_model).ok_or_else(|| RustAuthError::TableNotFound {
                table: join_model.clone(),
            })?;

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
                        join_model: join_model.clone(),
                    },
                    _ => RustAuthError::JoinForeignKeyAmbiguous {
                        base_model: base_model.to_owned(),
                        join_model: join_model.clone(),
                    },
                })?;
        let reference =
            field
                .foreign_key
                .as_ref()
                .ok_or_else(|| RustAuthError::JoinForeignKeyNotFound {
                    base_model: base_model.to_owned(),
                    join_model: join_model.clone(),
                })?;

        let (from, to, relation_field) = if is_forward_join {
            (
                logical_field_name(base_table, &reference.field)?,
                (*foreign_key).to_owned(),
                field,
            )
        } else {
            (
                (*foreign_key).to_owned(),
                logical_field_name(join_table, &reference.field)?,
                field,
            )
        };
        let relation = if to == "id" || relation_field.unique {
            JoinRelation::OneToOne
        } else {
            JoinRelation::OneToMany
        };
        let limit = if relation == JoinRelation::OneToOne {
            1
        } else {
            option.limit.unwrap_or(default_limit)
        };

        resolved.push(FallbackJoin {
            model: join_logical.to_owned(),
            from,
            to,
            relation,
            limit,
        });
    }

    Ok(resolved)
}

fn initialize_join_value(record: &mut DbRecord, join: &FallbackJoin) {
    let value = if join.relation == JoinRelation::OneToOne {
        DbValue::Null
    } else {
        DbValue::RecordArray(Vec::new())
    };
    record.insert(join.model.clone(), value);
}

fn in_value(values: Vec<DbValue>) -> Option<DbValue> {
    let mut strings = Vec::new();
    let mut numbers = Vec::new();

    for value in values {
        match value {
            DbValue::String(value) if !strings.contains(&value) => strings.push(value),
            DbValue::Number(value) if !numbers.contains(&value) => numbers.push(value),
            _ => {}
        }
    }

    if !strings.is_empty() {
        Some(DbValue::StringArray(strings))
    } else if !numbers.is_empty() {
        Some(DbValue::NumberArray(numbers))
    } else {
        None
    }
}

fn find_table<'a>(schema: &'a DbSchema, model: &str) -> Option<(&'a str, &'a DbTable)> {
    schema
        .tables()
        .find(|(logical_name, table)| *logical_name == model || table.name == model)
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

fn logical_field_name(table: &DbTable, field: &str) -> Result<String, RustAuthError> {
    table
        .fields
        .iter()
        .find_map(|(logical_name, metadata)| {
            (logical_name == field || metadata.name == field).then(|| logical_name.clone())
        })
        .ok_or_else(|| RustAuthError::FieldNotFound {
            table: table.name.clone(),
            field: field.to_owned(),
        })
}
