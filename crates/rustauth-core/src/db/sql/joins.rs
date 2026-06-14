use super::*;

#[derive(Debug, Clone)]
pub struct NativeJoin<'a> {
    pub model: String,
    pub table: &'a DbTable,
    pub selection: Vec<(&'a str, &'a DbField)>,
    pub from: String,
    pub to: String,
    pub relation: JoinRelation,
    pub limit: usize,
}

pub fn resolve_native_joins<'a>(
    schema: &'a DbSchema,
    base_model: &str,
    base_table: &'a DbTable,
    joins: &IndexMap<String, JoinOption>,
    default_limit: usize,
) -> Result<Vec<NativeJoin<'a>>, RustAuthError> {
    let mut resolved = Vec::new();
    for (join_model, option) in joins {
        if !option.enabled {
            continue;
        }
        let (join_logical, join_table) = resolve_table_with_logical(schema, join_model)?;
        let mut foreign_keys = foreign_keys_to_table(join_table, &base_table.name);
        let is_forward_join = !foreign_keys.is_empty();
        if foreign_keys.is_empty() {
            foreign_keys = foreign_keys_to_table(base_table, &join_table.name);
        }
        let [(_foreign_key, field)] =
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
        let (from, to, is_unique) = if is_forward_join {
            let (_, base_field) = resolve_field(base_table, &reference.field)?;
            (base_field.name.clone(), field.name.clone(), field.unique)
        } else {
            let (_, join_field) = resolve_field(join_table, &reference.field)?;
            (field.name.clone(), join_field.name.clone(), field.unique)
        };
        let relation = if !is_forward_join || is_unique {
            JoinRelation::OneToOne
        } else {
            JoinRelation::OneToMany
        };
        let limit = if relation == JoinRelation::OneToOne {
            1
        } else {
            option.limit.unwrap_or(default_limit)
        };
        resolved.push(NativeJoin {
            model: join_logical.to_owned(),
            table: join_table,
            selection: select_fields(join_table, &[])?,
            from,
            to,
            relation,
            limit,
        });
    }
    Ok(resolved)
}

pub fn internal_base_selection<'a>(
    table: &'a DbTable,
    select: &[String],
    joins: &[NativeJoin<'_>],
) -> Result<Vec<(&'a str, &'a DbField)>, RustAuthError> {
    let mut selection = select_fields(table, select)?;
    add_internal_field(table, &mut selection, "id")?;
    for join in joins {
        add_internal_field(table, &mut selection, &join.from)?;
    }
    Ok(selection)
}

pub fn joined_rows<Row, F>(
    rows: &[Row],
    base_selection: &[(&str, &DbField)],
    output_select: &[String],
    joins: &[NativeJoin<'_>],
    mut row_value: F,
) -> Result<Vec<DbRecord>, RustAuthError>
where
    F: FnMut(&Row, &DbField, &str) -> Result<DbValue, RustAuthError>,
{
    let mut records = Vec::<DbRecord>::new();
    let mut groups = IndexMap::<String, usize>::new();

    for row in rows {
        let base_id = row_value(
            row,
            resolve_field_from_selection(base_selection, "id")?,
            "__base_id",
        )?;
        let group_key = db_value_key(&base_id).ok_or_else(|| {
            RustAuthError::Adapter("joined query base row is missing an id".to_owned())
        })?;
        let record_index = if let Some(index) = groups.get(&group_key) {
            *index
        } else {
            let mut record = DbRecord::new();
            for (index, (logical_name, field)) in base_selection.iter().enumerate() {
                if !output_select.is_empty()
                    && !output_select.iter().any(|field| field == logical_name)
                {
                    continue;
                }
                record.insert(
                    (*logical_name).to_owned(),
                    row_value(row, field, &base_alias(index))?,
                );
            }
            for join in joins {
                let value = if join.relation == JoinRelation::OneToOne {
                    DbValue::Null
                } else {
                    DbValue::RecordArray(Vec::new())
                };
                record.insert(join.model.clone(), value);
            }
            records.push(record);
            let index = records.len() - 1;
            groups.insert(group_key, index);
            index
        };

        for (join_index, join) in joins.iter().enumerate() {
            let joined = joined_record(row, join_index, join, &mut row_value)?;
            let Some(joined) = joined else {
                continue;
            };
            if join.relation == JoinRelation::OneToOne {
                records[record_index].insert(join.model.clone(), DbValue::Record(joined));
            } else if let Some(DbValue::RecordArray(values)) =
                records[record_index].get_mut(&join.model)
            {
                if values.len() < join.limit && !contains_record(values, &joined) {
                    values.push(joined);
                }
            }
        }
    }

    Ok(records)
}

pub fn base_alias(index: usize) -> String {
    format!("__base_{index}")
}

pub fn join_alias(index: usize) -> String {
    format!("__join_{index}")
}

pub fn join_field_alias(join_index: usize, field_index: usize) -> String {
    format!("__join_{join_index}_{field_index}")
}

fn add_internal_field<'a>(
    table: &'a DbTable,
    selection: &mut Vec<(&'a str, &'a DbField)>,
    field: &str,
) -> Result<(), RustAuthError> {
    let resolved = resolve_field(table, field)?;
    if !selection
        .iter()
        .any(|(_, existing)| existing.name == resolved.1.name)
    {
        selection.push(resolved);
    }
    Ok(())
}

fn joined_record<Row, F>(
    row: &Row,
    join_index: usize,
    join: &NativeJoin<'_>,
    row_value: &mut F,
) -> Result<Option<DbRecord>, RustAuthError>
where
    F: FnMut(&Row, &DbField, &str) -> Result<DbValue, RustAuthError>,
{
    let mut record = DbRecord::new();
    for (field_index, (logical_name, field)) in join.selection.iter().enumerate() {
        record.insert(
            (*logical_name).to_owned(),
            row_value(row, field, &join_field_alias(join_index, field_index))?,
        );
    }
    if record.values().all(|value| *value == DbValue::Null) {
        Ok(None)
    } else {
        Ok(Some(record))
    }
}

fn contains_record(records: &[DbRecord], candidate: &DbRecord) -> bool {
    let candidate_id = candidate.get("id").and_then(db_value_key);
    records.iter().any(|record| {
        if let Some(candidate_id) = &candidate_id {
            record.get("id").and_then(db_value_key).as_ref() == Some(candidate_id)
        } else {
            record == candidate
        }
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

fn db_value_key(value: &DbValue) -> Option<String> {
    match value {
        DbValue::String(value) => Some(value.clone()),
        DbValue::Number(value) => Some(value.to_string()),
        _ => None,
    }
}
