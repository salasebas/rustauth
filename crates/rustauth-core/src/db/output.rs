use indexmap::IndexMap;

use super::DbField;

/// Return a copy of a DB record with non-returnable fields removed.
pub fn filter_output_fields<V: Clone>(
    data: &IndexMap<String, V>,
    fields: &IndexMap<String, DbField>,
) -> IndexMap<String, V> {
    data.iter()
        .filter(|(key, _)| fields.get(*key).map_or(true, |field| field.returned))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
