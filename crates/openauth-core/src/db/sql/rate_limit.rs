use super::*;

/// Builds the dialect-specific statement trio used by SQL-backed rate-limit stores.
pub fn rate_limit_consume_statements(
    dialect: SqlDialect,
    table: &str,
    key: &str,
    count: &str,
    last_request: &str,
) -> Result<SqlRateLimitPlan, OpenAuthError> {
    let table = dialect.quote_identifier(table)?;
    let key = dialect.quote_identifier(key)?;
    let count = dialect.quote_identifier(count)?;
    let last_request = dialect.quote_identifier(last_request)?;
    let insert_keyword = match dialect {
        SqlDialect::Postgres | SqlDialect::MySql => "INSERT",
        SqlDialect::Sqlite => "INSERT OR IGNORE",
    };
    let conflict_suffix = match dialect {
        SqlDialect::Postgres => format!(" ON CONFLICT ({key}) DO NOTHING"),
        SqlDialect::MySql => String::new(),
        SqlDialect::Sqlite => String::new(),
    };
    let insert_prefix = match dialect {
        SqlDialect::MySql => "INSERT IGNORE",
        SqlDialect::Postgres | SqlDialect::Sqlite => insert_keyword,
    };
    let lock_suffix = match dialect {
        SqlDialect::Postgres | SqlDialect::MySql => " FOR UPDATE",
        SqlDialect::Sqlite => "",
    };

    Ok(SqlRateLimitPlan {
        insert_ignore: SqlStatement::new(format!(
            "{insert_prefix} INTO {table} ({key}, {count}, {last_request}) VALUES ({}, 0, {}){conflict_suffix}",
            dialect.placeholder(1),
            dialect.placeholder(2)
        )),
        select: SqlStatement::new(format!(
            "SELECT {count} AS count, {last_request} AS last_request FROM {table} WHERE {key} = {}{lock_suffix}",
            dialect.placeholder(1)
        )),
        update: SqlStatement::new(format!(
            "UPDATE {table} SET {count} = {}, {last_request} = {} WHERE {key} = {}",
            dialect.placeholder(1),
            dialect.placeholder(2),
            dialect.placeholder(3)
        )),
    })
}

/// Applies OpenAuth rate-limit semantics to a locked database record.
///
/// SQL adapters share this decision logic after they insert/select the row
/// inside their own transaction or locking primitive.
pub fn consume_sql_rate_limit_record(
    input: RateLimitConsumeInput,
    existing: Option<RateLimitRecord>,
) -> (RateLimitDecision, RateLimitRecord, bool) {
    let window_ms = input.rule.window.saturating_mul(1000) as i64;
    match existing {
        Some(record)
            if input.now_ms.saturating_sub(record.last_request) <= window_ms
                && record.count >= input.rule.max =>
        {
            let retry_ms = record
                .last_request
                .saturating_add(window_ms)
                .saturating_sub(input.now_ms)
                .max(0);
            (
                RateLimitDecision {
                    permitted: false,
                    retry_after: ceil_millis_to_seconds(retry_ms),
                    limit: input.rule.max,
                    remaining: 0,
                    reset_after: ceil_millis_to_seconds(retry_ms),
                },
                record,
                true,
            )
        }
        Some(mut record) if input.now_ms.saturating_sub(record.last_request) <= window_ms => {
            record.key = input.key;
            record.count = record.count.saturating_add(1);
            record.last_request = input.now_ms;
            let remaining = input.rule.max.saturating_sub(record.count);
            (
                RateLimitDecision {
                    permitted: true,
                    retry_after: 0,
                    limit: input.rule.max,
                    remaining,
                    reset_after: input.rule.window,
                },
                record,
                true,
            )
        }
        Some(mut record) => {
            record.key = input.key;
            record.count = 1;
            record.last_request = input.now_ms;
            (
                RateLimitDecision {
                    permitted: true,
                    retry_after: 0,
                    limit: input.rule.max,
                    remaining: input.rule.max.saturating_sub(1),
                    reset_after: input.rule.window,
                },
                record,
                true,
            )
        }
        None => {
            let record = RateLimitRecord {
                key: input.key,
                count: 1,
                last_request: input.now_ms,
            };
            (
                RateLimitDecision {
                    permitted: true,
                    retry_after: 0,
                    limit: input.rule.max,
                    remaining: input.rule.max.saturating_sub(1),
                    reset_after: input.rule.window,
                },
                record,
                false,
            )
        }
    }
}

fn ceil_millis_to_seconds(milliseconds: i64) -> u64 {
    if milliseconds <= 0 {
        return 0;
    }
    ((milliseconds as u64).saturating_add(999)) / 1000
}
