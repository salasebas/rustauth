use openauth_core::db::sql::{
    consume_sql_rate_limit_record, count_statement, create_statement, delete_one_statement,
    ensure_executable_migration_plan, execute_schema_migration_plan, find_many_statement,
    internal_base_selection, joined_rows, plan_schema_migration, rate_limit_consume_statements,
    resolve_native_joins, update_one_plan, DeleteOneStrategy, SqlAdapterRunner, SqlColumnSnapshot,
    SqlDialect, SqlExecutor, SqlRateLimitNames, SqlRowReader, SqlSchemaSnapshot, SqlStatement,
    SqlUpdateOnePlan,
};
use openauth_core::db::{
    auth_schema, AdapterFuture, AuthSchemaOptions, Connector, Create, DbField, DbFieldType,
    DbRecord, DbValue, Delete, FindMany, ForeignKey, IdGeneration, IdPolicy, JoinOption,
    MigrationStatement, MigrationStatementKind, OnDelete, RateLimitStorage, SchemaMigrationPlan,
    SchemaMigrationWarning, Sort, SortDirection, TableOptions, Update, Where, WhereMode,
    WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{RateLimitConsumeInput, RateLimitRecord, RateLimitRule};

#[test]
fn sql_module_reexports_public_adapter_api_after_internal_split() {
    let _statement = openauth_core::db::sql::SqlStatement::new("SELECT 1");
    let _fragment = openauth_core::db::sql::SqlFragment::new("WHERE 1 = 1");
    let _dialect = openauth_core::db::sql::SqlDialect::Postgres;
    let _names = openauth_core::db::sql::SqlRateLimitNames::new("rate_limits");
}

#[test]
fn sql_dialect_where_clause_uses_postgres_placeholders_and_params() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let table = schema
        .table("user")
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: "user".to_owned(),
        })?;

    let fragment = SqlDialect::Postgres.where_clause(
        table,
        &[
            Where::new("email", DbValue::String("example.com".to_owned()))
                .operator(WhereOperator::EndsWith)
                .insensitive(),
            Where::new(
                "id",
                DbValue::StringArray(vec!["user_1".to_owned(), "user_2".to_owned()]),
            )
            .operator(WhereOperator::In),
        ],
    )?;

    assert_eq!(
        fragment.sql,
        " WHERE \"email\" ILIKE $1 ESCAPE '\\' AND \"id\" IN ($2, $3)"
    );
    assert_eq!(
        fragment
            .params
            .into_iter()
            .map(|param| param.value)
            .collect::<Vec<_>>(),
        vec![
            DbValue::String("%example.com".to_owned()),
            DbValue::String("user_1".to_owned()),
            DbValue::String("user_2".to_owned()),
        ]
    );
    Ok(())
}

#[test]
fn sql_dialect_applies_insensitive_mode_to_equality_and_array_predicates(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let table = schema
        .table("user")
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: "user".to_owned(),
        })?;

    let fragment = SqlDialect::Postgres.where_clause(
        table,
        &[
            Where::new("email", DbValue::String("Ada@Example.COM".to_owned())).insensitive(),
            Where::new(
                "name",
                DbValue::StringArray(vec!["Grace".to_owned(), "ALAN".to_owned()]),
            )
            .operator(WhereOperator::NotIn)
            .insensitive(),
        ],
    )?;

    assert_eq!(
        fragment.sql,
        " WHERE LOWER(\"email\") = LOWER($1) AND LOWER(\"name\") NOT IN (LOWER($2), LOWER($3))"
    );
    assert_eq!(
        fragment
            .params
            .into_iter()
            .map(|param| param.value)
            .collect::<Vec<_>>(),
        vec![
            DbValue::String("Ada@Example.COM".to_owned()),
            DbValue::String("Grace".to_owned()),
            DbValue::String("ALAN".to_owned()),
        ]
    );
    Ok(())
}

#[test]
fn sql_dialect_compiles_empty_in_predicates_as_boolean_constants() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let table = schema
        .table("user")
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: "user".to_owned(),
        })?;

    let empty_in = SqlDialect::Postgres.where_clause(
        table,
        &[Where::new("id", DbValue::StringArray(Vec::new())).operator(WhereOperator::In)],
    )?;
    let empty_not_in = SqlDialect::Postgres.where_clause(
        table,
        &[Where::new("id", DbValue::StringArray(Vec::new())).operator(WhereOperator::NotIn)],
    )?;

    assert_eq!(empty_in.sql, " WHERE 1 = 0");
    assert!(empty_in.params.is_empty());
    assert_eq!(empty_not_in.sql, " WHERE 1 = 1");
    assert!(empty_not_in.params.is_empty());
    Ok(())
}

#[test]
fn sql_dialect_maps_postgres_arrays_to_native_array_types() {
    assert_eq!(
        SqlDialect::Postgres.sql_type("tags", &DbField::new("tags", DbFieldType::StringArray)),
        "TEXT[]"
    );
    assert_eq!(
        SqlDialect::Postgres.sql_type("scores", &DbField::new("scores", DbFieldType::NumberArray)),
        "BIGINT[]"
    );
    assert!(
        SqlDialect::Postgres.type_matches("_text", &DbField::new("tags", DbFieldType::StringArray))
    );
    assert!(SqlDialect::Postgres
        .type_matches("_int8", &DbField::new("scores", DbFieldType::NumberArray)));
    assert!(!SqlDialect::Postgres
        .type_matches("jsonb", &DbField::new("tags", DbFieldType::StringArray)));
}

#[test]
fn sql_dialect_groups_and_or_predicates_deterministically() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let table = schema
        .table("user")
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: "user".to_owned(),
        })?;

    let fragment = SqlDialect::Postgres.where_clause(
        table,
        &[
            Where::new("email", DbValue::String("ada@example.com".to_owned())),
            Where {
                field: "name".to_owned(),
                value: DbValue::String("Ada".to_owned()),
                operator: WhereOperator::Eq,
                connector: Connector::Or,
                mode: WhereMode::Sensitive,
            },
            Where::new("email_verified", DbValue::Boolean(true)),
        ],
    )?;

    assert_eq!(
        fragment.sql,
        " WHERE \"email\" = $1 AND \"email_verified\" = $2 AND (\"name\" = $3)"
    );
    assert_eq!(
        fragment
            .params
            .into_iter()
            .map(|param| param.value)
            .collect::<Vec<_>>(),
        vec![
            DbValue::String("ada@example.com".to_owned()),
            DbValue::Boolean(true),
            DbValue::String("Ada".to_owned()),
        ]
    );
    Ok(())
}

#[test]
fn sql_dialect_escapes_like_wildcards_in_string_pattern_predicates() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let table = schema
        .table("user")
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: "user".to_owned(),
        })?;

    let fragment = SqlDialect::Postgres.where_clause(
        table,
        &[Where {
            field: "email".to_owned(),
            value: DbValue::String(r"100%_match\test".to_owned()),
            operator: WhereOperator::Contains,
            connector: openauth_core::db::Connector::And,
            mode: WhereMode::Insensitive,
        }],
    )?;

    assert_eq!(fragment.sql, " WHERE \"email\" ILIKE $1 ESCAPE '\\'");
    assert_eq!(
        fragment.params[0].value,
        DbValue::String(r"%100\%\_match\\test%".to_owned())
    );
    Ok(())
}

#[test]
fn sql_dialect_supports_database_generated_id_column_definitions() -> Result<(), OpenAuthError> {
    let serial = IdPolicy::new(IdGeneration::Serial).field();
    let postgres_uuid = IdPolicy::new(IdGeneration::Uuid)
        .with_database_uuid_support(true)
        .field();

    assert_eq!(
        SqlDialect::Postgres.column_definition("id", &serial)?,
        "\"id\" BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"
    );
    assert_eq!(
        SqlDialect::Postgres.column_definition("id", &postgres_uuid)?,
        "\"id\" UUID DEFAULT pg_catalog.gen_random_uuid() PRIMARY KEY"
    );
    assert_eq!(
        SqlDialect::Sqlite.column_definition("id", &serial)?,
        "\"id\" INTEGER PRIMARY KEY"
    );
    assert_eq!(
        SqlDialect::MySql.column_definition("id", &serial)?,
        "`id` BIGINT AUTO_INCREMENT PRIMARY KEY"
    );
    Ok(())
}

#[test]
fn create_statement_returns_generated_ids_for_returning_dialects() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Serial),
        ..AuthSchemaOptions::default()
    });

    let statement = create_statement(
        SqlDialect::Postgres,
        &schema,
        &Create::new("user")
            .data("email", DbValue::String("ada@example.com".to_owned()))
            .select(["id", "email"]),
    )?;

    assert_eq!(
        statement.sql,
        "INSERT INTO \"users\" (\"email\") VALUES ($1) RETURNING \"id\", \"email\""
    );
    Ok(())
}

#[test]
fn sql_dialect_rejects_invalid_identifiers() {
    assert!(SqlDialect::MySql.quote_identifier("users;drop").is_err());
}

#[test]
fn plan_schema_migration_creates_missing_tables_in_schema_order() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());

    let plan = plan_schema_migration(SqlDialect::Sqlite, &schema, &SqlSchemaSnapshot::default())?;

    assert_eq!(plan.to_be_created[0].logical_name, "user");
    Ok(())
}

#[test]
fn plan_schema_migration_reports_missing_columns_indexes_and_type_warnings(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default().with_field(
            "nickname",
            DbField::new("nickname", DbFieldType::String).indexed(),
        ),
        ..AuthSchemaOptions::default()
    });
    let snapshot = SqlSchemaSnapshot::default()
        .with_table("users")
        .with_column("users", SqlColumnSnapshot::new("email", "integer"))
        .with_column("users", SqlColumnSnapshot::new("id", "text"));

    let plan = plan_schema_migration(SqlDialect::Postgres, &schema, &snapshot)?;

    assert!(plan
        .to_be_added
        .iter()
        .any(|column| column.field_logical_name == "nickname"));
    assert!(plan
        .indexes_to_be_created
        .iter()
        .any(|index| index.field_logical_name == "nickname"));
    assert!(plan
        .warnings
        .contains(&SchemaMigrationWarning::ColumnTypeMismatch {
            table_name: "users".to_owned(),
            column_name: "email".to_owned(),
            expected: "TEXT".to_owned(),
            actual: "integer".to_owned(),
        }));
    Ok(())
}

#[test]
fn ensure_executable_migration_plan_rejects_warning_plans_and_accepts_clean_plans(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let warning_snapshot = SqlSchemaSnapshot::default()
        .with_table("users")
        .with_column("users", SqlColumnSnapshot::new("id", "text"))
        .with_column("users", SqlColumnSnapshot::new("email", "integer"));
    let warning_plan = plan_schema_migration(SqlDialect::Postgres, &schema, &warning_snapshot)?;
    assert!(warning_plan.has_warnings());
    assert!(matches!(
        ensure_executable_migration_plan(&warning_plan),
        Err(OpenAuthError::Adapter(message)) if message.contains("non-executable migration warnings")
    ));

    let clean_plan =
        plan_schema_migration(SqlDialect::Postgres, &schema, &SqlSchemaSnapshot::default())?;
    assert!(!clean_plan.has_warnings());
    assert!(ensure_executable_migration_plan(&clean_plan).is_ok());
    Ok(())
}

#[test]
fn plan_schema_migration_repairs_missing_unique_indexes() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let snapshot = SqlSchemaSnapshot::default()
        .with_table("users")
        .with_column("users", SqlColumnSnapshot::new("id", "text"))
        .with_column("users", SqlColumnSnapshot::new("email", "text"));

    let plan = plan_schema_migration(SqlDialect::Postgres, &schema, &snapshot)?;

    assert!(plan
        .indexes_to_be_created
        .iter()
        .any(|index| index.field_logical_name == "email" && index.unique));
    assert!(plan
        .statements
        .iter()
        .any(|statement| statement.sql.contains("CREATE UNIQUE INDEX")));
    Ok(())
}

#[test]
fn plan_schema_migration_warns_for_constraint_and_id_mismatches() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Serial),
        ..AuthSchemaOptions::default()
    });
    let snapshot = SqlSchemaSnapshot::default()
        .with_table("users")
        .with_column(
            "users",
            SqlColumnSnapshot::new("id", "bigint")
                .primary_key(false)
                .generated_id(None),
        )
        .with_column(
            "users",
            SqlColumnSnapshot::new("name", "text").nullable(true),
        )
        .with_column(
            "users",
            SqlColumnSnapshot::new("email", "text").nullable(false),
        )
        .with_column(
            "users",
            SqlColumnSnapshot::new("email_verified", "boolean").nullable(false),
        )
        .with_column(
            "users",
            SqlColumnSnapshot::new("image", "text").nullable(false),
        )
        .with_column(
            "users",
            SqlColumnSnapshot::new("created_at", "timestamptz").nullable(false),
        )
        .with_column(
            "users",
            SqlColumnSnapshot::new("updated_at", "timestamptz").nullable(false),
        );

    let plan = plan_schema_migration(SqlDialect::Postgres, &schema, &snapshot)?;

    assert!(plan
        .warnings
        .contains(&SchemaMigrationWarning::PrimaryKeyMismatch {
            table_name: "users".to_owned(),
            column_name: "id".to_owned(),
        }));
    assert!(plan
        .warnings
        .contains(&SchemaMigrationWarning::GeneratedIdMismatch {
            table_name: "users".to_owned(),
            column_name: "id".to_owned(),
            expected: IdGeneration::Serial,
            actual: None,
        }));
    assert!(plan
        .warnings
        .contains(&SchemaMigrationWarning::ColumnNullabilityMismatch {
            table_name: "users".to_owned(),
            column_name: "name".to_owned(),
            expected_nullable: false,
            actual_nullable: true,
        }));
    assert!(plan
        .warnings
        .contains(&SchemaMigrationWarning::ColumnNullabilityMismatch {
            table_name: "users".to_owned(),
            column_name: "image".to_owned(),
            expected_nullable: true,
            actual_nullable: false,
        }));
    Ok(())
}

#[test]
fn plan_schema_migration_warns_for_foreign_key_mismatch() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let snapshot = SqlSchemaSnapshot::default()
        .with_table("users")
        .with_column("users", SqlColumnSnapshot::new("id", "text"))
        .with_table("sessions")
        .with_column(
            "sessions",
            SqlColumnSnapshot::new("user_id", "text").references(ForeignKey::new(
                "users",
                "id",
                OnDelete::Restrict,
            )),
        );

    let plan = plan_schema_migration(SqlDialect::Postgres, &schema, &snapshot)?;

    assert!(plan
        .warnings
        .contains(&SchemaMigrationWarning::ForeignKeyMismatch {
            table_name: "sessions".to_owned(),
            column_name: "user_id".to_owned(),
            expected: ForeignKey::new("users", "id", OnDelete::Cascade),
            actual: Some(ForeignKey::new("users", "id", OnDelete::Restrict)),
        }));
    Ok(())
}

#[test]
fn joined_rows_groups_base_records_and_applies_join_limits() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let base_table = schema
        .table("user")
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: "user".to_owned(),
        })?;
    let joins = [("account".to_owned(), JoinOption::enabled().limit(1))]
        .into_iter()
        .collect();
    let resolved = resolve_native_joins(&schema, "user", base_table, &joins, 100)?;
    let base_selection = internal_base_selection(base_table, &[], &resolved)?;
    let rows = vec![
        FakeJoinedRow::new("user_1", "ada@example.com", Some(("account_1", "github"))),
        FakeJoinedRow::new("user_1", "ada@example.com", Some(("account_2", "google"))),
    ];

    let records = joined_rows(&rows, &base_selection, &[], &resolved, fake_row_value)?;

    assert_eq!(records.len(), 1);
    let Some(DbValue::RecordArray(accounts)) = records[0].get("account") else {
        return Err(OpenAuthError::Adapter(
            "expected account join records".to_owned(),
        ));
    };
    assert_eq!(accounts.len(), 1);
    assert_eq!(
        accounts[0].get("id"),
        Some(&DbValue::String("account_1".to_owned()))
    );
    assert_eq!(
        accounts[0].get("provider_id"),
        Some(&DbValue::String("github".to_owned()))
    );
    Ok(())
}

#[test]
fn create_statement_builds_insert_sql_and_params() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());

    let statement = create_statement(
        SqlDialect::Postgres,
        &schema,
        &Create::new("user")
            .data("id", DbValue::String("user_1".to_owned()))
            .data("email", DbValue::String("ada@example.com".to_owned())),
    )?;

    assert_eq!(
        statement.sql,
        "INSERT INTO \"users\" (\"id\", \"email\") VALUES ($1, $2)"
    );
    assert_eq!(
        statement
            .params
            .into_iter()
            .map(|param| param.value)
            .collect::<Vec<_>>(),
        vec![
            DbValue::String("user_1".to_owned()),
            DbValue::String("ada@example.com".to_owned()),
        ]
    );
    Ok(())
}

#[test]
fn find_many_statement_builds_select_sort_limit_offset() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());

    let read = find_many_statement(
        SqlDialect::MySql,
        &schema,
        &FindMany::new("user")
            .where_clause(
                Where::new("email", DbValue::String("example.com".to_owned()))
                    .operator(WhereOperator::EndsWith),
            )
            .sort_by(Sort::new("created_at", SortDirection::Desc))
            .limit(10)
            .offset(20)
            .select(["id", "email"]),
    )?;

    assert_eq!(
        read.statement.sql,
        "SELECT `id`, `email` FROM `users` WHERE `email` LIKE ? ESCAPE '\\\\' ORDER BY `created_at` DESC LIMIT 10 OFFSET 20"
    );
    assert_eq!(read.selection.len(), 2);
    assert_eq!(
        read.statement.params[0].value,
        DbValue::String("%example.com".to_owned())
    );
    Ok(())
}

#[test]
fn count_statement_builds_count_sql() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());

    let statement = count_statement(
        SqlDialect::Sqlite,
        &schema,
        &openauth_core::db::Count::new("session")
            .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
    )?;

    assert_eq!(
        statement.sql,
        "SELECT COUNT(*) FROM \"sessions\" WHERE \"user_id\" = ?"
    );
    Ok(())
}

#[test]
fn update_one_plan_uses_returning_for_postgres_and_preselect_for_mysql() -> Result<(), OpenAuthError>
{
    let schema = auth_schema(AuthSchemaOptions::default());
    let query = Update::new("session")
        .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
        .data("user_agent", DbValue::String("updated".to_owned()));

    let postgres = update_one_plan(SqlDialect::Postgres, &schema, &query)?;
    let mysql = update_one_plan(SqlDialect::MySql, &schema, &query)?;

    let SqlUpdateOnePlan::Returning(read) = postgres else {
        return Err(OpenAuthError::Adapter(
            "postgres should use returning".to_owned(),
        ));
    };
    assert!(read.statement.sql.contains(
        "WHERE ctid IN (SELECT ctid FROM \"sessions\" WHERE \"id\" = $2 LIMIT 1) RETURNING"
    ));

    let SqlUpdateOnePlan::PreselectThenUpdate { select, update, .. } = mysql else {
        return Err(OpenAuthError::Adapter(
            "mysql should use preselect".to_owned(),
        ));
    };
    assert!(select.statement.sql.ends_with("LIMIT 1"));
    assert_eq!(
        update.sql,
        "UPDATE `sessions` SET `user_agent` = ? WHERE `id` = ? LIMIT 1"
    );
    Ok(())
}

#[test]
fn delete_one_statement_uses_dialect_specific_single_row_strategy() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let query = Delete::new("session")
        .where_clause(Where::new("token", DbValue::String("token".to_owned())));

    let postgres = delete_one_statement(SqlDialect::Postgres, &schema, &query)?;
    let sqlite = delete_one_statement(SqlDialect::Sqlite, &schema, &query)?;
    let mysql = delete_one_statement(SqlDialect::MySql, &schema, &query)?;

    assert_eq!(postgres.strategy, DeleteOneStrategy::NestedId);
    assert!(postgres
        .statement
        .sql
        .contains("WHERE ctid IN (SELECT ctid FROM \"sessions\""));
    assert!(sqlite
        .statement
        .sql
        .contains("WHERE rowid IN (SELECT rowid FROM \"sessions\""));
    assert_eq!(
        mysql.statement.sql,
        "DELETE FROM `sessions` WHERE `token` = ? LIMIT 1"
    );
    Ok(())
}

#[test]
fn rate_limit_consume_statements_are_dialect_specific() -> Result<(), OpenAuthError> {
    let postgres = rate_limit_consume_statements(
        SqlDialect::Postgres,
        "rate_limits",
        "key",
        "count",
        "last_request",
    )?;
    let sqlite = rate_limit_consume_statements(
        SqlDialect::Sqlite,
        "rate_limits",
        "key",
        "count",
        "last_request",
    )?;
    let mysql = rate_limit_consume_statements(
        SqlDialect::MySql,
        "rate_limits",
        "key",
        "count",
        "last_request",
    )?;

    assert!(postgres.insert_ignore.sql.contains("ON CONFLICT"));
    assert!(postgres.select.sql.ends_with("FOR UPDATE"));
    assert!(sqlite.insert_ignore.sql.starts_with("INSERT OR IGNORE"));
    assert!(!sqlite.select.sql.ends_with("FOR UPDATE"));
    assert!(mysql.insert_ignore.sql.starts_with("INSERT IGNORE"));
    Ok(())
}

#[test]
fn sql_rate_limit_names_resolve_physical_schema_names() {
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        rate_limit: TableOptions::default()
            .with_name("auth_limits")
            .with_field_name("key", "bucket_key")
            .with_field_name("count", "attempt_count")
            .with_field_name("last_request", "last_seen_ms"),
        ..AuthSchemaOptions::default()
    });

    let names = SqlRateLimitNames::from_schema(&schema);

    assert_eq!(names.table, "auth_limits");
    assert_eq!(names.key, "bucket_key");
    assert_eq!(names.count, "attempt_count");
    assert_eq!(names.last_request, "last_seen_ms");
}

#[test]
fn consume_sql_rate_limit_record_resets_or_denies_without_adapter_logic() {
    let input = RateLimitConsumeInput {
        key: "ip:/sign-in".to_owned(),
        rule: RateLimitRule { window: 10, max: 2 },
        now_ms: 15_000,
    };
    let existing = RateLimitRecord {
        key: "old".to_owned(),
        count: 2,
        last_request: 10_000,
    };

    let (decision, record, update) = consume_sql_rate_limit_record(input, Some(existing));

    assert!(!decision.permitted);
    assert_eq!(decision.retry_after, 5);
    assert_eq!(record.count, 2);
    assert!(update);
}

#[tokio::test]
async fn execute_schema_migration_plan_runs_statements_through_sql_executor(
) -> Result<(), OpenAuthError> {
    let plan = SchemaMigrationPlan {
        statements: vec![
            MigrationStatement {
                kind: MigrationStatementKind::CreateTable,
                sql: "CREATE TABLE one (id TEXT PRIMARY KEY)".to_owned(),
            },
            MigrationStatement {
                kind: MigrationStatementKind::CreateIndex,
                sql: "CREATE INDEX idx_one_id ON one (id)".to_owned(),
            },
        ],
        ..SchemaMigrationPlan::default()
    };
    let mut executor = FakeSqlExecutor {
        rows: Vec::new(),
        scalar: 0,
        executed: Vec::new(),
    };

    execute_schema_migration_plan(&mut executor, &plan).await?;

    assert_eq!(
        executor.executed,
        vec![
            "CREATE TABLE one (id TEXT PRIMARY KEY)",
            "CREATE INDEX idx_one_id ON one (id)"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn sql_adapter_runner_reads_rows_without_sqlx() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let mut row = DbRecord::new();
    row.insert("id".to_owned(), DbValue::String("user_1".to_owned()));
    row.insert(
        "email".to_owned(),
        DbValue::String("ada@example.com".to_owned()),
    );
    let executor = FakeSqlExecutor {
        rows: vec![FakeSqlRow(row)],
        scalar: 0,
        executed: Vec::new(),
    };

    let records = SqlAdapterRunner::new(SqlDialect::Postgres, &schema, executor, FakeSqlRowReader)
        .find_many(FindMany::new("user").select(["id", "email"]))
        .await?;

    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    Ok(())
}

struct FakeJoinedRow {
    base_id: &'static str,
    base_email: &'static str,
    account: Option<(&'static str, &'static str)>,
}

struct FakeSqlExecutor {
    rows: Vec<FakeSqlRow>,
    scalar: i64,
    executed: Vec<String>,
}

impl SqlExecutor for FakeSqlExecutor {
    type Row = FakeSqlRow;

    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.executed.push(statement.sql);
            Ok(1)
        })
    }

    fn fetch_all<'a>(&'a mut self, _statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>> {
        Box::pin(async { Ok(std::mem::take(&mut self.rows)) })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        _statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async { Ok(self.rows.pop()) })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, _statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async { Ok(self.scalar) })
    }
}

struct FakeSqlRow(DbRecord);

struct FakeSqlRowReader;

impl SqlRowReader<FakeSqlRow> for FakeSqlRowReader {
    fn value_at(
        &self,
        row: &FakeSqlRow,
        _field: &DbField,
        alias: &str,
    ) -> Result<DbValue, OpenAuthError> {
        Ok(row.0.get(alias).cloned().unwrap_or(DbValue::Null))
    }
}

impl FakeJoinedRow {
    fn new(
        base_id: &'static str,
        base_email: &'static str,
        account: Option<(&'static str, &'static str)>,
    ) -> Self {
        Self {
            base_id,
            base_email,
            account,
        }
    }
}

fn fake_row_value(
    row: &FakeJoinedRow,
    field: &openauth_core::db::DbField,
    alias: &str,
) -> Result<DbValue, OpenAuthError> {
    match alias {
        "__base_id" => Ok(DbValue::String(row.base_id.to_owned())),
        "__base_0" if field.name == "id" => Ok(DbValue::String(row.base_id.to_owned())),
        alias if alias.starts_with("__base_") && field.name == "email" => {
            Ok(DbValue::String(row.base_email.to_owned()))
        }
        "__join_0_0" => Ok(row
            .account
            .map(|account| DbValue::String(account.0.to_owned()))
            .unwrap_or(DbValue::Null)),
        "__join_0_2" => Ok(row
            .account
            .map(|account| DbValue::String(account.1.to_owned()))
            .unwrap_or(DbValue::Null)),
        _ => Ok(DbValue::Null),
    }
}
