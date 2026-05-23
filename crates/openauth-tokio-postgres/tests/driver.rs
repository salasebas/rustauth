use openauth_core::db::{DbFieldType, DbValue, SqlParam};
use openauth_tokio_postgres::driver::{param_refs, postgres_params};

#[test]
fn driver_binds_open_auth_values_for_postgres_execution() -> Result<(), Box<dyn std::error::Error>>
{
    let values = postgres_params(&[
        SqlParam {
            field_type: DbFieldType::String,
            generated_id: None,
            value: DbValue::String("user@example.com".to_owned()),
        },
        SqlParam {
            field_type: DbFieldType::Number,
            generated_id: None,
            value: DbValue::Null,
        },
    ])?;

    assert_eq!(values.len(), 2);
    assert_eq!(param_refs(&values).len(), 2);
    Ok(())
}
