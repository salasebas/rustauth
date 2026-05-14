use openauth_core::context::create_auth_context;
use openauth_core::db::{DbFieldType, DbValue};
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::additional_fields::{
    additional_fields, AdditionalField, AdditionalFieldsOptions,
};

#[test]
fn exposes_additional_fields_placeholder() {
    assert_eq!(
        openauth_plugins::additional_fields::UPSTREAM_PLUGIN_ID,
        "additional-fields"
    );
}

#[test]
fn additional_fields_plugin_registers_user_and_session_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = additional_fields(
        AdditionalFieldsOptions::new()
            .user_field(
                "role",
                AdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("member".to_owned()))
                    .generated(),
            )
            .session_field(
                "theme",
                AdditionalField::new(DbFieldType::String).optional(),
            ),
    );

    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    })?;

    assert!(context
        .db_schema
        .table("user")
        .and_then(|table| table.field("role"))
        .is_some());
    assert!(context
        .db_schema
        .table("session")
        .and_then(|table| table.field("theme"))
        .is_some());
    assert!(context.options.user.additional_fields.contains_key("role"));
    assert!(context
        .options
        .session
        .additional_fields
        .contains_key("theme"));
    Ok(())
}
