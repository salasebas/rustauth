use openauth_core::db::{IdGeneration, IdPolicy, IdValue};

#[test]
fn id_policy_defaults_to_required_string_id() {
    let field = IdPolicy::default().field();

    assert!(field.required);
    assert_eq!(field.field_type, openauth_core::db::DbFieldType::String);
}

#[test]
fn id_policy_uses_number_for_serial_ids() {
    let field = IdPolicy::new(IdGeneration::Serial).field();

    assert!(!field.required);
    assert_eq!(field.field_type, openauth_core::db::DbFieldType::Number);
}

#[test]
fn id_policy_disables_required_id_when_generation_is_disabled() {
    let field = IdPolicy::new(IdGeneration::Disabled).field();

    assert!(!field.required);
}

#[test]
fn id_policy_converts_serial_input_to_number() {
    let policy = IdPolicy::new(IdGeneration::Serial);

    assert_eq!(
        policy.transform_input(Some("42")),
        Some(IdValue::Number(42))
    );
}

#[test]
fn id_policy_drops_invalid_serial_input() {
    let policy = IdPolicy::new(IdGeneration::Serial);

    assert_eq!(policy.transform_input(Some("not-a-number")), None);
}

#[test]
fn id_policy_drops_uuid_input_when_database_generates_uuid() {
    let policy = IdPolicy::new(IdGeneration::Uuid).with_database_uuid_support(true);

    assert_eq!(
        policy.transform_input(Some("550e8400-e29b-41d4-a716-446655440000")),
        None
    );
}

#[test]
fn id_policy_accepts_uuid_input_when_force_allow_id_is_true() {
    let policy = IdPolicy::new(IdGeneration::Uuid).with_force_allow_id(true);

    assert_eq!(
        policy.transform_input(Some("550e8400-e29b-41d4-a716-446655440000")),
        Some(IdValue::String(
            "550e8400-e29b-41d4-a716-446655440000".to_owned()
        ))
    );
}

#[test]
fn id_policy_drops_invalid_uuid_input_when_force_allow_id_is_true() {
    let policy = IdPolicy::new(IdGeneration::Uuid).with_force_allow_id(true);

    assert_eq!(policy.transform_input(Some("invalid")), None);
}

#[test]
fn id_policy_outputs_values_as_strings() {
    let policy = IdPolicy::default();

    assert_eq!(
        policy.transform_output(Some(IdValue::Number(123))),
        Some("123".to_owned())
    );
}
