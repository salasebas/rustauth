use http::Method;
use openauth_plugins::api_key::{
    api_key, ApiKeyConfiguration, ApiKeyReference, ApiKeyStorageMode, API_KEY_MODEL, API_KEY_TABLE,
    UPSTREAM_PLUGIN_ID,
};
use serde_json::json;

#[test]
fn exposes_api_key_plugin_surface() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(UPSTREAM_PLUGIN_ID, "api-key");
    assert_eq!(API_KEY_MODEL, "api_key");
    assert_eq!(API_KEY_TABLE, "api_keys");

    let plugin = api_key();
    assert_eq!(plugin.id, "api-key");

    for (method, path) in [
        (Method::POST, "/api-key/create"),
        (Method::POST, "/api-key/verify"),
        (Method::GET, "/api-key/get"),
        (Method::POST, "/api-key/update"),
        (Method::POST, "/api-key/delete"),
        (Method::GET, "/api-key/list"),
        (Method::POST, "/api-key/delete-all-expired-api-keys"),
    ] {
        assert!(
            plugin
                .endpoints
                .iter()
                .any(|endpoint| endpoint.method == method && endpoint.path == path),
            "missing endpoint {method} {path}",
        );
    }

    Ok(())
}

#[test]
fn api_key_endpoints_expose_openapi_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = api_key();
    for (method, path, operation_id) in [
        (Method::POST, "/api-key/create", "createApiKey"),
        (Method::POST, "/api-key/verify", "verifyApiKey"),
        (Method::GET, "/api-key/get", "getApiKey"),
        (Method::POST, "/api-key/update", "updateApiKey"),
        (Method::POST, "/api-key/delete", "deleteApiKey"),
        (Method::GET, "/api-key/list", "listApiKeys"),
        (
            Method::POST,
            "/api-key/delete-all-expired-api-keys",
            "deleteAllExpiredApiKeys",
        ),
    ] {
        let endpoint = plugin
            .endpoints
            .iter()
            .find(|endpoint| endpoint.method == method && endpoint.path == path)
            .ok_or_else(|| format!("missing endpoint {method} {path}"))?;
        assert_eq!(endpoint.options.operation_id.as_deref(), Some(operation_id));
        assert!(endpoint.options.openapi.is_some());
    }

    let create = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/api-key/create")
        .ok_or("missing create endpoint")?;
    assert!(create
        .options
        .body_schema
        .as_ref()
        .is_some_and(|schema| schema.fields.iter().any(|field| field.name == "name")));

    Ok(())
}

#[test]
fn public_options_serialize_with_camel_case_http_names() -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::to_value(ApiKeyConfiguration {
        storage: ApiKeyStorageMode::SecondaryStorage,
        reference: ApiKeyReference::Organization,
        default_key_length: 48,
        enable_session_for_api_keys: true,
        ..ApiKeyConfiguration::default()
    })?;

    assert_eq!(value["defaultKeyLength"], 48);
    assert_eq!(value["enableSessionForApiKeys"], true);
    assert_eq!(value["storage"], "secondaryStorage");
    assert_eq!(value["reference"], "organization");
    assert!(value["default_key_length"].is_null());

    let decoded: ApiKeyConfiguration = serde_json::from_value(json!({
        "storage": "secondaryStorage",
        "reference": "organization",
        "defaultKeyLength": 40
    }))?;
    assert_eq!(decoded.storage, ApiKeyStorageMode::SecondaryStorage);
    assert_eq!(decoded.reference, ApiKeyReference::Organization);
    assert_eq!(decoded.default_key_length, 40);
    Ok(())
}
