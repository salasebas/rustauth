#[path = "accounts.rs"]
mod accounts;
#[path = "address.rs"]
mod address;
#[path = "nonce.rs"]
mod nonce;
#[path = "schema.rs"]
mod schema;
#[path = "verify.rs"]
mod verify;

use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_plugins::siwe::{siwe_with, SiweOptions, SiweVerifyMessageArgs};
use serde_json::Value;

const DOMAIN: &str = "example.com";
const SECRET: &str = "test-secret-123456789012345678901234";
const WALLET: &str = "0x000000000000000000000000000000000000dEaD";

fn options() -> SiweOptions {
    SiweOptions::new(
        DOMAIN,
        || async { Ok("A1b2C3d4E5f6G7h8J".to_owned()) },
        |args: SiweVerifyMessageArgs| async move {
            Ok(args.message == "valid_message" && args.signature == "valid_signature")
        },
    )
}

fn options_rejecting_signature() -> SiweOptions {
    SiweOptions::new(
        DOMAIN,
        || async { Ok("nonce".to_owned()) },
        |_args: SiweVerifyMessageArgs| async { Ok(false) },
    )
}

fn router(
    adapter: Arc<MemoryAdapter>,
    siwe_options: SiweOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![siwe_with(siwe_options)?],
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn json_request(method: Method, path: &str, body: Value) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string().into_bytes())
}

async fn post_json(
    router: &AuthRouter,
    path: &str,
    body: Value,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(router
        .handle_async(json_request(Method::POST, path, body)?)
        .await?)
}

fn response_json(response: &http::Response<Vec<u8>>) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(response.body())
}

async fn nonce(
    router: &AuthRouter,
    wallet_address: &str,
    chain_id: Option<i64>,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut body = serde_json::Map::new();
    body.insert(
        "walletAddress".to_owned(),
        Value::String(wallet_address.to_owned()),
    );
    if let Some(chain_id) = chain_id {
        body.insert("chainId".to_owned(), Value::Number(chain_id.into()));
    }
    post_json(router, "/api/auth/siwe/nonce", Value::Object(body)).await
}

async fn verify(
    router: &AuthRouter,
    wallet_address: &str,
    chain_id: Option<i64>,
    message: &str,
    signature: &str,
    email: Option<&str>,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut body = serde_json::Map::new();
    body.insert("message".to_owned(), Value::String(message.to_owned()));
    body.insert("signature".to_owned(), Value::String(signature.to_owned()));
    body.insert(
        "walletAddress".to_owned(),
        Value::String(wallet_address.to_owned()),
    );
    if let Some(chain_id) = chain_id {
        body.insert("chainId".to_owned(), Value::Number(chain_id.into()));
    }
    if let Some(email) = email {
        body.insert("email".to_owned(), Value::String(email.to_owned()));
    }
    post_json(router, "/api/auth/siwe/verify", Value::Object(body)).await
}

async fn record_by_string(
    adapter: &MemoryAdapter,
    model: &str,
    field: &str,
    value: &str,
) -> Result<Option<openauth_core::db::DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned()))),
        )
        .await
}

#[test]
fn plugin_exposes_serializable_non_callback_options_metadata() -> Result<(), OpenAuthError> {
    let plugin = siwe_with(
        options()
            .anonymous(false)
            .email_domain_name("wallet.example.com")
            .schema(openauth_plugins::siwe::SiweSchemaOptions::new().table_name("wallet_address")),
    )?;
    let metadata = plugin
        .options
        .ok_or_else(|| OpenAuthError::Api("siwe plugin options metadata missing".to_owned()))?;

    assert_eq!(metadata["domain"], "example.com");
    assert_eq!(metadata["emailDomainName"], "wallet.example.com");
    assert_eq!(metadata["anonymous"], false);
    assert!(metadata.get("getNonce").is_none());
    assert!(metadata.get("verifyMessage").is_none());
    assert!(metadata.get("ensLookup").is_none());
    assert_eq!(
        metadata["schema"]["walletAddress"]["modelName"],
        "wallet_address"
    );
    Ok(())
}

#[test]
fn plugin_endpoint_registry_includes_siwe_operation_ids() -> Result<(), OpenAuthError> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options())?;
    let registry = router.endpoint_registry();

    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/siwe/nonce"
            && endpoint.operation_id.as_deref() == Some("getSiweNonce")));
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/siwe/verify"
            && endpoint.operation_id.as_deref() == Some("verifySiweMessage")));
    Ok(())
}

#[test]
fn public_types_include_wallet_address_and_extended_cacao_fields() {
    let _wallet = openauth_plugins::siwe::WalletAddress {
        id: "wallet_1".to_owned(),
        user_id: "user_1".to_owned(),
        address: WALLET.to_owned(),
        chain_id: 1,
        is_primary: true,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    let cacao = openauth_plugins::siwe::Cacao {
        h: openauth_plugins::siwe::CacaoHeader {
            t: "caip122".to_owned(),
        },
        p: openauth_plugins::siwe::CacaoPayload {
            domain: "example.com".to_owned(),
            aud: "example.com".to_owned(),
            nonce: "nonce".to_owned(),
            iss: "example.com".to_owned(),
            version: Some("1".to_owned()),
            iat: Some("2026-05-14T00:00:00Z".to_owned()),
            nbf: None,
            exp: None,
            statement: Some("Sign in".to_owned()),
            request_id: Some("request-1".to_owned()),
            resources: Some(vec!["https://example.com".to_owned()]),
            r#type: Some("eip4361".to_owned()),
        },
        s: openauth_plugins::siwe::CacaoSignature {
            t: "eip1271".to_owned(),
            s: "signature".to_owned(),
            m: Some("message".to_owned()),
        },
    };

    assert_eq!(cacao.p.request_id.as_deref(), Some("request-1"));
}
