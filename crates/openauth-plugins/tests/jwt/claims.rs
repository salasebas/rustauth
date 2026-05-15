use std::sync::Arc;

use http::Method;
use openauth_core::db::MemoryAdapter;
use openauth_plugins::jwt::{
    jwt_with_options, verify_jwt, JwtClaims, JwtOptions, JwtSigningOptions,
};
use serde_json::{json, Value};

use super::helpers::*;

#[tokio::test]
async fn token_endpoint_uses_custom_payload_and_subject() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let plugin = jwt_with_options(JwtOptions {
        jwt: JwtSigningOptions {
            define_payload: Some(Arc::new(|session| {
                let user_id = session.user.id.clone();
                Box::pin(async move {
                    let mut claims = JwtClaims::new();
                    claims.insert("role".to_owned(), json!("admin"));
                    claims.insert("user_id".to_owned(), json!(user_id));
                    Ok(claims)
                })
            })),
            get_subject: Some(Arc::new(|session| {
                let session_id = session.session.id.clone();
                Box::pin(async move { Ok(format!("session:{session_id}")) })
            })),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    })?;
    let context = openauth_core::context::create_auth_context_with_adapter(
        options_with_plugin(plugin.clone()),
        adapter.clone(),
    )?;
    let router = router_with_plugin(adapter, plugin)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/token", "", Some(&cookie))?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let payload = verify_jwt(
        &context,
        body["token"].as_str().ok_or("missing token")?,
        None,
    )
    .await?
    .ok_or("token should verify")?;

    assert_eq!(payload["sub"], "session:session_1");
    assert_eq!(payload["role"], "admin");
    assert_eq!(payload["user_id"], "user_1");
    assert!(payload.get("email").is_none());
    Ok(())
}
