use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use serde_json::json;

use crate::openapi::{
    id_body_schema, json_openapi_response, passkey_openapi_schema, update_passkey_body_schema,
};
use crate::options::PasskeyOptions;
use crate::response::{error_response, json_response, not_allowed, unauthorized};
use crate::routes::{adapter, IdBody, UpdatePasskeyBody};
use crate::session::current_session;
use crate::store::PasskeyStore;

pub(super) fn list_passkeys_endpoint(_options: Arc<PasskeyOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/list-user-passkeys",
        Method::GET,
        AuthEndpointOptions::new().openapi(
            OpenApiOperation::new("listPasskeys")
                .tag("Passkey")
                .description("List all passkeys for the authenticated user")
                .response(
                    "200",
                    json_openapi_response(
                        "Passkeys retrieved successfully",
                        json!({
                            "type": "array",
                            "items": passkey_openapi_schema(),
                        }),
                    ),
                ),
        ),
        move |context, request| {
            Box::pin(async move {
                let adapter = adapter(context)?;
                let Some((_, user, cookies)) = current_session(context, &request).await? else {
                    return unauthorized();
                };
                let passkeys = PasskeyStore::new(adapter.as_ref())
                    .list_by_user(&user.id)
                    .await?;
                json_response(StatusCode::OK, &passkeys, cookies)
            })
        },
    )
}

pub(super) fn delete_passkey_endpoint(_options: Arc<PasskeyOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/delete-passkey",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/json"])
            .body_schema(id_body_schema())
            .openapi(
                OpenApiOperation::new("deletePasskey")
                    .tag("Passkey")
                    .description("Delete a specific passkey")
                    .response(
                        "200",
                        json_openapi_response(
                            "Passkey deleted successfully",
                            json!({
                                "type": "object",
                                "properties": {
                                    "status": { "type": "boolean" },
                                },
                                "required": ["status"],
                            }),
                        ),
                    ),
            ),
        move |context, request| {
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: IdBody = parse_request_body(&request)?;
                let Some((_, user, cookies)) = current_session(context, &request).await? else {
                    return unauthorized();
                };
                let store = PasskeyStore::new(adapter.as_ref());
                let Some(passkey) = store.find_by_id(&body.id).await? else {
                    return error_response(
                        StatusCode::NOT_FOUND,
                        "PASSKEY_NOT_FOUND",
                        "Passkey not found",
                    );
                };
                if passkey.user_id != user.id {
                    return unauthorized();
                }
                store.delete_for_user(&body.id, &user.id).await?;
                json_response(StatusCode::OK, &json!({ "status": true }), cookies)
            })
        },
    )
}

pub(super) fn update_passkey_endpoint(_options: Arc<PasskeyOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/update-passkey",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/json"])
            .body_schema(update_passkey_body_schema())
            .openapi(
                OpenApiOperation::new("updatePasskey")
                    .tag("Passkey")
                    .description("Update a specific passkey name")
                    .response(
                        "200",
                        json_openapi_response(
                            "Passkey updated successfully",
                            json!({
                                "type": "object",
                                "properties": {
                                    "passkey": passkey_openapi_schema(),
                                },
                                "required": ["passkey"],
                            }),
                        ),
                    ),
            ),
        move |context, request| {
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: UpdatePasskeyBody = parse_request_body(&request)?;
                let Some((_, user, cookies)) = current_session(context, &request).await? else {
                    return unauthorized();
                };
                let store = PasskeyStore::new(adapter.as_ref());
                let Some(existing) = store.find_by_id(&body.id).await? else {
                    return error_response(
                        StatusCode::NOT_FOUND,
                        "PASSKEY_NOT_FOUND",
                        "Passkey not found",
                    );
                };
                if existing.user_id != user.id {
                    return not_allowed();
                }
                let Some(passkey) = store
                    .update_name_for_user(&body.id, &user.id, body.name)
                    .await?
                else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "FAILED_TO_UPDATE_PASSKEY",
                        "Failed to update passkey",
                    );
                };
                json_response(StatusCode::OK, &json!({ "passkey": passkey }), cookies)
            })
        },
    )
}
