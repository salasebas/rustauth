//! OpenAPI schema and reference plugin.

use http::{header, Method, StatusCode};
use openauth_core::api::{
    api_error, build_openapi_schema, core_auth_async_endpoints, create_auth_endpoint, ApiErrorCode,
    ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions, OpenApiOperation,
};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const UPSTREAM_PLUGIN_ID: &str = "open-api";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiOptions {
    pub path: String,
    pub disable_default_reference: bool,
    pub theme: String,
    pub nonce: Option<String>,
}

impl Default for OpenApiOptions {
    fn default() -> Self {
        Self {
            path: "/reference".to_owned(),
            disable_default_reference: false,
            theme: "default".to_owned(),
            nonce: None,
        }
    }
}

impl OpenApiOptions {
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = normalize_path(path.into());
        self
    }

    #[must_use]
    pub fn disable_default_reference(mut self, disabled: bool) -> Self {
        self.disable_default_reference = disabled;
        self
    }

    #[must_use]
    pub fn theme(mut self, theme: impl Into<String>) -> Self {
        self.theme = theme.into();
        self
    }

    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

pub fn open_api(options: OpenApiOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(serde_json::to_value(&options).unwrap_or(serde_json::Value::Null))
        .with_endpoint(generate_schema_endpoint())
        .with_endpoint(reference_endpoint(options))
}

fn generate_schema_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/open-api/generate-schema",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("generateOpenAPISchema")
            .openapi(
                OpenApiOperation::new("generateOpenAPISchema")
                    .description("Generate the OpenAPI schema for this OpenAuth instance")
                    .response(
                        "200",
                        json!({
                            "description": "OpenAPI schema",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object"
                                    }
                                }
                            }
                        }),
                    ),
            ),
        move |context, _request| {
            Box::pin(async move {
                json_response(
                    StatusCode::OK,
                    serde_json::to_vec(&schema_for_context(context))
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                )
            })
        },
    )
}

fn reference_endpoint(options: OpenApiOptions) -> AsyncAuthEndpoint {
    let path = options.path.clone();
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("openApiReference")
            .hide_from_openapi()
            .openapi(
                OpenApiOperation::new("openApiReference")
                    .summary("OpenAPI reference")
                    .description("Serve the interactive OpenAPI reference"),
            ),
        move |context, _request| {
            let options = options.clone();
            Box::pin(async move {
                if options.disable_default_reference {
                    return api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound);
                }
                html_response(get_html(
                    &schema_for_context(context),
                    &options.theme,
                    options.nonce.as_deref(),
                ))
            })
        },
    )
}

fn schema_for_context(context: &AuthContext) -> serde_json::Value {
    let mut endpoints = context
        .adapter()
        .map(core_auth_async_endpoints)
        .unwrap_or_default();
    for plugin in &context.plugins {
        endpoints.extend(plugin.endpoints.iter().cloned());
    }
    build_openapi_schema(context, &endpoints)
}

fn get_html(api_reference: &serde_json::Value, theme: &str, nonce: Option<&str>) -> String {
    let nonce_attr = nonce
        .map(|nonce| format!(" nonce=\"{}\"", escape_html_attr(nonce)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html>
  <head>
    <title>OpenAuth API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" type="application/json">{api_reference}</script>
    <script{nonce_attr}>
      var configuration = {{
        theme: "{theme}",
        metaData: {{
          title: "OpenAuth API",
          description: "API Reference for your OpenAuth instance"
        }}
      }}
      document.getElementById("api-reference").dataset.configuration =
        JSON.stringify(configuration)
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"{nonce_attr}></script>
  </body>
</html>"#,
        api_reference = api_reference,
        theme = escape_js_string(theme),
        nonce_attr = nonce_attr,
    )
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Result<ApiResponse, OpenAuthError> {
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn html_response(body: String) -> Result<ApiResponse, OpenAuthError> {
    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body.into_bytes())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn normalize_path(path: String) -> String {
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn escape_html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_js_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
