use http::{header, Method, StatusCode};

use crate::api::{
    create_auth_endpoint, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use crate::error::OpenAuthError;

pub(super) fn error_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/error",
        Method::GET,
        AuthEndpointOptions::new().openapi(
            OpenApiOperation::new("error")
                .description("Displays an error page")
                .response(
                    "200",
                    super::shared::json_openapi_response(
                        "Success",
                        serde_json::json!({
                            "type": "string",
                            "description": "The HTML content of the error page",
                        }),
                    ),
                ),
        ),
        move |context, request| {
            Box::pin(async move {
                let (code, description) = error_query(&request);
                let safe_code = if is_safe_code(&code) {
                    code
                } else {
                    "UNKNOWN".to_owned()
                };
                if context.options.production {
                    let separator = if "/".contains('?') { '&' } else { '?' };
                    return redirect(&format!("/{separator}error={}", percent_encode(&safe_code)));
                }
                html_response(&safe_code, description.as_deref())
            })
        },
    )
}

fn error_query(request: &ApiRequest) -> (String, Option<String>) {
    let mut code = "UNKNOWN".to_owned();
    let mut description = None;
    if let Some(query) = request.uri().query() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "error" => code = value.into_owned(),
                "error_description" => description = Some(value.into_owned()),
                _ => {}
            }
        }
    }
    (code, description)
}

fn html_response(code: &str, description: Option<&str>) -> Result<ApiResponse, OpenAuthError> {
    let description = description
        .map(sanitize_html)
        .unwrap_or_else(|| "We encountered an unexpected error.".to_owned());
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Error</title>
</head>
<body>
  <main>
    <h1>ERROR</h1>
    <h2>Something went wrong</h2>
    <p>CODE: <code>{}</code></p>
    <p>{}</p>
  </main>
</body>
</html>"#,
        sanitize_html(code),
        description
    );
    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(html.into_bytes())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn redirect(location: &str) -> Result<ApiResponse, OpenAuthError> {
    http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn is_safe_code(code: &str) -> bool {
    !code.is_empty()
        && code.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '\'')
        })
}

fn sanitize_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
