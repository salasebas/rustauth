use http::StatusCode;
use openauth_core::api::ApiResponse;
use serde_json::Value;

pub fn parse_json_error(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body).map_err(|error| error.to_string())
}

pub fn assert_error_code(body: &[u8], expected_code: &str) -> Result<(), String> {
    let json = parse_json_error(body)?;
    let code = json
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing error code in {json}"))?;
    if code == expected_code {
        Ok(())
    } else {
        Err(format!("expected code {expected_code}, got {code}"))
    }
}

pub fn assert_ok_status(response: &ApiResponse) -> Result<(), String> {
    if response.status() == StatusCode::OK {
        Ok(())
    } else {
        Err(format!("expected 200 OK, got {}", response.status()))
    }
}
