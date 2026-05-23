//! Error response translation helpers.

use http::header;
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;

use crate::types::TranslationDictionary;

pub(crate) fn translate_response(
    response: &mut ApiResponse,
    dictionary: &TranslationDictionary,
) -> Result<bool, OpenAuthError> {
    if response.status().is_success() || response.body().is_empty() || !is_json_response(response) {
        return Ok(false);
    }

    let mut error: ApiErrorResponse = match serde_json::from_slice(response.body()) {
        Ok(error) => error,
        Err(_) => return Ok(false),
    };
    if error.code.is_empty() || !translate_error(&mut error, dictionary) {
        return Ok(false);
    }

    let body = serde_json::to_vec(&error).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    *response.body_mut() = body;
    response.headers_mut().remove(header::CONTENT_LENGTH);
    Ok(true)
}

fn translate_error(error: &mut ApiErrorResponse, dictionary: &TranslationDictionary) -> bool {
    let Some(translated) = dictionary.get(&error.code) else {
        return false;
    };

    let previous_message = error.message.clone();
    error.message = translated.clone();
    if error.original_message.is_none() {
        error.original_message = Some(previous_message);
    }
    true
}

fn is_json_response(response: &ApiResponse) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_application_json)
}

fn is_application_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .eq_ignore_ascii_case("application/json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    fn dictionary() -> TranslationDictionary {
        [("NEEDS_TRANSLATION".to_owned(), "Message traduit".to_owned())]
            .into_iter()
            .collect()
    }

    fn response(
        status: StatusCode,
        content_type: Option<&str>,
        body: ApiErrorResponse,
    ) -> Result<ApiResponse, Box<dyn std::error::Error>> {
        let mut builder = http::Response::builder().status(status);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        Ok(builder
            .header(header::CONTENT_LENGTH, "999")
            .body(serde_json::to_vec(&body)?)?)
    }

    #[test]
    fn translate_response_requires_json_content_type() -> Result<(), Box<dyn std::error::Error>> {
        let mut response = response(
            StatusCode::BAD_REQUEST,
            Some("text/plain"),
            ApiErrorResponse {
                code: "NEEDS_TRANSLATION".to_owned(),
                message: "Original message".to_owned(),
                original_message: None,
            },
        )?;

        let translated = translate_response(&mut response, &dictionary())?;

        assert!(!translated);
        Ok(())
    }

    #[test]
    fn translate_response_preserves_existing_original_message(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut response = response(
            StatusCode::BAD_REQUEST,
            Some("application/json; charset=utf-8"),
            ApiErrorResponse {
                code: "NEEDS_TRANSLATION".to_owned(),
                message: "Already translated".to_owned(),
                original_message: Some("Original message".to_owned()),
            },
        )?;

        let translated = translate_response(&mut response, &dictionary())?;
        let body: ApiErrorResponse = serde_json::from_slice(response.body())?;

        assert!(translated);
        assert_eq!(body.message, "Message traduit");
        assert_eq!(body.original_message.as_deref(), Some("Original message"));
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
        Ok(())
    }
}
