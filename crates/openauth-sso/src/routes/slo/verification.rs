use http::Method;
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::context::AuthContext;

use crate::audit;
use crate::options::{SamlConfig, SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity, SsoOptions};
use crate::saml_impl::logout::{
    parse_post_logout_request_with_context, parse_post_logout_response_with_context,
    parse_redirect_logout_request_with_redirect_query,
    parse_redirect_logout_response_with_redirect_query, ParsedSamlLogoutRequest,
    ParsedSamlLogoutResponse, SamlLogoutParseContext,
};
use crate::saml_impl::signature::{
    verify_redirect_logout_request, verify_redirect_logout_response, verify_signed_logout_request,
    verify_signed_logout_response, SamlSignatureValidationError,
};
use crate::store::SsoProviderRecord;

use crate::routes::support::query_param;

pub(super) struct VerifiedLogoutMessage<T> {
    pub(super) message: T,
    pub(super) signature_verified: bool,
}

pub(super) async fn parse_verified_logout_response(
    context: &AuthContext,
    options: &SsoOptions,
    request: &ApiRequest,
    method: &Method,
    provider: &SsoProviderRecord,
    config: &SamlConfig,
    encoded_response: &str,
) -> Result<
    Result<VerifiedLogoutMessage<ParsedSamlLogoutResponse>, ApiResponse>,
    openauth_core::error::OpenAuthError,
> {
    let parse_context = SamlLogoutParseContext {
        config,
        base_url: &context.base_url,
        provider_id: &provider.provider_id,
        build_options: crate::routes::slo::logout_build_options(options),
    };
    let mut message = if method == Method::GET {
        parse_redirect_logout_response_with_redirect_query(
            encoded_response,
            &parse_context,
            &saml_redirect_query(request),
        )
    } else {
        parse_post_logout_response_with_context(encoded_response, &parse_context)
    }
    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
    let signature_verified = match verify_logout_response_signature(
        SignatureVerificationInput {
            context,
            options,
            request,
            method,
            provider,
            config,
            encoded: encoded_response,
        },
        &mut message,
    )
    .await?
    {
        Ok(verified) => verified,
        Err(response) => return Ok(Err(response)),
    };
    Ok(Ok(VerifiedLogoutMessage {
        message,
        signature_verified,
    }))
}

pub(super) async fn parse_verified_logout_request(
    context: &AuthContext,
    options: &SsoOptions,
    request: &ApiRequest,
    method: &Method,
    provider: &SsoProviderRecord,
    config: &SamlConfig,
    encoded_request: &str,
) -> Result<
    Result<VerifiedLogoutMessage<ParsedSamlLogoutRequest>, ApiResponse>,
    openauth_core::error::OpenAuthError,
> {
    let parse_context = SamlLogoutParseContext {
        config,
        base_url: &context.base_url,
        provider_id: &provider.provider_id,
        build_options: crate::routes::slo::logout_build_options(options),
    };
    let mut message = if method == Method::GET {
        parse_redirect_logout_request_with_redirect_query(
            encoded_request,
            &parse_context,
            &saml_redirect_query(request),
        )
    } else {
        parse_post_logout_request_with_context(encoded_request, &parse_context)
    }
    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
    let signature_verified = match verify_logout_request_signature(
        SignatureVerificationInput {
            context,
            options,
            request,
            method,
            provider,
            config,
            encoded: encoded_request,
        },
        &mut message,
    )
    .await?
    {
        Ok(verified) => verified,
        Err(response) => return Ok(Err(response)),
    };
    Ok(Ok(VerifiedLogoutMessage {
        message,
        signature_verified,
    }))
}

struct SignatureVerificationInput<'a> {
    context: &'a AuthContext,
    options: &'a SsoOptions,
    request: &'a ApiRequest,
    method: &'a Method,
    provider: &'a SsoProviderRecord,
    config: &'a SamlConfig,
    encoded: &'a str,
}

async fn verify_logout_response_signature(
    input: SignatureVerificationInput<'_>,
    parsed: &mut ParsedSamlLogoutResponse,
) -> Result<Result<bool, ApiResponse>, openauth_core::error::OpenAuthError> {
    let result = if input.method == Method::GET {
        verify_redirect_signature_if_present(
            input.request,
            &input.config.cert,
            verify_redirect_logout_response,
            &mut parsed.has_signature,
        )
    } else if parsed.signature.is_signed() {
        verify_signed_logout_response(input.encoded, parsed.signature, &input.config.cert)
            .await
            .map(|_| true)
    } else {
        Ok(false)
    };
    signature_result_response(input.context, input.options, input.provider, result).await
}

async fn verify_logout_request_signature(
    input: SignatureVerificationInput<'_>,
    parsed: &mut ParsedSamlLogoutRequest,
) -> Result<Result<bool, ApiResponse>, openauth_core::error::OpenAuthError> {
    let result = if input.method == Method::GET {
        verify_redirect_signature_if_present(
            input.request,
            &input.config.cert,
            verify_redirect_logout_request,
            &mut parsed.has_signature,
        )
    } else if parsed.signature.is_signed() {
        verify_signed_logout_request(input.encoded, parsed.signature, &input.config.cert)
            .await
            .map(|_| true)
    } else {
        Ok(false)
    };
    signature_result_response(input.context, input.options, input.provider, result).await
}

fn verify_redirect_signature_if_present(
    request: &ApiRequest,
    cert: &str,
    verify: impl FnOnce(&str, &str) -> Result<(), SamlSignatureValidationError>,
    has_signature: &mut bool,
) -> Result<bool, SamlSignatureValidationError> {
    if query_param(request, "Signature").is_none() {
        return Ok(false);
    }
    *has_signature = true;
    verify(
        request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or_default(),
        cert,
    )?;
    Ok(true)
}

async fn signature_result_response(
    context: &AuthContext,
    options: &SsoOptions,
    provider: &SsoProviderRecord,
    result: Result<bool, SamlSignatureValidationError>,
) -> Result<Result<bool, ApiResponse>, openauth_core::error::OpenAuthError> {
    match result {
        Ok(verified) => Ok(Ok(verified)),
        Err(error) => {
            audit::emit(
                context,
                options,
                SsoAuditEvent::new(
                    SsoAuditEventKind::SamlSignatureFailed,
                    SsoAuditSeverity::Warn,
                )
                .provider_id(provider.provider_id.clone())
                .reason(error.code()),
            )
            .await;
            Ok(Err(crate::routes::saml_signature_error_response(error)?))
        }
    }
}

fn saml_redirect_query(request: &ApiRequest) -> Vec<(String, String)> {
    request
        .uri()
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}
