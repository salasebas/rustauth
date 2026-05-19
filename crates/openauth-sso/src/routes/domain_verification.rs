use std::sync::Arc;

use http::Method;
use openauth_core::api::{create_auth_endpoint, parse_request_body, AsyncAuthEndpoint};
use openauth_core::crypto::random::generate_random_string;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::audit;
use crate::options::{SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity, SsoOptions};
use crate::org::can_verify_provider_domain;
use crate::state::SsoStateStore;
use crate::store::SsoProviderStore;
use crate::utils;

use super::support::{authenticated_user, provider_id_options, unauthorized, ProviderIdBody};

const DNS_LABEL_MAX_LENGTH: usize = 63;

pub(super) fn request_endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/request-domain-verification",
        Method::POST,
        provider_id_options("requestDomainVerification"),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some((adapter, user_id)) = authenticated_user(context, &request).await? else {
                    return unauthorized();
                };
                let body = parse_request_body::<ProviderIdBody>(&request)?;
                let Some(provider) = SsoProviderStore::new(adapter.as_ref())
                    .find_by_provider_id(&body.provider_id)
                    .await?
                else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                if !can_verify_provider_domain(context, adapter.as_ref(), &user_id, &provider)
                    .await?
                {
                    return utils::json(http::StatusCode::FORBIDDEN, &json!({"code": "FORBIDDEN"}));
                }
                if provider.domain_verified.unwrap_or(false) {
                    return utils::json(
                        http::StatusCode::CONFLICT,
                        &json!({"code": "DOMAIN_VERIFIED"}),
                    );
                }
                let identifier = verification_identifier(&options, &provider.provider_id);
                let state_store = SsoStateStore::new(context, adapter.as_ref());
                if let Some(active) = state_store.find(&identifier).await? {
                    audit::emit(
                        context,
                        &options,
                        SsoAuditEvent::new(
                            SsoAuditEventKind::DomainVerificationRequested,
                            SsoAuditSeverity::Info,
                        )
                        .provider_id(provider.provider_id.clone())
                        .user_id(user_id),
                    )
                    .await;
                    return utils::json(
                        http::StatusCode::CREATED,
                        &json!({"domainVerificationToken": active.value}),
                    );
                }
                let token = generate_random_string(24);
                state_store
                    .create(
                        identifier,
                        token.clone(),
                        OffsetDateTime::now_utc()
                            + Duration::seconds(
                                options.domain_verification.token_ttl_seconds as i64,
                            ),
                    )
                    .await?;
                audit::emit(
                    context,
                    &options,
                    SsoAuditEvent::new(
                        SsoAuditEventKind::DomainVerificationRequested,
                        SsoAuditSeverity::Info,
                    )
                    .provider_id(provider.provider_id.clone())
                    .user_id(user_id),
                )
                .await;
                utils::json(
                    http::StatusCode::CREATED,
                    &json!({"domainVerificationToken": token}),
                )
            })
        },
    )
}

pub(super) fn verify_endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/verify-domain",
        Method::POST,
        provider_id_options("verifyDomain"),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some((adapter, user_id)) = authenticated_user(context, &request).await? else {
                    return unauthorized();
                };
                let body = parse_request_body::<ProviderIdBody>(&request)?;
                let store = SsoProviderStore::new(adapter.as_ref());
                let Some(provider) = store.find_by_provider_id(&body.provider_id).await? else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                if !can_verify_provider_domain(context, adapter.as_ref(), &user_id, &provider)
                    .await?
                {
                    return utils::json(http::StatusCode::FORBIDDEN, &json!({"code": "FORBIDDEN"}));
                }
                if provider.domain_verified.unwrap_or(false) {
                    return utils::json(
                        http::StatusCode::CONFLICT,
                        &json!({"code": "DOMAIN_VERIFIED"}),
                    );
                }

                let identifier = verification_identifier(&options, &provider.provider_id);
                if identifier.len() > DNS_LABEL_MAX_LENGTH {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "IDENTIFIER_TOO_LONG", "message": "Verification identifier exceeds the DNS label limit"}),
                    );
                }

                let state_store = SsoStateStore::new(context, adapter.as_ref());
                let Some(active) = state_store.find(&identifier).await? else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "NO_PENDING_VERIFICATION"}),
                    );
                };
                let Some(hostname) = verification_hostname(&provider.domain) else {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_DOMAIN", "message": "Invalid domain"}),
                    );
                };

                let expected = format!("{}={}", active.identifier, active.value);
                let records = match resolve_txt_records(
                    &options,
                    &format!("{identifier}.{hostname}"),
                )
                .await
                {
                    Ok(records) => records,
                    Err(_) => {
                        audit::emit(
                            context,
                            &options,
                            SsoAuditEvent::new(
                                SsoAuditEventKind::DomainVerificationFailed,
                                SsoAuditSeverity::Warn,
                            )
                            .provider_id(provider.provider_id.clone())
                            .user_id(user_id.clone())
                            .reason("resolver_error"),
                        )
                        .await;
                        return domain_verification_failed("resolver_error");
                    }
                };
                if records.is_empty() {
                    audit::emit(
                        context,
                        &options,
                        SsoAuditEvent::new(
                            SsoAuditEventKind::DomainVerificationFailed,
                            SsoAuditSeverity::Warn,
                        )
                        .provider_id(provider.provider_id.clone())
                        .user_id(user_id.clone())
                        .reason("no_txt_records"),
                    )
                    .await;
                    return domain_verification_failed("no_txt_records");
                }
                if !records
                    .iter()
                    .any(|record| utils::constant_time_eq(record.trim(), &expected))
                {
                    audit::emit(
                        context,
                        &options,
                        SsoAuditEvent::new(
                            SsoAuditEventKind::DomainVerificationFailed,
                            SsoAuditSeverity::Warn,
                        )
                        .provider_id(provider.provider_id.clone())
                        .user_id(user_id.clone())
                        .reason("txt_value_mismatch"),
                    )
                    .await;
                    return domain_verification_failed("txt_value_mismatch");
                }

                store
                    .update_domain_verified(&provider.provider_id, true)
                    .await?;
                audit::emit(
                    context,
                    &options,
                    SsoAuditEvent::new(
                        SsoAuditEventKind::DomainVerificationSucceeded,
                        SsoAuditSeverity::Info,
                    )
                    .provider_id(provider.provider_id.clone())
                    .user_id(user_id),
                )
                .await;
                http::Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(Vec::new())
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))
            })
        },
    )
}

pub(super) fn verification_identifier(options: &SsoOptions, provider_id: &str) -> String {
    format!(
        "_{}-{}",
        options.domain_verification.token_prefix, provider_id
    )
}

fn domain_verification_failed(
    reason: &'static str,
) -> Result<http::Response<Vec<u8>>, openauth_core::error::OpenAuthError> {
    utils::json(
        http::StatusCode::BAD_GATEWAY,
        &json!({
            "code": "DOMAIN_VERIFICATION_FAILED",
            "message": "Unable to verify domain ownership. Try again later",
            "reason": reason,
        }),
    )
}

fn verification_hostname(domain: &str) -> Option<String> {
    let first = domain.split(',').next()?.trim();
    let without_scheme = first
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = without_scheme
        .split('/')
        .next()?
        .trim()
        .trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

async fn resolve_txt_records(
    options: &SsoOptions,
    name: &str,
) -> Result<Vec<String>, openauth_core::error::OpenAuthError> {
    if let Some(resolver) = &options.domain_verification.txt_resolver {
        return resolver.resolve(name).await;
    }
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|error| {
            openauth_core::error::OpenAuthError::Api(format!(
                "failed to initialize DNS resolver: {error}"
            ))
        })?
        .build()
        .map_err(|error| {
            openauth_core::error::OpenAuthError::Api(format!(
                "failed to build DNS resolver: {error}"
            ))
        })?;
    let lookup = resolver.txt_lookup(name).await.map_err(|error| {
        openauth_core::error::OpenAuthError::Api(format!("DNS TXT lookup failed: {error}"))
    })?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect())
}
