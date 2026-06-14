use super::*;

pub(super) fn required_adapter(
    context: &rustauth_core::context::AuthContext,
) -> Result<Arc<dyn DbAdapter>, RustAuthError> {
    context.require_adapter()
}

pub(super) fn ensure_scim_provider_scope_supported(
    context: &rustauth_core::context::AuthContext,
    provider: &AuthenticatedScimProvider,
) -> Result<(), ScimError> {
    if provider.organization_id.is_some() && !context.has_plugin("organization") {
        return Err(ScimError::bad_request(
            "Organization plugin is required for organization-scoped SCIM providers",
        )
        .with_scim_type("invalidValue"));
    }
    Ok(())
}

pub(super) fn provider_scope_supported_for_management(
    context: &rustauth_core::context::AuthContext,
    provider: &ScimProviderRecord,
) -> bool {
    provider.organization_id.is_none() || context.has_plugin("organization")
}

pub(super) async fn authenticate_scim_request(
    adapter: &dyn DbAdapter,
    secret: &str,
    options: &ScimOptions,
    request: &ApiRequest,
) -> Result<Option<AuthenticatedScimProvider>, RustAuthError> {
    let Some(token) = bearer_token(request) else {
        return Ok(None);
    };
    let Ok(decoded) = decode_bearer_token(token) else {
        return Ok(None);
    };

    for provider in &options.default_scim {
        if default_provider_matches(
            provider,
            &decoded.provider_id,
            decoded.organization_id.as_deref(),
            &decoded.base_token,
        ) {
            return Ok(Some(AuthenticatedScimProvider {
                provider_id: provider.provider_id.clone(),
                organization_id: provider.organization_id.clone(),
            }));
        }
    }

    let Some(provider) = ScimProviderStore::new(adapter)
        .find_by_provider_id(&decoded.provider_id)
        .await?
    else {
        return Ok(None);
    };
    if provider.organization_id != decoded.organization_id {
        return Ok(None);
    }
    if provider_matches(
        &provider,
        &options.token_storage,
        &decoded.base_token,
        secret,
    )
    .await?
    {
        Ok(Some(AuthenticatedScimProvider {
            provider_id: provider.provider_id,
            organization_id: provider.organization_id,
        }))
    } else {
        Ok(None)
    }
}

pub(super) fn bearer_token(request: &ApiRequest) -> Option<&str> {
    let value = authorization_header(request)?.trim();
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some() || token.is_empty() {
        return None;
    }
    scheme.eq_ignore_ascii_case("Bearer").then_some(token)
}

pub(super) fn authorization_header(request: &ApiRequest) -> Option<&str> {
    request.headers().get(header::AUTHORIZATION)?.to_str().ok()
}

pub(super) fn scim_auth_error(request: &ApiRequest) -> ScimError {
    if authorization_header(request).is_some() {
        ScimError::unauthorized("Invalid SCIM token")
    } else {
        ScimError::unauthorized("SCIM token is required")
    }
}

pub(super) async fn current_user(
    context: &rustauth_core::context::AuthContext,
    _adapter: &dyn DbAdapter,
    request: &ApiRequest,
) -> Result<Option<User>, RustAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    Ok(result.user)
}

pub(super) fn organization_creator_role(
    context: &rustauth_core::context::AuthContext,
) -> Option<String> {
    context
        .plugins
        .iter()
        .find(|plugin| plugin.id == "organization")
        .and_then(|plugin| plugin.options.as_ref())
        .and_then(|options| options.get("creatorRole"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

pub(super) async fn provider_access_allowed(
    adapter: &dyn DbAdapter,
    provider: &ScimProviderRecord,
    user: &User,
    options: &ScimOptions,
    creator_role: Option<&str>,
) -> Result<bool, RustAuthError> {
    if let Some(organization_id) = provider.organization_id.as_deref() {
        return Ok(member_role(adapter, organization_id, &user.id)
            .await?
            .map(|role| {
                role_has_required_access(&role, options.required_role.as_deref(), creator_role)
            })
            .unwrap_or(false));
    }
    if !options.provider_ownership.enabled {
        return Ok(false);
    }
    Ok(provider
        .user_id
        .as_deref()
        .is_some_and(|user_id| user_id == user.id))
}

pub(super) async fn store_scim_token(
    secret: &str,
    storage: &ScimTokenStorage,
    base_token: &str,
) -> Result<String, RustAuthError> {
    match storage {
        ScimTokenStorage::Plain => Ok(base_token.to_owned()),
        ScimTokenStorage::Hashed => Ok(hash_base_token(base_token)),
        ScimTokenStorage::Encrypted => symmetric_encrypt(secret, base_token),
        ScimTokenStorage::CustomHash { hash } => hash(base_token.to_owned()).await,
        ScimTokenStorage::CustomEncryption { encrypt, .. } => encrypt(base_token.to_owned()).await,
    }
}

pub(super) async fn member_role(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<Option<String>, RustAuthError> {
    Ok(organization_member(adapter, organization_id, user_id)
        .await?
        .map(|member| member.role))
}

pub(super) async fn organization_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<Option<ScimOrganizationMember>, RustAuthError> {
    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .select(["role"]),
        )
        .await?;
    let Some(member) = member else {
        return Ok(None);
    };
    match member.get("role") {
        Some(DbValue::String(role)) => Ok(Some(ScimOrganizationMember {
            organization_id: organization_id.to_owned(),
            user_id: user_id.to_owned(),
            role: role.to_owned(),
        })),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(RustAuthError::Adapter(
            "member field `role` must be string or null".to_owned(),
        )),
    }
}

pub(super) fn role_has_required_access(
    role: &str,
    required: Option<&[String]>,
    creator_role: Option<&str>,
) -> bool {
    let roles = parse_roles(role);
    match required {
        Some([]) => true,
        Some(required) => roles
            .iter()
            .any(|role| required.iter().any(|required| role == required)),
        _ => {
            let creator_role = creator_role.unwrap_or("owner");
            roles
                .iter()
                .any(|role| role == "admin" || role == creator_role)
        }
    }
}

pub(super) fn parse_roles(role: &str) -> Vec<String> {
    role.split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) async fn create_org_membership_if_missing(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user: &rustauth_core::db::User,
    organization_options: Option<&rustauth_plugins::organization::OrganizationOptions>,
) -> Result<(), RustAuthError> {
    if member_role(adapter, organization_id, &user.id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    if let Some(options) = organization_options {
        rustauth_plugins::organization::provision_organization_member(
            adapter,
            options,
            rustauth_plugins::organization::ProvisionOrganizationMemberInput {
                organization_id,
                user,
                role: "member",
            },
        )
        .await?;
        return Ok(());
    }
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String(generate_random_string(32)))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user.id.clone()))
                .data("role", DbValue::String("member".to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}
