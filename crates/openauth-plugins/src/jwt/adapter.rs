use openauth_core::context::AuthContext;
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, FindMany, Sort, SortDirection};
use openauth_core::error::OpenAuthError;

use super::{Jwk, JwkAlgorithm, JwtOptions};

const MODEL: &str = "jwks";
const FIELDS: [&str; 7] = [
    "id",
    "public_key",
    "private_key",
    "created_at",
    "expires_at",
    "alg",
    "crv",
];

pub(crate) async fn get_all_keys(
    context: &AuthContext,
    options: &JwtOptions,
) -> Result<Vec<Jwk>, OpenAuthError> {
    if let Some(get_jwks) = &options.adapter.get_jwks {
        return get_jwks(context).await;
    }
    let adapter = adapter(context)?;
    adapter
        .find_many(FindMany::new(MODEL).select(FIELDS))
        .await?
        .into_iter()
        .map(jwk_from_record)
        .collect()
}

pub(crate) async fn get_latest_key(
    context: &AuthContext,
    options: &JwtOptions,
) -> Result<Option<Jwk>, OpenAuthError> {
    if options.adapter.get_jwks.is_some() {
        return Ok(get_all_keys(context, options)
            .await?
            .into_iter()
            .max_by_key(|key| key.created_at));
    }
    let adapter = adapter(context)?;
    adapter
        .find_many(
            FindMany::new(MODEL)
                .sort_by(Sort::new("created_at", SortDirection::Desc))
                .limit(1)
                .select(FIELDS),
        )
        .await?
        .into_iter()
        .next()
        .map(jwk_from_record)
        .transpose()
}

pub(crate) async fn create_jwk(
    context: &AuthContext,
    options: &JwtOptions,
    jwk: Jwk,
) -> Result<Jwk, OpenAuthError> {
    if let Some(create_jwk) = &options.adapter.create_jwk {
        return create_jwk(context, jwk).await;
    }
    let adapter = adapter(context)?;
    let record = adapter
        .create(
            Create::new(MODEL)
                .data("id", DbValue::String(jwk.id))
                .data("public_key", DbValue::String(jwk.public_key))
                .data("private_key", DbValue::String(jwk.private_key))
                .data("created_at", DbValue::Timestamp(jwk.created_at))
                .data(
                    "expires_at",
                    jwk.expires_at
                        .map(DbValue::Timestamp)
                        .unwrap_or(DbValue::Null),
                )
                .data(
                    "alg",
                    jwk.alg
                        .map(|alg| DbValue::String(alg.as_str().to_owned()))
                        .unwrap_or(DbValue::Null),
                )
                .data("crv", jwk.crv.map(DbValue::String).unwrap_or(DbValue::Null))
                .select(FIELDS)
                .force_allow_id(),
        )
        .await?;
    jwk_from_record(record)
}

fn adapter(context: &AuthContext) -> Result<std::sync::Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("JWT plugin requires a database adapter".to_owned())
    })
}

fn jwk_from_record(record: DbRecord) -> Result<Jwk, OpenAuthError> {
    Ok(Jwk {
        id: required_string(&record, "id")?.to_owned(),
        public_key: required_string(&record, "public_key")?.to_owned(),
        private_key: required_string(&record, "private_key")?.to_owned(),
        created_at: required_timestamp(&record, "created_at")?,
        expires_at: optional_timestamp(&record, "expires_at")?,
        alg: optional_string(&record, "alg")?
            .map(parse_algorithm)
            .transpose()?,
        crv: optional_string(&record, "crv")?.map(str::to_owned),
    })
}

fn parse_algorithm(value: &str) -> Result<JwkAlgorithm, OpenAuthError> {
    match value {
        "EdDSA" => Ok(JwkAlgorithm::EdDsa),
        "ES256" => Ok(JwkAlgorithm::Es256),
        "ES512" => Ok(JwkAlgorithm::Es512),
        "RS256" => Ok(JwkAlgorithm::Rs256),
        "PS256" => Ok(JwkAlgorithm::Ps256),
        other => Err(OpenAuthError::Adapter(format!(
            "unsupported JWK alg `{other}`"
        ))),
    }
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string<'a>(
    record: &'a DbRecord,
    field: &str,
) -> Result<Option<&'a str>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn required_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<time::OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<time::OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("jwks record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("jwks record field `{field}` must be {expected}"))
}
