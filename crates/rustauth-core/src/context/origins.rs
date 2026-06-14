use super::AuthEnvironment;
use crate::options::RustAuthOptions;

pub(super) fn resolve_trusted_origins(
    base_url: &str,
    options: &RustAuthOptions,
    environment: &AuthEnvironment,
) -> Vec<String> {
    let mut origins = Vec::new();
    if let Some(origin) = origin_from_url(base_url) {
        push_trusted_origin(&mut origins, origin);
    }
    for origin in options.trusted_origins.as_static_slice() {
        push_trusted_origin(&mut origins, origin.clone());
    }
    if let Some(env_origins) = &environment.rustauth_trusted_origins {
        for origin in env_origins.split(',') {
            push_trusted_origin(&mut origins, origin.trim().to_owned());
        }
    }
    origins
}

pub(super) fn push_trusted_origin(origins: &mut Vec<String>, origin: String) {
    if origin.trim().is_empty() {
        return;
    }
    if !origins.iter().any(|existing| existing == &origin) {
        origins.push(origin);
    }
}

pub(super) fn push_unique(values: &mut Vec<String>, value: String) {
    if value.trim().is_empty() {
        return;
    }
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn origin_from_url(url: &str) -> Option<String> {
    let (protocol, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split('?').next().unwrap_or(host);
    (!host.is_empty()).then(|| format!("{protocol}://{host}"))
}
