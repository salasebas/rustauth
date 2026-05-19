use crate::options::SsoOptions;

pub fn oidc_redirect_uri(base_url: &str, provider_id: &str, options: &SsoOptions) -> String {
    if let Some(redirect_uri) = options
        .redirect_uri
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        if url::Url::parse(redirect_uri).is_ok() {
            return redirect_uri.to_owned();
        }
        let path = if redirect_uri.starts_with('/') {
            redirect_uri.to_owned()
        } else {
            format!("/{redirect_uri}")
        };
        return format!("{}{}", base_url.trim_end_matches('/'), path);
    }
    format!(
        "{}/sso/callback/{}",
        base_url.trim_end_matches('/'),
        provider_id
    )
}
