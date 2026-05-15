/// Normalize a request URL pathname by removing the auth base path and trailing slashes.
pub fn normalize_pathname(request_url: &str, base_path: &str) -> String {
    let Some(pathname) = pathname_from_url(request_url) else {
        return "/".to_owned();
    };

    let pathname = trim_trailing_slashes(&pathname);
    let base_path = trim_trailing_slashes(base_path);

    if base_path == "/" {
        return pathname;
    }

    if pathname == base_path {
        return "/".to_owned();
    }

    let base_prefix = format!("{base_path}/");
    if let Some(without_base_path) = pathname.strip_prefix(&base_prefix) {
        trim_trailing_slashes(&format!("/{without_base_path}"))
    } else {
        pathname
    }
}

fn pathname_from_url(request_url: &str) -> Option<String> {
    if request_url.starts_with('/') {
        let path = request_url
            .split_once('?')
            .map_or(request_url, |(path, _)| path);
        let path = path.split_once('#').map_or(path, |(path, _)| path);
        return Some(path.to_owned());
    }
    let (_, after_scheme) = request_url.split_once("://")?;
    let path_start = after_scheme.find('/')?;
    let path_with_query = &after_scheme[path_start..];
    let path = path_with_query
        .split_once('?')
        .map_or(path_with_query, |(path, _)| path);
    let path = path.split_once('#').map_or(path, |(path, _)| path);

    Some(path.to_owned())
}

fn trim_trailing_slashes(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}
