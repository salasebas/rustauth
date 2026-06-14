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

/// Reject unsafe `x-forwarded-proto` values (Better Auth `validateProxyHeader` parity).
pub fn is_valid_forwarded_proto(proto: &str) -> bool {
    matches!(proto.trim().to_ascii_lowercase().as_str(), "http" | "https")
}

/// Reject unsafe `x-forwarded-host` / authority values used for base URL inference.
pub fn is_valid_forwarded_host(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() || host.contains("..") || host.starts_with('.') {
        return false;
    }
    if host
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace() || byte == b'<' || byte == b'>')
    {
        return false;
    }

    let (name, port) = match split_host_and_port(host) {
        Some(parts) => parts,
        None => return false,
    };

    if let Some(port) = port {
        if port.parse::<u16>().is_err() {
            return false;
        }
    }

    if name.starts_with('[') && name.ends_with(']') {
        is_valid_ipv6_literal(&name[1..name.len() - 1])
    } else {
        is_valid_dns_or_ipv4_literal(name)
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

fn split_host_and_port(host: &str) -> Option<(&str, Option<&str>)> {
    if host.starts_with('[') {
        let end = host.find(']')?;
        let name = &host[..=end];
        let rest = &host[end + 1..];
        let port = if rest.is_empty() {
            None
        } else if let Some(port) = rest.strip_prefix(':') {
            Some(port)
        } else {
            return None;
        };
        return Some((name, port));
    }

    if let Some((name, port)) = host.rsplit_once(':') {
        if port.chars().all(|char| char.is_ascii_digit()) {
            return Some((name, Some(port)));
        }
    }

    Some((host, None))
}

fn is_valid_dns_or_ipv4_literal(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '.' | '-' | '_'))
}

fn is_valid_ipv6_literal(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|char| char.is_ascii_hexdigit() || matches!(char, ':' | '.' | '-' | '%'))
}
