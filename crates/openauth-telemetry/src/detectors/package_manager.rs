// Port of upstream `which-pm-runs` via `npm_config_user_agent`.

use crate::types::DetectionInfo;

pub fn detect_package_manager() -> Option<DetectionInfo> {
    if let Some(pm) = std::env::var("npm_config_user_agent")
        .ok()
        .and_then(|ua| detect_package_manager_from_user_agent(&ua))
    {
        return Some(pm);
    }

    let cargo_manifest_present = std::env::var_os("CARGO_MANIFEST_DIR").is_some()
        || std::env::current_dir()
            .ok()
            .is_some_and(|dir| dir.join("Cargo.toml").exists());
    let cargo_version = std::env::var("CARGO_VERSION").ok();
    detect_cargo_package_manager(cargo_manifest_present, cargo_version.as_deref())
}

fn detect_package_manager_from_user_agent(user_agent: &str) -> Option<DetectionInfo> {
    let pm_spec = user_agent.split_whitespace().next()?;
    let sep = pm_spec.rfind('/')?;
    let name = &pm_spec[..sep];
    let version = pm_spec.get(sep + 1..)?;
    let name = if name == "npminstall" { "cnpm" } else { name };
    Some(DetectionInfo {
        name: name.to_owned(),
        version: version.to_owned(),
    })
}

fn detect_cargo_package_manager(
    cargo_manifest_present: bool,
    cargo_version: Option<&str>,
) -> Option<DetectionInfo> {
    cargo_manifest_present.then(|| DetectionInfo {
        name: "cargo".to_owned(),
        version: cargo_version
            .filter(|version| !version.is_empty())
            .unwrap_or("unknown")
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_style_user_agent() {
        assert_eq!(
            detect_package_manager_from_user_agent("pnpm/9.0.0 npm/? node/?"),
            Some(DetectionInfo {
                name: "pnpm".to_owned(),
                version: "9.0.0".to_owned(),
            })
        );
    }

    #[test]
    fn falls_back_to_cargo_when_rust_manifest_env_exists() {
        assert_eq!(
            detect_cargo_package_manager(true, Some("1.85.0")),
            Some(DetectionInfo {
                name: "cargo".to_owned(),
                version: "1.85.0".to_owned(),
            })
        );
    }
}
