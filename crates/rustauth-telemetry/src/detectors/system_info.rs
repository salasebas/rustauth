use std::io::IsTerminal;

use serde_json::json;

fn env_any(keys: &[&str]) -> bool {
    keys.iter().any(|k| std::env::var_os(k).is_some())
}

fn deployment_vendor() -> Option<&'static str> {
    if env_any(&["CF_PAGES", "CF_PAGES_URL", "CF_ACCOUNT_ID"]) {
        return Some("cloudflare");
    }
    if env_any(&["VERCEL", "VERCEL_URL", "VERCEL_ENV"]) {
        return Some("vercel");
    }
    if env_any(&["NETLIFY", "NETLIFY_URL"]) {
        return Some("netlify");
    }
    if env_any(&[
        "RENDER",
        "RENDER_URL",
        "RENDER_INTERNAL_HOSTNAME",
        "RENDER_SERVICE_ID",
    ]) {
        return Some("render");
    }
    if env_any(&[
        "AWS_LAMBDA_FUNCTION_NAME",
        "AWS_EXECUTION_ENV",
        "LAMBDA_TASK_ROOT",
    ]) {
        return Some("aws");
    }
    if env_any(&[
        "GOOGLE_CLOUD_FUNCTION_NAME",
        "GOOGLE_CLOUD_PROJECT",
        "GCP_PROJECT",
        "K_SERVICE",
    ]) {
        return Some("gcp");
    }
    if env_any(&[
        "AZURE_FUNCTION_NAME",
        "FUNCTIONS_WORKER_RUNTIME",
        "WEBSITE_INSTANCE_ID",
        "WEBSITE_SITE_NAME",
    ]) {
        return Some("azure");
    }
    if env_any(&["DENO_DEPLOYMENT_ID", "DENO_REGION"]) {
        return Some("deno-deploy");
    }
    if env_any(&["FLY_APP_NAME", "FLY_REGION", "FLY_ALLOC_ID"]) {
        return Some("fly-io");
    }
    if env_any(&["RAILWAY_STATIC_URL", "RAILWAY_ENVIRONMENT_NAME"]) {
        return Some("railway");
    }
    if env_any(&["DYNO", "HEROKU_APP_NAME"]) {
        return Some("heroku");
    }
    if env_any(&["DO_DEPLOYMENT_ID", "DO_APP_NAME", "DIGITALOCEAN"]) {
        return Some("digitalocean");
    }
    if env_any(&["KOYEB", "KOYEB_DEPLOYMENT_ID", "KOYEB_APP_NAME"]) {
        return Some("koyeb");
    }
    None
}

pub fn detect_system_info() -> serde_json::Value {
    json!({
        "deploymentVendor": deployment_vendor(),
        "systemPlatform": std::env::consts::OS,
        "systemRelease": system_release(),
        "systemArchitecture": std::env::consts::ARCH,
        "cpuCount": std::thread::available_parallelism().ok().map(|count| count.get()),
        "cpuModel": serde_json::Value::Null,
        "cpuSpeed": serde_json::Value::Null,
        "memory": serde_json::Value::Null,
        "isWSL": is_wsl(),
        "isDocker": is_docker(),
        "isTTY": std::io::stdout().is_terminal(),
        "isCI": crate::env::is_ci(),
    })
}

fn system_release() -> serde_json::Value {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|release| serde_json::Value::String(release.trim().to_owned()))
        .unwrap_or(serde_json::Value::Null)
}

fn is_docker() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .is_some_and(|content| content.contains("docker"))
}

fn is_wsl() -> bool {
    if std::env::consts::OS != "linux" || is_docker() {
        return false;
    }
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let version = std::fs::read_to_string("/proc/version").unwrap_or_default();
    release.to_lowercase().contains("microsoft") || version.to_lowercase().contains("microsoft")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    const VENDOR_KEYS: &[&str] = &[
        "CF_PAGES",
        "CF_PAGES_URL",
        "CF_ACCOUNT_ID",
        "VERCEL",
        "VERCEL_URL",
        "VERCEL_ENV",
        "NETLIFY",
        "NETLIFY_URL",
        "RENDER",
        "RENDER_URL",
        "RENDER_INTERNAL_HOSTNAME",
        "RENDER_SERVICE_ID",
        "AWS_LAMBDA_FUNCTION_NAME",
        "AWS_EXECUTION_ENV",
        "LAMBDA_TASK_ROOT",
        "GOOGLE_CLOUD_FUNCTION_NAME",
        "GOOGLE_CLOUD_PROJECT",
        "GCP_PROJECT",
        "K_SERVICE",
        "AZURE_FUNCTION_NAME",
        "FUNCTIONS_WORKER_RUNTIME",
        "WEBSITE_INSTANCE_ID",
        "WEBSITE_SITE_NAME",
        "DENO_DEPLOYMENT_ID",
        "DENO_REGION",
        "FLY_APP_NAME",
        "FLY_REGION",
        "FLY_ALLOC_ID",
        "RAILWAY_STATIC_URL",
        "RAILWAY_ENVIRONMENT_NAME",
        "DYNO",
        "HEROKU_APP_NAME",
        "DO_DEPLOYMENT_ID",
        "DO_APP_NAME",
        "DIGITALOCEAN",
        "KOYEB",
        "KOYEB_DEPLOYMENT_ID",
        "KOYEB_APP_NAME",
    ];

    struct EnvRestore(Vec<(&'static str, Option<String>)>);

    impl EnvRestore {
        fn unset(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect::<Vec<_>>();
            for key in keys {
                std::env::remove_var(key);
            }
            Self(saved)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_env() -> MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn system_info_reports_available_rust_host_fields() {
        let info = detect_system_info();

        assert_eq!(info["systemPlatform"], std::env::consts::OS);
        assert_eq!(info["systemArchitecture"], std::env::consts::ARCH);
        assert!(info["cpuCount"].as_u64().is_some());
        assert!(info["isTTY"].as_bool().is_some());
    }

    #[test]
    fn deployment_vendor_is_none_without_vendor_env() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(VENDOR_KEYS);

        assert_eq!(deployment_vendor(), None);
    }

    #[test]
    fn deployment_vendor_detects_mocked_vercel_env() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(VENDOR_KEYS);
        std::env::set_var("VERCEL_URL", "preview.example.com");

        assert_eq!(deployment_vendor(), Some("vercel"));
        assert_eq!(detect_system_info()["deploymentVendor"], "vercel");
    }
}
