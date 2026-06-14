use serde::Serialize;

use crate::app::{AppContext, AppError, InfoArgs};
use crate::diagnostics::{doctor, DiagnosticReport};
use crate::output::copy_to_clipboard;
use crate::workspace::{inspect, DetectedItem};

#[derive(Debug, Serialize)]
pub struct InfoReport {
    pub rustauth: RustAuthInfo,
    pub toolchain: ToolchainInfo,
    pub workspace: WorkspaceInfoReport,
    pub config_loaded: bool,
    pub config: DiagnosticReport,
}

#[derive(Debug, Serialize)]
pub struct RustAuthInfo {
    pub cli_version: String,
}

#[derive(Debug, Serialize)]
pub struct ToolchainInfo {
    pub rust: String,
    pub cargo: String,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceInfoReport {
    pub root: Option<String>,
    pub target_package: Option<String>,
    pub detected_frameworks: Vec<DetectedItem>,
    pub detected_databases: Vec<DetectedItem>,
}

pub async fn run(context: &AppContext, args: InfoArgs) -> Result<(), AppError> {
    let (config, config_loaded) = context.load_config_or_default()?;
    let workspace = inspect(context.cwd()).ok();
    let report = doctor(context.cwd(), &config, false, config_loaded).await;
    let info = InfoReport {
        rustauth: RustAuthInfo {
            cli_version: report.rustauth_version.clone(),
        },
        toolchain: ToolchainInfo {
            rust: report.rust.clone(),
            cargo: report.cargo.clone(),
        },
        workspace: WorkspaceInfoReport {
            root: report.workspace_root.clone(),
            target_package: report.target_package.clone(),
            detected_frameworks: workspace
                .as_ref()
                .map(|info| info.detected_frameworks.clone())
                .unwrap_or_default(),
            detected_databases: workspace
                .as_ref()
                .map(|info| info.detected_databases.clone())
                .unwrap_or_default(),
        },
        config_loaded,
        config: report,
    };

    if args.json {
        let rendered = serde_json::to_string_pretty(&info)?;
        println!("{rendered}");
        if args.copy {
            copy_to_clipboard(&rendered)?;
            println!("Copied JSON to clipboard.");
        }
        return Ok(());
    }

    print_human(&info);
    if args.copy {
        let rendered = serde_json::to_string_pretty(&info)?;
        copy_to_clipboard(&rendered)?;
        println!("Copied JSON to clipboard.");
    }
    Ok(())
}

fn print_human(info: &InfoReport) {
    println!("RustAuth info");
    println!("CLI: {}", info.rustauth.cli_version);
    println!("Rust: {}", info.toolchain.rust);
    println!("Cargo: {}", info.toolchain.cargo);
    if let Some(root) = &info.workspace.root {
        println!("Workspace: {root}");
    }
    if let Some(package) = &info.workspace.target_package {
        println!("Package: {package}");
    }
    if !info.workspace.detected_frameworks.is_empty() {
        println!("Detected frameworks:");
        for item in &info.workspace.detected_frameworks {
            println!("  - {} ({:?})", item.name, item.confidence);
        }
    }
    if !info.workspace.detected_databases.is_empty() {
        println!("Detected databases:");
        for item in &info.workspace.detected_databases {
            println!("  - {} ({:?})", item.name, item.confidence);
        }
    }
    println!(
        "Config: {}",
        if info.config_loaded {
            "loaded from rustauth.toml"
        } else {
            "defaults (no rustauth.toml)"
        }
    );
    for finding in &info.config.findings {
        let label = match finding.severity {
            crate::diagnostics::Severity::Info => "INFO",
            crate::diagnostics::Severity::Warn => "WARN",
            crate::diagnostics::Severity::Error => "ERROR",
        };
        println!("[{label}] {}: {}", finding.code, finding.message);
    }
    println!("Tip: use --json for machine-readable output.");
}
