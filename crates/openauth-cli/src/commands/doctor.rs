use crate::app::{AppContext, AppError, DiagnosticArgs};
use crate::diagnostics::{doctor, DiagnosticReport, Severity};
use crate::output::print_json;

pub async fn run(context: &AppContext, args: DiagnosticArgs) -> Result<(), AppError> {
    let (config, config_loaded) = context.load_config_or_default()?;
    let report = doctor(context.cwd(), &config, args.production, config_loaded).await;
    if args.json {
        print_json(&report)?;
    } else {
        print_report(&report);
    }
    if report.has_errors() || (args.strict && report.has_warnings()) {
        return Err(AppError::SilentExit { code: 1 });
    }
    Ok(())
}

pub(crate) fn print_report(report: &DiagnosticReport) {
    println!("OpenAuth doctor");
    println!("Rust: {}", report.rust);
    println!("Cargo: {}", report.cargo);
    println!("OpenAuth: {}", report.openauth_version);
    if let Some(root) = &report.workspace_root {
        println!("Workspace: {root}");
    }
    if let Some(package) = &report.target_package {
        println!("Package: {package}");
    }
    for finding in &report.findings {
        let label = match finding.severity {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        };
        println!("[{label}] {}: {}", finding.code, finding.message);
    }
}
