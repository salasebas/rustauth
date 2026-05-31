use crate::app::{AppContext, AppError, InfoArgs};
use crate::diagnostics::doctor;
use crate::output::print_json;

pub async fn run(context: &AppContext, args: InfoArgs) -> Result<(), AppError> {
    let (config, config_loaded) = context.load_config_or_default()?;
    let report = doctor(context.cwd(), &config, false, config_loaded).await;
    if args.json {
        print_json(&report)?;
    } else {
        println!("OpenAuth info");
        println!("Rust: {}", report.rust);
        println!("Cargo: {}", report.cargo);
        println!("OpenAuth: {}", report.openauth_version);
        if let Some(root) = report.workspace_root {
            println!("Workspace: {root}");
        }
        if let Some(package) = report.target_package {
            println!("Package: {package}");
        }
        println!(
            "Framework: {}",
            config.project.framework.unwrap_or_default()
        );
        println!("Adapter: {}", config.database.adapter);
        println!(
            "Database provider: {}",
            config.database.provider.unwrap_or_default()
        );
        println!("Plugins: {}", config.plugins.enabled.join(", "));
    }
    Ok(())
}
