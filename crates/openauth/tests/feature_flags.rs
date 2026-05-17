use std::process::Command;

#[test]
fn sqlx_postgres_feature_does_not_enable_sqlite_driver() -> Result<(), Box<dyn std::error::Error>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "-p",
            "openauth",
            "-e",
            "features",
            "--edges",
            "normal,build",
            "--no-default-features",
            "--features",
            "sqlx-postgres",
            "--depth",
            "5",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("sqlx-postgres"));
    assert!(!stdout.contains("openauth-sqlx feature \"sqlite\""));
    assert!(!stdout.contains("sqlx feature \"sqlite\""));
    Ok(())
}
