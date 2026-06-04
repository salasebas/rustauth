use std::process::Command;

fn cargo_tree_stdout(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo).args(args).output()?;

    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn sqlx_postgres_feature_does_not_enable_sqlite_driver() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = cargo_tree_stdout(&[
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
    ])?;

    assert!(stdout.contains("sqlx-postgres"));
    assert!(!stdout.contains("openauth-sqlx feature \"sqlite\""));
    assert!(!stdout.contains("sqlx feature \"sqlite\""));
    Ok(())
}

#[test]
fn default_openauth_build_does_not_enable_telemetry_crate() -> Result<(), Box<dyn std::error::Error>>
{
    let stdout = cargo_tree_stdout(&[
        "tree",
        "-p",
        "openauth",
        "--edges",
        "normal,build",
        "--no-default-features",
    ])?;

    assert!(
        !stdout.contains("openauth-telemetry"),
        "default openauth build unexpectedly enabled openauth-telemetry"
    );
    Ok(())
}

#[test]
fn async_initializers_available_without_telemetry_feature() -> Result<(), Box<dyn std::error::Error>>
{
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "test",
            "-p",
            "openauth",
            "--no-default-features",
            "--test",
            "public_api",
            "without_telemetry_feature",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "async initializer smoke test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(())
}

#[test]
fn oidc_feature_does_not_enable_saml_or_xml_dependencies() -> Result<(), Box<dyn std::error::Error>>
{
    let stdout = cargo_tree_stdout(&[
        "tree",
        "-p",
        "openauth",
        "--edges",
        "normal,build",
        "--no-default-features",
        "--features",
        "oidc",
    ])?;

    for forbidden in [
        "openauth-saml",
        "quick-xml",
        "x509-parser",
        "samael",
        "xmlsec",
    ] {
        assert!(
            !stdout.contains(forbidden),
            "OIDC-only feature unexpectedly enabled {forbidden}"
        );
    }

    Ok(())
}
