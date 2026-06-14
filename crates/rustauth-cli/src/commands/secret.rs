use crate::app::{AppError, SecretArgs};
use crate::secret::{assess_secret, generate_secret, SecretSeverity};

pub fn run(args: SecretArgs) -> Result<(), AppError> {
    let value = match (args.check, args.check_env) {
        (Some(value), None) => Some(value),
        (None, Some(env)) => {
            Some(std::env::var(&env).map_err(|_| AppError::Message(format!("{env} is not set")))?)
        }
        (Some(_), Some(_)) => {
            return Err(AppError::Message(
                "Use only one of --check or --check-env.".to_owned(),
            ))
        }
        (None, None) => None,
    };
    let Some(secret) = value else {
        let secret = generate_secret(args.bytes);
        if args.env_line {
            println!("RUSTAUTH_SECRET={secret}");
        } else {
            println!("{secret}");
        }
        return Ok(());
    };

    let production = args.production && !args.dev;
    let assessment = assess_secret(&secret, production);
    match assessment.severity {
        SecretSeverity::Ok => {
            println!("{}", assessment.message);
            Ok(())
        }
        SecretSeverity::Warning => {
            eprintln!("{}", assessment.message);
            Ok(())
        }
        SecretSeverity::Error => Err(AppError::Message(assessment.message)),
    }
}
