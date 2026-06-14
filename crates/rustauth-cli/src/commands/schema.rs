use crate::app::{AppContext, AppError, SchemaFormat, SchemaPrintArgs};
use crate::output::print_json;
use crate::schema::{dialect_from_provider, full_schema_plan, target_schema};

pub fn print(context: &AppContext, args: SchemaPrintArgs) -> Result<(), AppError> {
    let (config, _config_loaded) = context.load_config_or_default()?;
    let schema = target_schema(&config)?;
    match args.format {
        SchemaFormat::Json => print_json(&schema)?,
        SchemaFormat::Sql => {
            let dialect = dialect_from_provider(&args.dialect).ok_or_else(|| {
                AppError::Message(format!("unsupported dialect `{}`", args.dialect))
            })?;
            let plan = full_schema_plan(dialect, &schema)?;
            println!("{}", plan.compile());
        }
    }
    Ok(())
}
