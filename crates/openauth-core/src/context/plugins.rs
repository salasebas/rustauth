use crate::error::OpenAuthError;
use crate::plugin::PluginInitOutput;

use super::builder::insert_social_provider;
use super::origins::{push_trusted_origin, push_unique};
use super::AuthContext;

pub(super) fn initialize_plugins(context: &mut AuthContext) -> Result<(), OpenAuthError> {
    let plugins = context.plugins.clone();
    for plugin in plugins {
        apply_plugin_output(
            context,
            &plugin.id,
            PluginInitOutput {
                schema: plugin.schema.clone(),
                rate_limit: plugin.rate_limit.clone(),
                error_codes: plugin.error_codes.clone(),
                database_hooks: plugin.database_hooks.clone(),
                migrations: plugin.migrations.clone(),
                social_providers: plugin.social_providers.clone(),
                ..PluginInitOutput::default()
            },
        )?;
        if let Some(init) = &plugin.init {
            let output = init(context)?;
            apply_plugin_output(context, &plugin.id, output)?;
        }
    }
    Ok(())
}

pub(super) fn apply_plugin_output(
    context: &mut AuthContext,
    plugin_id: &str,
    output: PluginInitOutput,
) -> Result<(), OpenAuthError> {
    for origin in output.trusted_origins {
        push_trusted_origin(&mut context.trusted_origins, origin);
    }
    for path in output.disabled_paths {
        push_unique(&mut context.disabled_paths, path);
    }
    for contribution in output.schema {
        contribution.apply(&mut context.db_schema)?;
    }
    context.rate_limit.plugin_rules.extend(output.rate_limit);
    for error_code in output.error_codes {
        error_code.validate()?;
        if let Some(existing) = context.plugin_error_codes.get(&error_code.code) {
            if existing != &error_code {
                return Err(OpenAuthError::InvalidConfig(format!(
                    "plugin `{plugin_id}` tried to register conflicting error code `{}`",
                    error_code.code
                )));
            }
            continue;
        }
        context
            .plugin_error_codes
            .insert(error_code.code.clone(), error_code);
    }
    for hook in output.database_hooks {
        let hook = hook.with_plugin_id(plugin_id);
        if context
            .plugin_database_hooks
            .iter()
            .any(|existing| existing.has_overlapping_phase(&hook))
        {
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin `{plugin_id}` tried to register duplicate database hook `{}` for {:?}",
                hook.name, hook.operation
            )));
        }
        context.plugin_database_hooks.push(hook);
    }
    for migration in output.migrations {
        if context
            .plugin_migrations
            .iter()
            .any(|existing| existing.name == migration.name)
        {
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin `{plugin_id}` tried to register duplicate migration `{}`",
                migration.name
            )));
        }
        context.plugin_migrations.push(migration);
    }
    for provider in output.social_providers {
        insert_social_provider(&mut context.social_providers, provider)?;
    }
    for (name, field) in output.user_additional_fields {
        insert_runtime_field(
            plugin_id,
            "user",
            &mut context.options.user.additional_fields,
            name,
            field,
        )?;
    }
    for (name, field) in output.session_additional_fields {
        insert_runtime_field(
            plugin_id,
            "session",
            &mut context.options.session.additional_fields,
            name,
            field,
        )?;
    }
    Ok(())
}

fn insert_runtime_field<T>(
    plugin_id: &str,
    table: &str,
    fields: &mut std::collections::BTreeMap<String, T>,
    name: String,
    field: T,
) -> Result<(), OpenAuthError>
where
    T: PartialEq,
{
    if let Some(existing) = fields.get(&name) {
        if existing == &field {
            return Ok(());
        }
        return Err(OpenAuthError::InvalidConfig(format!(
            "plugin `{plugin_id}` tried to register conflicting additional field `{name}` on `{table}`"
        )));
    }
    fields.insert(name, field);
    Ok(())
}
