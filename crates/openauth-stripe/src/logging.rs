//! Stripe plugin logging.
//!
//! HTTP handlers and webhooks use [`AuthContext::logger`]. Database hooks use
//! [`PluginDatabaseHookContext::logger`] (same application logger as upstream
//! `ctx.context.logger` in Better Auth database hooks).

use openauth_core::context::AuthContext;
use openauth_core::plugin::PluginDatabaseHookContext;

pub(crate) fn hook_error(context: &PluginDatabaseHookContext<'_>, message: &str, detail: &str) {
    context.logger.error(message, &[detail]);
}

pub(crate) fn hook_warn(context: &PluginDatabaseHookContext<'_>, message: &str, detail: &str) {
    context.logger.warn(message, &[detail]);
}

pub(crate) fn init_warn(context: &AuthContext, message: &str, detail: &str) {
    context.logger.warn(message, &[detail]);
}

pub(crate) fn init_error(context: &AuthContext, message: &str, detail: &str) {
    context.logger.error(message, &[detail]);
}

pub(crate) fn webhook_error(context: &AuthContext, message: &str) {
    context.logger.error(message, &[]);
}

pub(crate) fn webhook_warn(context: &AuthContext, message: &str) {
    context.logger.warn(message, &[]);
}

pub(crate) fn webhook_info(context: &AuthContext, message: &str) {
    context.logger.info(message, &[]);
}
