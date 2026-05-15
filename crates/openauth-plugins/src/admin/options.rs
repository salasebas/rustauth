use std::collections::BTreeMap;

use serde_json::json;

use super::access::{default_roles, Role};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOptions {
    pub default_role: String,
    pub admin_roles: Vec<String>,
    pub default_ban_reason: Option<String>,
    pub default_ban_expires_in: Option<i64>,
    pub impersonation_session_duration: i64,
    pub roles: BTreeMap<String, Role>,
    pub admin_user_ids: Vec<String>,
    pub banned_user_message: String,
    pub allow_impersonating_admins: bool,
    pub schema: AdminSchemaOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSchemaOptions {
    pub user_role_field: String,
    pub user_banned_field: String,
    pub user_ban_reason_field: String,
    pub user_ban_expires_field: String,
    pub session_impersonated_by_field: String,
}

impl Default for AdminOptions {
    fn default() -> Self {
        Self {
            default_role: "user".to_owned(),
            admin_roles: vec!["admin".to_owned()],
            default_ban_reason: None,
            default_ban_expires_in: None,
            impersonation_session_duration: 60 * 60,
            roles: default_roles(),
            admin_user_ids: Vec::new(),
            banned_user_message: "You have been banned from this application. Please contact support if you believe this is an error.".to_owned(),
            allow_impersonating_admins: false,
            schema: AdminSchemaOptions::default(),
        }
    }
}

impl Default for AdminSchemaOptions {
    fn default() -> Self {
        Self {
            user_role_field: "role".to_owned(),
            user_banned_field: "banned".to_owned(),
            user_ban_reason_field: "ban_reason".to_owned(),
            user_ban_expires_field: "ban_expires".to_owned(),
            session_impersonated_by_field: "impersonated_by".to_owned(),
        }
    }
}

impl AdminOptions {
    pub fn with_defaults(mut self) -> Self {
        if self.default_role.trim().is_empty() {
            self.default_role = "user".to_owned();
        }
        if self.admin_roles.is_empty() {
            self.admin_roles = vec!["admin".to_owned()];
        }
        if self.impersonation_session_duration <= 0 {
            self.impersonation_session_duration = 60 * 60;
        }
        if self.roles.is_empty() {
            self.roles = default_roles();
        }
        if self.banned_user_message.trim().is_empty() {
            self.banned_user_message = Self::default().banned_user_message;
        }
        self.schema = self.schema.with_defaults();
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        for role in &self.admin_roles {
            if !self
                .roles
                .keys()
                .any(|candidate: &String| candidate.eq_ignore_ascii_case(role))
            {
                return Err(format!(
                    "Invalid admin role `{role}`. Admin roles must be defined in roles."
                ));
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "defaultRole": self.default_role,
            "adminRoles": self.admin_roles,
            "adminUserIds": self.admin_user_ids,
            "bannedUserMessage": self.banned_user_message,
            "allowImpersonatingAdmins": self.allow_impersonating_admins,
        })
    }
}

impl AdminSchemaOptions {
    fn with_defaults(mut self) -> Self {
        let defaults = Self::default();
        if self.user_role_field.trim().is_empty() {
            self.user_role_field = defaults.user_role_field;
        }
        if self.user_banned_field.trim().is_empty() {
            self.user_banned_field = defaults.user_banned_field;
        }
        if self.user_ban_reason_field.trim().is_empty() {
            self.user_ban_reason_field = defaults.user_ban_reason_field;
        }
        if self.user_ban_expires_field.trim().is_empty() {
            self.user_ban_expires_field = defaults.user_ban_expires_field;
        }
        if self.session_impersonated_by_field.trim().is_empty() {
            self.session_impersonated_by_field = defaults.session_impersonated_by_field;
        }
        self
    }
}
