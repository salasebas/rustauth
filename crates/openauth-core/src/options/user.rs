/// User lifecycle configuration.
#[derive(Debug, Clone, Default)]
pub struct UserOptions {
    pub change_email: ChangeEmailOptions,
    pub delete_user: DeleteUserOptions,
}

/// Email change behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    pub update_email_without_verification: bool,
}

/// User deletion behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteUserOptions {
    pub enabled: bool,
}
