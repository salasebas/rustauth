//! Static inventory of route DTO serde policies (`rustauth-core/src/api/routes/`).
//!
//! Update this table when adding or changing request/response structs. The test
//! fails if the inventory length drifts without an intentional update.

#[allow(dead_code)]
struct RouteDtoInventory {
    route: &'static str,
    struct_name: &'static str,
    direction: &'static str,
    serde_policy: &'static str,
}

const ROUTE_DTO_INVENTORY: &[RouteDtoInventory] = &[
    RouteDtoInventory {
        route: "POST /sign-in/email",
        struct_name: "SignInEmailBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\" + callbackURL rename",
    },
    RouteDtoInventory {
        route: "POST /sign-in/email",
        struct_name: "AuthTokenUserBody",
        direction: "response",
        serde_policy: "user via user_output_value (HttpUser camelCase)",
    },
    RouteDtoInventory {
        route: "GET|POST /get-session",
        struct_name: "SessionUserBody",
        direction: "response",
        serde_policy: "needsRefresh rename + session/user via output helpers",
    },
    RouteDtoInventory {
        route: "POST /sign-up/email",
        struct_name: "SignUpEmailBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\" + callbackURL rename",
    },
    RouteDtoInventory {
        route: "POST /sign-up/email",
        struct_name: "AuthTokenUserBody",
        direction: "response",
        serde_policy: "user via user_output_value (HttpUser camelCase)",
    },
    RouteDtoInventory {
        route: "POST /update-user",
        struct_name: "UpdateUserBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\" + flatten extra",
    },
    RouteDtoInventory {
        route: "POST /change-password",
        struct_name: "ChangePasswordBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "POST /set-password",
        struct_name: "SetPasswordBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "POST /request-password-reset",
        struct_name: "RequestPasswordResetBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "POST /reset-password",
        struct_name: "ResetPasswordBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "POST /change-email",
        struct_name: "ChangeEmailBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "POST /delete-user",
        struct_name: "DeleteUserBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "POST /send-verification-email",
        struct_name: "SendVerificationEmailBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "GET /list-accounts",
        struct_name: "AccountResponse",
        direction: "response",
        serde_policy: "rename_all = \"camelCase\"",
    },
    RouteDtoInventory {
        route: "GET /list-sessions",
        struct_name: "Session list",
        direction: "response",
        serde_policy: "session_to_http_value per entry",
    },
    RouteDtoInventory {
        route: "POST /sign-in/social",
        struct_name: "SocialSignInBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\" + callbackURL rename",
    },
    RouteDtoInventory {
        route: "POST /sign-in/social",
        struct_name: "SocialSessionBody",
        direction: "response",
        serde_policy: "user Value via user_response_value (HttpUser camelCase)",
    },
    RouteDtoInventory {
        route: "POST /link-social",
        struct_name: "LinkSocialBody",
        direction: "request",
        serde_policy: "rename_all = \"camelCase\" + callbackURL rename",
    },
    RouteDtoInventory {
        route: "POST /verify-email",
        struct_name: "VerifyEmailResponse",
        direction: "response",
        serde_policy: "user Value via user_response_value",
    },
    RouteDtoInventory {
        route: "POST /change-email",
        struct_name: "ChangeEmailResponse",
        direction: "response",
        serde_policy: "user Value via user_response_value",
    },
    RouteDtoInventory {
        route: "*",
        struct_name: "ApiErrorResponse",
        direction: "response",
        serde_policy: "snake_case + rename originalMessage",
    },
];

#[test]
fn route_dto_inventory_has_expected_entry_count() {
    assert_eq!(
        ROUTE_DTO_INVENTORY.len(),
        21,
        "update ROUTE_DTO_INVENTORY and docs/http-json-conventions.md when adding DTOs"
    );
}
